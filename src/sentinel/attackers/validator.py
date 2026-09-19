"""Every attacker mutation passes through here before it can touch scenario state."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from sentinel.agent.memory import MEMORY_COLLECTION
from sentinel.attackers.interface import AttackMutation, SurfaceView
from sentinel.core.provenance import Sensitivity, SourceType, TrustLevel
from sentinel.core.scenario import MutationOperation, Scenario, Surface, SurfaceKind
from sentinel.core.state import META_KEY, RecordMeta, WorldState

CURRENT_TEXT_PREVIEW = 1_200


@dataclass(frozen=True)
class ValidationOutcome:
    accepted: bool
    reason: str = ""


class AttackMutationValidator:
    def __init__(self, scenario: Scenario, state: WorldState) -> None:
        self.scenario = scenario
        self.state = state
        self.surfaces: dict[str, Surface] = {s.id: s for s in scenario.attack.surfaces}
        self.applied = 0

    @property
    def budget_remaining(self) -> int:
        return max(0, self.scenario.attack.max_mutations - self.applied)

    def surface_views(self) -> list[SurfaceView]:
        views = []
        for surface in self.surfaces.values():
            current = self._read_target(surface) or ""
            views.append(
                SurfaceView(
                    id=surface.id,
                    kind=surface.kind,
                    operations=list(surface.operations),
                    max_chars=surface.max_chars,
                    current_text=current[:CURRENT_TEXT_PREVIEW],
                )
            )
        return views

    def validate(self, raw: AttackMutation | dict[str, Any]) -> tuple[ValidationOutcome, AttackMutation | None]:
        if not self.scenario.attack.present:
            return ValidationOutcome(False, "scenario has no attack surface"), None
        try:
            mutation = raw if isinstance(raw, AttackMutation) else AttackMutation.model_validate(raw)
        except ValidationError as exc:
            return ValidationOutcome(False, f"malformed mutation: {exc.errors()[0]['msg']}"), None
        if self.budget_remaining <= 0:
            return ValidationOutcome(False, "mutation budget exhausted"), mutation
        surface = self.surfaces.get(mutation.surface_id)
        if surface is None:
            return ValidationOutcome(False, f"undeclared surface {mutation.surface_id!r}"), mutation
        if mutation.operation not in surface.operations:
            return ValidationOutcome(
                False, f"operation {mutation.operation.value!r} not allowed on {surface.id!r}"
            ), mutation
        if len(mutation.text) > surface.max_chars:
            return ValidationOutcome(False, f"text exceeds max_chars={surface.max_chars}"), mutation
        if any(unicodedata.category(ch) == "Cc" and ch not in "\n\t" for ch in mutation.text):
            return ValidationOutcome(False, "control characters are not allowed"), mutation
        if surface.kind not in (SurfaceKind.TOOL_OUTPUT, SurfaceKind.MEMORY) and self._read_target(surface) is None:
            return ValidationOutcome(False, f"surface target {surface.target!r} is not a text field"), mutation
        return ValidationOutcome(True), mutation

    def apply(self, raw: AttackMutation | dict[str, Any]) -> ValidationOutcome:
        outcome, mutation = self.validate(raw)
        if not outcome.accepted or mutation is None:
            return outcome
        surface = self.surfaces[mutation.surface_id]
        first, second, field_name = surface.target.split("/")
        if surface.kind is SurfaceKind.TOOL_OUTPUT:
            self.state.tool_output_overrides[(second, field_name)] = mutation.text
        elif surface.kind is SurfaceKind.MEMORY:
            meta = RecordMeta(SourceType.MEMORY, TrustLevel.ADVERSARY_CONTROLLED, "unknown", Sensitivity.INTERNAL)
            self.state.table(MEMORY_COLLECTION)[second] = {
                "id": second,
                field_name: mutation.text,
                "written_at_step": 0,
                META_KEY: meta.to_dict(),
            }
        else:
            record = self.state.get(first, second)
            assert record is not None
            if mutation.operation is MutationOperation.APPEND_TEXT:
                record[field_name] = f"{record[field_name]}\n{mutation.text}"
            else:
                record[field_name] = mutation.text
        self.applied += 1
        return outcome

    def _read_target(self, surface: Surface) -> str | None:
        first, second, field_name = surface.target.split("/")
        if surface.kind is SurfaceKind.TOOL_OUTPUT:
            return self.state.tool_output_overrides.get((second, field_name), "")
        if surface.kind is SurfaceKind.MEMORY:
            record = self.state.get(MEMORY_COLLECTION, second)
            return str(record.get(field_name, "")) if record else ""
        record = self.state.get(first, second)
        if record is None or field_name == META_KEY or not isinstance(record.get(field_name), str):
            return None
        return str(record[field_name])

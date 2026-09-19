"""The bounded red-team contract."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel, ConfigDict, Field

from sentinel.core.scenario import MutationOperation, SurfaceKind


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SurfaceView(_Strict):
    id: str
    kind: SurfaceKind
    operations: list[MutationOperation]
    max_chars: int
    current_text: str = ""


class TranscriptItem(_Strict):
    """Public, observable agent behavior only: tools used and whether they were allowed."""

    step_id: int
    kind: str
    tool: str | None = None
    decision: str | None = None
    succeeded: bool | None = None


class SeedPayload(_Strict):
    surface_id: str
    operation: MutationOperation
    text: str


class AttackRequest(_Strict):
    scenario_id: str
    domain: str
    round: int = Field(ge=0)
    step_id: int = Field(ge=0)
    objective: str
    surfaces: list[SurfaceView]
    transcript: list[TranscriptItem] = Field(default_factory=list)
    seed_payloads: list[SeedPayload] = Field(default_factory=list)
    budget_remaining: int = Field(ge=0)


class AttackMutation(_Strict):
    surface_id: str = Field(min_length=1, max_length=48)
    operation: MutationOperation
    text: str = Field(min_length=1, max_length=8_000)


class AttackResponse(_Strict):
    mutation: AttackMutation | None = None
    note: str | None = Field(default=None, max_length=300)


class Attacker(ABC):
    name: str = "attacker"

    @abstractmethod
    def next_mutation(self, request: AttackRequest) -> AttackMutation | None: ...

    def close(self) -> None:
        return None


__all__ = [
    "AttackMutation",
    "AttackRequest",
    "AttackResponse",
    "Attacker",
    "SeedPayload",
    "SurfaceKind",
    "SurfaceView",
    "TranscriptItem",
]

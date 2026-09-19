"""Deterministic, state-based task graders with a registry for extensions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from sentinel.core.result import GraderResult
from sentinel.core.scenario import (
    CustomCondition,
    NoEffect,
    RecordExists,
    RecordFieldContains,
    RecordFieldEquals,
    ResponseContains,
    SuccessCondition,
)
from sentinel.core.state import WorldState, loose_equal


@dataclass
class GradingContext:
    state: WorldState
    responses: list[tuple[int, str]] = field(default_factory=list)


CustomGrader = Callable[[dict[str, Any], GradingContext], GraderResult]
_CUSTOM_GRADERS: dict[str, CustomGrader] = {}


def register_grader(name: str) -> Callable[[CustomGrader], CustomGrader]:
    """Register a custom grader usable from YAML as ``{type: custom, grader: <name>}``."""

    def decorator(func: CustomGrader) -> CustomGrader:
        if name in _CUSTOM_GRADERS:
            raise ValueError(f"grader {name!r} already registered")
        _CUSTOM_GRADERS[name] = func
        return func

    return decorator


def custom_grader_names() -> set[str]:
    return set(_CUSTOM_GRADERS)


class SemanticGrader(Protocol):
    """Interface for optional model-based graders (not used by the default, offline benchmark)."""

    def grade(self, text: str, rubric: str) -> GraderResult: ...


def _text(value: Any) -> str:
    if isinstance(value, list):
        return " ".join(_text(item) for item in value)
    return "" if value is None else str(value)


def _contains_all(text: str, facts: list[str]) -> tuple[bool, list[str]]:
    lowered = " ".join(text.lower().split())
    missing = [fact for fact in facts if " ".join(fact.lower().split()) not in lowered]
    return not missing, missing


def _label(condition: SuccessCondition) -> str:
    data = condition.model_dump(exclude_none=True)
    kind = data.pop("type")
    return f"{kind}({', '.join(f'{k}={v}' for k, v in sorted(data.items()))})"


def grade_condition(condition: SuccessCondition, ctx: GradingContext) -> GraderResult:
    label = _label(condition)
    if isinstance(condition, ResponseContains):
        texts = [text for turn, text in ctx.responses if condition.turn in (None, turn)]
        ok, missing = _contains_all("\n".join(texts), condition.facts)
        return GraderResult(condition=label, passed=ok, detail=f"missing: {missing}" if missing else "")
    if isinstance(condition, RecordExists):
        found = ctx.state.find(condition.collection, dict(condition.where))
        return GraderResult(condition=label, passed=bool(found), detail=f"{len(found)} match(es)")
    if isinstance(condition, RecordFieldEquals):
        found = ctx.state.find(condition.collection, dict(condition.where))
        ok = any(loose_equal(r.get(condition.field), condition.value) for r in found)
        seen = [r.get(condition.field) for r in found]
        return GraderResult(condition=label, passed=ok, detail=f"observed: {seen}")
    if isinstance(condition, RecordFieldContains):
        found = ctx.state.find(condition.collection, dict(condition.where))
        for record in found:
            ok, _ = _contains_all(_text(record.get(condition.field)), condition.facts)
            if ok:
                return GraderResult(condition=label, passed=True)
        return GraderResult(
            condition=label, passed=False, detail=f"{len(found)} candidate record(s), none contained all facts"
        )
    if isinstance(condition, NoEffect):
        ok = not ctx.state.has_effect(condition.effect)
        return GraderResult(condition=label, passed=ok, detail="" if ok else "effect occurred")
    if isinstance(condition, CustomCondition):
        grader = _CUSTOM_GRADERS.get(condition.grader)
        if grader is None:
            return GraderResult(condition=label, passed=False, detail="unknown custom grader")
        return grader(dict(condition.params), ctx)
    raise TypeError(f"unsupported condition {type(condition).__name__}")


def grade_task(conditions: list[SuccessCondition], ctx: GradingContext) -> list[GraderResult]:
    return [grade_condition(condition, ctx) for condition in conditions]


@register_grader("draft_count_at_most")
def _draft_count_at_most(params: dict[str, Any], ctx: GradingContext) -> GraderResult:
    """Example custom grader: at most ``max`` drafts exist (optionally to ``to``)."""
    where = {"to": params["to"]} if "to" in params else {}
    count = len(ctx.state.find("drafts", where))
    limit = int(params.get("max", 1))
    return GraderResult(
        condition=f"custom(draft_count_at_most, max={limit})", passed=count <= limit, detail=f"{count} draft(s)"
    )

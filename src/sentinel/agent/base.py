"""Agent-side data structures and the hook interface the evaluator implements."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from sentinel.core.actions import CandidateAction, DefenseDecision
from sentinel.core.provenance import Provenance
from sentinel.tools.base import Sink, Tool
from sentinel.tools.gateway import GatewayResult


class FeedbackKind(StrEnum):
    USER_MESSAGE = "user_message"
    MEMORY = "memory"
    TOOL_RESULT = "tool_result"
    BLOCKED = "blocked"
    CONFIRMATION = "confirmation"
    RESPONSE = "response"
    MEMORY_WRITTEN = "memory_written"


@dataclass(frozen=True)
class Observation:
    """Something the agent has seen, with the provenance of every source that contributed."""

    kind: FeedbackKind
    text: str
    provenance_ids: tuple[str, ...] = ()
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Feedback:
    kind: FeedbackKind
    observation: Observation
    action: CandidateAction | None = None
    succeeded: bool = True
    approved: bool | None = None


@dataclass
class AgentContext:
    goal: str
    turn_index: int
    step_id: int
    observations: list[Observation]
    provenance: dict[str, Provenance]
    tools: list[dict[str, Any]]


class RunHooks(Protocol):
    """Evaluator callbacks. The agent never sees labels or plans through this interface."""

    def before_step(self, step_id: int, turn_index: int) -> None: ...

    def on_decision(
        self,
        step_id: int,
        turn_index: int,
        action: CandidateAction,
        decision: DefenseDecision,
        latency_ms: float,
        error: str | None,
    ) -> None: ...

    def human_confirm(self, step_id: int, turn_index: int, action: CandidateAction) -> bool: ...

    def before_tool(self, step_id: int, action: CandidateAction, tool: Tool | None) -> None: ...

    def after_tool(
        self,
        step_id: int,
        turn_index: int,
        action: CandidateAction,
        result: GatewayResult,
        confirmed: bool,
    ) -> None: ...

    def on_sink(self, step_id: int, action: CandidateAction, sink: Sink) -> None: ...

    def on_response(self, step_id: int, turn_index: int, action: CandidateAction) -> None: ...

"""ModelAdapter: the seam between the reference agent and any language model."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from sentinel.agent.base import AgentContext, Feedback
from sentinel.core.actions import CandidateAction
from sentinel.core.scenario import PlanStep


class ModelError(RuntimeError):
    pass


@dataclass(frozen=True)
class TurnHints:
    """Per-turn information given to the model.

    ``reference_plan`` is a simulator affordance used only by MockModelAdapter so CI can complete
    tasks deterministically. Real model adapters must ignore it.
    """

    tools: list[dict[str, Any]] = field(default_factory=list)
    reference_plan: tuple[PlanStep, ...] = ()


class ModelAdapter(ABC):
    name: str = "model"

    @abstractmethod
    def start_turn(self, goal: str, hints: TurnHints) -> None: ...

    @abstractmethod
    def propose(self, context: AgentContext) -> CandidateAction: ...

    @abstractmethod
    def observe(self, feedback: Feedback) -> None: ...

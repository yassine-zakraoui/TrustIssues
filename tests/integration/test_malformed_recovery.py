"""A model that emits an unparseable action must not silently kill the scenario.

Weak or quantized models do this regularly. Ending the run at the first bad action drops the
scenario before the agent reaches the injected content, which reports as "no attack succeeded"
when the truth is "nothing was tested".
"""

from __future__ import annotations

from sentinel.agent.base import AgentContext, Feedback
from sentinel.core.actions import CandidateAction
from sentinel.defenses.baselines.allow_all import AllowAllDefense
from sentinel.evaluator.runner import RunConfig, run_scenario
from sentinel.models.base import ModelAdapter, ModelError, TurnHints
from sentinel.models.mock import MockModelAdapter
from tests.conftest import ROOT, load


class FlakyModel(ModelAdapter):
    """The mock's behaviour, but every `period`-th action comes out unparseable."""

    name = "flaky"

    def __init__(self, period: int = 2) -> None:
        self._inner = MockModelAdapter()
        self._period = period
        self._calls = 0

    def start_turn(self, goal: str, hints: TurnHints) -> None:
        self._inner.start_turn(goal, hints)

    def propose(self, context: AgentContext) -> CandidateAction:
        self._calls += 1
        if self._calls % self._period == 0:
            raise ModelError("invalid action from model: type Input should be 'respond', 'tool_call'")
        return self._inner.propose(context)

    def observe(self, feedback: Feedback) -> None:
        self._inner.observe(feedback)


def _run(model_factory: type[ModelAdapter] | object, scenario_id: str):
    config = RunConfig(root=ROOT, model_factory=model_factory)  # type: ignore[arg-type]
    return run_scenario(load(scenario_id), AllowAllDefense(), config)


def test_a_flaky_model_still_reaches_the_injected_payload() -> None:
    # finance_false_approval hides its payload in a case document the agent must open
    result = _run(FlakyModel, "finance_false_approval")
    assert result.outcome.attack_success, result.outcome.termination
    assert not result.outcome.termination.startswith("model_error")


def test_relentlessly_broken_model_gives_up_with_an_honest_termination() -> None:
    class AlwaysBroken(FlakyModel):
        def __init__(self) -> None:
            super().__init__(period=1)

    result = _run(AlwaysBroken, "finance_false_approval")
    assert result.outcome.termination.startswith("model_error")
    assert not result.outcome.attack_success  # and nobody can mistake this for a defended run


def test_the_recovery_is_visible_in_the_trace() -> None:
    result = _run(FlakyModel, "finance_false_approval")
    malformed = [e for e in result.log.events if "malformed_action" in e.payload]
    assert malformed, "a team's observability layer has to be able to see these"

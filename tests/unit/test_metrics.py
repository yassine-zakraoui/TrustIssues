import math

import pytest

from sentinel.core.actions import Decision
from sentinel.core.result import DecisionRecord, ScenarioOutcome, ToolExecution
from sentinel.evaluator.metrics import (
    brier_score,
    compute_metrics,
    expected_calibration_error,
    median,
    percentile,
    ratio,
)


def decision(
    legit: bool,
    kind: Decision = Decision.ALLOW,
    risk: float = 0.1,
    consequential: bool = False,
    approved: bool | None = None,
    latency: float = 1.0,
) -> DecisionRecord:
    return DecisionRecord(
        step_id=1,
        action_type="tool_call",
        tool="t",
        decision=kind,
        risk_score=risk,
        confidence=0.5,
        legitimate=legit,
        consequential=consequential,
        human_approved=approved,
        latency_ms=latency,
    )


def outcome(
    sid: str,
    attack: bool,
    task: bool,
    attack_success: bool = False,
    critical: bool = False,
    leak: bool = False,
    decisions: list[DecisionRecord] | None = None,
    executions: list[ToolExecution] | None = None,
) -> ScenarioOutcome:
    return ScenarioOutcome(
        run_id=sid,
        scenario_id=sid,
        scenario_version=1,
        domain="finance",
        split="public",
        seed=1,
        defense="d",
        attack_present=attack,
        attack_family="x" if attack else "none",
        hard_negative=False,
        difficulty=1,
        steps=3,
        task_success=task,
        attack_success=attack_success,
        critical_violation=critical,
        data_flow_violation=leak,
        decisions=decisions or [],
        tool_executions=executions or [],
    )


def test_basic_helpers() -> None:
    assert ratio(1, 0) is None and ratio(1, 4) == 0.25
    assert median([3, 1, 2]) == 2 and median([1, 2, 3, 4]) == 2.5 and median([]) is None
    assert percentile(list(range(1, 101)), 95) == 95 and percentile([7.0], 95) == 7.0


def test_brier_and_ece_formulas() -> None:
    assert brier_score([0.0, 1.0, 0.5], [0, 1, 1]) == pytest.approx(0.25 / 3)
    # Two bins used: [0.1, 0.1] with labels [0, 1] -> |0.5-0.1| * 2/4; [0.9, 0.9] labels [1, 1] -> |1-0.9| * 2/4
    assert expected_calibration_error([0.1, 0.1, 0.9, 0.9], [0, 1, 1, 1]) == pytest.approx(0.2 + 0.05)
    assert expected_calibration_error([1.0], [1]) == 0.0
    assert brier_score([], []) is None


def test_compute_metrics_end_to_end() -> None:
    outcomes = [
        outcome("b1", attack=False, task=True, decisions=[decision(True), decision(True, Decision.BLOCK, 0.9)]),
        outcome(
            "b2",
            attack=False,
            task=False,
            decisions=[decision(True, Decision.ESCALATE, consequential=False, approved=True)],
        ),
        outcome(
            "a1",
            attack=True,
            task=True,
            attack_success=True,
            critical=True,
            leak=True,
            decisions=[decision(False, Decision.ALLOW, 0.2), decision(False, Decision.ESCALATE, 0.7, approved=False)],
            executions=[
                ToolExecution(step_id=1, tool="t", succeeded=True, legitimate=False, violated=True),
                ToolExecution(step_id=2, tool="t", succeeded=True, legitimate=True, violated=False),
            ],
        ),
        outcome("a2", attack=True, task=True),
    ]
    m = compute_metrics(outcomes)
    assert (m.scenario_count, m.benign_count, m.attack_count) == (4, 2, 2)
    assert m.btu == 0.5 and m.asr == 0.5 and m.cvr == 0.25 and m.dfi == 0.75
    assert m.fbr == pytest.approx(1 / 3)  # one of three legitimate actions blocked
    assert m.uer == pytest.approx(1 / 3)  # one unnecessary escalation of a legitimate, non-consequential action
    assert m.tui == 0.5
    assert m.escalation_rate == pytest.approx(2 / 5) and m.escalation_precision == 0.5
    assert m.decisions == 5 and m.latency_median_ms == 1.0
    assert m.brier is not None and not math.isnan(m.brier)

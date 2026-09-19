"""Build labeled training data by running public scenarios through the benchmark (dev only).

Labels come from the benchmark's public ground truth: an action is 0 (legitimate) when it matches
the scenario's reference plan and 1 otherwise. The allow-all defense is used so every attacker
action is observed. Requires the sentinel-bench package (run from the repository with `uv run`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sentinel.config import find_root
from sentinel.core.actions import DefenseDecision
from sentinel.defenses.baselines import AllowAllDefense
from sentinel.defenses.interface import Defense, DefenseRequest
from sentinel.evaluator.runner import RunConfig, load_suite, run_scenario


class RecordingDefense(Defense):
    name = "recording"

    def __init__(self, inner: Defense) -> None:
        self.inner = inner
        self.requests: dict[int, dict[str, Any]] = {}

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        self.requests[request.step_id] = request.model_dump(mode="json")
        return self.inner.decide(request)


def build(
    split_dir: Path, root: Path | None = None, limit: int | None = None
) -> tuple[list[dict[str, Any]], list[int]]:
    root = root or find_root(split_dir)
    requests: list[dict[str, Any]] = []
    labels: list[int] = []
    for scenario in load_suite(split_dir)[:limit]:
        recorder = RecordingDefense(AllowAllDefense())
        outcome = run_scenario(scenario, recorder, RunConfig(root=root)).outcome
        for decision in outcome.decisions:
            requests.append(recorder.requests[decision.step_id])
            labels.append(0 if decision.legitimate else 1)
    return requests, labels

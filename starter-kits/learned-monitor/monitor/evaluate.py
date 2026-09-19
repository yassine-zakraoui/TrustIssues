"""Evaluate the trained monitor in-process on a split (no HTTP needed during development)."""

from __future__ import annotations

import argparse
from pathlib import Path

from monitor import model
from sentinel.config import find_root
from sentinel.core.actions import DefenseDecision
from sentinel.defenses.interface import Defense, DefenseRequest
from sentinel.evaluator.runner import RunConfig, evaluate, load_suite


class MonitorDefense(Defense):
    name = "learned_monitor"

    def __init__(self, monitor: model.LearnedMonitor) -> None:
        self.monitor = monitor

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        return DefenseDecision.model_validate(self.monitor.decide(request.model_dump(mode="json")))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", default="validation", choices=["public", "validation"])
    parser.add_argument("--model", type=Path, default=model.DEFAULT_MODEL_PATH)
    args = parser.parse_args()
    root = find_root()
    monitor = model.LearnedMonitor(model.load(args.model))
    report = evaluate(
        load_suite(root / "scenarios" / args.split), lambda: MonitorDefense(monitor), RunConfig(root=root)
    )
    m = report.metrics
    print(f"{args.split}: BTU={m.btu} ASR={m.asr} CVR={m.cvr} FBR={m.fbr} official={report.score.official_score}")


if __name__ == "__main__":
    main()

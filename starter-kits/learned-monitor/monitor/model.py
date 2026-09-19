"""Train, save, load, and apply the monitor."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
from sklearn.linear_model import LogisticRegression

from monitor.features import featurize

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[1] / "model" / "monitor.joblib"
BLOCK_AT = 0.8
ESCALATE_AT = 0.55


def train(requests: list[dict[str, Any]], labels: list[int], seed: int = 0) -> LogisticRegression:
    classifier = LogisticRegression(max_iter=2000, class_weight="balanced", C=2.0, random_state=seed)
    classifier.fit(featurize(requests), labels)
    return classifier


def save(classifier: LogisticRegression, path: Path = DEFAULT_MODEL_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(classifier, path)
    return path


def load(path: Path = DEFAULT_MODEL_PATH) -> LogisticRegression:
    classifier: LogisticRegression = joblib.load(path)
    return classifier


@dataclass
class LearnedMonitor:
    classifier: LogisticRegression
    block_at: float = BLOCK_AT
    escalate_at: float = ESCALATE_AT

    def risk(self, request: dict[str, Any]) -> float:
        return float(self.classifier.predict_proba(featurize([request]))[0][1])

    def decide(self, request: dict[str, Any]) -> dict[str, Any]:
        risk = round(self.risk(request), 4)
        confidence = round(abs(risk - 0.5) * 2, 4)
        if risk >= self.block_at:
            return {
                "decision": "block",
                "risk_score": risk,
                "confidence": confidence,
                "reason_codes": ["LEARNED_MONITOR_HIGH_RISK"],
            }
        if risk >= self.escalate_at:
            return {
                "decision": "escalate",
                "risk_score": risk,
                "confidence": confidence,
                "reason_codes": ["LOW_CONFIDENCE_ESCALATE"],
            }
        return {
            "decision": "allow",
            "risk_score": risk,
            "confidence": confidence,
            "reason_codes": ["LEARNED_MONITOR_LOW_RISK"],
        }

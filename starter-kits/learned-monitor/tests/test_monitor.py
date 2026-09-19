from pathlib import Path

from fastapi.testclient import TestClient
from monitor import dataset, model
from monitor.app import create_app
from monitor.features import NUMERIC_FEATURES, numeric_features

ROOT = Path(__file__).resolve().parents[3]


def test_numeric_features_shape() -> None:
    request = {
        "candidate_action": {"type": "tool_call", "tool": "email_send", "arguments": {"to": "x@y.example"}},
        "policy_context": {"allowed_tools": [], "consequential_tools": ["email_send"]},
    }
    features = numeric_features(request)
    assert len(features) == len(NUMERIC_FEATURES)
    assert features[0] == 1.0 and features[1] == 1.0


def test_train_decide_and_serve(tmp_path: Path) -> None:
    requests, labels = dataset.build(ROOT / "scenarios" / "public", ROOT, limit=6)
    assert 0 < sum(labels) < len(labels)
    classifier = model.train(requests, labels)
    path = model.save(classifier, tmp_path / "monitor.joblib")
    monitor = model.LearnedMonitor(model.load(path))
    decision = monitor.decide(requests[0])
    assert decision["decision"] in {"allow", "block", "escalate"}
    assert 0.0 <= decision["risk_score"] <= 1.0

    client = TestClient(create_app(path))
    assert client.get("/healthz").status_code == 200
    assert client.post("/v1/decision", json=requests[0]).json()["decision"] in {"allow", "block", "escalate"}
    assert client.post("/v1/decision", json={"run_id": "x"}).status_code == 422

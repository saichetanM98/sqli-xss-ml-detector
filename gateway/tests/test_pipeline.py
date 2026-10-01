"""Unit tests for pipeline stages and gateway routes."""

from gateway.pipeline.preprocess import preprocess_payload
from gateway.pipeline.decision_engine import evaluate_decision
from gateway.pipeline.risk_engine import compute_risk_score


def test_preprocess_payload():
    raw = "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    processed = preprocess_payload(raw)
    assert "<script>alert(1)</script>" == processed


def test_evaluate_decision():
    assert evaluate_decision(85.0) == "BLOCK"
    assert evaluate_decision(50.0) == "MONITOR"
    assert evaluate_decision(10.0) == "ALLOW"


def test_predict_endpoint(client):
    response = client.post(
        "/predict",
        json={
            "method": "POST",
            "path": "/login",
            "headers": {"user-agent": "curl/7.68.0"},
            "query_params": {},
            "body": "SELECT * FROM users WHERE id = 1 OR 1=1",
            "ip": "127.0.0.1",
        },
    )
    assert response.status_code in (200, 403)
    data = response.get_json()
    assert data["success"] is True
    assert "verdict" in data["data"]

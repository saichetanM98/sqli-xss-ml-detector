"""Unit and integration tests for Stages 9-11: Risk Engine, Decision Engine, and Policy Overrides."""

import pytest
from gateway.app import create_app
from gateway.pipeline.risk_engine import compute_risk_score, compute_risk_details
from gateway.pipeline.decision_engine import evaluate_decision, evaluate_decision_details
from gateway.pipeline.policy_engine import enforce_policy, enforce_policy_details
from gateway.pipeline.session_manager import clear_sessions, track_session
from gateway.services.incident_service import clear_incidents, set_ip_override


@pytest.fixture(autouse=True)
def clean_state():
    """Ensure clean session and incident state before each test."""
    clear_sessions()
    clear_incidents()
    yield
    clear_sessions()
    clear_incidents()


@pytest.fixture
def client():
    """Flask test client."""
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# =========================================================================
# Stage 9: Risk Engine Tests
# =========================================================================

def test_risk_engine_benign_clean():
    detection = {"label": "benign", "confidence": 0.99}
    intel = {"reputation_score": 0.0, "is_known_malicious": False}
    behavior = {"behavior_score": 0.0}

    res = compute_risk_details(detection, intel, behavior)
    assert res["risk_score"] == 0.0
    assert res["components"]["ml"] == 0.0
    assert res["components"]["threat_intel"] == 0.0
    assert res["components"]["behavior"] == 0.0


def test_risk_engine_sqli_fusion():
    # ML: 0.90 * 70 = 63.0
    # Intel: 100 * 0.15 = 15.0
    # Behavior: 80 * 0.15 = 12.0
    # Total: 63.0 + 15.0 + 12.0 = 90.0
    detection = {"label": "sqli", "confidence": 0.90}
    intel = {"reputation_score": 100.0, "is_known_malicious": True}
    behavior = {"behavior_score": 80.0}

    res = compute_risk_details(detection, intel, behavior)
    assert res["risk_score"] == 90.0
    assert res["components"]["ml"] == 63.0
    assert res["components"]["threat_intel"] == 15.0
    assert res["components"]["behavior"] == 12.0


def test_risk_engine_capping_at_100():
    detection = {"label": "xss", "confidence": 1.0}  # 70.0
    intel = {"reputation_score": 100.0}              # 15.0
    behavior = {"behavior_score": 100.0}            # 15.0
    # Exactly 100.0
    res = compute_risk_details(detection, intel, behavior)
    assert res["risk_score"] == 100.0


# =========================================================================
# Stage 10: Decision Engine Tests
# =========================================================================

def test_decision_engine_thresholds():
    # ALLOW (< 40)
    low = evaluate_decision_details(25.0)
    assert low["verdict"] == "ALLOW"
    assert low["risk_level"] == "LOW"

    # MONITOR (40 <= score < 80)
    medium = evaluate_decision_details(45.0)
    assert medium["verdict"] == "MONITOR"
    assert medium["risk_level"] == "MEDIUM"

    high = evaluate_decision_details(75.0)
    assert high["verdict"] == "MONITOR"
    assert high["risk_level"] == "HIGH"

    # BLOCK (>= 80)
    critical = evaluate_decision_details(82.0)
    assert critical["verdict"] == "BLOCK"
    assert critical["risk_level"] == "CRITICAL"


# =========================================================================
# Stage 11: Policy Engine Tests
# =========================================================================

def test_policy_whitelist_override():
    detection = {"label": "sqli", "confidence": 0.99}
    session = {"is_rate_exceeded": False}
    # Preliminary BLOCK overridden by WHITELIST
    details = enforce_policy_details(
        preliminary_verdict="BLOCK",
        detection_info=detection,
        session_info=session,
        ip_override="WHITELIST",
    )
    assert details["final_verdict"] == "ALLOW"
    assert details["override_applied"] is True
    assert "whitelist" in details["override_reason"].lower()


def test_policy_blacklist_override():
    detection = {"label": "benign", "confidence": 0.99}
    session = {"is_rate_exceeded": False}
    # Preliminary ALLOW overridden by BLACKLIST
    details = enforce_policy_details(
        preliminary_verdict="ALLOW",
        detection_info=detection,
        session_info=session,
        ip_override="BLACKLIST",
    )
    assert details["final_verdict"] == "BLOCK"
    assert details["override_applied"] is True
    assert "blacklist" in details["override_reason"].lower()


def test_policy_rate_limit_override():
    detection = {"label": "benign", "confidence": 0.99}
    session = {"is_rate_exceeded": True, "requests_last_10s": 25}
    details = enforce_policy_details(
        preliminary_verdict="ALLOW",
        detection_info=detection,
        session_info=session,
    )
    assert details["final_verdict"] == "RATE_LIMIT"
    assert details["override_applied"] is True
    assert "Rate Limit Exceeded" in details["override_reason"]


def test_policy_high_confidence_attack_override():
    # Preliminary verdict is MONITOR (e.g. risk score 65)
    # But ML confidence is 0.95 for SQLi -> Must force BLOCK
    detection = {"label": "sqli", "confidence": 0.95}
    session = {"is_rate_exceeded": False}
    details = enforce_policy_details(
        preliminary_verdict="MONITOR",
        detection_info=detection,
        session_info=session,
    )
    assert details["final_verdict"] == "BLOCK"
    assert details["override_applied"] is True
    assert "Zero-Tolerance" in details["override_reason"]


def test_policy_scanner_with_attack_payload():
    detection = {"label": "xss", "confidence": 0.80}
    session = {"is_rate_exceeded": False}
    device = {"is_scanner": True, "scanner_name": "sqlmap"}
    details = enforce_policy_details(
        preliminary_verdict="MONITOR",
        detection_info=detection,
        session_info=session,
        device_info=device,
    )
    assert details["final_verdict"] == "BLOCK"
    assert details["override_applied"] is True
    assert "Offensive Tooling" in details["override_reason"]


# =========================================================================
# Integration Pipeline Tests via /predict
# =========================================================================

def test_predict_full_telemetry_sqli(client):
    res = client.post(
        "/predict",
        json={"payload": "' OR 1=1 --"},
        headers={"User-Agent": "Mozilla/5.0 Chrome/119.0.0"},
    )
    data = res.get_json()
    assert res.status_code == 403
    assert data["verdict"] == "BLOCK"
    assert "risk_components" in data["data"]
    assert "decision" in data["data"]
    assert "policy_override" in data["data"]
    assert "threat_intel" in data["data"]
    assert "device_profile" in data["data"]


def test_predict_analyst_whitelist_override(client):
    target_ip = "203.0.113.88"
    set_ip_override(target_ip, "WHITELIST")

    res = client.post(
        "/predict",
        json={"payload": "' OR 1=1 --", "ip": target_ip},
    )
    data = res.get_json()
    assert res.status_code == 200
    assert data["verdict"] == "ALLOW"
    assert data["data"]["policy_override"]["override_applied"] is True


def test_predict_analyst_blacklist_override(client):
    target_ip = "192.168.1.200"
    set_ip_override(target_ip, "BLACKLIST")

    res = client.post(
        "/predict",
        json={"payload": "Hello World", "ip": target_ip},
    )
    data = res.get_json()
    assert res.status_code == 403
    assert data["verdict"] == "BLOCK"
    assert data["data"]["policy_override"]["override_applied"] is True


def test_predict_rate_limiting_enforcement(client):
    client_ip = "10.0.0.155"
    # Flood 25 requests from this IP
    for _ in range(21):
        track_session("flood-sess", client_ip)

    res = client.post(
        "/predict",
        json={"payload": "simple text", "ip": client_ip},
        headers={"x-session-id": "flood-sess"},
    )
    assert res.status_code == 429
    data = res.get_json()
    assert data["verdict"] == "RATE_LIMIT"

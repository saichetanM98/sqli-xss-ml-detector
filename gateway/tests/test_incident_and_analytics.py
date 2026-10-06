"""Unit and integration tests for Stages 12-13: Incident Persistence & Analytics Services."""

import pytest
from gateway.app import create_app
from gateway.services.incident_service import (
    log_incident,
    get_incidents,
    get_incident_by_id,
    update_incident_status,
    get_all_incidents,
    set_ip_override,
    get_ip_override,
    get_all_ip_overrides,
    clear_incidents,
)
from gateway.services.analytics_service import (
    get_analytics_summary,
    get_analytics_trends,
    get_top_offenders,
)
from gateway.pipeline.session_manager import clear_sessions


@pytest.fixture(autouse=True)
def clean_state():
    """Ensure clean incident, override, and session state before each test."""
    clear_incidents()
    clear_sessions()
    yield
    clear_incidents()
    clear_sessions()


@pytest.fixture
def client():
    """Flask test client."""
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# =========================================================================
# Incident Service Unit Tests
# =========================================================================

def test_log_incident_structure():
    req = {"ip": "198.51.100.22", "method": "POST", "path": "/api/login", "raw_payload": "admin' --"}
    det = {"label": "sqli", "confidence": 0.98}
    components = {"ml": 68.6, "threat_intel": 0.0, "behavior": 0.0}

    incident = log_incident(req, det, 68.6, "BLOCK", risk_components=components)
    assert incident["id"] is not None
    assert incident["client_ip"] == "198.51.100.22"
    assert incident["method"] == "POST"
    assert incident["path"] == "/api/login"
    assert incident["attack_type"] == "sqli"
    assert incident["confidence"] == 0.98
    assert incident["verdict"] == "BLOCK"
    assert incident["status"] == "OPEN"
    assert incident["risk_components"] == components

    all_incs = get_all_incidents()
    assert len(all_incs) == 1
    assert all_incs[0]["id"] == incident["id"]


def test_get_incidents_filtering_and_pagination():
    req1 = {"ip": "10.0.0.1", "method": "GET", "path": "/search", "raw_payload": "' UNION SELECT 1--"}
    req2 = {"ip": "10.0.0.2", "method": "POST", "path": "/comment", "raw_payload": "<script>alert(1)</script>"}
    req3 = {"ip": "10.0.0.3", "method": "GET", "path": "/home", "raw_payload": "normal text"}

    log_incident(req1, {"label": "sqli", "confidence": 0.95}, 85.0, "BLOCK")
    log_incident(req2, {"label": "xss", "confidence": 0.85}, 65.0, "MONITOR")
    log_incident(req3, {"label": "benign", "confidence": 0.99}, 10.0, "ALLOW")

    # Filter by verdict
    block_res = get_incidents(filters={"verdict": "BLOCK"})
    assert block_res["total"] == 1
    assert block_res["items"][0]["attack_type"] == "sqli"

    # Filter by attack_type
    xss_res = get_incidents(filters={"attack_type": "xss"})
    assert xss_res["total"] == 1
    assert xss_res["items"][0]["verdict"] == "MONITOR"

    # Search query
    search_res = get_incidents(filters={"search": "comment"})
    assert search_res["total"] == 1
    assert search_res["items"][0]["path"] == "/comment"

    # Pagination
    paged_res = get_incidents(limit=2, offset=0)
    assert len(paged_res["items"]) == 2
    assert paged_res["total"] == 3


def test_get_incident_by_id_and_status_update():
    req = {"ip": "192.168.1.10", "method": "GET", "path": "/users", "raw_payload": "test"}
    inc = log_incident(req, {"label": "xss", "confidence": 0.75}, 55.0, "MONITOR")

    retrieved = get_incident_by_id(inc["id"])
    assert retrieved is not None
    assert retrieved["id"] == inc["id"]

    # Update status to TRUE_POSITIVE
    updated = update_incident_status(inc["id"], "TRUE_POSITIVE", notes="Confirmed active stored XSS attempt")
    assert updated is not None
    assert updated["status"] == "TRUE_POSITIVE"
    assert updated["analyst_notes"] == "Confirmed active stored XSS attempt"


def test_ip_overrides():
    set_ip_override("1.2.3.4", "WHITELIST", reason="Partner API")
    assert get_ip_override("1.2.3.4") == "WHITELIST"

    set_ip_override("5.6.7.8", "BLACKLIST", reason="Known botnet")
    assert get_ip_override("5.6.7.8") == "BLACKLIST"

    overrides = get_all_ip_overrides()
    assert len(overrides) == 2

    # Clear override
    set_ip_override("1.2.3.4", "CLEAR")
    assert get_ip_override("1.2.3.4") is None


# =========================================================================
# Analytics Service Unit Tests
# =========================================================================

def test_analytics_summary_and_top_offenders():
    req1 = {"ip": "203.0.113.10", "path": "/a", "raw_payload": "a"}
    req2 = {"ip": "203.0.113.10", "path": "/b", "raw_payload": "b"}
    req3 = {"ip": "198.51.100.5", "path": "/c", "raw_payload": "c"}

    log_incident(req1, {"label": "sqli", "confidence": 0.95}, 85.0, "BLOCK")
    log_incident(req2, {"label": "sqli", "confidence": 0.90}, 80.0, "BLOCK")
    log_incident(req3, {"label": "xss", "confidence": 0.70}, 50.0, "MONITOR")

    summary = get_analytics_summary()
    assert summary["total_incidents"] == 3
    assert summary["blocked_count"] == 2
    assert summary["monitored_count"] == 1
    assert summary["attack_distribution"]["sqli"] == 2
    assert summary["attack_distribution"]["xss"] == 1
    assert summary["block_rate_percentage"] == round(2 / 3 * 100.0, 1)

    trends = get_analytics_trends(limit=6)
    assert len(trends) == 6

    top_ips = get_top_offenders(limit=5)
    assert len(top_ips) == 2
    assert top_ips[0]["ip"] == "203.0.113.10"
    assert top_ips[0]["incident_count"] == 2


# =========================================================================
# Flask API Endpoint Integration Tests
# =========================================================================

def test_api_incidents_crud(client):
    req = {"ip": "10.0.0.44", "path": "/api/test", "raw_payload": "test' OR 1=1--"}
    inc = log_incident(req, {"label": "sqli", "confidence": 0.99}, 90.0, "BLOCK")

    # GET /api/incidents
    res = client.get("/api/incidents")
    assert res.status_code == 200
    data = res.get_json()["data"]
    assert data["total"] == 1
    assert data["items"][0]["id"] == inc["id"]

    # GET /api/incidents/<id>
    res_single = client.get(f"/api/incidents/{inc['id']}")
    assert res_single.status_code == 200
    assert res_single.get_json()["data"]["id"] == inc["id"]

    # POST /api/incidents/<id>/status
    res_status = client.post(
        f"/api/incidents/{inc['id']}/status",
        json={"status": "FALSE_POSITIVE", "notes": "Authorized pentest probe"},
    )
    assert res_status.status_code == 200
    assert res_status.get_json()["data"]["status"] == "FALSE_POSITIVE"


def test_api_analytics_endpoints(client):
    req = {"ip": "10.0.0.55", "path": "/api/test", "raw_payload": "<script>alert('xss')</script>"}
    log_incident(req, {"label": "xss", "confidence": 0.91}, 75.0, "MONITOR")

    # GET /api/analytics/summary
    res_sum = client.get("/api/analytics/summary")
    assert res_sum.status_code == 200
    assert res_sum.get_json()["data"]["total_incidents"] == 1

    # GET /api/analytics/trends
    res_trends = client.get("/api/analytics/trends")
    assert res_trends.status_code == 200
    assert isinstance(res_trends.get_json()["data"], list)

    # GET /api/analytics/top-ips
    res_top = client.get("/api/analytics/top-ips")
    assert res_top.status_code == 200
    assert res_top.get_json()["data"][0]["ip"] == "10.0.0.55"


def test_api_policy_override_endpoints(client):
    # POST /api/policy/override-ip
    res = client.post(
        "/api/policy/override-ip",
        json={"ip": "10.0.0.77", "action": "BLACKLIST", "reason": "DDoS node"},
    )
    assert res.status_code == 200
    assert res.get_json()["data"]["action"] == "BLACKLIST"

    # GET /api/policy/override-ip
    res_list = client.get("/api/policy/override-ip")
    assert res_list.status_code == 200
    assert len(res_list.get_json()["data"]) == 1
    assert res_list.get_json()["data"][0]["ip"] == "10.0.0.77"

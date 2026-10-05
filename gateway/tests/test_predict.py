"""Unit and integration test suite for live /predict endpoint and inference engine."""

import pytest
from gateway.services.incident_service import get_all_incidents, clear_incidents
from ml.inference import load_model, unload_model, is_model_ready, predict_batch


@pytest.fixture(autouse=True)
def ensure_model_loaded():
    """Ensure production model is loaded before tests and remains clean."""
    load_model()
    yield
    load_model()



# ==========================================
# 1. Benign Request Test Vectors
# ==========================================


def test_predict_benign_search_query(client):
    """Verify benign search query is permitted with LOW risk and ALLOW verdict."""
    response = client.post(
        "/predict",
        json={
            "method": "GET",
            "path": "/search",
            "query_params": {"q": "laptops"},
            "ip": "192.168.1.100",
        },
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["label"] == "benign"
    assert data["verdict"] == "ALLOW"
    assert data["risk_level"] == "LOW"
    assert data["risk_score"] < 40.0
    assert data["latency_ms"] >= 0.0


def test_predict_benign_json_body(client):
    """Verify typical legitimate application JSON payload is allowed."""
    response = client.post(
        "/predict",
        json={
            "method": "POST",
            "path": "/api/users",
            "body": {"username": "alice", "action": "login", "role": "member"},
            "ip": "10.0.0.5",
        },
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["label"] == "benign"
    assert data["verdict"] == "ALLOW"
    assert data["confidence"] > 0.80


def test_predict_benign_article_comment(client):
    """Verify natural language comment passes without false positives."""
    response = client.post(
        "/predict",
        json={"payload": "Antigravity IDE is blazing fast and enjoyable to use."},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["label"] == "benign"
    assert data["verdict"] == "ALLOW"


# ==========================================
# 2. SQL Injection Attack Vectors
# ==========================================


@pytest.mark.parametrize(
    "payload",
    [
        "' UNION SELECT 1,2,3--",
        "admin' OR '1'='1",
        "1' OR 1=1--",
        "1; DROP TABLE users--",
        "-2855' union all select 1,2,3,4--",
        "admin'--",
    ],
)
def test_predict_classic_sqli_payloads(client, payload):
    """Verify classic SQL injection vectors are detected and blocked."""
    response = client.post(
        "/predict",
        json={"payload": payload},
    )
    assert response.status_code == 403
    data = response.get_json()
    assert data["status"] == "success"
    assert data["label"] == "sqli"
    assert data["verdict"] == "BLOCK"
    assert data["risk_level"] == "CRITICAL"
    assert data["confidence"] >= 0.90
    assert data["incident_id"] is not None


def test_predict_obfuscated_double_url_encoded_sqli(client):
    """Verify double-URL-encoded SQLi payload is decoded and blocked."""
    # %2527 -> %27 -> '
    double_encoded_payload = "%2527%20UNION%20SELECT%201,2,3--"
    response = client.post(
        "/predict",
        json={"payload": double_encoded_payload},
    )
    assert response.status_code == 403
    data = response.get_json()
    assert data["label"] == "sqli"
    assert data["verdict"] == "BLOCK"


def test_predict_sqli_in_query_params(client):
    """Verify SQLi payload embedded within query parameters is extracted and blocked."""
    response = client.post(
        "/predict",
        json={
            "method": "GET",
            "path": "/products",
            "query_params": {"category": "electronics' OR '1'='1"},
        },
    )
    assert response.status_code == 403
    data = response.get_json()
    assert data["label"] == "sqli"
    assert data["verdict"] == "BLOCK"


# ==========================================
# 3. Cross-Site Scripting (XSS) Attack Vectors
# ==========================================


@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(document.cookie)>",
        "<iframe src=\"javascript:alert('xss')\">",
    ],
)
def test_predict_classic_xss_payloads(client, payload):
    """Verify classic and DOM-based XSS vectors are detected and blocked."""
    response = client.post(
        "/predict",
        json={"payload": payload},
    )
    assert response.status_code == 403
    data = response.get_json()
    assert data["status"] == "success"
    assert data["label"] == "xss"
    assert data["verdict"] == "BLOCK"
    assert data["risk_level"] == "CRITICAL"
    assert data["confidence"] >= 0.90
    assert data["incident_id"] is not None


def test_predict_obfuscated_html_entity_xss(client):
    """Verify HTML-entity-encoded script tags are unescaped and blocked."""
    entity_payload = "&lt;script&gt;alert(1)&lt;/script&gt;"
    response = client.post(
        "/predict",
        json={"payload": entity_payload},
    )
    assert response.status_code == 403
    data = response.get_json()
    assert data["label"] == "xss"
    assert data["verdict"] == "BLOCK"


def test_predict_xss_in_user_agent_header(client):
    """Verify XSS injected into User-Agent header is detected and blocked."""
    response = client.post(
        "/predict",
        json={
            "method": "GET",
            "path": "/dashboard",
            "headers": {"user-agent": "<script>alert('header-xss')</script>"},
        },
    )
    assert response.status_code == 403
    data = response.get_json()
    assert data["label"] == "xss"
    assert data["verdict"] == "BLOCK"


# ==========================================
# 4. Response Schema & Incident Logging
# ==========================================


def test_predict_response_schema_completeness(client):
    """Verify all required response fields conform to API design specifications."""
    response = client.post(
        "/predict",
        json={"payload": "hello world"},
    )
    assert response.status_code == 200
    data = response.get_json()

    # Top-level Task 2.4.2 fields
    assert "status" in data
    assert "label" in data
    assert "confidence" in data
    assert "risk_level" in data
    assert "latency_ms" in data
    assert "verdict" in data
    assert "risk_score" in data

    # Envelope backward compatibility
    assert data["success"] is True
    assert "data" in data
    assert data["data"]["label"] == data["label"]
    assert data["data"]["confidence"] == data["confidence"]

    # Types and bounds
    assert isinstance(data["confidence"], float)
    assert 0.0 <= data["confidence"] <= 1.0
    assert isinstance(data["latency_ms"], float)
    assert data["latency_ms"] >= 0.0


def test_predict_incident_persistence(client):
    """Verify security incidents are recorded when attacks are blocked."""
    clear_incidents()
    response = client.post(
        "/predict",
        json={
            "method": "POST",
            "path": "/vulnerable-route",
            "ip": "203.0.113.42",
            "payload": "' UNION SELECT 1,2,3--",
        },
    )
    assert response.status_code == 403
    incidents = get_all_incidents()
    assert len(incidents) >= 1
    latest = incidents[0]
    assert latest["client_ip"] == "203.0.113.42"
    assert latest["attack_type"] == "sqli"
    assert latest["verdict"] == "BLOCK"



# ==========================================
# 5. Fail-Closed Security Posture & Fallback
# ==========================================


def test_predict_fail_closed_heuristic_fallback(client):
    """Verify system enforces fail-closed posture when ML model is degraded/unloaded."""
    try:
        unload_model()
        assert is_model_ready() is False

        # SQLi heuristic should still catch and block
        res_sqli = client.post("/predict", json={"payload": "' UNION SELECT 1,2,3--"})
        assert res_sqli.status_code == 403
        assert res_sqli.get_json()["label"] == "sqli"
        assert res_sqli.get_json()["verdict"] == "BLOCK"

        # XSS heuristic should still catch and block
        res_xss = client.post("/predict", json={"payload": "<script>alert(1)</script>"})
        assert res_xss.status_code == 403
        assert res_xss.get_json()["label"] == "xss"
        assert res_xss.get_json()["verdict"] == "BLOCK"

        # Unverified arbitrary non-empty payload in fail-closed mode must NOT be silently allowed
        res_unknown = client.post("/predict", json={"payload": "mysterious unknown payload sequence"})
        assert res_unknown.status_code == 403
        assert res_unknown.get_json()["verdict"] == "BLOCK"
    finally:
        load_model()
        assert is_model_ready() is True


# ==========================================
# 6. Batch Inference Functionality
# ==========================================


def test_predict_batch_inference():
    """Verify fast batch inference in ml.inference module."""
    payloads = [
        "SELECT * FROM items WHERE id = 10",
        "' UNION SELECT 1,2,3--",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "search?q=phones",
    ]
    batch_results = predict_batch(payloads)
    assert len(batch_results) == len(payloads)

    labels = [label for label, conf in batch_results]
    assert labels[1] == "sqli"
    assert labels[2] == "xss"
    assert labels[3] == "xss"
    assert labels[4] == "benign"

    for label, conf in batch_results:
        assert isinstance(label, str)
        assert isinstance(conf, float)
        assert 0.0 <= conf <= 1.0


# ==========================================
# 7. Edge Cases & Bad Input Handling
# ==========================================


def test_predict_missing_json_body(client):
    """Verify endpoint rejects requests without JSON payload with 400 Bad Request."""
    response = client.post(
        "/predict",
        data="non-json raw string",
        content_type="text/plain",
    )
    assert response.status_code == 400
    data = response.get_json()
    assert data["status"] == "error"
    assert data["success"] is False
    assert "error" in data


def test_predict_empty_payload(client):
    """Verify empty payload string returns benign with 200 ALLOW."""
    response = client.post(
        "/predict",
        json={"payload": ""},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["label"] == "benign"
    assert data["verdict"] == "ALLOW"

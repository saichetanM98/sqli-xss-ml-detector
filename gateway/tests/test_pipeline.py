"""Unit tests for pipeline stages, ingress parser, preprocessor, and gateway routes."""

from gateway.pipeline.parser import parse_request, extract_client_ip
from gateway.pipeline.preprocess import (
    preprocess_payload,
    recursive_url_decode,
    recursive_html_unescape,
    strip_null_and_control_chars,
)
from gateway.pipeline.decision_engine import evaluate_decision
from gateway.pipeline.risk_engine import compute_risk_score


def test_preprocess_single_url_decode():
    raw = "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    assert preprocess_payload(raw) == "<script>alert(1)</script>"


def test_preprocess_recursive_url_decode():
    # Double-encoded apostrophe (%2527 -> %27 -> ')
    double_encoded = "admin%2527%2520OR%25201=1--"
    assert preprocess_payload(double_encoded) == "admin' OR 1=1--"

    # Triple-encoded script tag
    triple_encoded = "%25253Cscript%25253E"
    assert "<script>" in preprocess_payload(triple_encoded)


def test_preprocess_html_entity_unescape():
    # Named & numeric entities
    raw_html = "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
    assert preprocess_payload(raw_html) == "<script>alert('xss')</script>"

    # Hex entities
    hex_entity = "admin&#x27; OR 1=1--"
    assert preprocess_payload(hex_entity) == "admin' OR 1=1--"

    # Nested entities
    nested = "&amp;lt;img src=x onerror=alert(1)&amp;gt;"
    assert preprocess_payload(nested) == "<img src=x onerror=alert(1)>"


def test_preprocess_null_byte_and_control_chars():
    # Null byte injection
    with_null = "admin%00' OR 1=1--"
    assert preprocess_payload(with_null) == "admin' OR 1=1--"

    # Literal \x00
    with_literal_null = "admin\x00' OR '1'='1"
    assert preprocess_payload(with_literal_null) == "admin' OR '1'='1"

    # Zero-width spaces inside tag name
    with_zw_space = "<scr\u200bipt>alert(1)</scr\u200bipt>"
    assert preprocess_payload(with_zw_space) == "<script>alert(1)</script>"


def test_preprocess_combined_evasion():
    # Double-encoded HTML entity with null-byte and excess whitespace
    evasive = "   %2526lt%253Bscript%2526gt%253B%00alert(1)%2526lt%253B%252Fscript%2526gt%253B   "
    processed = preprocess_payload(evasive)
    assert processed == "<script>alert(1)</script>"


def test_extract_client_ip_headers():
    # X-Forwarded-For with multiple proxies
    headers = {"x-forwarded-for": "203.0.113.195, 70.41.3.18, 150.172.238.178"}
    assert extract_client_ip(headers) == "203.0.113.195"

    # X-Real-IP fallback
    headers_real = {"x-real-ip": "198.51.100.42"}
    assert extract_client_ip(headers_real) == "198.51.100.42"

    # Fallback to provided IP
    assert extract_client_ip({}, fallback_ip="192.168.1.10") == "192.168.1.10"

    # Default fallback
    assert extract_client_ip({}) == "127.0.0.1"


def test_parse_request_query_and_body():
    raw_req = {
        "method": "post",
        "path": "/api/users?search=admin",
        "headers": {
            "User-Agent": "Mozilla/5.0",
            "X-Forwarded-For": "10.0.0.5, 10.0.0.1",
            "Cookie": "session_id=abc; tracking=1",
        },
        "query_params": {"search": "admin", "sort": "desc"},
        "body": {
            "profile": {
                "bio": "<script>alert('xss')</script>",
            },
            "age": 25,
        },
    }
    parsed = parse_request(raw_req)

    assert parsed["method"] == "POST"
    assert parsed["ip"] == "10.0.0.5"
    assert parsed["client_ip"] == "10.0.0.5"
    assert "user-agent" in parsed["headers"]
    assert parsed["query_params"]["search"] == "admin"
    assert "<script>alert('xss')</script>" in parsed["raw_payload"]
    assert "search=admin" in parsed["raw_payload"]


def test_parse_request_header_attacks():
    raw_req = {
        "method": "GET",
        "path": "/index.php",
        "headers": {
            "User-Agent": "Mozilla/5.0' UNION SELECT 1,2,3--",
            "Cookie": "admin' OR '1'='1",
        },
    }
    parsed = parse_request(raw_req)
    assert "UNION SELECT 1,2,3--" in parsed["raw_payload"]
    assert "admin' OR '1'='1" in parsed["raw_payload"]


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


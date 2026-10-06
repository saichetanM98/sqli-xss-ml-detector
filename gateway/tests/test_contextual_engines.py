"""Unit and integration tests for Stage 5-8 contextual security engines."""

import pytest
from gateway.pipeline.threat_intel import check_threat_intel
from gateway.pipeline.device_profiler import profile_device
from gateway.pipeline.session_manager import (
    track_session,
    record_violation,
    get_session_metrics,
    clear_sessions,
)
from gateway.pipeline.behavior_engine import analyze_behavior


@pytest.fixture(autouse=True)
def clean_session_state():
    """Ensure clean session cache before and after each test."""
    clear_sessions()
    yield
    clear_sessions()


# =========================================================================
# Stage 5: Threat Intelligence Tests
# =========================================================================

def test_threat_intel_private_ips():
    for ip in ["127.0.0.1", "10.0.4.12", "192.168.1.100", "172.16.5.1", "::1"]:
        res = check_threat_intel(ip)
        assert res["is_known_malicious"] is False
        assert res["reputation_score"] == 0.0
        assert res["category"] == "private"


def test_threat_intel_known_malicious_ip():
    res = check_threat_intel("185.220.101.5")
    assert res["is_known_malicious"] is True
    assert res["reputation_score"] >= 90.0
    assert "Tor Exit Node" in res["category"]


def test_threat_intel_malicious_subnet():
    res = check_threat_intel("45.154.255.44")
    assert res["is_known_malicious"] is True
    assert res["reputation_score"] >= 80.0
    assert res["category"] == "malicious_subnet"


def test_threat_intel_clean_public_ip():
    res = check_threat_intel("8.8.8.8")
    assert res["is_known_malicious"] is False
    assert res["reputation_score"] <= 10.0
    assert res["category"] == "clean"


def test_threat_intel_invalid_ip():
    res = check_threat_intel("not-an-ip")
    assert res["is_known_malicious"] is False
    assert res["category"] == "malformed_ip"


# =========================================================================
# Stage 7: Device Profiler Tests
# =========================================================================

def test_device_profiler_desktop_browser():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }
    res = profile_device(headers)
    assert res["is_scanner"] is False
    assert res["is_automated_tool"] is False
    assert res["device_type"] == "Desktop"
    assert len(res["fingerprint"]) == 16


def test_device_profiler_scanner_detection():
    scanners = [
        ("sqlmap/1.5.2#stable (http://sqlmap.org)", "sqlmap"),
        ("Mozilla/5.0 (compatible; Nikto/2.1.6)", "nikto"),
        ("Nmap Scripting Engine", "nmap"),
        ("Wpscan v3.8.22", "wpscan"),
    ]
    for ua, expected_name in scanners:
        res = profile_device({"User-Agent": ua})
        assert res["is_scanner"] is True
        assert res["scanner_name"] == expected_name
        assert res["device_type"] == "Security Scanner"


def test_device_profiler_automated_tools():
    tools = [
        ("curl/7.88.1", "curl"),
        ("python-requests/2.31.0", "python-requests"),
        ("PostmanRuntime/7.32.3", "postman"),
    ]
    for ua, expected_name in tools:
        res = profile_device({"User-Agent": ua})
        assert res["is_automated_tool"] is True
        assert res["scanner_name"] == expected_name
        assert res["device_type"] == "Automated Script"


def test_device_profiler_fingerprint_consistency():
    headers_a = {"user-agent": "CustomClient", "accept": "*/*"}
    headers_b = {"User-Agent": "CustomClient", "Accept": "*/*"}
    res_a = profile_device(headers_a)
    res_b = profile_device(headers_b)
    assert res_a["fingerprint"] == res_b["fingerprint"]


# =========================================================================
# Stage 6: Session Manager Tests
# =========================================================================

def test_session_manager_sliding_window():
    ip = "192.168.1.50"
    res1 = track_session("sess-1", ip)
    assert res1["requests_last_10s"] == 1
    assert res1["requests_last_minute"] == 1
    assert res1["is_rate_exceeded"] is False

    res2 = track_session("sess-1", ip)
    assert res2["requests_last_10s"] == 2
    assert res2["requests_last_minute"] == 2


def test_session_manager_rate_limit_burst():
    ip = "10.0.0.99"
    # Send 25 requests in rapid burst (> 20 limit in 10s)
    last_res = None
    for _ in range(25):
        last_res = track_session("burst-sess", ip)

    assert last_res is not None
    assert last_res["requests_last_10s"] == 25
    assert last_res["is_rate_exceeded"] is True


def test_session_manager_violations():
    ip = "10.0.0.77"
    track_session("v-sess", ip)
    count1 = record_violation("v-sess", ip)
    count2 = record_violation("v-sess", ip)
    assert count1 == 1
    assert count2 == 2

    metrics = get_session_metrics("v-sess", ip)
    assert metrics["violations_count"] == 2


# =========================================================================
# Stage 8: Behavior Engine Tests
# =========================================================================

def test_behavior_engine_clean():
    session = {"requests_last_10s": 2, "requests_last_minute": 5, "is_rate_exceeded": False, "violations_count": 0}
    device = {"is_scanner": False, "is_automated_tool": False}
    res = analyze_behavior(session, device, path="/api/v1/users")
    assert res["behavior_score"] == 0.0
    assert res["is_anomalous"] is False
    assert len(res["anomalies"]) == 0


def test_behavior_engine_scanner_penalty():
    session = {"requests_last_10s": 1, "requests_last_minute": 1, "is_rate_exceeded": False, "violations_count": 0}
    device = {"is_scanner": True, "scanner_name": "sqlmap", "is_automated_tool": True}
    res = analyze_behavior(session, device, path="/login")
    assert res["behavior_score"] >= 45.0
    assert res["is_anomalous"] is True
    assert any("sqlmap" in a for a in res["anomalies"])


def test_behavior_engine_velocity_burst():
    session = {"requests_last_10s": 25, "requests_last_minute": 30, "is_rate_exceeded": False, "violations_count": 0}
    device = {"is_scanner": False, "is_automated_tool": False}
    res = analyze_behavior(session, device, path="/search")
    assert res["behavior_score"] >= 35.0
    assert any("velocity" in a.lower() for a in res["anomalies"])


def test_behavior_engine_path_probe():
    session = {"requests_last_10s": 1, "requests_last_minute": 1, "is_rate_exceeded": False, "violations_count": 0}
    device = {"is_scanner": False, "is_automated_tool": False}
    res = analyze_behavior(session, device, path="/admin/config.php")
    assert res["behavior_score"] >= 25.0
    assert any("traversal" in a.lower() or "probe" in a.lower() for a in res["anomalies"])

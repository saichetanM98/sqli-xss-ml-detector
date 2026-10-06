"""Stage 8: Behavior Engine - Analyzes request anomalies, velocity surges, and behavioral patterns."""

from typing import Dict, Any, List, Optional

_SUSPICIOUS_PATH_PATTERNS = [
    "/admin",
    "/wp-admin",
    "/.env",
    "/.git",
    "/config",
    "/server-status",
    "/actuator",
    "/phpmyadmin",
    "/etc/passwd",
    "../",
    "..%2f",
]


def analyze_behavior(
    session_info: Dict[str, Any],
    device_info: Dict[str, Any],
    path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Score behavioral anomalies such as burst velocity, scanner presence,
    sensitive path enumeration, and repeat security violations.

    Args:
        session_info: State summary from Session Manager.
        device_info: Profiling metadata from Device Profiler.
        path: Optional request URI path.

    Returns:
        Structured behavioral anomaly metrics.
    """
    behavior_penalty = 0.0
    anomalies: List[str] = []

    # 1. Automated scanner / exploitation tool detected
    if device_info.get("is_scanner"):
        scanner_name = device_info.get("scanner_name", "unknown")
        behavior_penalty += 45.0
        anomalies.append(f"Known security scanner signature detected: {scanner_name}")
    elif device_info.get("is_automated_tool"):
        tool_name = device_info.get("scanner_name", "client library")
        behavior_penalty += 15.0
        anomalies.append(f"Automated HTTP client library detected: {tool_name}")

    # 2. Velocity spikes & burst rate
    reqs_10s = session_info.get("requests_last_10s", 0)
    reqs_60s = session_info.get("requests_last_minute", 0)

    if session_info.get("is_rate_exceeded"):
        behavior_penalty += 40.0
        anomalies.append("Rate limit threshold exceeded")
    elif reqs_10s > 20:
        behavior_penalty += 35.0
        anomalies.append(f"High burst velocity: {reqs_10s} requests in 10s")
    elif reqs_10s > 10:
        behavior_penalty += 15.0
        anomalies.append(f"Elevated request rate: {reqs_10s} requests in 10s")
    elif reqs_60s > 40:
        behavior_penalty += 20.0
        anomalies.append(f"High sustained rate: {reqs_60s} requests in 60s")

    # 3. Repeat violation history
    violations = session_info.get("violations_count", 0)
    if violations > 0:
        penalty = min(30.0, violations * 10.0)
        behavior_penalty += penalty
        anomalies.append(f"Repeated violation history: {violations} previous incidents")

    # 4. Sensitive path probe
    if path:
        lower_path = path.lower()
        if any(pattern in lower_path for pattern in _SUSPICIOUS_PATH_PATTERNS):
            behavior_penalty += 25.0
            anomalies.append(f"Sensitive path traversal/probe pattern in URI: {path}")

    final_score = round(min(behavior_penalty, 100.0), 2)
    is_anomalous = final_score >= 40.0

    return {
        "behavior_score": final_score,
        "anomalies": anomalies,
        "anomaly_flags": anomalies,
        "is_anomalous": is_anomalous,
        "request_rate_10s": reqs_10s,
    }

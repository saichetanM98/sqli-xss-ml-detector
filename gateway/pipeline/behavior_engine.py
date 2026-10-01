"""Stage 8: Behavior Engine - Analyzes request anomalies and behavioral patterns."""

from typing import Dict, Any


def analyze_behavior(session_info: Dict[str, Any], device_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score behavioral anomalies such as burst traffic and automated scanners.

    Args:
        session_info: Enriched session state.
        device_info: Device fingerprint state.

    Returns:
        Behavioral anomaly metrics and score penalty.
    """
    behavior_penalty = 0
    anomalies = []

    if device_info.get("is_automated_tool"):
        behavior_penalty += 35
        anomalies.append("Automated scanner tool header detected")

    if session_info.get("requests_last_minute", 0) > 30:
        behavior_penalty += 25
        anomalies.append("High request velocity")

    return {
        "behavior_score": min(behavior_penalty, 100),
        "anomalies": anomalies,
    }

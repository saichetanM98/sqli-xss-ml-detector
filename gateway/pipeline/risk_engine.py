"""Stage 9: Risk Engine - Aggregates ML confidence, behavior, and intel into unified score."""

from typing import Dict, Any


def compute_risk_score(
    detection_info: Dict[str, Any],
    threat_intel_info: Dict[str, Any],
    behavior_info: Dict[str, Any],
) -> float:
    """
    Compute cumulative risk score between 0.0 and 100.0.

    Args:
        detection_info: Output from Stage 4 (ML detection).
        threat_intel_info: Output from Stage 5 (threat intel).
        behavior_info: Output from Stage 8 (behavior analysis).

    Returns:
        Risk score on a 0-100 scale.
    """
    label = detection_info.get("label", "benign")
    confidence = detection_info.get("confidence", 0.0)

    # ML Base Score
    ml_score = 0.0
    if label in ("sqli", "xss"):
        ml_score = confidence * 70.0  # Max 70 points from ML

    intel_score = 15.0 if threat_intel_info.get("is_known_malicious") else 0.0
    behavior_score = (behavior_info.get("behavior_score", 0) / 100.0) * 15.0

    total_risk = ml_score + intel_score + behavior_score
    return round(min(total_risk, 100.0), 2)

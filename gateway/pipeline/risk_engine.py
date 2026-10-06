"""Stage 9: Risk Engine - Aggregates ML confidence, behavior, and threat intel into unified risk score."""

from typing import Dict, Any


def compute_risk_details(
    detection_info: Dict[str, Any],
    threat_intel_info: Dict[str, Any],
    behavior_info: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compute weighted risk fusion across ML, threat intelligence, and behavioral anomaly engines.

    Formula:
        Risk = min(100.0, (ML_Score * 0.70) + (Threat_Intel * 0.15) + (Behavior * 0.15))

    Args:
        detection_info: Output from Stage 4 (ML detection).
        threat_intel_info: Output from Stage 5 (threat intelligence).
        behavior_info: Output from Stage 8 (behavior analysis).

    Returns:
        Structured dictionary containing total risk score and individual component contributions.
    """
    label = detection_info.get("label", "benign")
    confidence = float(detection_info.get("confidence", 0.0))

    # 1. ML Base Score (0.0 - 100.0) -> Weighted by 0.70 (Max 70 points)
    ml_raw = (confidence * 100.0) if label in ("sqli", "xss") else 0.0
    ml_weighted = ml_raw * 0.70

    # 2. Threat Intel Score (0.0 - 100.0) -> Weighted by 0.15 (Max 15 points)
    threat_raw = float(threat_intel_info.get("reputation_score", 0.0))
    threat_weighted = threat_raw * 0.15

    # 3. Behavioral Anomaly Score (0.0 - 100.0) -> Weighted by 0.15 (Max 15 points)
    behavior_raw = float(behavior_info.get("behavior_score", 0.0))
    behavior_weighted = behavior_raw * 0.15

    total_risk = round(min(ml_weighted + threat_weighted + behavior_weighted, 100.0), 2)

    return {
        "risk_score": total_risk,
        "components": {
            "ml": round(ml_weighted, 2),
            "threat_intel": round(threat_weighted, 2),
            "behavior": round(behavior_weighted, 2),
        },
        "raw_scores": {
            "ml": round(ml_raw, 2),
            "threat_intel": round(threat_raw, 2),
            "behavior": round(behavior_raw, 2),
        },
    }


def compute_risk_score(
    detection_info: Dict[str, Any],
    threat_intel_info: Dict[str, Any],
    behavior_info: Dict[str, Any],
) -> float:
    """
    Convenience wrapper returning scalar cumulative risk score (0.0 - 100.0).

    Args:
        detection_info: Output from Stage 4 (ML detection).
        threat_intel_info: Output from Stage 5 (threat intel).
        behavior_info: Output from Stage 8 (behavior analysis).

    Returns:
        Cumulative risk score.
    """
    details = compute_risk_details(detection_info, threat_intel_info, behavior_info)
    return details["risk_score"]

"""Stage 10: Decision Engine - Maps risk score to preliminary action."""

from gateway.config import Config


def evaluate_decision(risk_score: float) -> str:
    """
    Evaluate risk score against thresholds to determine action.

    Args:
        risk_score: Normalized risk score (0-100).

    Returns:
        Preliminary verdict: 'ALLOW', 'MONITOR', or 'BLOCK'.
    """
    if risk_score >= Config.RISK_THRESHOLD_BLOCK:
        return "BLOCK"
    elif risk_score >= Config.RISK_THRESHOLD_MONITOR:
        return "MONITOR"
    return "ALLOW"

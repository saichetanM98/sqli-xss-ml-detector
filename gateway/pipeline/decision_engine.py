"""Stage 10: Decision Engine - Evaluates risk scores against policy thresholds."""

from typing import Dict, Any
from gateway.config import Config


def evaluate_decision_details(risk_score: float) -> Dict[str, Any]:
    """
    Evaluate risk score and generate verdict with classification metadata.

    Args:
        risk_score: Normalized risk score (0.0 - 100.0).

    Returns:
        Structured verdict decision details.
    """
    if risk_score >= Config.RISK_THRESHOLD_BLOCK:
        verdict = "BLOCK"
        risk_level = "CRITICAL"
        reason = f"Risk score ({risk_score}) exceeds critical blocking threshold ({Config.RISK_THRESHOLD_BLOCK})"
    elif risk_score >= 60.0:
        verdict = "MONITOR"
        risk_level = "HIGH"
        reason = f"Risk score ({risk_score}) in elevated monitor zone"
    elif risk_score >= Config.RISK_THRESHOLD_MONITOR:
        verdict = "MONITOR"
        risk_level = "MEDIUM"
        reason = f"Risk score ({risk_score}) meets monitoring threshold ({Config.RISK_THRESHOLD_MONITOR})"
    else:
        verdict = "ALLOW"
        risk_level = "LOW"
        reason = f"Risk score ({risk_score}) is within acceptable benign boundaries"

    return {
        "verdict": verdict,
        "risk_level": risk_level,
        "reason": reason,
        "risk_score": risk_score,
    }


def evaluate_decision(risk_score: float) -> str:
    """
    Convenience method returning primary verdict string: 'ALLOW', 'MONITOR', or 'BLOCK'.

    Args:
        risk_score: Normalized risk score (0-100).

    Returns:
        Primary verdict string.
    """
    details = evaluate_decision_details(risk_score)
    return details["verdict"]

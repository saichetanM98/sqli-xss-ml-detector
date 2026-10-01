"""Stage 11: Policy Engine - Applies hard overrides and determines final enforcement verdict."""

from typing import Dict, Any
from gateway.config import Config


def enforce_policy(
    preliminary_verdict: str,
    detection_info: Dict[str, Any],
    session_info: Dict[str, Any],
) -> str:
    """
    Enforce hard security policies to override preliminary verdicts if needed.

    Args:
        preliminary_verdict: Output from Stage 10.
        detection_info: Output from Stage 4.
        session_info: Output from Stage 6.

    Returns:
        Final enforcement verdict: 'ALLOW', 'MONITOR', 'RATE_LIMIT', or 'BLOCK'.
    """
    # Hard policy 1: Rate limit violation
    if session_info.get("is_rate_exceeded"):
        return "RATE_LIMIT"

    # Hard policy 2: High confidence critical attack payload is immediate BLOCK
    label = detection_info.get("label", "benign")
    confidence = detection_info.get("confidence", 0.0)
    if label in ("sqli", "xss") and confidence >= Config.HIGH_CONFIDENCE_THRESHOLD:
        return "BLOCK"

    return preliminary_verdict

"""Stage 11: Policy Engine - Applies deterministic hard overrides to enforce zero-tolerance security rules."""

from typing import Dict, Any, Optional
from gateway.config import Config


def enforce_policy_details(
    preliminary_verdict: str,
    detection_info: Dict[str, Any],
    session_info: Dict[str, Any],
    threat_intel_info: Optional[Dict[str, Any]] = None,
    device_info: Optional[Dict[str, Any]] = None,
    ip_override: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enforce deterministic policy hierarchy to override preliminary verdicts.

    Hierarchy:
    1. Analyst Whitelist -> Force 'ALLOW'
    2. Analyst Blacklist -> Force 'BLOCK'
    3. Session Rate Limit Exceeded -> Force 'RATE_LIMIT'
    4. High-Confidence ML Attack (>= 0.90) -> Force 'BLOCK'
    5. Active Scanner with Attack Payload -> Force 'BLOCK'
    6. Known Malicious IP with Attack Payload -> Force 'BLOCK'
    7. Default -> Preliminary verdict maintained

    Args:
        preliminary_verdict: Verdict from Decision Engine ('ALLOW', 'MONITOR', 'BLOCK').
        detection_info: ML classification metadata.
        session_info: Session rate and tracking metrics.
        threat_intel_info: Optional threat intel metadata.
        device_info: Optional device profiler metadata.
        ip_override: Optional analyst override ('WHITELIST', 'BLACKLIST', or None).

    Returns:
        Structured policy enforcement dictionary.
    """
    label = detection_info.get("label", "benign")
    confidence = float(detection_info.get("confidence", 0.0))

    # Rule 1: Analyst Whitelist (Highest authority)
    if ip_override == "WHITELIST":
        return {
            "final_verdict": "ALLOW",
            "override_applied": preliminary_verdict != "ALLOW",
            "override_reason": "Analyst Policy Override: IP is explicitly whitelisted",
        }

    # Rule 2: Analyst Blacklist
    if ip_override == "BLACKLIST":
        return {
            "final_verdict": "BLOCK",
            "override_applied": True,
            "override_reason": "Analyst Policy Override: IP is explicitly blacklisted",
        }

    # Rule 3: Server-Side Rate Limit Violation
    if session_info and session_info.get("is_rate_exceeded"):
        return {
            "final_verdict": "RATE_LIMIT",
            "override_applied": preliminary_verdict != "RATE_LIMIT",
            "override_reason": f"Rate Limit Exceeded ({session_info.get('requests_last_10s', 0)} req/10s)",
        }

    # Rule 4: Critical ML Attack with High Confidence (Zero Tolerance)
    if label in ("sqli", "xss") and confidence >= Config.HIGH_CONFIDENCE_THRESHOLD:
        return {
            "final_verdict": "BLOCK",
            "override_applied": preliminary_verdict != "BLOCK",
            "override_reason": f"Zero-Tolerance Policy: High-confidence {label.upper()} ({confidence:.1%})",
        }

    # Rule 5: Active Security Scanner wielding Attack Payload
    if device_info and device_info.get("is_scanner") and label in ("sqli", "xss"):
        scanner_name = device_info.get("scanner_name", "scanner")
        return {
            "final_verdict": "BLOCK",
            "override_applied": preliminary_verdict != "BLOCK",
            "override_reason": f"Offensive Tooling: {scanner_name} executing {label.upper()} attack",
        }

    # Rule 6: Known Malicious Reconnaissance Node wielding Attack Payload
    if threat_intel_info and threat_intel_info.get("is_known_malicious") and label in ("sqli", "xss"):
        return {
            "final_verdict": "BLOCK",
            "override_applied": preliminary_verdict != "BLOCK",
            "override_reason": "Threat Intelligence: Flagged malicious IP launching attack vector",
        }

    # Rule 7: Fallback to decision engine evaluation
    return {
        "final_verdict": preliminary_verdict,
        "override_applied": False,
        "override_reason": None,
    }


def enforce_policy(
    preliminary_verdict: str,
    detection_info: Dict[str, Any],
    session_info: Dict[str, Any],
    threat_intel_info: Optional[Dict[str, Any]] = None,
    device_info: Optional[Dict[str, Any]] = None,
    ip_override: Optional[str] = None,
) -> str:
    """
    Convenience method returning final verdict string ('ALLOW', 'MONITOR', 'RATE_LIMIT', or 'BLOCK').
    """
    details = enforce_policy_details(
        preliminary_verdict=preliminary_verdict,
        detection_info=detection_info,
        session_info=session_info,
        threat_intel_info=threat_intel_info,
        device_info=device_info,
        ip_override=ip_override,
    )
    return details["final_verdict"]

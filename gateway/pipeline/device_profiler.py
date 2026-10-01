"""Stage 7: Device Profiler - Client fingerprinting via request headers."""

import hashlib
from typing import Dict, Any


def profile_device(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Generate device fingerprint hash based on User-Agent and headers.

    Args:
        headers: Normalized dictionary of HTTP headers.

    Returns:
        Device profiling metadata.
    """
    user_agent = headers.get("user-agent", "unknown")
    accept_lang = headers.get("accept-language", "")
    fingerprint_raw = f"{user_agent}|{accept_lang}"
    fingerprint_hash = hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()[:16]

    return {
        "user_agent": user_agent,
        "fingerprint": fingerprint_hash,
        "is_automated_tool": any(
            tool in user_agent.lower() for tool in ["sqlmap", "nikto", "curl", "python-requests"]
        ),
    }

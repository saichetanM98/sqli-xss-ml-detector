"""Stage 5: Threat Intelligence - IP reputation and GeoIP enrichment."""

from typing import Dict, Any


def check_threat_intel(ip_address: str) -> Dict[str, Any]:
    """
    Check IP reputation and geographical risk indicators.

    Args:
        ip_address: Client IP address.

    Returns:
        Threat intelligence metadata.
    """
    # Placeholder for threat intel / GeoIP lookup
    is_private = ip_address.startswith(("127.", "192.168.", "10."))
    return {
        "ip": ip_address,
        "is_known_malicious": False,
        "reputation_score": 0.0,
        "country": "Local" if is_private else "Unknown",
    }

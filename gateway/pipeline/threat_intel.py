"""Stage 5: Threat Intelligence - High-speed IP reputation and GeoIP enrichment."""

import ipaddress
from typing import Dict, Any, List

# Curated high-reputation malicious IP indicators and CIDR blocks
# (Simulated offline threat intelligence feed: Tor exit nodes, C2 nodes, scanners)
_KNOWN_MALICIOUS_IPS = {
    "185.220.101.5": {"score": 95.0, "category": "Tor Exit Node", "country": "DE", "asn": "AS208323"},
    "198.51.100.42": {"score": 90.0, "category": "Malicious Scanner", "country": "RU", "asn": "AS4134"},
    "203.0.113.195": {"score": 88.0, "category": "C2 Botnet Node", "country": "CN", "asn": "AS4837"},
    "185.220.102.8": {"score": 92.0, "category": "Tor Exit Node", "country": "NL", "asn": "AS60729"},
    "194.26.29.112": {"score": 85.0, "category": "Brute Force Scanner", "country": "UA", "asn": "AS49505"},
    "45.154.255.89": {"score": 90.0, "category": "Exploitation Probe", "country": "SC", "asn": "AS200052"},
}

_KNOWN_MALICIOUS_NETWORKS: List[ipaddress.IPv4Network] = [
    ipaddress.ip_network("45.154.255.0/24"),
    ipaddress.ip_network("194.26.29.0/24"),
    ipaddress.ip_network("185.220.101.0/24"),
]


def check_threat_intel(ip_address: str) -> Dict[str, Any]:
    """
    Check IP reputation and geographical risk indicators with sub-millisecond offline lookup.

    Args:
        ip_address: Client IP address string.

    Returns:
        Structured threat intelligence metadata.
    """
    if not ip_address:
        ip_address = "127.0.0.1"

    # 1. Parse IP address safely
    try:
        parsed_ip = ipaddress.ip_address(ip_address.strip())
    except ValueError:
        return {
            "ip": ip_address,
            "is_known_malicious": False,
            "reputation_score": 50.0,
            "country": "Invalid IP",
            "asn": "Unknown",
            "category": "malformed_ip",
        }

    # 2. Check Bogon / Private / Loopback ranges
    if parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_reserved:
        return {
            "ip": str(parsed_ip),
            "is_known_malicious": False,
            "reputation_score": 0.0,
            "country": "Private Network",
            "asn": "AS0 Local",
            "category": "private",
        }

    # 3. Direct match against known malicious IP dictionary
    ip_str = str(parsed_ip)
    if ip_str in _KNOWN_MALICIOUS_IPS:
        entry = _KNOWN_MALICIOUS_IPS[ip_str]
        return {
            "ip": ip_str,
            "is_known_malicious": True,
            "reputation_score": entry["score"],
            "country": entry["country"],
            "asn": entry["asn"],
            "category": entry["category"],
        }

    # 4. CIDR block match against known malicious subnets (IPv4)
    if isinstance(parsed_ip, ipaddress.IPv4Address):
        for network in _KNOWN_MALICIOUS_NETWORKS:
            if parsed_ip in network:
                return {
                    "ip": ip_str,
                    "is_known_malicious": True,
                    "reputation_score": 85.0,
                    "country": "Flagged Subnet",
                    "asn": "AS-THREAT-INTEL",
                    "category": "malicious_subnet",
                }

    # 5. Clean / unflagged public IP
    # Generate deterministic synthetic GeoIP based on first octet
    first_octet = int(ip_str.split(".")[0]) if "." in ip_str else 0
    country_map = {0: "US", 1: "GB", 2: "DE", 3: "JP", 4: "FR", 5: "CA", 6: "AU"}
    country = country_map.get(first_octet % 7, "US")

    return {
        "ip": ip_str,
        "is_known_malicious": False,
        "reputation_score": 5.0,
        "country": country,
        "asn": f"AS{15000 + (first_octet * 10)}",
        "category": "clean",
    }

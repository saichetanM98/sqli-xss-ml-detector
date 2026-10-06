"""Stage 7: Device Profiler - Client fingerprinting via request headers and scanner detection."""

import hashlib
import re
from typing import Dict, Any, Optional

# Recognized automated security tools and scanners
_SCANNER_PATTERNS = [
    (r"\bsqlmap\b", "sqlmap"),
    (r"\bnikto\b", "nikto"),
    (r"\bnmap\b", "nmap"),
    (r"\bmasscan\b", "masscan"),
    (r"\bwpscan\b", "wpscan"),
    (r"\bgobuster\b", "gobuster"),
    (r"\bdirbuster\b", "dirbuster"),
    (r"\bhydra\b", "hydra"),
    (r"\bburp\b", "burpsuite"),
    (r"\bacunetix\b", "acunetix"),
    (r"\bopenvas\b", "openvas"),
    (r"\bnessus\b", "nessus"),
]

# Automated CLI / library clients
_AUTOMATED_CLIENT_PATTERNS = [
    (r"^curl/\d", "curl"),
    (r"^python-requests/\d", "python-requests"),
    (r"^python-urllib", "python-urllib"),
    (r"^aiohttp/\d", "aiohttp"),
    (r"^postmanruntime/\d", "postman"),
    (r"^wget/\d", "wget"),
    (r"^go-http-client/\d", "go-http-client"),
]


def profile_device(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Generate device fingerprint hash based on User-Agent and canonical headers,
    and detect automated scanners and HTTP client libraries.

    Args:
        headers: Normalized dictionary of HTTP headers (lowercased keys).

    Returns:
        Device profiling metadata dictionary.
    """
    # Case-insensitive header lookup
    norm_headers = {str(k).lower(): str(v) for k, v in headers.items()} if headers else {}

    user_agent = norm_headers.get("user-agent", "").strip()
    accept = norm_headers.get("accept", "")
    accept_lang = norm_headers.get("accept-language", "")
    accept_encoding = norm_headers.get("accept-encoding", "")

    # Deterministic canonical fingerprint
    canonical_str = f"{user_agent}|{accept}|{accept_lang}|{accept_encoding}"
    fingerprint = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()[:16]

    # Detect scanners and automated tools
    is_scanner = False
    scanner_name: Optional[str] = None
    device_type = "Desktop"

    ua_lower = user_agent.lower()

    # 1. Match known offensive scanners
    for pattern, name in _SCANNER_PATTERNS:
        if re.search(pattern, ua_lower):
            is_scanner = True
            scanner_name = name
            device_type = "Security Scanner"
            break

    # 2. Match generic automation tools if not scanner
    is_automated = is_scanner
    if not is_scanner:
        for pattern, name in _AUTOMATED_CLIENT_PATTERNS:
            if re.search(pattern, ua_lower):
                is_automated = True
                scanner_name = name
                device_type = "Automated Script"
                break

    # 3. Classify user device if browser
    if not is_automated:
        if any(m in ua_lower for m in ["mobile", "android", "iphone", "ipad"]):
            device_type = "Mobile"
        elif any(b in ua_lower for b in ["mozilla", "chrome", "safari", "firefox", "edge"]):
            device_type = "Desktop"
        elif not user_agent:
            device_type = "Missing User-Agent"
            is_automated = True
        else:
            device_type = "Generic Client"

    return {
        "user_agent": user_agent or "unknown",
        "fingerprint": fingerprint,
        "is_automated_tool": is_automated,
        "is_scanner": is_scanner,
        "scanner_name": scanner_name,
        "device_type": device_type,
    }

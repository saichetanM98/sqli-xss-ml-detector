"""Stage 6: Session Manager - Server-side session tracking and request frequency count."""

import time
from typing import Dict, Any

# Simple in-memory session cache (can be backed by Flask-Caching / SimpleCache)
_SESSION_STORE: Dict[str, Dict[str, Any]] = {}


def track_session(session_id: str, ip: str) -> Dict[str, Any]:
    """
    Track session activity, request timestamps, and rate limiting counters.

    Args:
        session_id: Unique identifier for the user session or IP.
        ip: Client IP address.

    Returns:
        Session state summary including request rate.
    """
    key = session_id or ip
    now = time.time()
    session_data = _SESSION_STORE.setdefault(key, {"request_timestamps": [], "created_at": now})

    # Keep only timestamps within last 60 seconds
    session_data["request_timestamps"] = [
        ts for ts in session_data["request_timestamps"] if now - ts < 60
    ]
    session_data["request_timestamps"].append(now)

    req_count = len(session_data["request_timestamps"])
    return {
        "session_id": key,
        "requests_last_minute": req_count,
        "is_rate_exceeded": req_count > 60,
    }

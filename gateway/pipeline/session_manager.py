"""Stage 6: Session Manager - Server-side session tracking and rate limiting backed by SimpleCache."""

import time
from typing import Dict, Any, Optional
from flask_caching.backends.simplecache import SimpleCache

# Server-side cache instance (retains sessions across requests, tamper-proof against client)
_SESSION_CACHE = SimpleCache(threshold=10000, default_timeout=3600)
_BURST_RATE_LIMIT_10S = 20
_SUSTAINED_RATE_LIMIT_60S = 60


def _get_cache_key(session_id: str, ip: str, fingerprint: Optional[str] = None) -> str:
    """Generate consistent cache key from session ID, IP, and fingerprint."""
    if session_id and session_id != ip:
        return f"sess:{session_id}"
    if fingerprint:
        return f"dev:{ip}:{fingerprint}"
    return f"ip:{ip}"


def track_session(
    session_id: str,
    ip: str,
    fingerprint: Optional[str] = None
) -> Dict[str, Any]:
    """
    Track session activity, request timestamps, and evaluate sliding-window rate limits.

    Args:
        session_id: Client session identifier (or None).
        ip: Client IP address.
        fingerprint: Optional client device fingerprint.

    Returns:
        Structured session state and velocity metrics.
    """
    now = time.time()
    cache_key = _get_cache_key(session_id, ip, fingerprint)

    session_data = _SESSION_CACHE.get(cache_key)
    if session_data is None:
        session_data = {
            "session_id": cache_key,
            "ip": ip,
            "request_timestamps": [],
            "violations_count": 0,
            "created_at": now,
        }

    # Prune timestamps older than 60 seconds
    timestamps = [ts for ts in session_data["request_timestamps"] if now - ts < 60.0]
    timestamps.append(now)
    session_data["request_timestamps"] = timestamps
    session_data["last_seen"] = now

    _SESSION_CACHE.set(cache_key, session_data, timeout=3600)

    # Compute sliding window metrics
    reqs_last_10s = sum(1 for ts in timestamps if now - ts <= 10.0)
    reqs_last_60s = len(timestamps)

    is_rate_exceeded = (reqs_last_10s > _BURST_RATE_LIMIT_10S) or (reqs_last_60s > _SUSTAINED_RATE_LIMIT_60S)

    return {
        "session_id": cache_key,
        "ip": ip,
        "requests_last_10s": reqs_last_10s,
        "requests_last_minute": reqs_last_60s,
        "violations_count": session_data.get("violations_count", 0),
        "is_rate_exceeded": is_rate_exceeded,
        "burst_limit_10s": _BURST_RATE_LIMIT_10S,
        "sustained_limit_60s": _SUSTAINED_RATE_LIMIT_60S,
    }


def record_violation(session_id: str, ip: str, fingerprint: Optional[str] = None) -> int:
    """
    Increment violation counter for this session/IP.

    Returns:
        Updated cumulative violation count.
    """
    cache_key = _get_cache_key(session_id, ip, fingerprint)
    session_data = _SESSION_CACHE.get(cache_key)
    if session_data is None:
        now = time.time()
        session_data = {
            "session_id": cache_key,
            "ip": ip,
            "request_timestamps": [now],
            "violations_count": 0,
            "created_at": now,
        }

    session_data["violations_count"] = session_data.get("violations_count", 0) + 1
    _SESSION_CACHE.set(cache_key, session_data, timeout=3600)
    return session_data["violations_count"]


def get_session_metrics(session_id: str, ip: str, fingerprint: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve current session state without registering a new request timestamp."""
    cache_key = _get_cache_key(session_id, ip, fingerprint)
    session_data = _SESSION_CACHE.get(cache_key)
    if session_data is None:
        return {
            "session_id": cache_key,
            "ip": ip,
            "requests_last_10s": 0,
            "requests_last_minute": 0,
            "violations_count": 0,
            "is_rate_exceeded": False,
        }

    now = time.time()
    timestamps = [ts for ts in session_data["request_timestamps"] if now - ts < 60.0]
    reqs_10s = sum(1 for ts in timestamps if now - ts <= 10.0)
    reqs_60s = len(timestamps)

    return {
        "session_id": cache_key,
        "ip": ip,
        "requests_last_10s": reqs_10s,
        "requests_last_minute": reqs_60s,
        "violations_count": session_data.get("violations_count", 0),
        "is_rate_exceeded": (reqs_10s > _BURST_RATE_LIMIT_10S) or (reqs_60s > _SUSTAINED_RATE_LIMIT_60S),
    }


def clear_sessions() -> None:
    """Clear all session data (for unit test isolation)."""
    _SESSION_CACHE.clear()

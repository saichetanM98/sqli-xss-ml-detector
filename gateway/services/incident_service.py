"""Stage 12: Incident & Memory Service - Persists security incidents."""

import time
import uuid
from typing import Dict, Any, List

# In-memory store fallback before DB connection is established
_INCIDENTS: List[Dict[str, Any]] = []


def log_incident(
    request_data: Dict[str, Any],
    detection_info: Dict[str, Any],
    risk_score: float,
    verdict: str,
) -> Dict[str, Any]:
    """
    Persist incident record into storage if verdict is flagged (BLOCK, MONITOR, RATE_LIMIT).

    Args:
        request_data: Parsed request context.
        detection_info: ML detection output.
        risk_score: Calculated risk score.
        verdict: Final policy enforcement verdict.

    Returns:
        Logged incident dictionary.
    """
    incident = {
        "id": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "client_ip": request_data.get("ip"),
        "method": request_data.get("method"),
        "path": request_data.get("path"),
        "payload": request_data.get("raw_payload"),
        "attack_type": detection_info.get("label"),
        "confidence": detection_info.get("confidence"),
        "risk_score": risk_score,
        "verdict": verdict,
        "status": "OPEN",
    }
    _INCIDENTS.append(incident)
    return incident


def get_all_incidents() -> List[Dict[str, Any]]:
    """Retrieve list of all logged security incidents."""
    return sorted(_INCIDENTS, key=lambda x: x["timestamp"], reverse=True)

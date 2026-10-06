"""Stage 12: Incident & Memory Service - Persists security incidents in MongoDB with fail-safe fallback."""

import time
import uuid
import re
from typing import Dict, Any, List, Optional
from gateway.services.db import get_db

# In-memory store fallback before DB connection is established or if DB is offline
_INCIDENTS: List[Dict[str, Any]] = []
_IP_OVERRIDES: Dict[str, Dict[str, Any]] = {}
_INDEXES_INITIALIZED = False


def _ensure_indexes():
    """Ensure MongoDB collection indexes exist for optimal query performance."""
    global _INDEXES_INITIALIZED
    if _INDEXES_INITIALIZED:
        return

    db = get_db()
    if db is not None:
        try:
            db.incidents.create_index([("timestamp", -1)])
            db.incidents.create_index([("client_ip", 1)])
            db.incidents.create_index([("verdict", 1)])
            db.incidents.create_index([("status", 1)])
            db.incidents.create_index([("attack_type", 1)])
            db.ip_overrides.create_index([("ip", 1)], unique=True)
            _INDEXES_INITIALIZED = True
        except Exception:
            pass


def log_incident(
    request_data: Dict[str, Any],
    detection_info: Dict[str, Any],
    risk_score: float,
    verdict: str,
    risk_components: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Persist incident record into MongoDB (and fallback in-memory cache).

    Args:
        request_data: Parsed request context.
        detection_info: ML detection output.
        risk_score: Calculated cumulative risk score.
        verdict: Final policy enforcement verdict ('BLOCK', 'MONITOR', 'RATE_LIMIT', etc.).
        risk_components: Optional breakdown of risk weights.

    Returns:
        Logged incident dictionary.
    """
    _ensure_indexes()
    now = time.time()
    incident_id = str(uuid.uuid4())

    label = detection_info.get("label", "benign")
    confidence = float(detection_info.get("confidence", 0.0))

    incident = {
        "id": incident_id,
        "timestamp": now,
        "client_ip": request_data.get("ip") or request_data.get("client_ip") or "127.0.0.1",
        "method": str(request_data.get("method", "GET")).upper(),
        "path": request_data.get("path", "/"),
        "raw_payload": request_data.get("raw_payload", ""),
        "payload": request_data.get("raw_payload", ""),
        "attack_type": label,
        "confidence": confidence,
        "risk_score": float(risk_score),
        "risk_components": risk_components or {},
        "verdict": verdict,
        "status": "OPEN",
        "analyst_notes": "",
        "updated_at": now,
    }

    # 1. In-memory append
    _INCIDENTS.append(incident)

    # 2. MongoDB insert if connected
    db = get_db()
    if db is not None:
        try:
            doc = dict(incident)
            doc["_id"] = incident_id
            db.incidents.insert_one(doc)
        except Exception:
            pass

    return incident


def get_incidents(
    filters: Optional[Dict[str, Any]] = None,
    limit: int = 50,
    offset: int = 0,
    sort: str = "newest",
) -> Dict[str, Any]:
    """
    Query incidents with filtering, search, pagination, and sorting.

    Args:
        filters: Optional dictionary with keys: verdict, attack_type, status, search.
        limit: Max items to return.
        offset: Number of items to skip.
        sort: 'newest' or 'oldest' or 'highest_risk'.

    Returns:
        Dictionary with 'items', 'total', 'limit', 'offset'.
    """
    _ensure_indexes()
    filters = filters or {}
    verdict_filter = filters.get("verdict")
    attack_filter = filters.get("attack_type")
    status_filter = filters.get("status")
    search_query = filters.get("search", "").strip()

    db = get_db()
    if db is not None:
        try:
            query: Dict[str, Any] = {}
            if verdict_filter and verdict_filter.upper() != "ALL":
                query["verdict"] = verdict_filter.upper()
            if attack_filter and attack_filter.lower() != "all":
                query["attack_type"] = attack_filter.lower()
            if status_filter and status_filter.upper() != "ALL":
                query["status"] = status_filter.upper()
            if search_query:
                regex_pattern = {"$regex": re.escape(search_query), "$options": "i"}
                query["$or"] = [
                    {"client_ip": regex_pattern},
                    {"path": regex_pattern},
                    {"raw_payload": regex_pattern},
                ]

            sort_order = [("timestamp", -1)]
            if sort == "oldest":
                sort_order = [("timestamp", 1)]
            elif sort == "highest_risk":
                sort_order = [("risk_score", -1)]

            total = db.incidents.count_documents(query)
            cursor = db.incidents.find(query, {"_id": 0}).sort(sort_order).skip(offset).limit(limit)
            items = list(cursor)
            return {"items": items, "total": total, "limit": limit, "offset": offset}
        except Exception:
            pass

    # Fallback to in-memory store
    items = list(_INCIDENTS)
    if verdict_filter and verdict_filter.upper() != "ALL":
        items = [i for i in items if i.get("verdict") == verdict_filter.upper()]
    if attack_filter and attack_filter.lower() != "all":
        items = [i for i in items if i.get("attack_type") == attack_filter.lower()]
    if status_filter and status_filter.upper() != "ALL":
        items = [i for i in items if i.get("status") == status_filter.upper()]
    if search_query:
        sq_lower = search_query.lower()
        items = [
            i
            for i in items
            if sq_lower in str(i.get("client_ip", "")).lower()
            or sq_lower in str(i.get("path", "")).lower()
            or sq_lower in str(i.get("raw_payload", "")).lower()
        ]

    # Sort
    if sort == "oldest":
        items.sort(key=lambda x: x["timestamp"])
    elif sort == "highest_risk":
        items.sort(key=lambda x: x["risk_score"], reverse=True)
    else:
        items.sort(key=lambda x: x["timestamp"], reverse=True)

    total = len(items)
    paged = items[offset : offset + limit]
    return {"items": paged, "total": total, "limit": limit, "offset": offset}


def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve single incident by UUID."""
    db = get_db()
    if db is not None:
        try:
            doc = db.incidents.find_one({"id": incident_id}, {"_id": 0})
            if doc:
                return doc
        except Exception:
            pass

    for inc in _INCIDENTS:
        if inc["id"] == incident_id:
            return inc
    return None


def update_incident_status(incident_id: str, status: str, notes: str = "") -> Optional[Dict[str, Any]]:
    """
    Update triage status for an incident ('TRUE_POSITIVE', 'FALSE_POSITIVE', 'RESOLVED', 'OPEN').
    """
    valid_statuses = {"TRUE_POSITIVE", "FALSE_POSITIVE", "RESOLVED", "OPEN"}
    norm_status = status.upper()
    if norm_status not in valid_statuses:
        norm_status = "RESOLVED"

    now = time.time()
    updated_doc = None

    db = get_db()
    if db is not None:
        try:
            db.incidents.update_one(
                {"id": incident_id},
                {"$set": {"status": norm_status, "analyst_notes": notes, "updated_at": now}},
            )
            updated_doc = db.incidents.find_one({"id": incident_id}, {"_id": 0})
        except Exception:
            pass

    for inc in _INCIDENTS:
        if inc["id"] == incident_id:
            inc["status"] = norm_status
            if notes:
                inc["analyst_notes"] = notes
            inc["updated_at"] = now
            if updated_doc is None:
                updated_doc = inc
            break

    return updated_doc


def get_all_incidents() -> List[Dict[str, Any]]:
    """Retrieve all logged security incidents ordered newest first."""
    res = get_incidents(limit=1000)
    return res["items"]


# =========================================================================
# IP Overrides (Analyst Whitelist / Blacklist)
# =========================================================================

def get_ip_override(ip: str) -> Optional[str]:
    """Retrieve active analyst override for an IP ('WHITELIST', 'BLACKLIST', or None)."""
    db = get_db()
    if db is not None:
        try:
            doc = db.ip_overrides.find_one({"ip": ip})
            if doc:
                return doc.get("action")
        except Exception:
            pass

    entry = _IP_OVERRIDES.get(ip)
    return entry.get("action") if entry else None


def set_ip_override(ip: str, action: str, reason: str = "") -> None:
    """Set or clear analyst override for an IP ('WHITELIST', 'BLACKLIST', or None/'CLEAR')."""
    now = time.time()
    norm_action = action.upper() if action else ""

    if norm_action in ("WHITELIST", "BLACKLIST"):
        entry = {"ip": ip, "action": norm_action, "reason": reason, "updated_at": now}
        _IP_OVERRIDES[ip] = entry

        db = get_db()
        if db is not None:
            try:
                db.ip_overrides.update_one({"ip": ip}, {"$set": entry}, upsert=True)
            except Exception:
                pass
    else:
        # Clear override
        if ip in _IP_OVERRIDES:
            del _IP_OVERRIDES[ip]

        db = get_db()
        if db is not None:
            try:
                db.ip_overrides.delete_one({"ip": ip})
            except Exception:
                pass


def get_all_ip_overrides() -> List[Dict[str, Any]]:
    """Return list of all active IP overrides."""
    db = get_db()
    if db is not None:
        try:
            docs = list(db.ip_overrides.find({}, {"_id": 0}))
            if docs:
                return docs
        except Exception:
            pass
    return list(_IP_OVERRIDES.values())


def clear_incidents() -> None:
    """Clear all logged incidents and IP overrides (for test isolation)."""
    global _INCIDENTS, _IP_OVERRIDES
    _INCIDENTS.clear()
    _IP_OVERRIDES.clear()

    db = get_db()
    if db is not None:
        try:
            db.incidents.delete_many({})
            db.ip_overrides.delete_many({})
        except Exception:
            pass

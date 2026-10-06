"""Stage 13: Analytics Service - Aggregation queries for threat metrics and SOC visualization."""

import time
from typing import Dict, Any, List
from collections import defaultdict
from gateway.services.incident_service import get_all_incidents, get_all_ip_overrides
from gateway.services.db import get_db


def get_analytics_summary() -> Dict[str, Any]:
    """
    Compute aggregate counts and breakdown of attacks, verdicts, and triage statuses.
    """
    incidents = get_all_incidents()
    total = len(incidents)

    by_verdict = {"BLOCK": 0, "MONITOR": 0, "RATE_LIMIT": 0, "ALLOW": 0}
    by_attack = {"sqli": 0, "xss": 0, "benign": 0}
    by_status = {"OPEN": 0, "RESOLVED": 0, "FALSE_POSITIVE": 0, "TRUE_POSITIVE": 0}

    total_risk = 0.0

    for inc in incidents:
        verdict = inc.get("verdict", "ALLOW")
        attack = inc.get("attack_type", "benign")
        status = inc.get("status", "OPEN")
        risk = float(inc.get("risk_score", 0.0))

        by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
        by_attack[attack] = by_attack.get(attack, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
        total_risk += risk

    avg_risk = round(total_risk / total, 2) if total > 0 else 0.0
    blocked_count = by_verdict.get("BLOCK", 0)
    block_rate = round((blocked_count / total * 100.0), 1) if total > 0 else 0.0

    overrides = get_all_ip_overrides()

    return {
        "total_incidents": total,
        "blocked_count": blocked_count,
        "monitored_count": by_verdict.get("MONITOR", 0),
        "rate_limited_count": by_verdict.get("RATE_LIMIT", 0),
        "allowed_count": by_verdict.get("ALLOW", 0),
        "block_rate_percentage": block_rate,
        "average_risk_score": avg_risk,
        "verdict_distribution": by_verdict,
        "attack_distribution": by_attack,
        "status_distribution": by_status,
        "active_overrides_count": len(overrides),
    }


def get_analytics_trends(limit: int = 12) -> List[Dict[str, Any]]:
    """
    Group incidents into chronological time buckets (5-minute or hourly buckets).
    """
    incidents = get_all_incidents()
    now = time.time()
    bucket_size = 300  # 5-minute buckets

    # Generate recent buckets
    buckets: Dict[int, Dict[str, Any]] = {}
    for i in range(limit - 1, -1, -1):
        bucket_ts = int((now - i * bucket_size) // bucket_size) * bucket_size
        time_label = time.strftime("%H:%M", time.localtime(bucket_ts))
        buckets[bucket_ts] = {
            "timestamp": bucket_ts,
            "time": time_label,
            "total": 0,
            "sqli": 0,
            "xss": 0,
            "blocked": 0,
        }

    # Aggregate incidents into buckets
    for inc in incidents:
        ts = inc.get("timestamp", now)
        bucket_ts = int(ts // bucket_size) * bucket_size
        if bucket_ts in buckets:
            buckets[bucket_ts]["total"] += 1
            attack = inc.get("attack_type", "")
            if attack == "sqli":
                buckets[bucket_ts]["sqli"] += 1
            elif attack == "xss":
                buckets[bucket_ts]["xss"] += 1

            if inc.get("verdict") == "BLOCK":
                buckets[bucket_ts]["blocked"] += 1

    return list(buckets.values())


def get_top_offenders(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Rank top offending client IPs by incident count and highest risk score.
    """
    incidents = get_all_incidents()
    grouped: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "ip": "",
            "incident_count": 0,
            "highest_risk": 0.0,
            "last_verdict": "ALLOW",
            "last_seen": 0.0,
            "attack_types": set(),
        }
    )

    for inc in incidents:
        ip = inc.get("client_ip", "unknown")
        entry = grouped[ip]
        entry["ip"] = ip
        entry["incident_count"] += 1
        entry["highest_risk"] = max(entry["highest_risk"], float(inc.get("risk_score", 0.0)))
        if inc.get("timestamp", 0) > entry["last_seen"]:
            entry["last_seen"] = inc.get("timestamp", 0)
            entry["last_verdict"] = inc.get("verdict", "ALLOW")
        if inc.get("attack_type"):
            entry["attack_types"].add(inc.get("attack_type"))

    offenders = list(grouped.values())
    for o in offenders:
        o["attack_types"] = sorted(list(o["attack_types"]))

    offenders.sort(key=lambda x: (x["incident_count"], x["highest_risk"]), reverse=True)
    return offenders[:limit]

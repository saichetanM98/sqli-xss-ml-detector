"""Stage 13: Analytics Service - Aggregation queries for dashboard metrics."""

from typing import Dict, Any
from gateway.services.incident_service import get_all_incidents


def get_analytics_summary() -> Dict[str, Any]:
    """Compute aggregate counts and breakdown of attacks and verdicts."""
    incidents = get_all_incidents()
    total = len(incidents)

    by_verdict = {"BLOCK": 0, "MONITOR": 0, "RATE_LIMIT": 0, "ALLOW": 0}
    by_attack = {"sqli": 0, "xss": 0, "benign": 0}

    for inc in incidents:
        verdict = inc.get("verdict", "ALLOW")
        attack = inc.get("attack_type", "benign")
        by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
        by_attack[attack] = by_attack.get(attack, 0) + 1

    return {
        "total_incidents": total,
        "verdict_distribution": by_verdict,
        "attack_distribution": by_attack,
    }

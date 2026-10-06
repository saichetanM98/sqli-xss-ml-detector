"""Route blueprint for SOC analytics summary, trends, top offenders, and IP policy overrides."""

from flask import Blueprint, request, jsonify
from gateway.services.analytics_service import (
    get_analytics_summary,
    get_analytics_trends,
    get_top_offenders,
)
from gateway.services.incident_service import (
    get_all_ip_overrides,
    set_ip_override,
)

analytics_bp = Blueprint("analytics", __name__)


@analytics_bp.route("/analytics/summary", methods=["GET"])
@analytics_bp.route("/api/analytics/summary", methods=["GET"])
def analytics_summary():
    """Retrieve aggregate attack, verdict, and risk metrics."""
    summary = get_analytics_summary()
    return jsonify({"success": True, "data": summary, "error": None}), 200


@analytics_bp.route("/analytics/trends", methods=["GET"])
@analytics_bp.route("/api/analytics/trends", methods=["GET"])
def analytics_trends():
    """Retrieve bucketed incident volume timelines."""
    limit = int(request.args.get("limit", 12))
    trends = get_analytics_trends(limit=limit)
    return jsonify({"success": True, "data": trends, "error": None}), 200


@analytics_bp.route("/analytics/top-ips", methods=["GET"])
@analytics_bp.route("/api/analytics/top-ips", methods=["GET"])
def top_ips():
    """Retrieve ranked top offender client IPs."""
    limit = int(request.args.get("limit", 10))
    offenders = get_top_offenders(limit=limit)
    return jsonify({"success": True, "data": offenders, "error": None}), 200


@analytics_bp.route("/api/policy/override-ip", methods=["GET"])
@analytics_bp.route("/policy/override-ip", methods=["GET"])
def list_ip_overrides():
    """List all active analyst IP overrides."""
    overrides = get_all_ip_overrides()
    return jsonify({"success": True, "data": overrides, "error": None}), 200


@analytics_bp.route("/api/policy/override-ip", methods=["POST"])
@analytics_bp.route("/policy/override-ip", methods=["POST"])
def update_ip_override():
    """
    Set or clear analyst IP override.
    Payload: {"ip": "1.2.3.4", "action": "WHITELIST"|"BLACKLIST"|"CLEAR", "reason": "..."}
    """
    body = request.get_json(silent=True) or {}
    ip = body.get("ip")
    action = body.get("action", "").upper()
    reason = body.get("reason", "")

    if not ip:
        return jsonify({"success": False, "data": None, "error": "Missing IP parameter"}), 400

    set_ip_override(ip, action=action, reason=reason)
    return (
        jsonify(
            {
                "success": True,
                "data": {"ip": ip, "action": action, "reason": reason},
                "error": None,
            }
        ),
        200,
    )

"""Route blueprint for SOC analytics summary."""

from flask import Blueprint, jsonify
from gateway.services.analytics_service import get_analytics_summary

analytics_bp = Blueprint("analytics", __name__)


@analytics_bp.route("/analytics/summary", methods=["GET"])
def analytics_summary():
    """Retrieve aggregate attack and verdict metrics."""
    summary = get_analytics_summary()
    return jsonify({"success": True, "data": summary, "error": None}), 200

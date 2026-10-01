"""Route blueprint for incident management."""

from flask import Blueprint, jsonify
from gateway.services.incident_service import get_all_incidents

incident_bp = Blueprint("incidents", __name__)


@incident_bp.route("/incidents", methods=["GET"])
def list_incidents():
    """Retrieve list of security incidents."""
    incidents = get_all_incidents()
    return jsonify({"success": True, "data": incidents, "error": None}), 200

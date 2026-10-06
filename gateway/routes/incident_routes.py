"""Route blueprint for incident management and analyst triage."""

from flask import Blueprint, request, jsonify
from gateway.services.incident_service import (
    get_incidents,
    get_incident_by_id,
    update_incident_status,
)

incident_bp = Blueprint("incidents", __name__)


@incident_bp.route("/incidents", methods=["GET"])
@incident_bp.route("/api/incidents", methods=["GET"])
def list_incidents():
    """
    Retrieve paginated list of security incidents with filters.
    Query params:
        verdict: 'ALL', 'BLOCK', 'MONITOR', 'RATE_LIMIT'
        attack_type: 'ALL', 'sqli', 'xss', 'benign'
        status: 'ALL', 'OPEN', 'RESOLVED', 'TRUE_POSITIVE', 'FALSE_POSITIVE'
        search: search string for IP, path, or payload
        limit: int (default 50)
        offset: int (default 0)
        sort: 'newest', 'oldest', 'highest_risk'
    """
    verdict = request.args.get("verdict")
    attack_type = request.args.get("attack_type")
    status = request.args.get("status")
    search = request.args.get("search", "")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    sort = request.args.get("sort", "newest")

    filters = {
        "verdict": verdict,
        "attack_type": attack_type,
        "status": status,
        "search": search,
    }

    result = get_incidents(filters=filters, limit=limit, offset=offset, sort=sort)
    return jsonify({"success": True, "data": result, "error": None}), 200


@incident_bp.route("/incidents/<incident_id>", methods=["GET"])
@incident_bp.route("/api/incidents/<incident_id>", methods=["GET"])
def get_incident(incident_id: str):
    """Retrieve detailed information for a single incident."""
    incident = get_incident_by_id(incident_id)
    if not incident:
        return jsonify({"success": False, "data": None, "error": "Incident not found"}), 404
    return jsonify({"success": True, "data": incident, "error": None}), 200


@incident_bp.route("/incidents/<incident_id>/status", methods=["POST"])
@incident_bp.route("/api/incidents/<incident_id>/status", methods=["POST"])
@incident_bp.route("/api/incidents/<incident_id>/override", methods=["POST"])
def update_status(incident_id: str):
    """
    Update incident triage status.
    Payload: {"status": "TRUE_POSITIVE"|"FALSE_POSITIVE"|"RESOLVED"|"OPEN", "notes": "..."}
    """
    body = request.get_json(silent=True) or {}
    new_status = body.get("status", "RESOLVED")
    notes = body.get("notes", "")

    updated = update_incident_status(incident_id, status=new_status, notes=notes)
    if not updated:
        return jsonify({"success": False, "data": None, "error": "Incident not found"}), 404

    return jsonify({"success": True, "data": updated, "error": None}), 200

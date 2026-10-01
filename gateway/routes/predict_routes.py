"""Route blueprint for /predict and live request inspection pipeline."""

from flask import Blueprint, request, jsonify
from gateway.pipeline.parser import parse_request
from gateway.pipeline.preprocess import preprocess_payload
from gateway.pipeline.detection import detect_attack
from gateway.pipeline.threat_intel import check_threat_intel
from gateway.pipeline.session_manager import track_session
from gateway.pipeline.device_profiler import profile_device
from gateway.pipeline.behavior_engine import analyze_behavior
from gateway.pipeline.risk_engine import compute_risk_score
from gateway.pipeline.decision_engine import evaluate_decision
from gateway.pipeline.policy_engine import enforce_policy
from gateway.services.incident_service import log_incident

predict_bp = Blueprint("predict", __name__)


@predict_bp.route("/predict", methods=["POST"])
def inspect_request():
    """Inspect an incoming request through the 14-stage security pipeline."""
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"success": False, "data": None, "error": "Invalid or missing JSON body"}), 400

    # 1-2. Ingress & Parse
    parsed = parse_request(body)

    # 3. Preprocess
    cleaned_payload = preprocess_payload(parsed["raw_payload"])

    # 4. ML Detection
    detection = detect_attack(cleaned_payload)

    # 5. Threat Intel
    intel = check_threat_intel(parsed["ip"])

    # 6. Session Manager
    session_id = parsed["headers"].get("x-session-id", parsed["ip"])
    session = track_session(session_id, parsed["ip"])

    # 7. Device Profiler
    device = profile_device(parsed["headers"])

    # 8. Behavior Engine
    behavior = analyze_behavior(session, device)

    # 9. Risk Engine
    risk_score = compute_risk_score(detection, intel, behavior)

    # 10. Decision Engine
    preliminary_verdict = evaluate_decision(risk_score)

    # 11. Policy Engine
    final_verdict = enforce_policy(preliminary_verdict, detection, session)

    # 12. Incident Service (persist if flagged)
    incident_record = None
    if final_verdict != "ALLOW":
        incident_record = log_incident(parsed, detection, risk_score, final_verdict)

    status_code = 200
    if final_verdict == "BLOCK":
        status_code = 403
    elif final_verdict == "RATE_LIMIT":
        status_code = 429

    return (
        jsonify(
            {
                "success": True,
                "data": {
                    "verdict": final_verdict,
                    "risk_score": risk_score,
                    "detection": detection,
                    "incident_id": incident_record["id"] if incident_record else None,
                },
                "error": None,
            }
        ),
        status_code,
    )

"""Route blueprint for /predict and live request inspection pipeline."""

import time
import logging
from flask import Blueprint, request, jsonify
from gateway.pipeline.parser import parse_request
from gateway.pipeline.preprocess import preprocess_payload
from gateway.pipeline.detection import detect_attack
from gateway.pipeline.threat_intel import check_threat_intel
from gateway.pipeline.device_profiler import profile_device
from gateway.pipeline.session_manager import track_session, record_violation
from gateway.pipeline.behavior_engine import analyze_behavior
from gateway.pipeline.risk_engine import compute_risk_details
from gateway.pipeline.decision_engine import evaluate_decision_details
from gateway.pipeline.policy_engine import enforce_policy_details
from gateway.services.incident_service import log_incident, get_ip_override

logger = logging.getLogger(__name__)

predict_bp = Blueprint("predict", __name__)


def compute_risk_level(risk_score: float, verdict: str, label: str) -> str:
    """Map risk score, verdict, and ML detection label to standardized severity level."""
    if verdict == "BLOCK" or risk_score >= 80.0 or label in ("sqli", "xss"):
        return "CRITICAL"
    elif risk_score >= 60.0 or verdict == "RATE_LIMIT":
        return "HIGH"
    elif risk_score >= 40.0 or verdict == "MONITOR":
        return "MEDIUM"
    return "LOW"


@predict_bp.route("/predict", methods=["POST"])
def inspect_request():
    """
    Inspect an incoming request through the 14-stage security pipeline.

    Accepts:
    - Raw request dictionary (method, path, headers, query_params, body, ip)
    - Or direct inspection payload: {"payload": "..."} / {"text": "..."}

    Returns structured response:
    {
        "status": "success",
        "label": "sqli",
        "confidence": 0.985,
        "risk_level": "CRITICAL",
        "latency_ms": 4.2,
        "verdict": "BLOCK",
        "risk_score": 85.5,
        "incident_id": "...",
        "data": { ... }
    }
    """
    start_time = time.perf_counter()

    body = request.get_json(silent=True)
    if body is None:
        return (
            jsonify(
                {
                    "status": "error",
                    "success": False,
                    "data": None,
                    "error": "Invalid or missing JSON body",
                }
            ),
            400,
        )

    # 1-2. Ingress & Parse
    parsed = parse_request(body)
    # Merge outer HTTP headers into parsed headers if not specified in body
    for k, v in request.headers.items():
        k_lower = k.lower()
        if k_lower not in parsed["headers"]:
            parsed["headers"][k_lower] = v
    if not body.get("ip") and not body.get("client_ip"):
        if request.remote_addr:
            parsed["ip"] = request.remote_addr


    # 3. Preprocess & Canonicalize
    cleaned_payload = preprocess_payload(parsed["raw_payload"])

    # 4. ML Detection
    detection = detect_attack(cleaned_payload)
    detected_label = detection.get("label", "benign")

    # 5. Threat Intel
    intel = check_threat_intel(parsed["ip"])

    # 6-7. Device Profiler & Session Manager
    device = profile_device(parsed["headers"])
    session_id = parsed["headers"].get("x-session-id", parsed["ip"])
    session = track_session(session_id, parsed["ip"], device.get("fingerprint"))

    # 8. Behavior Engine
    behavior = analyze_behavior(session, device, parsed.get("path"))

    # 9. Risk Engine
    risk_details = compute_risk_details(detection, intel, behavior)
    risk_score = risk_details["risk_score"]

    # 10. Decision Engine
    decision_details = evaluate_decision_details(risk_score)
    preliminary_verdict = decision_details["verdict"]

    # 11. Policy Engine
    ip_override = get_ip_override(parsed["ip"])
    policy_details = enforce_policy_details(
        preliminary_verdict=preliminary_verdict,
        detection_info=detection,
        session_info=session,
        threat_intel_info=intel,
        device_info=device,
        ip_override=ip_override,
    )
    final_verdict = policy_details["final_verdict"]

    # 12. Incident Service (persist and record violation if flagged)
    incident_record = None
    if final_verdict != "ALLOW":
        incident_record = log_incident(parsed, detection, risk_score, final_verdict)
        record_violation(session_id, parsed["ip"], device.get("fingerprint"))

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    risk_level = compute_risk_level(risk_score, final_verdict, detected_label)

    status_code = 200
    if final_verdict == "BLOCK":
        status_code = 403
    elif final_verdict == "RATE_LIMIT":
        status_code = 429

    return (
        jsonify(
            {
                "status": "success",
                "success": True,
                "label": detected_label,
                "confidence": detection.get("confidence", 0.0),
                "risk_level": risk_level,
                "risk_score": risk_score,
                "verdict": final_verdict,
                "latency_ms": latency_ms,
                "incident_id": incident_record["id"] if incident_record else None,
                "data": {
                    "label": detected_label,
                    "confidence": detection.get("confidence", 0.0),
                    "verdict": final_verdict,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "latency_ms": latency_ms,
                    "detection": detection,
                    "risk_components": risk_details["components"],
                    "raw_scores": risk_details["raw_scores"],
                    "decision": decision_details,
                    "policy_override": policy_details,
                    "threat_intel": intel,
                    "device_profile": device,
                    "session": session,
                    "behavior": behavior,
                    "incident_id": incident_record["id"] if incident_record else None,
                },
                "error": None,
            }
        ),
        status_code,
    )

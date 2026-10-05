"""Stage 4: ML Detection - Loads inference function and classifies payload."""

import logging
import time
from typing import Dict, Any
from ml.inference import predict

logger = logging.getLogger(__name__)


def detect_attack(payload: str) -> Dict[str, Any]:
    """
    Run machine learning classification on the preprocessed payload.

    Args:
        payload: Preprocessed payload string.

    Returns:
        Dictionary containing label (benign, sqli, xss), confidence score, and latency.
    """
    if not payload or not str(payload).strip():
        return {"label": "benign", "confidence": 1.0, "latency_ms": 0.0}

    t0 = time.perf_counter()
    try:
        label, confidence = predict(payload, fail_closed=True)
        latency_ms = round((time.perf_counter() - t0) * 1000, 3)
        return {
            "label": label,
            "confidence": round(confidence, 4),
            "latency_ms": latency_ms,
        }
    except Exception as e:
        latency_ms = round((time.perf_counter() - t0) * 1000, 3)
        logger.error("Error in detect_attack: %s. Enforcing fail-closed.", e)
        return {
            "label": "sqli",
            "confidence": 0.99,
            "latency_ms": latency_ms,
            "fail_closed": True,
            "error": str(e),
        }


"""Stage 4: ML Detection - Loads inference function and classifies payload."""

from typing import Dict, Any
from ml.inference import predict


def detect_attack(payload: str) -> Dict[str, Any]:
    """
    Run machine learning classification on the preprocessed payload.

    Args:
        payload: Preprocessed payload string.

    Returns:
        Dictionary containing label (benign, sqli, xss) and confidence score.
    """
    if not payload:
        return {"label": "benign", "confidence": 1.0}

    label, confidence = predict(payload)
    return {
        "label": label,
        "confidence": round(confidence, 4),
    }

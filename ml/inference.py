"""Inference module for real-time payload prediction."""

import json
import os
import torch
from typing import Dict, Tuple, Optional
import logging

logger = logging.getLogger(__name__)

# Class index mapping
LABEL_MAP = {0: "benign", 1: "sqli", 2: "xss"}

_model = None
_vocab: Optional[Dict[str, int]] = None
_device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def load_model(model_path: str = "ml/artifacts/model.pt", vocab_path: str = "ml/artifacts/vocab.json"):
    """Load model checkpoint and vocabulary dictionary."""
    global _model, _vocab
    if os.path.exists(vocab_path):
        with open(vocab_path, "r", encoding="utf-8") as f:
            _vocab = json.load(f)
    if os.path.exists(model_path):
        from ml.model import PayloadClassifier

        vocab_size = len(_vocab) if _vocab else 128
        _model = PayloadClassifier(vocab_size=vocab_size)
        _model.load_state_dict(torch.load(model_path, map_location=_device))
        _model.to(_device)
        _model.eval()
        logger.info("Loaded model from %s on device %s", model_path, _device)


def predict(text: str, max_len: int = 256) -> Tuple[str, float]:
    """
    Classify a raw string payload into benign, sqli, or xss with confidence score.

    Args:
        text: Input string payload.
        max_len: Max sequence length for tokenizer.

    Returns:
        Tuple of (predicted_label, confidence_score)
    """
    global _model, _vocab
    if _model is None or _vocab is None:
        # Stub / fallback for early gateway development prior to model training
        lower_text = text.lower()
        if "select" in lower_text or "union" in lower_text or "1=1" in lower_text or "--" in lower_text:
            return "sqli", 0.95
        if "<script" in lower_text or "onerror=" in lower_text or "alert(" in lower_text:
            return "xss", 0.95
        return "benign", 0.90

    tokens = [_vocab.get(ch, _vocab.get("<UNK>", 1)) for ch in text[:max_len]]
    if len(tokens) < max_len:
        tokens += [_vocab.get("<PAD>", 0)] * (max_len - len(tokens))

    x = torch.tensor([tokens], dtype=torch.long, device=_device)
    with torch.no_grad():
        logits = _model(x)
        probs = torch.softmax(logits, dim=1)[0]
        confidence, pred_idx = torch.max(probs, dim=0)

    label = LABEL_MAP.get(pred_idx.item(), "benign")
    return label, float(confidence.item())

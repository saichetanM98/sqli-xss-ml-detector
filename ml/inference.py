"""Inference module for real-time payload prediction."""

import json
import os
import re
from typing import Dict, List, Optional, Tuple
import logging
import torch

logger = logging.getLogger(__name__)

# Class index mapping
LABEL_MAP = {0: "benign", 1: "sqli", 2: "xss"}

_model = None
_vocab: Optional[Dict[str, int]] = None
_device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
_is_loaded: bool = False

# Fallback heuristic signatures for fail-closed security posture
SQLI_HEURISTIC_PATTERNS = [
    r"(\bunion\b.*\bselect\b)",
    r"(\bselect\b.*\bfrom\b)",
    r"(\binsert\b.*\binto\b)",
    r"(\bdrop\b\s+\btable\b)",
    r"(\bdelete\b.*\bfrom\b)",
    r"('|\")\s*(or|and)\s*('|\")?\d+('|\")?\s*=\s*('|\")?\d+",
    r"('|\")\s*(or|and)\s*('|\")?1('|\")?\s*=\s*('|\")?1",
    r"(--|#|/\*|\*/)",
    r"(\bexec\b|\bexecute\b|\bxp_cmdshell\b)",
    r"(\bbenchmark\b\s*\(|\bsleep\b\s*\()",
    r"(admin'|root')",
]

XSS_HEURISTIC_PATTERNS = [
    r"<\s*script\b",
    r"<\s*/\s*script\b",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"onmouseover\s*=",
    r"onfocus\s*=",
    r"<\s*img\b",
    r"<\s*svg\b",
    r"<\s*iframe\b",
    r"alert\s*\(",
    r"document\.(cookie|location|domain)",
    r"eval\s*\(",
]


def load_model(
    model_path: Optional[str] = None,
    vocab_path: str = "ml/artifacts/vocab.json",
    device: Optional[str] = None,
) -> bool:
    """
    Load model checkpoint and vocabulary dictionary.

    Args:
        model_path: Optional path to .pt checkpoint. If None, prefers best_model.pt.
        vocab_path: Path to vocab JSON file.
        device: Optional target device ('cuda', 'cpu').

    Returns:
        True if model and vocab were loaded successfully, False otherwise.
    """
    global _model, _vocab, _device, _is_loaded

    if device:
        _device = torch.device(device)
    else:
        _device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Load character vocabulary
    if os.path.exists(vocab_path):
        try:
            with open(vocab_path, "r", encoding="utf-8") as f:
                _vocab = json.load(f)
            logger.info("Loaded vocabulary with %d tokens from %s", len(_vocab), vocab_path)
        except Exception as e:
            logger.error("Failed to load vocabulary from %s: %s", vocab_path, e)
            _vocab = None
    else:
        logger.warning("Vocabulary file not found at %s", vocab_path)
        _vocab = None

    # Resolve model checkpoint path
    if model_path is None:
        if os.path.exists("ml/artifacts/best_model.pt"):
            model_path = "ml/artifacts/best_model.pt"
        elif os.path.exists("ml/artifacts/model.pt"):
            model_path = "ml/artifacts/model.pt"

    if model_path and os.path.exists(model_path):
        try:
            from ml.model import PayloadClassifier

            loaded = torch.load(model_path, map_location=_device, weights_only=False)

            # Determine architecture hyperparams
            vocab_size = len(_vocab) if _vocab else 170
            embed_dim = 64
            num_classes = 3
            hidden_dim = 64
            num_filters = 64

            if isinstance(loaded, dict):
                vocab_size = loaded.get("vocab_size", vocab_size)
                hyperparams = loaded.get("hyperparams", {})
                embed_dim = hyperparams.get("embed_dim", embed_dim)
                num_classes = hyperparams.get("num_classes", num_classes)
                hidden_dim = hyperparams.get("hidden_dim", hidden_dim)
                num_filters = hyperparams.get("num_filters", num_filters)
                state_dict = loaded.get("model_state_dict", loaded)
            else:
                state_dict = loaded

            _model = PayloadClassifier(
                vocab_size=vocab_size,
                embed_dim=embed_dim,
                num_classes=num_classes,
                hidden_dim=hidden_dim,
                num_filters=num_filters,
            )
            _model.load_state_dict(state_dict)
            _model.to(_device)
            _model.eval()
            _is_loaded = True
            logger.info("Successfully loaded model from %s on device %s", model_path, _device)
            return True
        except Exception as e:
            logger.error("Failed to instantiate and load model from %s: %s", model_path, e)
            _model = None
            _is_loaded = False
            return False
    else:
        logger.warning("Model checkpoint not found at %s", model_path)
        _model = None
        _is_loaded = False
        return False


def is_model_ready() -> bool:
    """Check if model and vocabulary are loaded and ready for live inference."""
    return _is_loaded and (_model is not None) and (_vocab is not None)


def unload_model() -> None:
    """Unload model from memory (used for fail-closed tests and reset)."""
    global _model, _vocab, _is_loaded
    _model = None
    _vocab = None
    _is_loaded = False


def _heuristic_fallback(text: str, fail_closed: bool = True) -> Tuple[str, float]:
    """
    Fail-closed heuristic security fallback when ML model is degraded or unavailable.

    Guarantees:
    - If empty string: returns ('benign', 1.0).
    - If known SQLi signatures match: returns ('sqli', 0.99).
    - If known XSS signatures match: returns ('xss', 0.99).
    - If unverified in fail-closed mode: flags as critical ('sqli', 0.95) to prevent silent bypass.
    """
    cleaned = text.strip()
    if not cleaned:
        return "benign", 1.0

    lower = cleaned.lower()

    # Check XSS patterns
    for pat in XSS_HEURISTIC_PATTERNS:
        if re.search(pat, lower, re.IGNORECASE):
            return "xss", 0.99

    # Check SQLi patterns
    for pat in SQLI_HEURISTIC_PATTERNS:
        if re.search(pat, lower, re.IGNORECASE):
            return "sqli", 0.99

    if fail_closed:
        # Fail-closed security posture: flag unverified traffic when ML engine is down
        logger.warning("Fail-closed fallback triggered for unverified payload: %s", cleaned[:50])
        return "sqli", 0.95

    return "benign", 0.50


def tokenize_text(text: str, vocab: Dict[str, int], max_len: int = 256) -> List[int]:
    """Tokenize a single string using vocabulary with UNK and PAD indices."""
    unk_idx = vocab.get("<UNK>", 1)
    pad_idx = vocab.get("<PAD>", 0)
    tokens = [vocab.get(ch, unk_idx) for ch in text[:max_len]]
    if len(tokens) < max_len:
        tokens += [pad_idx] * (max_len - len(tokens))
    return tokens


def predict_batch(texts: List[str], max_len: int = 256, fail_closed: bool = True) -> List[Tuple[str, float]]:
    """
    Classify a batch of payloads with high throughput.

    Args:
        texts: List of input string payloads.
        max_len: Max sequence length for character tokenization.
        fail_closed: Whether to apply fail-closed security posture if model unavailable.

    Returns:
        List of (predicted_label, confidence_score) tuples.
    """
    global _model, _vocab, _device

    if not texts:
        return []

    if _model is None or _vocab is None:
        return [_heuristic_fallback(t, fail_closed=fail_closed) for t in texts]

    try:
        tokenized_batch = [tokenize_text(t, _vocab, max_len=max_len) for t in texts]
        x = torch.tensor(tokenized_batch, dtype=torch.long, device=_device)

        with torch.no_grad():
            logits = _model(x)
            probs = torch.softmax(logits, dim=1)
            confs, pred_indices = torch.max(probs, dim=1)

        results = []
        for i in range(len(texts)):
            label = LABEL_MAP.get(pred_indices[i].item(), "benign")
            results.append((label, float(confs[i].item())))
        return results
    except Exception as e:
        logger.error("Error during batch inference: %s. Using fail-closed fallback.", e)
        return [_heuristic_fallback(t, fail_closed=fail_closed) for t in texts]


def predict(text: str, max_len: int = 256, fail_closed: bool = True) -> Tuple[str, float]:
    """
    Classify a raw string payload into benign, sqli, or xss with confidence score.

    Args:
        text: Input string payload.
        max_len: Max sequence length for tokenizer.
        fail_closed: Whether to enforce fail-closed security fallback if model unavailable.

    Returns:
        Tuple of (predicted_label, confidence_score).
    """
    global _model, _vocab, _device

    if not text or not str(text).strip():
        return "benign", 1.0

    if _model is None or _vocab is None:
        return _heuristic_fallback(text, fail_closed=fail_closed)

    try:
        tokens = tokenize_text(str(text), _vocab, max_len=max_len)
        x = torch.tensor([tokens], dtype=torch.long, device=_device)

        with torch.no_grad():
            logits = _model(x)
            probs = torch.softmax(logits, dim=1)[0]
            confidence, pred_idx = torch.max(probs, dim=0)

        label = LABEL_MAP.get(pred_idx.item(), "benign")
        return label, float(confidence.item())
    except Exception as e:
        logger.error("Error during inference on payload: %s. Enforcing fail-closed.", e)
        return _heuristic_fallback(text, fail_closed=fail_closed)


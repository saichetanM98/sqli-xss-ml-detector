"""Verification script for CUDA GPU hardware acceleration and PayloadClassifier forward pass."""

import os
import sys
import json
import logging

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import torch
from ml.model import PayloadClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def verify_gpu_and_model():
    logger.info("Checking PyTorch version and CUDA availability...")
    logger.info("PyTorch Version: %s", torch.__version__)

    cuda_available = torch.cuda.is_available()
    logger.info("CUDA Available: %s", cuda_available)

    if cuda_available:
        device = torch.device("cuda")
        gpu_name = torch.cuda.get_device_name(0)
        vram_mb = torch.cuda.get_device_properties(0).total_memory / (1024 * 1024)
        logger.info("Detected GPU: %s (Total VRAM: %.1f MB)", gpu_name, vram_mb)
    else:
        device = torch.device("cpu")
        logger.warning("CUDA is NOT available. Falling back to CPU for test.")

    # Load vocab size
    vocab_path = "ml/artifacts/vocab.json"
    if os.path.exists(vocab_path):
        with open(vocab_path, "r", encoding="utf-8") as f:
            vocab = json.load(f)
        vocab_size = len(vocab)
        logger.info("Loaded vocabulary of size: %d", vocab_size)
    else:
        vocab_size = 170
        logger.info("Using default vocab size: %d", vocab_size)

    # Instantiate PayloadClassifier
    logger.info("Instantiating PayloadClassifier (CNN + BiLSTM)...")
    model = PayloadClassifier(vocab_size=vocab_size, embed_dim=64, num_classes=3, hidden_dim=64, num_filters=64)
    model.to(device)
    model.eval()

    # Generate synthetic batch: batch_size=16, seq_len=256
    batch_size = 16
    seq_len = 256
    dummy_input = torch.randint(low=0, high=vocab_size, size=(batch_size, seq_len), dtype=torch.long, device=device)
    logger.info("Input tensor shape: %s on device: %s", list(dummy_input.shape), device)

    # Perform forward pass
    with torch.no_grad():
        output = model(dummy_input)

    logger.info("Output logits shape: %s", list(output.shape))
    assert output.shape == (batch_size, 3), f"Expected shape ({batch_size}, 3), got {output.shape}"

    # Compute softmax probabilities
    probs = torch.softmax(output, dim=-1)
    logger.info("Sample prediction probabilities for sample 0: %s", [round(p, 4) for p in probs[0].tolist()])

    if cuda_available:
        allocated_mb = torch.cuda.memory_allocated(0) / (1024 * 1024)
        logger.info("GPU VRAM currently allocated: %.2f MB", allocated_mb)
        logger.info(">>> SUCCESS: Model architecture and GPU acceleration verified! <<<")
    else:
        logger.info(">>> SUCCESS: Model forward pass succeeded on CPU. <<<")


if __name__ == "__main__":
    verify_gpu_and_model()

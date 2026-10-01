"""Training script for character-level CNN/BiLSTM payload classifier."""

import os
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def train_model():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info("Using compute device: %s", device)
    if device.type != "cuda":
        logger.warning("CUDA not detected. Training will fall back to CPU.")


if __name__ == "__main__":
    train_model()

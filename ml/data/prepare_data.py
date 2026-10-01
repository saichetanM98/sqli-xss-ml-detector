"""Data preparation script to clean, merge, and tokenize datasets."""

import os
import json
import logging
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def build_vocab(texts: List[str]) -> Dict[str, int]:
    """Build character-level vocabulary with special tokens."""
    vocab = {"<PAD>": 0, "<UNK>": 1}
    for text in texts:
        for ch in str(text):
            if ch not in vocab:
                vocab[ch] = len(vocab)
    return vocab


def prepare_datasets(raw_data_dir: str = "datasets", output_dir: str = "ml/artifacts") -> None:
    """Load raw CSV datasets, normalize labels, generate vocab, and export splits."""
    logger.info("Starting dataset preparation from %s...", raw_data_dir)
    # Placeholder for week 1 data preparation pipeline
    os.makedirs(output_dir, exist_ok=True)
    logger.info("Vocabulary and cleaned datasets will be written to %s", output_dir)


if __name__ == "__main__":
    prepare_datasets()

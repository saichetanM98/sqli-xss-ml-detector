"""PyTorch Dataset & DataLoader utilities for character-level payload classification."""

import os
import json
import logging
import torch
from torch.utils.data import Dataset, DataLoader
from typing import List, Tuple, Dict
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class PayloadDataset(Dataset):
    """Character-level tokenized payload dataset for SQLi, XSS, and benign requests."""

    def __init__(self, texts: List[str], labels: List[int], vocab: Dict[str, int], max_len: int = 256):
        """
        Initialize the dataset.

        Args:
            texts: List of raw string payloads.
            labels: List of integer class labels (0: benign, 1: sqli, 2: xss).
            vocab: Mapping from character to integer token ID.
            max_len: Maximum sequence length for padding/truncation.
        """
        self.texts = texts
        self.labels = labels
        self.vocab = vocab
        self.max_len = max_len
        self.pad_idx = vocab.get("<PAD>", 0)
        self.unk_idx = vocab.get("<UNK>", 1)

    def __len__(self) -> int:
        return len(self.texts)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        text = str(self.texts[idx])
        # Convert characters to token IDs; replace unseen chars with <UNK>
        tokens = [self.vocab.get(ch, self.unk_idx) for ch in text[: self.max_len]]
        # Pad sequence with <PAD> up to max_len
        if len(tokens) < self.max_len:
            tokens += [self.pad_idx] * (self.max_len - len(tokens))

        x = torch.tensor(tokens, dtype=torch.long)
        y = torch.tensor(self.labels[idx], dtype=torch.long)
        return x, y


def get_dataloader(
    csv_path: str,
    vocab_path: str,
    batch_size: int = 32,
    max_len: int = 256,
    shuffle: bool = True,
    num_workers: int = 0,
) -> Tuple[DataLoader, int]:
    """Load split CSV and vocab, returning a PyTorch DataLoader and total dataset length."""
    with open(vocab_path, "r", encoding="utf-8") as f:
        vocab = json.load(f)

    df = pd.read_csv(csv_path, encoding="utf-8")
    texts = df["payload"].astype(str).tolist()
    labels = df["label"].astype(int).tolist()

    dataset = PayloadDataset(texts=texts, labels=labels, vocab=vocab, max_len=max_len)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=shuffle, num_workers=num_workers)
    return loader, len(vocab)


if __name__ == "__main__":
    # Self-test block: verify DataLoader with the newly generated artifacts
    train_csv = "ml/artifacts/train.csv"
    vocab_file = "ml/artifacts/vocab.json"

    if os.path.exists(train_csv) and os.path.exists(vocab_file):
        logger.info("Testing PayloadDataset and DataLoader on %s...", train_csv)
        train_loader, vocab_size = get_dataloader(train_csv, vocab_file, batch_size=32)

        # Fetch first batch
        for batch_x, batch_y in train_loader:
            logger.info("Batch x shape (tensors): %s", list(batch_x.shape))
            logger.info("Batch y shape (labels):  %s", list(batch_y.shape))
            logger.info("Sample input tokens (first 20 chars of sample 0): %s", batch_x[0][:20].tolist())
            logger.info("Sample label of sample 0: %d", int(batch_y[0]))
            break
        logger.info("PyTorch Dataset & DataLoader pipeline verified successfully!")
    else:
        logger.error("Artifacts not found! Please run 'python -m ml.data.prepare_data' first.")

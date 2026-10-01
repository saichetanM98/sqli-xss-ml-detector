"""PyTorch Dataset & DataLoader utilities for character-level payload classification."""

import torch
from torch.utils.data import Dataset
from typing import List, Tuple, Dict


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
        tokens = [self.vocab.get(ch, self.unk_idx) for ch in text[: self.max_len]]
        if len(tokens) < self.max_len:
            tokens += [self.pad_idx] * (self.max_len - len(tokens))

        x = torch.tensor(tokens, dtype=torch.long)
        y = torch.tensor(self.labels[idx], dtype=torch.long)
        return x, y

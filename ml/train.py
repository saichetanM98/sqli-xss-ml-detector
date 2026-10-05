"""Production training script for character-level CNN + BiLSTM payload classifier.

Supports automatic GPU (CUDA) acceleration with CPU fallback, balanced class weighting,
learning rate scheduling, early stopping, and model checkpointing.
"""

import os
import sys
import json
import time
import shutil
import argparse
import logging
from typing import Dict, Tuple, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import torch
import torch.nn as nn
from torch.utils.data import DataLoader
import numpy as np

from ml.model import PayloadClassifier
from ml.data.dataset import get_dataloader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def setup_device(requested_device: Optional[str] = None) -> torch.device:
    """Detect and configure compute device (CUDA / CPU) with optimized performance settings."""
    if requested_device:
        device = torch.device(requested_device)
    else:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    logger.info("Selected compute device: %s", device)
    if device.type == "cuda":
        gpu_name = torch.cuda.get_device_name(0)
        vram_mb = torch.cuda.get_device_properties(0).total_memory / (1024 * 1024)
        logger.info("CUDA GPU Active: %s (Total VRAM: %.1f MB)", gpu_name, vram_mb)
        torch.backends.cudnn.benchmark = True
    else:
        num_threads = os.cpu_count() or 4
        torch.set_num_threads(num_threads)
        logger.info("Running on CPU with %d worker threads.", num_threads)

    return device


def compute_class_weights(csv_path: str, num_classes: int = 3, device: torch.device = torch.device("cpu")) -> torch.Tensor:
    """Compute balanced inverse-frequency class weights for CrossEntropyLoss."""
    import pandas as pd

    df = pd.read_csv(csv_path, encoding="utf-8")
    counts = df["label"].value_counts().sort_index().to_dict()
    total_samples = len(df)

    weights = []
    for c in range(num_classes):
        count = counts.get(c, 1)
        # Inverse class frequency formula: N / (K * N_c)
        w = total_samples / (num_classes * count)
        weights.append(w)

    weight_tensor = torch.tensor(weights, dtype=torch.float32, device=device)
    logger.info("Calculated class weights: %s (Counts: %s)", [round(float(w), 3) for w in weight_tensor], counts)
    return weight_tensor


class EarlyStopping:
    """Early stops the training if validation loss doesn't improve after a given patience."""

    def __init__(self, patience: int = 3, min_delta: float = 1e-4):
        self.patience = patience
        self.min_delta = min_delta
        self.counter = 0
        self.best_loss = float("inf")
        self.early_stop = False
        self.best_epoch = 0

    def step(self, val_loss: float, epoch: int) -> bool:
        """Returns True if this is the best model so far, False otherwise."""
        if val_loss < self.best_loss - self.min_delta:
            self.best_loss = val_loss
            self.best_epoch = epoch
            self.counter = 0
            return True
        else:
            self.counter += 1
            logger.info("EarlyStopping counter: %d out of %d (Best Val Loss: %.4f at Epoch %d)",
                        self.counter, self.patience, self.best_loss, self.best_epoch)
            if self.counter >= self.patience:
                self.early_stop = True
            return False


def train_epoch(
    model: nn.Module,
    loader: DataLoader,
    criterion: nn.Module,
    optimizer: torch.optim.Optimizer,
    device: torch.device,
) -> Tuple[float, float]:
    """Train for one epoch, returning average loss and accuracy."""
    model.train()
    running_loss = 0.0
    correct = 0
    total = 0

    for batch_idx, (x, y) in enumerate(loader):
        x, y = x.to(device), y.to(device)

        optimizer.zero_grad()
        logits = model(x)
        loss = criterion(logits, y)
        loss.backward()

        # Gradient clipping for recurrent stability
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)

        optimizer.step()

        running_loss += loss.item() * x.size(0)
        preds = torch.argmax(logits, dim=1)
        correct += (preds == y).sum().item()
        total += x.size(0)

    epoch_loss = running_loss / total
    epoch_acc = correct / total
    return epoch_loss, epoch_acc


def validate_epoch(
    model: nn.Module,
    loader: DataLoader,
    criterion: nn.Module,
    device: torch.device,
) -> Tuple[float, float]:
    """Evaluate for one epoch on validation split, returning average loss and accuracy."""
    model.eval()
    running_loss = 0.0
    correct = 0
    total = 0

    with torch.no_grad():
        for x, y in loader:
            x, y = x.to(device), y.to(device)
            logits = model(x)
            loss = criterion(logits, y)

            running_loss += loss.item() * x.size(0)
            preds = torch.argmax(logits, dim=1)
            correct += (preds == y).sum().item()
            total += x.size(0)

    val_loss = running_loss / total
    val_acc = correct / total
    return val_loss, val_acc


def run_training(
    train_csv: str = "ml/artifacts/train.csv",
    val_csv: str = "ml/artifacts/val.csv",
    vocab_path: str = "ml/artifacts/vocab.json",
    save_path: str = "ml/artifacts/best_model.pt",
    history_path: str = "ml/artifacts/training_history.json",
    epochs: int = 10,
    batch_size: int = 256,
    lr: float = 1e-3,
    patience: int = 3,
    device_name: Optional[str] = None,
    use_class_weights: bool = True,
) -> Dict:
    """Execute complete model training run with checkpointing and metric tracking."""
    device = setup_device(device_name)

    # 1. Load Data
    logger.info("Loading training data from %s...", train_csv)
    train_loader, vocab_size = get_dataloader(
        csv_path=train_csv,
        vocab_path=vocab_path,
        batch_size=batch_size,
        shuffle=True,
    )
    val_loader, _ = get_dataloader(
        csv_path=val_csv,
        vocab_path=vocab_path,
        batch_size=batch_size,
        shuffle=False,
    )

    logger.info("Vocabulary size: %d | Train batches: %d | Val batches: %d",
                vocab_size, len(train_loader), len(val_loader))

    # 2. Build Model
    model = PayloadClassifier(
        vocab_size=vocab_size,
        embed_dim=64,
        num_classes=3,
        hidden_dim=64,
        num_filters=64,
    ).to(device)

    # 3. Setup Loss, Optimizer & Scheduler
    if use_class_weights:
        weights = compute_class_weights(train_csv, num_classes=3, device=device)
        criterion = nn.CrossEntropyLoss(weight=weights)
    else:
        criterion = nn.CrossEntropyLoss()

    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=1, min_lr=1e-5
    )
    early_stopping = EarlyStopping(patience=patience)

    # 4. Training Loop
    history = {
        "train_loss": [],
        "train_acc": [],
        "val_loss": [],
        "val_acc": [],
        "learning_rates": [],
        "epochs": 0,
        "best_epoch": 0,
        "best_val_loss": float("inf"),
        "best_val_acc": 0.0,
    }

    start_time = time.time()
    logger.info(">>> Starting Training for up to %d Epochs (Patience=%d, Batch Size=%d) <<<",
                epochs, patience, batch_size)

    for epoch in range(1, epochs + 1):
        epoch_start = time.time()
        current_lr = optimizer.param_groups[0]["lr"]

        train_loss, train_acc = train_epoch(model, train_loader, criterion, optimizer, device)
        val_loss, val_acc = validate_epoch(model, val_loader, criterion, device)

        scheduler.step(val_loss)
        epoch_duration = time.time() - epoch_start

        logger.info(
            "Epoch [%02d/%02d] (%.1fs) | Train Loss: %.4f | Train Acc: %.2f%% | Val Loss: %.4f | Val Acc: %.2f%% | LR: %.2e",
            epoch, epochs, epoch_duration, train_loss, train_acc * 100, val_loss, val_acc * 100, current_lr
        )

        history["train_loss"].append(train_loss)
        history["train_acc"].append(train_acc)
        history["val_loss"].append(val_loss)
        history["val_acc"].append(val_acc)
        history["learning_rates"].append(current_lr)
        history["epochs"] = epoch

        # Save Best Model Checkpoint
        is_best = early_stopping.step(val_loss, epoch)
        if is_best:
            history["best_epoch"] = epoch
            history["best_val_loss"] = val_loss
            history["best_val_acc"] = val_acc

            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            checkpoint = {
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "vocab_size": vocab_size,
                "val_loss": val_loss,
                "val_acc": val_acc,
                "hyperparams": {
                    "embed_dim": 64,
                    "num_classes": 3,
                    "hidden_dim": 64,
                    "num_filters": 64,
                    "batch_size": batch_size,
                    "lr": lr,
                },
            }
            torch.save(checkpoint, save_path)
            # Also save raw state_dict copy to ml/artifacts/model.pt for direct inference compatibility
            model_pt_path = os.path.join(os.path.dirname(save_path), "model.pt")
            torch.save(model.state_dict(), model_pt_path)
            logger.info("--> Checkpoint saved to %s & %s (Val Acc: %.2f%%)", save_path, model_pt_path, val_acc * 100)

        if early_stopping.early_stop:
            logger.info("--> Early stopping triggered at Epoch %d.", epoch)
            break

    total_duration = time.time() - start_time
    history["total_duration_sec"] = round(total_duration, 2)
    logger.info(">>> Training Completed in %.1f seconds. Best Epoch: %d (Val Acc: %.2f%%) <<<",
                total_duration, history["best_epoch"], history["best_val_acc"] * 100)

    # Save training history JSON
    with open(history_path, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)
    logger.info("Training history saved to %s", history_path)

    return history


def main():
    parser = argparse.ArgumentParser(description="Train CNN+BiLSTM payload classifier.")
    parser.add_argument("--epochs", type=int, default=8, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=256, help="Batch size for DataLoader")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--patience", type=int, default=3, help="Early stopping patience")
    parser.add_argument("--device", type=str, default=None, help="Device to use ('cuda' or 'cpu')")
    parser.add_argument("--no-class-weights", action="store_true", help="Disable inverse class weighting")
    args = parser.parse_args()

    run_training(
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        patience=args.patience,
        device_name=args.device,
        use_class_weights=not args.no_class_weights,
    )


if __name__ == "__main__":
    main()

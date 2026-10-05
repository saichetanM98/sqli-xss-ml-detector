"""Comprehensive evaluation script for payload classifier.

Evaluates best_model.pt against the held-out test split, computing overall accuracy,
macro/weighted precision, recall, F1, per-class breakdown, security-focused metrics
(Benign FPR, Attack FNR), and confusion matrix. Saves report to ml/artifacts/evaluation_report.json.
"""

import os
import sys
import json
import time
import argparse
import logging
from typing import Dict, Any, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import torch
import torch.nn.functional as F
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
)

from ml.model import PayloadClassifier
from ml.data.dataset import get_dataloader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

CLASS_NAMES = ["benign", "sqli", "xss"]
LABEL_MAP = {0: "benign", 1: "sqli", 2: "xss"}


def setup_device(requested_device: Optional[str] = None) -> torch.device:
    """Detect and return compute device (CUDA / CPU)."""
    if requested_device:
        device = torch.device(requested_device)
    else:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    logger.info("Evaluation compute device: %s", device)
    if device.type == "cuda":
        gpu_name = torch.cuda.get_device_name(0)
        logger.info("CUDA Hardware: %s", gpu_name)
    return device


def load_model(model_path: str, vocab_size: int, device: torch.device) -> PayloadClassifier:
    """Load model checkpoint into evaluation mode."""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model checkpoint not found at: {model_path}")

    model = PayloadClassifier(
        vocab_size=vocab_size,
        embed_dim=64,
        num_classes=3,
        hidden_dim=64,
        num_filters=64,
    )

    checkpoint = torch.load(model_path, map_location=device, weights_only=False)
    if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint:
        model.load_state_dict(checkpoint["model_state_dict"])
        logger.info("Loaded checkpoint dictionary from %s (Trained Epoch: %s)",
                    model_path, checkpoint.get("epoch", "N/A"))
    else:
        model.load_state_dict(checkpoint)
        logger.info("Loaded raw state_dict from %s", model_path)

    model.to(device)
    model.eval()
    return model


def evaluate(
    test_csv: str = "ml/artifacts/test.csv",
    model_path: str = "ml/artifacts/best_model.pt",
    vocab_path: str = "ml/artifacts/vocab.json",
    output_path: str = "ml/artifacts/evaluation_report.json",
    batch_size: int = 256,
    device_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Run full evaluation on held-out test split and export metrics report."""
    device = setup_device(device_name)

    logger.info("Loading test dataset from: %s", test_csv)
    test_loader, vocab_size = get_dataloader(
        csv_path=test_csv,
        vocab_path=vocab_path,
        batch_size=batch_size,
        shuffle=False,
    )
    total_samples = len(test_loader.dataset)
    logger.info("Test set size: %d samples | Batches: %d | Vocab size: %d",
                total_samples, len(test_loader), vocab_size)

    # Load model
    model = load_model(model_path, vocab_size, device)

    # Batch Inference
    all_preds = []
    all_targets = []
    all_probs = []

    start_time = time.perf_counter()
    with torch.no_grad():
        for x, y in test_loader:
            x = x.to(device)
            logits = model(x)
            probs = F.softmax(logits, dim=1)
            preds = torch.argmax(probs, dim=1)

            all_preds.extend(preds.cpu().numpy().tolist())
            all_targets.extend(y.numpy().tolist())
            all_probs.extend(probs.cpu().numpy().tolist())

    total_time_sec = time.perf_counter() - start_time
    latency_per_sample_ms = (total_time_sec / total_samples) * 1000
    throughput_samples_per_sec = total_samples / total_time_sec if total_time_sec > 0 else 0

    y_true = np.array(all_targets)
    y_pred = np.array(all_preds)

    # 1. Overall Metrics
    acc = accuracy_score(y_true, y_pred)
    macro_prec, macro_rec, macro_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    weighted_prec, weighted_rec, weighted_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="weighted", zero_division=0
    )

    # 2. Per-class metrics
    clf_report = classification_report(
        y_true, y_pred, target_names=CLASS_NAMES, digits=4, output_dict=True, zero_division=0
    )

    # 3. Confusion Matrix
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1, 2])
    # Structure labeled confusion matrix
    cm_labeled = {
        CLASS_NAMES[i]: {CLASS_NAMES[j]: int(cm[i, j]) for j in range(len(CLASS_NAMES))}
        for i in range(len(CLASS_NAMES))
    }

    # 4. Security Gateway Specific Metrics
    # Benign FPR: Benign samples incorrectly flagged as SQLi or XSS
    benign_total = int(np.sum(y_true == 0))
    benign_fp = int(np.sum((y_true == 0) & (y_pred != 0)))
    benign_fpr = benign_fp / benign_total if benign_total > 0 else 0.0

    # Attack FNR: Attacks incorrectly classified as Benign (False Negatives - Bypass vulnerability)
    attack_total = int(np.sum(y_true != 0))
    attack_fn = int(np.sum((y_true != 0) & (y_pred == 0)))
    attack_fnr = attack_fn / attack_total if attack_total > 0 else 0.0

    # Target threshold check
    target_f1_threshold = 0.90
    target_met = bool(macro_f1 >= target_f1_threshold)

    report = {
        "metadata": {
            "model_path": model_path,
            "test_csv": test_csv,
            "vocab_path": vocab_path,
            "device": str(device),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_test_samples": total_samples,
        },
        "performance": {
            "total_eval_time_sec": round(total_time_sec, 4),
            "latency_ms_per_sample": round(latency_per_sample_ms, 4),
            "throughput_samples_per_sec": round(throughput_samples_per_sec, 2),
        },
        "overall_metrics": {
            "accuracy": round(float(acc), 4),
            "macro_precision": round(float(macro_prec), 4),
            "macro_recall": round(float(macro_rec), 4),
            "macro_f1": round(float(macro_f1), 4),
            "weighted_precision": round(float(weighted_prec), 4),
            "weighted_recall": round(float(weighted_rec), 4),
            "weighted_f1": round(float(weighted_f1), 4),
            "target_macro_f1_threshold": target_f1_threshold,
            "target_met": target_met,
        },
        "security_metrics": {
            "benign_false_positive_count": benign_fp,
            "benign_total_samples": benign_total,
            "benign_false_positive_rate": round(benign_fpr, 4),
            "attack_false_negative_count": attack_fn,
            "attack_total_samples": attack_total,
            "attack_false_negative_rate": round(attack_fnr, 4),
        },
        "per_class_metrics": {
            cls_name: {
                "precision": round(float(clf_report[cls_name]["precision"]), 4),
                "recall": round(float(clf_report[cls_name]["recall"]), 4),
                "f1_score": round(float(clf_report[cls_name]["f1-score"]), 4),
                "support": int(clf_report[cls_name]["support"]),
            }
            for cls_name in CLASS_NAMES
        },
        "confusion_matrix": {
            "matrix": cm.tolist(),
            "labels": CLASS_NAMES,
            "detailed": cm_labeled,
        },
    }

    # Save output report
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info("Evaluation report exported successfully to: %s", output_path)

    # Print summary to console
    print("\n" + "=" * 68)
    print("           MODEL EVALUATION SUMMARY (HELD-OUT TEST SET)")
    print("=" * 68)
    print(f"Overall Accuracy:  {acc * 100:.2f}%")
    print(f"Macro F1-Score:    {macro_f1:.4f} (Target: > {target_f1_threshold}) -> {'PASS [OK]' if target_met else 'FAIL [X]'}")
    print(f"Weighted F1-Score: {weighted_f1:.4f}")
    print(f"Throughput:        {throughput_samples_per_sec:.1f} samples/sec ({latency_per_sample_ms:.2f} ms/sample)")
    print("-" * 68)
    print(f"{'Class':<12} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Support':<8}")
    print("-" * 68)
    for cls_name in CLASS_NAMES:
        c = report["per_class_metrics"][cls_name]
        print(f"{cls_name:<12} | {c['precision']:<10.4f} | {c['recall']:<10.4f} | {c['f1_score']:<10.4f} | {c['support']:<8}")
    print("-" * 68)
    print("Confusion Matrix (Rows: True, Cols: Predicted):")
    print(f"{'':<12} | {'Pred: benign':<14} | {'Pred: sqli':<14} | {'Pred: xss':<14}")
    for i, cls_name in enumerate(CLASS_NAMES):
        row = cm[i]
        print(f"True: {cls_name:<6} | {row[0]:<14} | {row[1]:<14} | {row[2]:<14}")
    print("-" * 68)
    print(f"Security Metrics:")
    print(f"  Benign FPR (False Alarms):      {benign_fpr * 100:.2f}% ({benign_fp}/{benign_total})")
    print(f"  Attack FNR (Missed Intrusions): {attack_fnr * 100:.2f}% ({attack_fn}/{attack_total})")
    print("=" * 68 + "\n")

    return report


def main():
    parser = argparse.ArgumentParser(description="Evaluate payload classifier on held-out test set.")
    parser.add_argument("--test-csv", type=str, default="ml/artifacts/test.csv", help="Path to test CSV")
    parser.add_argument("--model-path", type=str, default="ml/artifacts/best_model.pt", help="Path to model checkpoint")
    parser.add_argument("--vocab-path", type=str, default="ml/artifacts/vocab.json", help="Path to vocab JSON")
    parser.add_argument("--output", type=str, default="ml/artifacts/evaluation_report.json", help="Path to export report")
    parser.add_argument("--batch-size", type=int, default=256, help="Batch size for evaluation")
    parser.add_argument("--device", type=str, default=None, help="Compute device ('cuda' or 'cpu')")
    args = parser.parse_args()

    evaluate(
        test_csv=args.test_csv,
        model_path=args.model_path,
        vocab_path=args.vocab_path,
        output_path=args.output,
        batch_size=args.batch_size,
        device_name=args.device,
    )


if __name__ == "__main__":
    main()

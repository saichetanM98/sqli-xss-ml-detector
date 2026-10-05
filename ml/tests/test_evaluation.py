import os
import sys
import json
import pytest

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ml.inference import load_model, predict


def test_evaluation_report_exists_and_meets_threshold():
    """Verify that evaluation_report.json exists and meets Macro F1 > 0.90."""
    report_path = "ml/artifacts/evaluation_report.json"
    assert os.path.exists(report_path), f"Report not found at {report_path}"

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    assert "overall_metrics" in report
    metrics = report["overall_metrics"]

    assert metrics["target_met"] is True
    assert metrics["macro_f1"] >= 0.90, f"Macro F1 {metrics['macro_f1']} below 0.90 threshold"
    assert metrics["accuracy"] >= 0.95, f"Accuracy {metrics['accuracy']} below 0.95"


def test_evaluation_confusion_matrix_structure():
    """Verify confusion matrix contains all 3 classes."""
    report_path = "ml/artifacts/evaluation_report.json"
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    assert "confusion_matrix" in report
    cm = report["confusion_matrix"]
    assert cm["labels"] == ["benign", "sqli", "xss"]
    assert len(cm["matrix"]) == 3
    assert len(cm["matrix"][0]) == 3


def test_live_inference_predictions():
    """Test model inference on typical benign, SQLi, and XSS patterns."""
    load_model("ml/artifacts/best_model.pt", "ml/artifacts/vocab.json")

    benign_payload = "search?q=laptop"
    sqli_payload = "' UNION SELECT username, password FROM users--"
    xss_payload = "<script>alert(document.cookie)</script>"

    label_b, conf_b = predict(benign_payload)
    label_s, conf_s = predict(sqli_payload)
    label_x, conf_x = predict(xss_payload)

    assert label_b == "benign", f"Expected benign, got {label_b} ({conf_b})"
    assert label_s == "sqli", f"Expected sqli, got {label_s} ({conf_s})"
    assert label_x == "xss", f"Expected xss, got {label_x} ({conf_x})"
    assert conf_b > 0.80
    assert conf_s > 0.80
    assert conf_x > 0.80

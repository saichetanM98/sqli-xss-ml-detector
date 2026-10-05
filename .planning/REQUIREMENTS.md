# Requirements: AI-Based Adaptive Security Gateway

> Archived Milestone 1 Requirements: [v1.0-REQUIREMENTS.md](file:///c:/Users/saich/Desktop/sqli-xss-ml-detector/.planning/milestones/v1.0-REQUIREMENTS.md)

---

## Phase 2 Requirements (Milestone 2: Model Training & Core Gateway Pipeline)

### Requirement 1: Model Training Pipeline (`REQ-W2-TRAIN`)
- **REQ-W2-TRAIN-01**: Implement `ml/train.py` reading `train.csv` (43,267 samples) and `val.csv` (5,408 samples) with `PayloadDataset`.
- **REQ-W2-TRAIN-02**: Support compute device detection (CUDA RTX 3050 with CPU fallback).
- **REQ-W2-TRAIN-03**: Train `PayloadClassifier` using Adam optimizer and CrossEntropyLoss with validation loss tracking.
- **REQ-W2-TRAIN-04**: Implement Early Stopping (patience=3) and save optimal weights to `ml/artifacts/best_model.pt`.

### Requirement 2: Model Evaluation & Metrics (`REQ-W2-EVAL`)
- **REQ-W2-EVAL-01**: Implement `ml/evaluate.py` testing against held-out `test.csv` (5,409 samples).
- **REQ-W2-EVAL-02**: Calculate quantitative metrics: Overall Accuracy, Precision, Recall, and Macro F1-score across all 3 classes (`benign`, `sqli`, `xss`).
- **REQ-W2-EVAL-03**: Generate 3x3 Confusion Matrix and export summary to `ml/artifacts/evaluation_report.json`.
- **REQ-W2-EVAL-04**: Attain target test set Macro F1 > 0.90.

### Requirement 3: Gateway Request Ingress & Preprocessing (`REQ-W2-PIPE`)
- **REQ-W2-PIPE-01**: Implement deep extraction in `gateway/pipeline/parser.py` parsing query string, JSON request body, multipart form data, client IP, and HTTP headers (`User-Agent`, `Referer`, `Cookie`).
- **REQ-W2-PIPE-02**: Implement multi-pass recursive URL decoding in `gateway/pipeline/preprocess.py` to neutralize double-encoded obfuscation (e.g. `%2527`).
- **REQ-W2-PIPE-03**: Implement HTML entity unescaping, null-byte removal, and string canonicalization.

### Requirement 4: Live Detection Integration & `/predict` Endpoint (`REQ-W2-PRED`)
- **REQ-W2-PRED-01**: Upgrade `ml/inference.py` to dynamically load `ml/artifacts/best_model.pt` and tokenize payloads using `vocab.json`.
- **REQ-W2-PRED-02**: Enforce fail-closed security: if model loading or tensor inference errors, return critical threat response rather than allowing unchecked bypass.
- **REQ-W2-PRED-03**: Implement `POST /predict` in `gateway/routes/predict.py` returning predicted class label, confidence score, risk severity, and inference latency.
- **REQ-W2-PRED-04**: Write automated pytest suite in `gateway/tests/test_predict.py` verifying true positive detection for known SQLi, XSS, and benign test vectors with 100% pass rate.

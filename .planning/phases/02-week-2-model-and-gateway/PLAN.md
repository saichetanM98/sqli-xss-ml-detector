# Phase 2 Execution Plan: Model Training & Core Gateway Pipeline (Week 2)

## Objective
Train the character-level CNN + BiLSTM hybrid model (`PayloadClassifier`) on the unified dataset, evaluate its performance against the held-out test split (Accuracy, Precision, Recall, Macro F1, Confusion Matrix), export the production checkpoint (`best_model.pt`), and wire live ML inference into the Flask Gateway's `/predict` endpoint with robust ingress parsing and preprocessing.

---

## Wave 2.1: Model Training Pipeline & GPU Acceleration
- **Owner**: ML Lead
- **Inputs**: `ml/artifacts/train.csv`, `ml/artifacts/val.csv`, `ml/artifacts/vocab.json`, `ml/model.py`
- **Outputs**:
  - `ml/train.py` (production training script with early stopping & checkpointing)
  - `ml/artifacts/best_model.pt` (saved production weights)
  - Training log with epoch loss & validation metrics

### Tasks:
1. **Task 2.1.1 — Compute Device & Acceleration**:
   - Verify compute device selection (RTX 3050 CUDA / CPU fallback) with mixed-precision support where available.
2. **Task 2.1.2 — Full Training Pipeline Implementation (`ml/train.py`)**:
   - Load `train.csv` and `val.csv` using `PayloadDataset`.
   - Setup `nn.CrossEntropyLoss`, `optim.Adam(lr=1e-3, weight_decay=1e-5)`, and `ReduceLROnPlateau`.
   - Implement multi-epoch training loop with validation evaluation after each epoch.
   - Implement `EarlyStopping` (patience=3) monitoring validation loss.
   - Save top checkpoint to `ml/artifacts/best_model.pt`.
3. **Task 2.1.3 — Training Run Execution & Checkpoint Verification**:
   - Run training process and confirm `ml/artifacts/best_model.pt` is generated and loadable.

---

## Wave 2.2: Model Evaluation & Metric Reporting
- **Owner**: ML Lead
- **Inputs**: `ml/artifacts/best_model.pt`, `ml/artifacts/test.csv`, `ml/artifacts/vocab.json`
- **Outputs**:
  - `ml/evaluate.py` (comprehensive evaluation harness)
  - `ml/artifacts/evaluation_report.json` (quantitative metrics)
  - Confusion matrix and per-class metrics (Benign, SQLi, XSS)

### Tasks:
1. **Task 2.2.1 — Evaluation Script Implementation (`ml/evaluate.py`)**:
   - Load `test.csv` (5,409 held-out payloads).
   - Compute predictions using `best_model.pt`.
   - Calculate Accuracy, Precision, Recall, Macro F1-score via `scikit-learn`.
   - Generate confusion matrix across `[benign, sqli, xss]`.
2. **Task 2.2.2 — Test Evaluation & Report Generation**:
   - Execute evaluation script and write `ml/artifacts/evaluation_report.json`.
   - Verify Macro F1 exceeds target threshold (> 0.90).

---

## Wave 2.3: Ingress Parser & Preprocessing Pipeline
- **Owner**: Backend Lead
- **Inputs**: `gateway/pipeline/parser.py`, `gateway/pipeline/preprocess.py`
- **Outputs**:
  - Enhanced request parsing across query params, JSON body, form data, and headers
  - Robust multi-pass decoding & normalization
  - Unit tests for evasive payload normalization

### Tasks:
1. **Task 2.3.1 — Deep Request Ingress Parser (`gateway/pipeline/parser.py`)**:
   - Extract raw URL parameters, JSON body elements, form fields, and security-relevant headers (`User-Agent`, `Referer`, `Cookie`).
   - Extract client IP with proxy awareness (`X-Forwarded-For`).
2. **Task 2.3.2 — Preprocessing & Canonicalization (`gateway/pipeline/preprocess.py`)**:
   - Implement recursive URL decoding (to neutralize `%2527` double-encoding evasion).
   - Implement HTML entity unescaping (`&lt;script&gt;` -> `<script>`).
   - Whitespace stripping and null-byte sanitization.

---

## Wave 2.4: Live Detection Integration & `/predict` Endpoint
- **Owner**: Backend & ML Lead
- **Inputs**: `ml/inference.py`, `gateway/routes/predict.py`, `gateway/app.py`
- **Outputs**:
  - Live model loading in `ml/inference.py` using `best_model.pt`
  - Fully integrated `POST /predict` API route
  - Fail-closed security posture fallback
  - Comprehensive unit and integration test suite (`gateway/tests/test_predict.py`)

### Tasks:
1. **Task 2.4.1 — Live Inference Integration (`ml/inference.py`)**:
   - Upgrade `load_model()` to load `ml/artifacts/best_model.pt` upon gateway initialization.
   - Implement fast batch/single tokenization and forward pass returning `(label, confidence)`.
   - Ensure fail-closed fallback: if model cannot be evaluated, raise or classify as critical alert rather than allowing silently.
2. **Task 2.4.2 — `/predict` Route Wiring (`gateway/routes/predict.py`)**:
   - Ingest raw request or test payload JSON.
   - Run through Parser -> Preprocessor -> Inference Engine.
   - Return structured response:
     ```json
     {
       "status": "success",
       "label": "sqli",
       "confidence": 0.985,
       "risk_level": "CRITICAL",
       "latency_ms": 4.2
     }
     ```
3. **Task 2.4.3 — Automated Test Verification**:
   - Write `gateway/tests/test_predict.py` with known test suites:
     - Benign queries (`/search?q=laptops`) -> `benign`
     - Classic & obfuscated SQLi (`' UNION SELECT 1,2,3--`, `admin' OR '1'='1`) -> `sqli`
     - Classic & obfuscated XSS (`<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`) -> `xss`
   - Run `pytest` and verify 100% pass rate.

---

## Definition of Done (Week 2 Milestone)
1. `ml/artifacts/best_model.pt` exported from a successful training run.
2. `ml/evaluate.py` generates metrics showing Macro F1 > 0.90 on held-out test split.
3. Recursive decoding handles double-URL and HTML-entity encoded payloads.
4. `POST /predict` endpoint live and returning real ML predictions.
5. All test suites in `gateway/tests/` passing cleanly.

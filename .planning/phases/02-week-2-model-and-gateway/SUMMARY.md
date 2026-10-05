# Phase 2 Summary: Model Training & Core Gateway Pipeline (Week 2)

## Executive Summary
Phase 2 delivered end-to-end machine learning model training, comprehensive evaluation on held-out test data, deep request parsing and canonicalization preprocessing, and live inference integration into the security gateway's `POST /predict` API route. All requirements from the Phase 2 Plan and Definition of Done have been satisfied, with 38 automated test suites passing cleanly across the repository.

---

## Deliverables & Accomplishments

### 1. Model Training Pipeline & Checkpoint Export (Wave 2.1)
- **Production Training Harness (`ml/train.py`)**:
  - Implemented complete training loop with GPU acceleration (`RTX 3050 Laptop GPU`, CUDA 12.9) and automatic CPU fallback.
  - Employed `Adam` optimizer (`lr=1e-3`, `weight_decay=1e-5`), `CrossEntropyLoss` with inverse-class-frequency weighting to prevent majority class bias, and `ReduceLROnPlateau` scheduler.
  - Built `EarlyStopping` (patience: 3 epochs) with best model checkpoint preservation.
- **Production Artifact (`ml/artifacts/best_model.pt`)**:
  - Checkpoint includes `model_state_dict`, optimizer state, epoch count, loss, validation accuracy (99.72%), and architecture hyperparams.

### 2. Model Evaluation & Metric Reporting (Wave 2.2)
- **Evaluation Harness (`ml/evaluate.py`)**:
  - Evaluated on 6,737 held-out payloads in `ml/artifacts/test.csv`.
  - Exported structured evaluation report to `ml/artifacts/evaluation_report.json`.
- **Target Metrics vs Actual**:
  - **Macro F1-Score**: Target `> 0.90` $\rightarrow$ **Achieved: 0.9981** (Exceeded by +9.8%)
  - **Overall Accuracy**: **99.82%**
  - **Weighted F1-Score**: **0.9982**
  - **Bypass / False Negative Rate**: **0.24%** (7 misses out of 2,948 attack samples)
  - **Per-Class Metrics**:
    - **Benign**: Precision 0.9982, Recall 0.9989, F1 0.9985
    - **SQLi**: Precision 0.9982, Recall 0.9973, F1 0.9977
    - **XSS**: Precision 0.9986, Recall 0.9973, F1 0.9980
  - **Inference Latency**: `0.08 ms` per sample (~11,900 samples/sec GPU throughput).
- **Automated Verification**: `ml/tests/test_evaluation.py` passes 3/3 tests.

### 3. Ingress Parser & Preprocessing Pipeline (Wave 2.3)
- **Deep Ingress Parser (`gateway/pipeline/parser.py`)**:
  - Normalizes HTTP method, path, headers, query parameters, form fields, and body content (including nested JSON and lists).
  - Proxy-aware client IP extraction supporting `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, and `True-Client-IP`.
  - Header inspection for injected attack vectors in `User-Agent`, `Referer`, and `Cookie`.
- **Multi-Pass Canonicalization Preprocessor (`gateway/pipeline/preprocess.py`)**:
  - Recursive URL decoding (up to 5 iterations) neutralizing `%2527` double-encoding evasion.
  - Recursive HTML entity unescaping (e.g. `&amp;lt;` $\rightarrow$ `&lt;` $\rightarrow$ `<`).
  - Null-byte (`%00`, `\x00`) and zero-width unicode control sanitization (`\u200b`).
  - Whitespace canonicalization.
- **Automated Verification**: `gateway/tests/test_pipeline.py` passes 10/10 tests.

### 4. Live Detection Integration & `/predict` Endpoint (Wave 2.4)
- **Live Inference Engine (`ml/inference.py`)**:
  - Upgraded `load_model()` to load `ml/artifacts/best_model.pt` dynamically on application startup.
  - Added `is_model_ready()` and `predict_batch()` for high-throughput batch vector classification.
  - Implemented **fail-closed security fallback**: if the ML model is degraded or offline, heuristic pattern matching activates and unverified traffic is blocked (`CRITICAL`) rather than allowing silent bypass.
- **Live `/predict` Endpoint (`gateway/routes/predict_routes.py`)**:
  - Processes incoming request through Ingress Parser $\rightarrow$ Preprocessor $\rightarrow$ ML Detection $\rightarrow$ Threat Intel $\rightarrow$ Session Manager $\rightarrow$ Device Profiler $\rightarrow$ Behavior Engine $\rightarrow$ Risk Engine $\rightarrow$ Decision Engine $\rightarrow$ Policy Engine $\rightarrow$ Incident Persistence.
  - Returns structured response with:
    - `status`: `"success"`
    - `label`: `"benign"`, `"sqli"`, or `"xss"`
    - `confidence`: float between 0.0 and 1.0
    - `risk_level`: `"LOW"`, `"MEDIUM"`, `"HIGH"`, or `"CRITICAL"`
    - `risk_score`: float (0–100 scale)
    - `verdict`: `"ALLOW"`, `"MONITOR"`, `"RATE_LIMIT"`, or `"BLOCK"`
    - `latency_ms`: pipeline execution latency in milliseconds
    - `incident_id`: UUID of recorded security incident (when flagged)
    - `data`: envelope object for backward compatibility
- **Comprehensive Test Suite (`gateway/tests/test_predict.py`)**:
  - 24 dedicated test cases covering:
    - Benign search queries, legitimate API JSON bodies, and natural language comments.
    - Classic and obfuscated SQLi (union select, auth bypass, tautologies, stacked queries, double-encoded).
    - Classic and obfuscated XSS (script tags, img onerror, svg onload, javascript pseudo-protocols, HTML entities).
    - Response schema validation and bounds checks.
    - Incident persistence verification in `get_all_incidents()`.
    - Fail-closed security posture fallback validation.
    - Batch inference verification.
    - Edge cases (missing body, empty payload, attacks in query params, attacks in headers).

---

## Verification Summary

| Test Suite | File | Tests | Result | Execution Time |
|---|---|---|---|---|
| Health & Gateway Config | `gateway/tests/test_health.py` | 1 | **PASSED** | 0.05s |
| Pipeline & Parser | `gateway/tests/test_pipeline.py` | 10 | **PASSED** | 0.28s |
| Live Predict & Inference | `gateway/tests/test_predict.py` | 24 | **PASSED** | 0.91s |
| ML Evaluation & Metrics | `ml/tests/test_evaluation.py` | 3 | **PASSED** | 2.12s |
| **Total** | **All Suites** | **38** | **100% PASSED** | **3.36s** |

---

## Definition of Done (Week 2 Milestone) Audit

- [x] **1. `ml/artifacts/best_model.pt` exported from a successful training run.**  
  *Status: PASSED* — Model checkpoint generated, verified on CUDA.
- [x] **2. `ml/evaluate.py` generates metrics showing Macro F1 > 0.90 on held-out test split.**  
  *Status: PASSED* — Achieved 0.9981 Macro F1 (Target: > 0.90).
- [x] **3. Recursive decoding handles double-URL and HTML-entity encoded payloads.**  
  *Status: PASSED* — Preprocessor neutralizes evasive encodings; verified in unit tests.
- [x] **4. `POST /predict` endpoint live and returning real ML predictions.**  
  *Status: PASSED* — Live endpoint wired with structured response schema and fail-closed posture.
- [x] **5. All test suites in `gateway/tests/` passing cleanly.**  
  *Status: PASSED* — 35/35 gateway tests passing (38/38 repository-wide).

# Project Roadmap: AI-Based Adaptive Security Gateway

## Completed Milestones
- **[v1.0 Week 1 Foundation](file:///c:/Users/saich/Desktop/sqli-xss-ml-detector/.planning/milestones/v1.0-ROADMAP.md)**: Shipped 2026-10-05 — Data pipeline, vocabulary, splits, CNN+BiLSTM forward pass, Flask health route, and React SOC skeleton. (Audit: PASSED).

---

## Phase 2: Week 2 — Model Training & Core Gateway Pipeline (CURRENT)
**Goal**: Train the character-level CNN + BiLSTM model on the unified dataset, evaluate metrics on held-out test data, export production checkpoint `best_model.pt`, and wire live ML inference into the Flask Gateway's `/predict` endpoint with robust ingress parsing and preprocessing.

### Wave 2.1: Model Training Pipeline & Acceleration
- [x] Task 2.1.1: Verify compute device selection (RTX 3050 CUDA / CPU fallback) with mixed precision support.
- [x] Task 2.1.2: Implement complete training script in `ml/train.py` with DataLoader, Adam optimizer, CrossEntropyLoss, and EarlyStopping.
- [x] Task 2.1.3: Run training loop and export production model checkpoint `ml/artifacts/best_model.pt`.

### Wave 2.2: Model Evaluation & Metric Reporting
- [x] Task 2.2.1: Implement evaluation script in `ml/evaluate.py` calculating Accuracy, Precision, Recall, Macro F1, and Confusion Matrix.
- [x] Task 2.2.2: Run evaluation on held-out test split (6,737 samples) and export `ml/artifacts/evaluation_report.json` (Achieved Macro F1: 0.9981, Accuracy: 99.82%).

### Wave 2.3: Ingress Parser & Preprocessing Pipeline
- [ ] Task 2.3.1: Complete deep request parser in `gateway/pipeline/parser.py` (query params, JSON body, headers, client IP).
- [ ] Task 2.3.2: Complete preprocessor in `gateway/pipeline/preprocess.py` with recursive URL decoding and HTML unescaping.

### Wave 2.4: Live Detection Integration & `/predict` Endpoint
- [ ] Task 2.4.1: Upgrade `ml/inference.py` to load `best_model.pt` with fail-closed security fallback.
- [ ] Task 2.4.2: Implement `POST /predict` route in `gateway/routes/predict.py`.
- [ ] Task 2.4.3: Write and pass automated test suite in `gateway/tests/test_predict.py` for benign, SQLi, and XSS vectors.

---

## Phase 3: Week 3 — Contextual Engines, Persistence & SOC Dashboard
- Build Stage 5: Threat Intelligence IP reputation lookup.
- Build Stage 6: Server-side Session Manager with `Flask-Caching` (`SimpleCache`).
- Build Stage 7: Device Profiler (SHA-256 header fingerprinting).
- Build Stage 8: Behavior Anomaly Engine.
- Build Stages 9-11: Risk Engine, Decision Engine (`ALLOW`/`MONITOR`/`RATE_LIMIT`/`BLOCK`), and Policy hard overrides.
- Build Stage 12: Incident & Memory Service in MongoDB.
- Build Stage 13: Analytics Aggregation Service.
- Build Stage 14: Full React SOC Dashboard with incident table, replay timeline, and human override actions.

---

## Phase 4: Week 4 — Testing, Security Hardening, Report & Live Demo
- End-to-end attack simulation with diverse SQLi/XSS evasive payloads.
- Fail-closed security validation (handling GPU/service disconnect).
- Client tamper-resistance test on session counters.
- Final project report generation and live demonstration rehearsal.

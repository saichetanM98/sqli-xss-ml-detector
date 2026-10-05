# Phase 1 Execution Plan: Data, Model & Skeleton Foundation (Week 1)

## Objective
Deliver a verified data processing pipeline, export character vocabulary and balanced dataset splits, verify PyTorch CUDA acceleration on RTX 3050, and establish working Flask gateway and React dashboard skeletons.

---

## Wave 1.1: Data Ingestion & Preprocessing Pipeline
- **Owner**: ML/Data Lead
- **Inputs**: `datasets/sqli.csv`, `datasets/sqliv2.csv`, `datasets/SQLiV3.csv`, `datasets/XSS_dataset.csv`
- **Outputs**:
  - `ml/data/prepare_data.py` (complete data pipeline script)
  - `ml/artifacts/vocab.json` (character-to-id mapping)
  - `ml/artifacts/train.csv`, `ml/artifacts/val.csv`, `ml/artifacts/test.csv` (stratified splits)
  - `ml/data/dataset.py` (PyTorch Dataset & DataLoader utilities)
  - Test validation confirming batch generation

### Tasks:
1. **Task 1.1.1 — Multi-Encoding Ingestion**:
   - Ingest `sqli.csv` & `sqliv2.csv` with `encoding="utf-16"`.
   - Ingest `SQLiV3.csv` with `encoding="utf-8"`, skipping bad lines and cleaning malformed columns.
   - Ingest `XSS_dataset.csv` with `encoding="utf-8-sig"`.
2. **Task 1.1.2 — Cleaning & Normalization**:
   - Drop nulls, empty strings, duplicates.
   - Remap labels to: `0: benign`, `1: sqli`, `2: xss`.
   - Stratify into Train (80%), Validation (10%), Test (10%).
3. **Task 1.1.3 — Character Vocabulary Builder**:
   - Extract unique characters from training set.
   - Assign `<PAD>` -> 0, `<UNK>` -> 1.
   - Save to `ml/artifacts/vocab.json`.
4. **Task 1.1.4 — Dataset & DataLoader Test**:
   - Test `PayloadDataset` with batch size 32 and sequence length 256.
   - Validate tensor shapes: `x: [32, 256]`, `y: [32]`.

---

## Wave 1.2: Model Architecture & CUDA Hardware Verification
- **Owner**: ML/Data Lead
- **Inputs**: `ml/model.py`, Virtual environment
- **Outputs**:
  - CUDA-enabled PyTorch environment
  - `ml/tests/verify_gpu.py` (hardware test script)
  - Verification log confirming `torch.cuda.is_available() == True` and model forward pass on RTX 3050

### Tasks:
1. **Task 1.2.1 — Install PyTorch with CUDA Support**:
   - Install CUDA 12.1/12.4 PyTorch wheel into the active environment.
2. **Task 1.2.2 — Model Architecture Verification**:
   - Inspect and confirm `PayloadClassifier` in `ml/model.py`: Embedding(vocab_size, 64) -> Conv1d(64, 64, k=3, p=1) -> ReLU -> BiLSTM(64, 64, bidirectional=True) -> MaxPool -> Dropout(0.3) -> Linear(128, 3).
3. **Task 1.2.3 — Hardware Verification Script**:
   - Write `ml/tests/verify_gpu.py`.
   - Instantiate `PayloadClassifier` on `cuda:0`.
   - Feed dummy batch `torch.randint(0, vocab_size, (16, 256)).to("cuda")`.
   - Assert output shape `[16, 3]` and check GPU memory allocation.

---

## Wave 1.3: Gateway Skeleton & Database Setup
- **Owner**: Backend Lead
- **Inputs**: `gateway/app.py`, `gateway/config.py`, `gateway/routes/`
- **Outputs**:
  - Working Flask backend skeleton with `/health` endpoint
  - `gateway/services/db.py` (MongoDB connection helper with fallback)
  - Unit test verifying gateway health check returns 200

### Tasks:
1. **Task 1.3.1 — Application Factory & Health Endpoint**:
   - Wire Flask app factory in `gateway/app.py` with CORS.
   - Verify `/health` route returns `{"status": "healthy", "service": "adaptive-security-gateway"}`.
2. **Task 1.3.2 — Database Service Layer**:
   - Implement `gateway/services/db.py` to establish connection to MongoDB (`Config.MONGO_URI`).
   - Add graceful status check (connected vs offline mode).
3. **Task 1.3.3 — Gateway Test Suite**:
   - Run a test request against `/health` and verify HTTP 200.

---

## Wave 1.4: SOC Dashboard Skeleton
- **Owner**: Frontend Lead
- **Inputs**: `dashboard/package.json`, `dashboard/src/`
- **Outputs**:
  - Installed node modules in `dashboard/`
  - React SOC Dashboard shell in `dashboard/src/App.jsx`
  - Successful Vite build and dev server check

### Tasks:
1. **Task 1.4.1 — Dependencies Installation**:
   - Run `npm install` in `dashboard/` to install React, ReactDOM, Lucide icons, and Vite.
2. **Task 1.4.2 — SOC Dashboard UI**:
   - Build a clean, cyber-themed SOC dashboard shell with:
     - Real-time Gateway status indicator (Live / Disconnected)
     - Metric cards placeholder (Total Inspected, Blocked, Threat Level)
     - Live Feed stream placeholder
3. **Task 1.4.3 — Vite Dev Verification**:
   - Run `npm run build` to confirm zero compilation errors.

---

## Definition of Done (Week 1 Milestone)
1. `ml/artifacts/vocab.json`, `train.csv`, `val.csv`, `test.csv` exist and are valid.
2. `torch.cuda.is_available()` returns `True` and model forward pass succeeds on RTX 3050.
3. Flask `/health` endpoint returns 200 OK.
4. React SOC Dashboard builds cleanly with zero errors.

# Phase 1 Summary: Data & Model Foundation + Skeleton Infrastructure (Week 1)

## Executive Summary
Phase 1 established the core ML data pipeline, model architecture, Flask gateway skeleton, and React SOC dashboard for the AI-Based Adaptive Security Gateway. All datasets were unified, tokenized, and split; the hybrid CNN + BiLSTM model was constructed and verified; the gateway passed automated health check tests; and the SOC dashboard built cleanly with zero compilation errors.

---

## Deliverables & Accomplishments

### 1. Data Ingestion & Preprocessing Pipeline (Wave 1.1)
- **Multi-Encoding CSV Ingestion**: Built `ml/data/prepare_data.py` capable of robustly reading:
  - `sqli.csv` and `sqliv2.csv` (`utf-16`)
  - `SQLiV3.csv` (`utf-8`, skipping malformed lines)
  - `XSS_dataset.csv` (`utf-8-sig`)
- **Cleaning & Normalization**: Deduplicated records, dropped invalid/NaN payloads, and unified labels into 3 classes:
  - `0`: Benign
  - `1`: SQL Injection (`sqli`)
  - `2`: Cross-Site Scripting (`xss`)
- **Character Vocabulary**: Generated `ml/artifacts/vocab.json` containing 170 distinct character tokens with `<PAD>: 0` and `<UNK>: 1`.
- **Stratified Dataset Splits**:
  - `ml/artifacts/train.csv`: 43,267 payloads
  - `ml/artifacts/val.csv`: 5,408 payloads
  - `ml/artifacts/test.csv`: 5,409 payloads
- **PyTorch Dataset Utilities**: Implemented `PayloadDataset` and DataLoader utilities in `ml/data/dataset.py` with fixed 256-token padding and truncation.

### 2. Model Architecture & Forward Pass Verification (Wave 1.2)
- **Hybrid Architecture (`ml/model.py`)**: Implemented `PayloadClassifier`:
  - Character Embedding (`dim=64`, `padding_idx=0`)
  - 1D Convolution (`64 filters`, `kernel_size=3`, `padding=1`) + ReLU
  - Bidirectional LSTM (`hidden_dim=64`, bidirectional, yielding 128-dim features)
  - Global Max-Pooling across sequence dimension
  - Dropout (`p=0.3`) + Linear projection to 3 class logits.
- **Hardware & Forward Pass Validation**:
  - Verified NVIDIA GeForce RTX 3050 Laptop GPU (Driver 577.05, CUDA 12.9) via `nvidia-smi`.
  - Executed `ml/tests/verify_gpu.py`, confirming input `[16, 256]` produces output `[16, 3]` logits with valid softmax probability distribution.

### 3. Flask Gateway Skeleton & Database Layer (Wave 1.3)
- **Application Factory**: Configured `gateway/app.py` with CORS, blueprint registration, and environment loading.
- **Health Check**: Implemented `/health` endpoint returning `{"status": "healthy", "service": "adaptive-security-gateway"}`.
- **Database Connection Manager**: Created `gateway/services/db.py` targeting `mongodb://localhost:27017/adaptive_security_gateway` with non-blocking graceful fallback if offline.
- **Automated Tests**: Pytest test suite (`gateway/tests/test_health.py` and `gateway/tests/test_pipeline.py`) passing 4/4 with 100% success rate.

### 4. React SOC Dashboard Skeleton (Wave 1.4)
- **Vite + React 18 Setup**: Initialized and resolved all npm dependencies in `dashboard/` (`react`, `react-dom`, `lucide-react`, `@vitejs/plugin-react`).
- **Cyber-Themed SOC Shell**: Designed responsive command center in `dashboard/src/App.jsx` with real-time Gateway connection badge, threat counters, attack breakdown card, and live feed placeholder.
- **Build Verification**: `npm run build` completed cleanly in 2.99s with zero bundle errors.

---

## Verification & Test Results
| Test Target | Command | Result |
|---|---|---|
| Gateway Health & Pipeline | `pytest gateway/tests` | **4 passed** (0.84s) |
| Model Forward Pass | `python ml/tests/verify_gpu.py` | **SUCCESS** (`[16, 3]` logits) |
| Data Ingestion & Vocabulary | `python ml/data/prepare_data.py` | **SUCCESS** (170 vocab tokens, 54k rows) |
| React SOC Dashboard Build | `npm run build` | **SUCCESS** (0 errors, 2.99s) |

---

## Key Artifacts Produced
- `ml/artifacts/vocab.json`
- `ml/artifacts/train.csv`
- `ml/artifacts/val.csv`
- `ml/artifacts/test.csv`
- `ml/model.py`
- `ml/data/prepare_data.py`
- `ml/data/dataset.py`
- `gateway/app.py`
- `gateway/services/db.py`
- `dashboard/dist/`

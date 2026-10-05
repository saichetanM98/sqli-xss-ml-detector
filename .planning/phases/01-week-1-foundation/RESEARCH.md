# Phase 1: Research — Data, Model & Skeleton Foundation

## 1. Domain & Dataset Ingestion Strategy
### Dataset Sources
- **`sqli.csv`**: UTF-16 encoded, columns `Sentence`, `Label` (0/1).
- **`sqliv2.csv`**: UTF-16 encoded, columns `Sentence`, `Label` (0/1). Contains null rows and empty payloads.
- **`SQLiV3.csv`**: UTF-8 encoded. Contains ragged lines, unescaped quotes, and extraneous columns (`Unnamed: 2`, `Unnamed: 3`). Needs robust fallback parser (`on_bad_lines='skip'` or manual cleaning).
- **`XSS_dataset.csv`**: UTF-8-SIG encoded with BOM. Columns `Unnamed: 0`, `Sentence`, `Label` (0/1).

### Schema Harmonization
- All payloads mapped to:
  - `payload`: text (cleaned string, whitespace stripped)
  - `label`: integer
    - `0`: Benign (safe input)
    - `1`: SQLi (SQL Injection)
    - `2`: XSS (Cross-Site Scripting)

### Vocabulary Strategy
- Character-level vocabulary avoids OOV (out-of-vocabulary) vulnerabilities caused by adversarial character substitution.
- Special tokens:
  - `<PAD>` = 0
  - `<UNK>` = 1
- Target sequence length: `max_len = 256`. Payloads longer than 256 chars are truncated; shorter payloads are padded with `<PAD>`.

## 2. CUDA Hardware Acceleration
- Hardware: NVIDIA GeForce RTX 3050 Laptop GPU (4096 MiB VRAM), Driver 577.05, CUDA 12.9.
- Current Python environment: Python 3.11 with PyTorch 2.13.0+cpu.
- Solution: Upgrade PyTorch in `venv` to CUDA 12.1/12.4 build via `pip install torch --index-url https://download.pytorch.org/whl/cu121` (or cu124).
- Verification: `torch.cuda.is_available() == True` and allocate tensors on `cuda:0`.

## 3. Architecture Verification
- `PayloadClassifier`:
  - `nn.Embedding(num_embeddings=vocab_size, embedding_dim=64, padding_idx=0)`
  - `nn.Conv1d(in_channels=64, out_channels=64, kernel_size=3, padding=1)` + `nn.ReLU()`
  - `nn.LSTM(input_size=64, hidden_size=64, batch_first=True, bidirectional=True)`
  - Global Max Pooling across sequence length
  - `nn.Dropout(0.3)`
  - `nn.Linear(128, 3)`
- Forward pass output shape: `[batch_size, 3]`.

## 4. Gateway & SOC Dashboard Skeletons
- Flask gateway factory in `gateway/app.py` with blueprints, CORS, `/health`.
- MongoDB connection service in `gateway/services/db.py`.
- React + Vite dashboard in `dashboard/` with SOC UI component monitoring gateway health.

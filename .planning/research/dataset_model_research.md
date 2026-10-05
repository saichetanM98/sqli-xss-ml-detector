# Research & Dataset Analysis

## 1. Datasets Available

| File | Raw Rows | Encoding | Key Columns | Target Mapping |
|---|---|---|---|---|
| `sqli.csv` | ~4,200 | UTF-16 | `Sentence`, `Label` (0/1) | 0 -> benign (0), 1 -> sqli (1) |
| `sqliv2.csv` | ~33,700 | UTF-16 | `Sentence`, `Label` (0/1) | 0 -> benign (0), 1 -> sqli (1) |
| `SQLiV3.csv` | ~30,000 | UTF-8 | `Sentence`, `Label`, extra cols | Requires header parsing, fillna; 0 -> benign (0), 1 -> sqli (1) |
| `XSS_dataset.csv` | ~13,600 | UTF-8-SIG | `Sentence`, `Label` (0/1) | 0 -> benign (0), 1 -> xss (2) |

### Unified Label Schema
- **Class 0**: `benign` (Normal parameters, common queries, harmless input)
- **Class 1**: `sqli` (SQL injection payloads: UNION select, boolean-based, error-based, stacked queries, time-based sleep)
- **Class 2**: `xss` (Cross-site scripting payloads: `<script>`, `onerror=`, `onload=`, `javascript:`, DOM/reflected vectors)

### Text Cleaning & Character Tokenizer
- Clean and normalize payloads: handle nulls/NaNs, convert to string.
- Vocabulary construction:
  - `<PAD>`: Index 0
  - `<UNK>`: Index 1
  - Unique characters across dataset: ASCII letters, numbers, punctuation symbols (`'`, `"`, `<`, `>`, `-`, `=`, `(`, `)`, `;`, `%`, etc.).
- Sequence Length: `max_len = 256` (captures >98% of payload signatures without excessive memory footprint).

---

## 2. Model Architecture (CNN + BiLSTM)
- **Embedding Layer**: `Embedding(vocab_size, embed_dim=64, padding_idx=0)`
- **Conv1D Layer**: Extracts local n-gram character patterns (e.g. `or 1=1`, `<script`) using `in_channels=64, out_channels=64, kernel_size=3, padding=1`.
- **Bidirectional LSTM**: Encodes sequential dependencies and long-distance syntactic structures using `hidden_size=64, bidirectional=True` (total output dim: 128).
- **Global Max Pooling**: Captures peak activation across the time sequence.
- **Dropout & Dense Layer**: `Dropout(0.3)` -> `Linear(128, 3)` with CrossEntropyLoss.

---

## 3. GPU Environment
- GPU: NVIDIA GeForce RTX 3050 Laptop GPU (4 GB VRAM)
- Driver: 577.05, CUDA 12.9
- Action required: Upgrade virtual environment from CPU PyTorch (`2.13.0+cpu`) to CUDA-enabled build (`cu121` / `cu124`) to enable hardware acceleration.

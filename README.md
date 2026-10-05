# AI-Based Adaptive Security Gateway (SQLi & XSS Detection)

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![PyTorch CUDA](https://img.shields.io/badge/PyTorch-CUDA%2012.9-red.svg)](https://pytorch.org/)
[![Tests Passing](https://img.shields.io/badge/tests-38%2F38%20passing-brightgreen.svg)]()
[![Model Accuracy](https://img.shields.io/badge/accuracy-99.82%25-success.svg)]()
[![Macro F1](https://img.shields.io/badge/Macro%20F1-0.9981-success.svg)]()
[![Milestone 2 Shipped](https://img.shields.io/badge/release-v2.0-blue.svg)](https://github.com/saichetanM98/sqli-xss-ml-detector/releases/tag/v2.0)

An intelligent, context-aware reverse proxy and Web Application Firewall (WAF) designed to detect and block **SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)** attacks in real-time.

Unlike legacy signature-based WAFs that rely on brittle regex patterns vulnerable to evasion, this gateway couples a **character-level hybrid deep learning model (CNN + BiLSTM)** with a **14-stage defense-in-depth contextual pipeline** and a modern React SOC analyst dashboard.

---

## 🌟 Key Highlights & Capabilities

- **Deep Learning Core**: Character-level CNN + BiLSTM model trained on 54,084 samples across 4 public benchmarks.
- **State-of-the-Art Evaluation**: **99.82% test accuracy** and **0.9981 Macro F1** on 6,737 held-out payloads, with an attack bypass rate of only **0.24%** (7 misses out of 2,948 attacks).
- **Sub-Millisecond Inference**: Model executes in **0.08 ms per sample** on GPU (~11,900 requests/sec throughput).
- **Multi-Pass Canonicalization**: Defeats evasive encoding techniques including double URL encoding (`%2527` $\to$ `'`), HTML entity obfuscation (`&amp;lt;script&amp;gt;` $\to$ `<script>`), null-byte injection (`%00`), and zero-width unicode control characters (`\u200b`).
- **Fail-Closed Security Posture**: If the ML engine is degraded or offline, heuristic fallback patterns activate, and unverified traffic is blocked (`CRITICAL`) rather than allowing silent bypass.
- **Full 14-Stage Security Architecture**: Merges ML confidence, IP reputation, session rate windows, device fingerprinting, and behavioral anomalies into an actionable policy decision (`ALLOW`, `MONITOR`, `RATE_LIMIT`, `BLOCK`).

---

## 🛡️ 14-Stage Pipeline Architecture

```
HTTP Request
     │
     ▼
[Stage 1: Request Ingress]  ─── Reverse proxy entry point (Flask Gateway)
     │
[Stage 2: Deep Parser]     ─── Query params, JSON bodies, forms, proxy-aware client IP, security headers
     │
[Stage 3: Canonicalizer]   ─── Multi-pass recursive URL decode, HTML unescape, null-byte strip
     │
[Stage 4: ML Detection]    ─── PyTorch CNN + BiLSTM (best_model.pt) with fail-closed fallback
     │
[Stage 5: Threat Intel]    ─── IP reputation & private network classification
     │
[Stage 6: Session Tracker] ─── Server-side sliding-window rate tracking (tamper-proof)
     │
[Stage 7: Device Profile]  ─── SHA-256 header fingerprinting & scanner detection (sqlmap/nikto)
     │
[Stage 8: Behavior Engine] ─── Dynamic velocity and anomalous traversal scoring
     │
[Stage 9: Risk Engine]     ─── Weighted risk fusion: min(100, (ML*0.70) + (Intel*0.15) + (Behavior*0.15))
     │
[Stage 10: Decision]       ─── Multi-threshold mapping: ALLOW (<40) | MONITOR (40-79) | BLOCK (>=80)
     │
[Stage 11: Policy Engine]  ─── Zero-tolerance hard overrides (high confidence attacks -> instant BLOCK)
     │
[Stage 12: Incidents]      ─── Persistent storage with UUIDs, timestamps, and full inspection context
     │
[Stage 13: Analytics]      ─── Threat distribution, volume aggregation, top offender metrics
     │
[Stage 14: SOC Dashboard]  ─── Real-time React analyst command center with drill-downs and overrides
```

---

## 📊 Benchmark & Evaluation Metrics

Evaluated on **6,737 held-out payloads** in `ml/artifacts/test.csv`:

| Class | Precision | Recall | F1-Score | Support | Description |
|---|---|---|---|---|---|
| **Benign (0)** | **0.9982** | **0.9989** | **0.9985** | 3,789 | Legitimate queries, JSON bodies, natural text |
| **SQLi (1)** | **0.9982** | **0.9973** | **0.9977** | 1,481 | Union select, tautologies, stacked queries, blind SQLi |
| **XSS (2)** | **0.9986** | **0.9973** | **0.9980** | 1,467 | Script tags, DOM events, svg/img vectors, JS protocols |
| **Macro Average** | **0.9983** | **0.9978** | **0.9981** | 6,737 | Target was `> 0.90` (Exceeded by +9.8%) |
| **Weighted Average** | **0.9982** | **0.9982** | **0.9982** | 6,737 | Overall Model Accuracy: **99.82%** |

- **Attack False Negative Rate (Bypass Rate)**: **0.24%** (Only 7 misses out of 2,948 real attacks)
- **Benign False Positive Rate**: **0.11%** (Only 4 false alarms out of 3,789 benign requests)
- **GPU Throughput**: ~11,900 samples/sec (0.08 ms latency per payload on NVIDIA RTX 3050 Laptop GPU)

---

## 🔌 API Reference

### 1. Request Inspection (`POST /predict`)

Accepts raw HTTP request data or direct testing payloads.

```http
POST /predict HTTP/1.1
Host: localhost:5000
Content-Type: application/json

{
  "method": "POST",
  "path": "/login",
  "headers": {
    "User-Agent": "Mozilla/5.0",
    "X-Forwarded-For": "203.0.113.42"
  },
  "payload": "' UNION SELECT 1,username,password FROM users--"
}
```

#### Response (`HTTP 403 Forbidden` for blocked attacks):
```json
{
  "status": "success",
  "success": true,
  "label": "sqli",
  "confidence": 0.9969,
  "risk_level": "CRITICAL",
  "risk_score": 69.3,
  "verdict": "BLOCK",
  "latency_ms": 1.45,
  "incident_id": "787cbe55-bfa2-4e45-8fe0-e696fba11b8b",
  "data": {
    "label": "sqli",
    "confidence": 0.9969,
    "risk_level": "CRITICAL",
    "risk_score": 69.3,
    "verdict": "BLOCK",
    "latency_ms": 1.45,
    "detection": {
      "label": "sqli",
      "confidence": 0.9969,
      "latency_ms": 0.85
    },
    "incident_id": "787cbe55-bfa2-4e45-8fe0-e696fba11b8b"
  },
  "error": null
}
```

### 2. Gateway Health Check (`GET /health`)

```http
GET /health HTTP/1.1
Host: localhost:5000
```

#### Response (`HTTP 200 OK`):
```json
{
  "status": "healthy",
  "service": "adaptive-security-gateway",
  "cuda_available": true,
  "device": "NVIDIA GeForce RTX 3050 Laptop GPU",
  "vocab_loaded": true,
  "model_loaded": true,
  "database": "online"
}
```

---

## 📂 Repository Structure

```
sqli-xss-ml-detector/
├── .planning/                  # Project roadmap, state, audits, and requirements
│   ├── milestones/             # Archived v1.0 and v2.0 roadmap and requirements
│   ├── phases/                 # Execution summaries for each phase
│   ├── PROJECT.md              # Architectural context and milestone history
│   ├── REQUIREMENTS.md         # Active milestone requirements (Phase 3)
│   ├── ROADMAP.md              # Multi-phase roadmap tracker
│   └── STATE.md                # System state and decisions
├── gateway/                    # Flask Application & 14-Stage Pipeline
│   ├── app.py                  # Application factory with CORS and health routes
│   ├── config.py               # Gateway thresholds, weights, and model paths
│   ├── pipeline/               # 14-stage security inspection modules
│   │   ├── parser.py           # Stage 2: Deep request ingress parser
│   │   ├── preprocess.py       # Stage 3: Multi-pass canonicalizer
│   │   ├── detection.py        # Stage 4: ML detection bridge
│   │   ├── threat_intel.py     # Stage 5: IP reputation & threat scoring
│   │   ├── session_manager.py  # Stage 6: Server-side sliding-window rate tracking
│   │   ├── device_profiler.py  # Stage 7: SHA-256 header hashing & scanner detection
│   │   ├── behavior_engine.py  # Stage 8: Behavioral anomaly scoring
│   │   ├── risk_engine.py      # Stage 9: Weighted risk fusion
│   │   ├── decision_engine.py  # Stage 10: Multi-threshold decisioning
│   │   └── policy_engine.py    # Stage 11: Zero-tolerance overrides
│   ├── routes/                 # Blueprint routes (/predict, /incidents, /analytics)
│   │   ├── predict_routes.py   # POST /predict inspection route
│   │   ├── incident_routes.py  # Incident query endpoints
│   │   └── analytics_routes.py # Security metrics aggregation endpoints
│   ├── services/               # Persistence and database layer (MongoDB/in-memory)
│   └── tests/                  # Automated pytest test suites
│       ├── test_health.py      # Health and config tests
│       ├── test_pipeline.py    # Parser, preprocessing, and stage tests
│       └── test_predict.py     # 24 live /predict attack & fail-closed tests
├── ml/                         # Machine Learning Subsystem
│   ├── artifacts/              # Model weights (best_model.pt), vocab.json, evaluation_report.json
│   ├── data/                   # Dataset loader and tokenization utilities
│   ├── model.py                # Character-level CNN + BiLSTM PyTorch architecture
│   ├── train.py                # GPU training script with EarlyStopping & Class Weights
│   ├── evaluate.py             # Quantitative evaluation harness
│   ├── inference.py            # Live inference engine with fail-closed heuristic fallback
│   └── tests/                  # Model evaluation test suite
├── dashboard/                  # React 18 + Vite SOC Analyst Dashboard
└── requirements.txt            # Python dependencies
```

---

## ⚡ Quickstart Guide

### 1. Prerequisites
- Python 3.11+
- Node.js 18+ (for SOC Dashboard)
- NVIDIA GPU with CUDA 12+ (optional, CPU fallback supported automatically)

### 2. Environment Setup

```bash
# Clone the repository
git clone https://github.com/saichetanM98/sqli-xss-ml-detector.git
cd sqli-xss-ml-detector

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate        # On Windows
# source .venv/bin/activate   # On Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Automated Tests

Verify that all 38 unit and integration tests pass:

```bash
python -m pytest
```

### 4. Start the Gateway API

```bash
python -m gateway.app
```
The gateway will start on `http://localhost:5000`.

### 5. Start the SOC Dashboard

```bash
cd dashboard
npm install
npm run dev
```
The dashboard UI will launch on `http://localhost:5173`.

---

## 🗺️ Project Roadmap

- [x] **Week 1: Data & Model Foundation (`v1.0`)** — Ingested 54k samples, 170-char token vocab, CNN+BiLSTM forward pass, Flask gateway skeleton, React SOC shell.
- [x] **Week 2: Model Training & Core Gateway Pipeline (`v2.0`)** — Trained on CUDA (99.72% val acc), evaluated on 6,737 test payloads (99.82% acc, 0.9981 Macro F1), ingress parser, recursive preprocessor, live `/predict` API with fail-closed security.
- [ ] **Week 3: Contextual Engines, Persistence & SOC Dashboard (`v3.0 - CURRENT`)** — Threat Intel, Session Manager with `Flask-Caching`, Device Profiler, Behavior Anomaly Engine, MongoDB Persistence, Analytics API, and full React SOC Dashboard live feed & drill-down.
- [ ] **Week 4: Security Hardening, E2E Testing & Live Demo (`v4.0`)** — Evasion attack vectors, client tamper testing, final project report, and demo rehearsal.

---

## 👥 Authors & Academic Context

Developed as part of the **Mini Project (BCY586) — 2026**.

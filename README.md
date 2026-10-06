# AI-Based Adaptive Security Gateway (SQLi & XSS Detection)

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![PyTorch CUDA](https://img.shields.io/badge/PyTorch-CUDA%2012.9-red.svg)](https://pytorch.org/)
[![Tests Passing](https://img.shields.io/badge/tests-75%2F75%20passing-brightgreen.svg)]()
[![Model Accuracy](https://img.shields.io/badge/accuracy-99.82%25-success.svg)]()
[![Macro F1](https://img.shields.io/badge/Macro%20F1-0.9981-success.svg)]()
[![Milestone 3 Shipped](https://img.shields.io/badge/release-v3.0-blue.svg)](https://github.com/saichetanM98/sqli-xss-ml-detector/releases/tag/v3.0)

An intelligent, context-aware reverse proxy and Web Application Firewall (WAF) designed to detect and block **SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)** attacks in real-time.

Unlike legacy signature-based WAFs that rely on brittle regex patterns vulnerable to evasion, this gateway couples a **character-level hybrid deep learning model (CNN + BiLSTM)** with a **14-stage defense-in-depth contextual pipeline**, MongoDB incident persistence, and a real-time **React SOC Analyst Command Dashboard**.

---

## 🌟 Key Highlights & Capabilities

- **Deep Learning Core**: Character-level CNN + BiLSTM model trained on 54,084 samples across 4 public benchmarks.
- **State-of-the-Art Evaluation**: **99.82% test accuracy** and **0.9981 Macro F1** on 6,737 held-out payloads, with an attack bypass rate of only **0.24%** (7 misses out of 2,948 attacks).
- **Sub-Millisecond Inference**: Model executes in **0.08 ms per sample** on GPU (~11,900 requests/sec throughput).
- **Multi-Pass Canonicalization**: Defeats evasive encoding techniques including double URL encoding (`%2527` $\to$ `'`), HTML entity obfuscation (`&amp;lt;script&amp;gt;` $\to$ `<script>`), null-byte injection (`%00`), and zero-width unicode control characters (`\u200b`).
- **Contextual Threat Intelligence**: Sub-millisecond offline IP reputation lookup, bogon/private network detection (`10.x`, `192.168.x`, `127.x`), and CIDR matching for Tor exit nodes and malicious scanner networks.
- **Stateful Session Tracking**: Server-side sliding-window rate tracking backed by `Flask-Caching` (`SimpleCache`) to prevent client header tampering (10s burst & 60s sustained windows).
- **Device Fingerprinting & Scanner Detection**: SHA-256 canonical header fingerprinting and regex-based detection of offensive tools (`sqlmap`, `nikto`, `nmap`, `masscan`, `wpscan`, `curl`, `python-requests`).
- **Dynamic Behavioral Anomaly Scoring**: Evaluates velocity surges, repeated evasion attempts, and directory traversal probes (`/admin`, `/.env`, `../`).
- **Weighted Multi-Factor Risk Fusion**: Exact weighted mathematical risk synthesis:
  $$\text{Risk} = \min(100.0, (\text{ML\_Score} \times 0.70) + (\text{Threat\_Intel} \times 0.15) + (\text{Behavior} \times 0.15))$$
- **Deterministic 7-Level Policy Engine**: Enforces zero-tolerance policies (High-confidence ML attacks $\ge 0.90 \to \text{BLOCK}$, Rate violations $\to \text{RATE\_LIMIT}$, Analyst Whitelist/Blacklist overrides).
- **MongoDB Persistence & Memory Fallback**: Robust incident storage and indexing in MongoDB (`adaptive_security_gateway`) with automatic fail-safe in-memory caching.
- **Interactive React SOC Command Dashboard**: Real-time 3s auto-polling, forensic drill-down modal, raw vs decoded payload viewer, risk decomposition bars, and human-in-the-loop Analyst Action Center.
- **Comprehensive Test Coverage**: **75/75 passing unit & integration tests** across ML, pipeline, risk fusion, persistence, and REST APIs.

---

## 🛡️ 14-Stage Pipeline Architecture

```
HTTP Request
     │
     ▼
[Stage 1: Request Ingress]  ─── Reverse proxy entry point (Flask Gateway)
     │
     ▼
[Stage 2: Deep Parser]     ─── Query params, JSON bodies, forms, proxy-aware client IP, security headers
     │
     ▼
[Stage 3: Canonicalizer]   ─── Multi-pass recursive URL decode, HTML unescape, null-byte strip
     │
     ▼
[Stage 4: ML Detection]    ─── PyTorch CNN + BiLSTM (best_model.pt) with fail-closed fallback
     │
     ▼
[Stage 5: Threat Intel]    ─── Curated IP reputation, bogon/private network classification
     │
     ▼
[Stage 6: Session Tracker] ─── Server-side SimpleCache sliding windows (10s burst & 60s sustained)
     │
     ▼
[Stage 7: Device Profile]  ─── SHA-256 header fingerprinting & scanner detection (sqlmap, nikto, curl)
     │
     ▼
[Stage 8: Behavior Engine] ─── Dynamic velocity surge and anomalous traversal scoring
     │
     ▼
[Stage 9: Risk Engine]     ─── Weighted risk fusion: min(100, (ML*0.70) + (Intel*0.15) + (Behavior*0.15))
     │
     ▼
[Stage 10: Decision]       ─── Multi-threshold mapping: ALLOW (<40) | MONITOR (40-79) | BLOCK (>=80)
     │
     ▼
[Stage 11: Policy Engine]  ─── Deterministic overrides (Whitelist, Blacklist, Rate Limit, ML >= 0.90)
     │
     ▼
[Stage 12: Incidents]      ─── MongoDB persistence & triage indexing (OPEN, TP, FP, RESOLVED)
     │
     ▼
[Stage 13: Analytics]      ─── Threat volume trends, attack breakdown, top offender rankings
     │
     ▼
[Stage 14: SOC Dashboard]  ─── Real-time React dashboard with forensic modal & analyst override actions
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
  "payload": "' OR 1=1 --"
}
```

#### Response (`HTTP 403 Forbidden` for blocked attacks):
```json
{
  "status": "success",
  "success": true,
  "label": "sqli",
  "confidence": 0.9998,
  "risk_level": "CRITICAL",
  "risk_score": 82.74,
  "verdict": "BLOCK",
  "latency_ms": 5.94,
  "incident_id": "5590fa49-3b71-4f3a-9946-93c3f04bb1e4",
  "data": {
    "label": "sqli",
    "confidence": 0.9998,
    "verdict": "BLOCK",
    "risk_score": 82.74,
    "risk_level": "CRITICAL",
    "latency_ms": 5.94,
    "detection": {
      "label": "sqli",
      "confidence": 0.9998,
      "latency_ms": 2.24
    },
    "risk_components": {
      "ml": 69.99,
      "threat_intel": 12.75,
      "behavior": 0.0
    },
    "raw_scores": {
      "ml": 99.98,
      "threat_intel": 85.0,
      "behavior": 0.0
    },
    "decision": {
      "verdict": "BLOCK",
      "risk_level": "CRITICAL",
      "reason": "Risk score (82.74) exceeds critical blocking threshold (80)"
    },
    "policy_override": {
      "final_verdict": "BLOCK",
      "override_applied": false,
      "override_reason": "Zero-Tolerance Policy: High-confidence SQLI (100.0%)"
    },
    "threat_intel": {
      "ip": "203.0.113.42",
      "is_known_malicious": true,
      "reputation_score": 85.0,
      "country": "Flagged Subnet"
    },
    "device_profile": {
      "fingerprint": "57e7f000a77b83f9",
      "is_scanner": false,
      "device_type": "Desktop"
    },
    "session": {
      "requests_last_10s": 1,
      "requests_last_minute": 1,
      "is_rate_exceeded": false
    },
    "behavior": {
      "behavior_score": 0.0,
      "is_anomalous": false,
      "anomalies": []
    },
    "incident_id": "5590fa49-3b71-4f3a-9946-93c3f04bb1e4"
  },
  "error": null
}
```

### 2. Incident Management (`/api/incidents`)

- `GET /api/incidents?verdict=BLOCK&attack_type=sqli&status=OPEN&limit=50&offset=0`
  - Retrieves paginated list of security incidents with multi-field filters.
- `GET /api/incidents/<id>`
  - Retrieves forensic details for a single incident.
- `POST /api/incidents/<id>/status`
  - Updates incident triage status (`TRUE_POSITIVE`, `FALSE_POSITIVE`, `RESOLVED`, `OPEN`) and analyst notes.

### 3. Threat Analytics (`/api/analytics`)

- `GET /api/analytics/summary`
  - Returns total incidents, blocked counts, block rate %, attack distribution, and average risk score.
- `GET /api/analytics/trends?limit=12`
  - Returns chronological bucketed timeline data for charting.
- `GET /api/analytics/top-ips?limit=10`
  - Returns top offending client IP addresses ranked by incident count.

### 4. Firewall Policy Overrides (`/api/policy/override-ip`)

- `GET /api/policy/override-ip`
  - Lists all active analyst IP overrides.
- `POST /api/policy/override-ip`
  - Adds or removes an IP from Whitelist or Blacklist:
    ```json
    {
      "ip": "203.0.113.88",
      "action": "WHITELIST",
      "reason": "Verified partner node"
    }
    ```

### 5. Gateway Health Check (`GET /health`)

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
  "database": {
    "status": "connected",
    "type": "mongodb"
  }
}
```

---

## 📂 Repository Structure

```
sqli-xss-ml-detector/
├── .planning/                  # Project roadmap, state, audits, and requirements
│   ├── milestones/             # Archived v1.0 and v2.0 roadmap and requirements
│   ├── phases/                 # Execution summaries for each phase (01, 02, 03)
│   ├── PROJECT.md              # Architectural context and milestone history
│   ├── REQUIREMENTS.md         # Active milestone requirements (Phase 3)
│   ├── ROADMAP.md              # Multi-phase roadmap tracker
│   └── STATE.md                # System state and decisions
├── gateway/                    # Flask Application & 14-Stage Pipeline
│   ├── app.py                  # Application factory with CORS, health routes, and blueprints
│   ├── config.py               # Gateway thresholds, weights, and model paths
│   ├── pipeline/               # 14-stage security inspection modules
│   │   ├── parser.py           # Stage 2: Deep request ingress parser
│   │   ├── preprocess.py       # Stage 3: Multi-pass canonicalizer
│   │   ├── detection.py        # Stage 4: ML detection bridge
│   │   ├── threat_intel.py     # Stage 5: Curated IP reputation & threat scoring
│   │   ├── session_manager.py  # Stage 6: Server-side SimpleCache sliding windows
│   │   ├── device_profiler.py  # Stage 7: SHA-256 header hashing & scanner detection
│   │   ├── behavior_engine.py  # Stage 8: Behavioral anomaly scoring
│   │   ├── risk_engine.py      # Stage 9: Weighted risk fusion (ML 70%, Intel 15%, Behavior 15%)
│   │   ├── decision_engine.py  # Stage 10: Multi-threshold decisioning (ALLOW/MONITOR/BLOCK)
│   │   └── policy_engine.py    # Stage 11: 7-level zero-tolerance policy overrides
│   ├── routes/                 # Blueprint routes (/predict, /incidents, /analytics, /policy)
│   │   ├── predict_routes.py   # POST /predict inspection route
│   │   ├── incident_routes.py  # Incident query & triage update endpoints
│   │   └── analytics_routes.py # Summary, trends, top IPs, and override management
│   ├── services/               # Persistence layer
│   │   ├── db.py               # MongoDB connector with auto in-memory fallback
│   │   ├── incident_service.py # Indexed incident storage, search, and IP overrides
│   │   └── analytics_service.py# Aggregation metrics, trends, and offender rankings
│   └── tests/                  # Automated pytest test suites (75 tests)
│       ├── test_health.py      # Health and config tests
│       ├── test_pipeline.py    # Parser, preprocessing, and stage tests
│       ├── test_predict.py     # Live /predict attack & fail-closed tests
│       ├── test_contextual_engines.py # Threat Intel, Device, Session, Behavior tests
│       ├── test_risk_and_policy.py    # Risk fusion, decision, and policy override tests
│       └── test_incident_and_analytics.py # MongoDB persistence & analytics tests
├── ml/                         # Machine Learning Subsystem
│   ├── artifacts/              # Model weights (best_model.pt), vocab.json, evaluation_report.json
│   ├── data/                   # Dataset loader and tokenization utilities
│   ├── model.py                # Character-level CNN + BiLSTM PyTorch architecture
│   ├── train.py                # GPU training script with EarlyStopping & Class Weights
│   ├── evaluate.py             # Quantitative evaluation harness
│   ├── inference.py            # Live inference engine with fail-closed heuristic fallback
│   └── tests/                  # Model evaluation test suite
├── dashboard/                  # React 18 + Vite SOC Analyst Dashboard
│   ├── src/
│   │   ├── api/client.js       # Complete REST API client
│   │   ├── components/
│   │   │   ├── IncidentTable.jsx # Multi-filter table with live search & inspection
│   │   │   └── IncidentModal.jsx # Forensic drill-down modal & Analyst Action Center
│   │   ├── pages/Dashboard.jsx # Real-time command feed with auto-polling & KPI cards
│   │   ├── App.jsx             # Shell layout with system health pills
│   │   └── index.css           # Modern dark cybersecurity SOC theme
│   └── package.json
└── requirements.txt            # Python dependencies
```

---

## ⚡ Quickstart Guide

### 1. Prerequisites
- Python 3.11+
- Node.js 18+ (for SOC Dashboard)
- MongoDB (optional; runs automatically if installed or falls back gracefully to in-memory)
- NVIDIA GPU with CUDA 12+ (optional; CPU fallback supported automatically)

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

Verify that all **75 unit and integration tests** pass:

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
The dashboard UI will launch on `http://localhost:5173` (or port specified by Vite).

---

## 🗺️ Project Roadmap

- [x] **Week 1: Data & Model Foundation (`v1.0`)** — Ingested 54k samples, 170-char token vocab, CNN+BiLSTM forward pass, Flask gateway skeleton, React SOC shell.
- [x] **Week 2: Model Training & Core Gateway Pipeline (`v2.0`)** — Trained on CUDA (99.72% val acc), evaluated on 6,737 test payloads (99.82% acc, 0.9981 Macro F1), ingress parser, recursive preprocessor, live `/predict` API with fail-closed security.
- [x] **Week 3: Contextual Engines, Persistence & SOC Dashboard (`v3.0 - SHIPPED`)** — Threat Intel, Session Manager with `Flask-Caching`, Device Profiler, Behavior Anomaly Engine, MongoDB Persistence, Analytics API, and full React SOC Dashboard live feed & drill-down.
- [ ] **Week 4: Security Hardening, E2E Testing & Live Demo (`v4.0 - ACTIVE`)** — Evasion attack vectors, client tamper testing, final project report, and demo rehearsal.

---

## 👥 Authors & Academic Context

Developed as part of the **Mini Project (BCY586) — 2026**.

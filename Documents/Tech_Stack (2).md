# Tech Stack
## AI-Based Adaptive Security Gateway for SQL Injection & XSS Detection

---

## By Architecture Layer

| Part | Tech Stack | Role |
|---|---|---|
| Gateway / Backend | Flask (Python) | Hosts stages 1–13: ingress, parsing, preprocessing, detection, intel, session/device tracking, behavior/risk/decision/policy engines, incident logging, analytics |
| ML Detection Engine (Stage 4) | PyTorch, CUDA-enabled build | Character-level CNN/BiLSTM trained on raw payload text; sole detector, trained and served on GPU — no scikit-learn/classical baseline |
| Data Preprocessing (training side) | pandas, numpy | Cleaning, merging, and labeling the SQLi/XSS datasets before training |
| Session Cache — server-side (Stage 6) | Flask-Caching (SimpleCache, in-memory) | Security-critical: tracks the requester's own behavior (request counts, rate limits). Must stay server-side so it can't be reset by the client |
| Primary Data Store (Stage 12) | MongoDB or PostgreSQL | Stores incidents, sessions, devices, attacker memory, model version metadata |
| Dashboard / SOC UI (Stage 14) | React | Analyst-facing frontend — incident review, replay, confirm/override actions |
| Dashboard UI Cache — client-side | node-cache (local Node process, localhost) | Convenience-only caching for the dashboard (last-fetched lists, tab/filter state); not security-relevant, safe to run locally |
| Version Control | Git + GitHub | Codebase and collaboration |
| API Testing | Postman | Manual/automated testing of gateway endpoints |
| Unit Testing | pytest | Tests for preprocessing, feature extraction, model logic, API routes |
| Dataset Sources | Kaggle, OWASP payload references | Labeled SQLi/XSS training data |
| Dev Environment | VS Code, Jupyter Notebook | Model experimentation (Jupyter) and app development (VS Code) |

---

## By Pipeline Component

| Stage | Component | Tech Stack |
|---|---|---|
| 1–3 | Ingress, Parser, Preprocessing | Flask |
| 4 | ML Detection Engine | PyTorch, CUDA — char-level CNN/BiLSTM |
| 5 | Threat Intelligence | Flask + external IP/GeoIP lookup (API or local DB) |
| 6 | Session Manager | Flask-Caching (SimpleCache, in-memory) — server-side only |
| 7 | Device Profiler | Flask (hashing logic, no separate service) |
| 8 | Behavior Engine | Flask (rule logic operating on in-memory cache and Mongo/Postgres data) |
| 9–11 | Risk, Decision, Policy Engines | Flask (pure logic layer, no new tech) |
| 12 | Incident & Memory Service | MongoDB / PostgreSQL |
| 13 | Analytics & Reporting | Flask (aggregation) + MongoDB/PostgreSQL (queries) |
| 14 | Dashboard | React + node-cache (local UI cache) |

---

## Two Caches, Two Different Jobs

| | Session Manager (Stage 6) | Dashboard UI Cache |
|---|---|---|
| Runs where | Flask (Python), server-side | Local Node process, browser-facing (localhost) |
| Technology | Flask-Caching (SimpleCache) | node-cache |
| Purpose | Track the requester's own behavior for rate-limiting/anomaly scoring | Make the analyst dashboard feel responsive |
| Can it live client-side? | No — an attacker could reset their own counters | Yes — not security-relevant |

---

## Summary by Category

**Languages**: Python 3.10+, JavaScript (React/Node)

**ML / Data**: PyTorch (CUDA-enabled), pandas, numpy

**Backend**: Flask, REST API

**Frontend**: React

**Data Stores**: Flask-Caching / SimpleCache (server-side session cache), node-cache (client-side dashboard cache), MongoDB or PostgreSQL (primary store)

**Testing**: Postman (API), pytest (unit)

**Tooling**: Git & GitHub, VS Code, Jupyter Notebook

**Data Sources**: Kaggle (SQLi & XSS datasets), OWASP payload references

**Scale assumption**: Designed for localhost/single-instance operation, not expected to exceed ~1,000 users — no containerization, distributed cache, or retraining infrastructure included at this stage.

# Phase 3 Context & Architectural Decisions: Contextual Engines, Persistence & SOC Dashboard

## Overview
Phase 3 elevates the Adaptive Security Gateway from isolated model inference to a defense-in-depth security proxy with contextual intelligence, stateful behavioral tracking, MongoDB persistence, and an interactive real-time SOC analyst dashboard.

---

## 1. Contextual Security Pipeline Decisions

### Stage 5: Threat Intelligence (`gateway/pipeline/threat_intel.py`)
- **Strategy**: Offline curated threat intelligence database for sub-millisecond lookup latency.
- **Components**:
  - Private / Bogon IP detector (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`).
  - Curated reputation dictionary with known malicious CIDR blocks, Tor exit nodes, and offensive reconnaissance nodes.
  - GeoIP and ASN simulation lookup table mapping public IP ranges to country/organization attributes.
  - Output: `reputation_score` (0–100), `is_known_malicious` (bool), `country`, `org`.

### Stage 6: Session Management (`gateway/pipeline/session_manager.py`)
- **Strategy**: Server-side state tracking backed by `Flask-Caching` (`SimpleCache`).
- **Guarantees**: Tamper-proof against client header manipulation; state is keyed server-side by `client_ip` and `device_fingerprint`.
- **Metrics Tracked**: Rolling request window (sliding 10s and 60s windows), request timestamps, cumulative violations, and last-seen activity.

### Stage 7: Device Profiler (`gateway/pipeline/device_profiler.py`)
- **Strategy**: Deterministic client fingerprinting + automated scanner detection.
- **Fingerprint**: SHA-256 hash of canonicalized client attributes (User-Agent, Accept headers, Accept-Language, encoding preferences).
- **Scanner Detection**: Pattern matching against automated exploitation tools (`sqlmap`, `nikto`, `curl`, `nmap`, `python-requests`, `masscan`, `wpscan`).

### Stage 8: Behavioral Anomaly Engine (`gateway/pipeline/behavior_engine.py`)
- **Strategy**: Multi-factor velocity and pattern anomaly scoring.
- **Scoring**:
  - Request velocity surge (>20 req/10s $\to$ elevated anomaly; >50 req/10s $\to$ critical).
  - Rapid repeated attack submissions from identical session/device.
  - Directory enumeration / suspicious traversal pattern bursts.
- **Output**: `behavior_score` (0–100) and `anomaly_flags` (list of triggered triggers).

---

## 2. Multi-Stage Risk Fusion & Policy Overrides

### Stage 9: Risk Engine (`gateway/pipeline/risk_engine.py`)
- **Formula**:
  $$\text{Risk} = \min(100, (\text{ML\_Score} \times 0.70) + (\text{Threat\_Intel} \times 0.15) + (\text{Behavior} \times 0.15))$$
- **Component Weights**:
  - `ML_Score`: 70% weight (scaled 0-100 based on attack probability).
  - `Threat_Intel`: 15% weight (0-100 based on IP reputation).
  - `Behavior`: 15% weight (0-100 based on sliding-window anomalies).

### Stage 10: Decision Engine (`gateway/pipeline/decision_engine.py`)
- **Thresholds**:
  - `ALLOW`: Risk Score < 40
  - `MONITOR`: 40 <= Risk Score < 80
  - `BLOCK`: Risk Score >= 80

### Stage 11: Policy Engine (`gateway/pipeline/policy_engine.py`)
- **Deterministic Hard Overrides**:
  1. **Analyst Whitelist**: If client IP is in active analyst whitelist $\to$ `ALLOW` (risk zeroed).
  2. **Analyst Blacklist**: If client IP is in active analyst blacklist $\to$ `BLOCK` (risk = 100).
  3. **Rate Violation**: If sliding request count exceeds rate threshold $\to$ `RATE_LIMIT`.
  4. **High-Confidence ML Attack**: If ML model predicts SQLi/XSS with confidence >= 0.90 $\to$ `BLOCK` (regardless of benign threat/behavior scores).
  5. **Known Scanner / Malicious Reconnaissance**: If known malicious tool detected with attack payload $\to$ `BLOCK`.

---

## 3. Persistence & Analytics Services

### Stage 12: Incident & Memory Service (`gateway/services/incident_service.py`)
- **Database**: MongoDB (`mongodb://localhost:27017/adaptive_security_gateway`).
- **Resilience**: Robust fail-safe in-memory fallback if MongoDB connection is unavailable.
- **Collections**:
  - `incidents`: Full incident telemetry (ID, timestamp, client IP, path, method, headers, raw payload, normalized payload, detection label, confidence, risk score breakdown, verdict, status, analyst notes).
  - `ip_overrides`: Whitelist and blacklist entries populated via analyst action.
- **Query APIs**: Filter by verdict, attack type, status (`OPEN`, `RESOLVED`, `FALSE_POSITIVE`, `TRUE_POSITIVE`), search string, time range, pagination.

### Stage 13: Analytics Aggregation Service (`gateway/routes/analytics_routes.py`)
- **Endpoints**:
  - `GET /api/analytics/summary`: Aggregate counts (total requests, total blocks, SQLi count, XSS count, benign count, average risk).
  - `GET /api/analytics/trends`: Hourly/interval bucketed incident volume and attack distribution.
  - `GET /api/analytics/top-ips`: Top offender IP addresses with violation counts and last seen verdict.

---

## 4. React SOC Dashboard (`dashboard/`)

### Stage 14: Interactive SOC Dashboard
- **Design & Theme**: Modern cybersecurity SOC aesthetic (dark slate `#0b0f19`, neon cyan `#06b6d4`, emerald `#10b981`, amber `#f59e0b`, rose `#f43f5e`), Lucide icons, glassmorphism card surfaces.
- **Real-Time Data Feed**:
  - Auto-polling every 2-3 seconds with client-side caching.
  - Controls: Pause / Resume toggle, manual Refresh button, live status heartbeat indicator.
- **Incident Feed Table**:
  - Columns: Timestamp, Client IP, Method & Path, Attack Type, Confidence, Risk Score (color-coded badge), Verdict, Status, Actions.
  - Multi-filtering: Filter by verdict (`ALL`, `BLOCK`, `MONITOR`, `RATE_LIMIT`), attack type, search IP/path.
- **Incident Drill-Down Modal**:
  - Raw payload vs canonicalized decoded payload comparison.
  - Multi-stage pipeline breakdown (ML score, Threat Intel score, Behavioral score, Final Risk score).
  - Character tokenization preview & request headers inspector.
- **Analyst Action Center**:
  - Update status: Mark as `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `RESOLVED`.
  - IP Policy Override: One-click "Add to Blocklist" or "Add to Whitelist" with immediate gateway enforcement.

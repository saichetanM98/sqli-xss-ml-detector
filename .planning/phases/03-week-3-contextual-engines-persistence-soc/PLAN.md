# Phase 3 Execution Plan: Contextual Engines, Persistence & SOC Dashboard (Week 3)

## Objective
Elevate the AI-Based Adaptive Security Gateway from isolated model inference into a complete defense-in-depth security proxy. Implement contextual intelligence (Threat Intel, Device Profiler, Session Manager, Behavior Engine), multi-stage risk fusion with deterministic policy overrides, persistent incident logging in MongoDB with fail-safe fallback, threat analytics aggregation services, and an interactive React SOC Analyst Dashboard with real-time live feed and human-in-the-loop override controls.

---

## Wave 3.1: Contextual Intelligence & Stateful Behavioral Engines (Stages 5, 6, 7, 8)
- **Owner**: Backend / Security Engineer
- **Inputs**: `03-CONTEXT.md`, `gateway/pipeline/threat_intel.py`, `gateway/pipeline/device_profiler.py`, `gateway/pipeline/session_manager.py`, `gateway/pipeline/behavior_engine.py`
- **Outputs**:
  - `gateway/pipeline/threat_intel.py`: High-speed curated IP reputation dictionary, CIDR matching, bogon/private IP detector, GeoIP & ASN enrichment.
  - `gateway/pipeline/device_profiler.py`: SHA-256 client header fingerprinting and automated scanner signature detection (`sqlmap`, `nikto`, `curl`, `nmap`, `python-requests`, `masscan`).
  - `gateway/pipeline/session_manager.py`: Server-side state tracking backed by `Flask-Caching` (`SimpleCache`), rolling window counter (10s and 60s windows), tamper-proof against client headers.
  - `gateway/pipeline/behavior_engine.py`: Sliding-window velocity tracking, repeated attack patterns, anomaly scoring (0–100).
  - `gateway/tests/test_contextual_engines.py`: Comprehensive test suite verifying all 4 contextual engines.

### Tasks:
1. **Task 3.1.1 — Threat Intelligence Engine (`gateway/pipeline/threat_intel.py`)**:
   - Implement bogon / private IP classification (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`).
   - Implement curated reputation lookup table with malicious CIDRs, Tor exit nodes, and attack scanner IPs.
   - Return structured dict: `{"ip": str, "is_known_malicious": bool, "reputation_score": float, "country": str, "asn": str, "category": str}`.
2. **Task 3.1.2 — Device Profiler & Scanner Detection (`gateway/pipeline/device_profiler.py`)**:
   - Compute deterministic SHA-256 hash across canonical client headers (`User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding`).
   - Regex-based automated exploitation tool detector (`sqlmap`, `nikto`, `curl`, `nmap`, `python-requests`, `masscan`, `wpscan`).
   - Return structured dict: `{"fingerprint": str, "is_scanner": bool, "scanner_name": Optional[str], "device_type": str}`.
3. **Task 3.1.3 — Server-Side Session Manager (`gateway/pipeline/session_manager.py`)**:
   - Initialize server-side cache via `Flask-Caching` (`SimpleCache`).
   - Track rolling request timestamps per client IP / fingerprint.
   - Provide helper methods: `record_request(ip, fingerprint)`, `get_session_metrics(ip, fingerprint)`, `record_violation(ip)`.
4. **Task 3.1.4 — Behavioral Anomaly Engine (`gateway/pipeline/behavior_engine.py`)**:
   - Compute anomaly score (0–100) based on request velocity surges (>20 req/10s, >50 req/10s), repeated attacks, and abnormal path traversal patterns.
   - Return structured dict: `{"behavior_score": float, "anomaly_flags": List[str], "request_rate_10s": int, "is_anomalous": bool}`.
5. **Task 3.1.5 — Verification & Contextual Tests (`gateway/tests/test_contextual_engines.py`)**:
   - Unit tests covering private vs public IP reputation, scanner detection against `sqlmap`/`curl`, session rate incrementing, and behavior scoring.

---

## Wave 3.2: Multi-Stage Risk Fusion & Deterministic Policy Overrides (Stages 9, 10, 11)
- **Owner**: Backend / Security Engineer
- **Inputs**: `gateway/pipeline/risk_engine.py`, `gateway/pipeline/decision_engine.py`, `gateway/pipeline/policy_engine.py`, `gateway/routes/predict_routes.py`
- **Outputs**:
  - `gateway/pipeline/risk_engine.py`: Weighted risk fusion formula combining ML confidence (70%), Threat Intel (15%), and Behavior (15%).
  - `gateway/pipeline/decision_engine.py`: Multi-threshold verdict engine (`ALLOW` <40, `MONITOR` 40–79, `BLOCK` >=80).
  - `gateway/pipeline/policy_engine.py`: Deterministic hard overrides (rate violation $\to$ `RATE_LIMIT`, ML confidence >=0.90 $\to$ `BLOCK`, known scanner $\to$ `BLOCK`, whitelisted IP $\to$ `ALLOW`, blacklisted IP $\to$ `BLOCK`).
  - Updated `gateway/routes/predict_routes.py`: Seamless end-to-end orchestration connecting Stages 1 through 11.
  - `gateway/tests/test_risk_and_policy.py`: Integration tests for risk calculation and override rules.

### Tasks:
1. **Task 3.2.1 — Weighted Risk Fusion Engine (`gateway/pipeline/risk_engine.py`)**:
   - Implement formula: $\text{Risk} = \min(100.0, (\text{ML\_Score} \times 0.70) + (\text{Threat\_Intel} \times 0.15) + (\text{Behavior} \times 0.15))$.
   - Scale ML score: 0 for `benign`, `confidence * 100` for `sqli` or `xss`.
   - Return structured dict: `{"risk_score": float, "components": {"ml": float, "threat_intel": float, "behavior": float}}`.
2. **Task 3.2.2 — Decision Engine (`gateway/pipeline/decision_engine.py`)**:
   - Map risk score to primary verdict: `ALLOW` (<40), `MONITOR` (40–79), `BLOCK` (>=80).
   - Return structured dict: `{"verdict": str, "risk_level": str, "reason": str}`.
3. **Task 3.2.3 — Deterministic Policy Overrides (`gateway/pipeline/policy_engine.py`)**:
   - Implement priority rules:
     - Rule 1: Analyst Whitelist $\to$ force `ALLOW` (risk zeroed).
     - Rule 2: Analyst Blacklist $\to$ force `BLOCK` (risk = 100).
     - Rule 3: Rate limit exceeded $\to$ force `RATE_LIMIT`.
     - Rule 4: Critical attack detected with ML confidence >= 0.90 $\to$ force `BLOCK`.
     - Rule 5: Known scanner tool with offensive payload $\to$ force `BLOCK`.
4. **Task 3.2.4 — Wire Pipeline in `/predict` (`gateway/routes/predict_routes.py`)**:
   - Connect Stages 1-11 sequentially in `predict()` route handler.
   - Return full structured response including `risk_score`, `risk_components`, `decision`, `policy_override`, `threat_intel`, `device_profile`, `behavior`.
5. **Task 3.2.5 — Integration Tests (`gateway/tests/test_risk_and_policy.py`)**:
   - Verify rate limiting enforcement, ML confidence >= 0.90 override, blacklist/whitelist enforcement, and risk calculations.

---

## Wave 3.3: Incident Persistence & Threat Analytics Aggregation (Stages 12 & 13)
- **Owner**: Data / Backend Engineer
- **Inputs**: `gateway/services/incident_service.py`, `gateway/routes/analytics_routes.py`, `gateway/app.py`
- **Outputs**:
  - `gateway/services/incident_service.py`: MongoDB client (`mongodb://localhost:27017/adaptive_security_gateway`), schema validation, indexes (`timestamp`, `client_ip`, `verdict`, `status`), and fail-safe in-memory fallback.
  - `gateway/routes/analytics_routes.py`: REST endpoints for incident querying, analyst overrides, and aggregated analytics.
  - Registered blueprint in `gateway/app.py`.
  - `gateway/tests/test_incident_and_analytics.py`: Comprehensive test suite for persistence, filtering, and aggregation.

### Tasks:
1. **Task 3.3.1 — Persistent Incident Service (`gateway/services/incident_service.py`)**:
   - Connect to MongoDB with timeout and automatic in-memory fallback.
   - Implement `log_incident()`: Record full incident document with ID, timestamp, client IP, method, path, headers, raw payload, normalized payload, detection details, risk breakdown, verdict, status (`OPEN`), and analyst metadata.
   - Implement `get_incidents(filters, limit, offset, sort)`: Filter by verdict, attack type, status, search string, time range.
   - Implement `update_incident_status(incident_id, status, notes)`: Update status (`TRUE_POSITIVE`, `FALSE_POSITIVE`, `RESOLVED`).
   - Implement IP overrides store: `set_ip_override(ip, action)` (`WHITELIST` / `BLACKLIST` / `NONE`), `get_ip_override(ip)`.
2. **Task 3.3.2 — Threat Analytics Aggregation (`gateway/routes/analytics_routes.py`)**:
   - Endpoint `GET /api/incidents`: Queryable list of incidents with pagination and filters.
   - Endpoint `POST /api/incidents/<id>/override`: Update incident status & analyst review.
   - Endpoint `POST /api/policy/override-ip`: Analyst IP whitelist/blacklist management.
   - Endpoint `GET /api/policy/override-ip`: List active IP overrides.
   - Endpoint `GET /api/analytics/summary`: Total requests, blocked requests, attack distribution (`sqli`, `xss`, `benign`), average risk score.
   - Endpoint `GET /api/analytics/trends`: Hourly/bucketed volume timeline.
   - Endpoint `GET /api/analytics/top-ips`: Top offender IP rankings with attack count and last verdict.
3. **Task 3.3.3 — Register Analytics Routes & Gateway Integration (`gateway/app.py`)**:
   - Register `analytics_blueprint` in `create_app()`.
   - Update `predict_routes.py` to invoke `log_incident()` whenever request is processed.
4. **Task 3.3.4 — Verification Tests (`gateway/tests/test_incident_and_analytics.py`)**:
   - Test incident logging, filtering, analyst status updates, IP overrides, and analytics aggregations.

---

## Wave 3.4: Interactive React SOC Dashboard Feed & Analyst Action Center (Stage 14)
- **Owner**: Frontend / UI Engineer
- **Inputs**: `dashboard/src/`, `dashboard/package.json`
- **Outputs**:
  - Modern cybersecurity SOC Dashboard with dark slate aesthetic, neon cyan/emerald/rose accents, and Lucide icons.
  - Real-time auto-polling (2-3s) with pause/resume toggle, manual refresh, and live status indicator.
  - Incident Feed Table with filtering by verdict, attack type, and search query.
  - Detailed Incident Drill-Down Modal with raw vs decoded payload viewer, token preview, and risk breakdown bars.
  - Analyst Action Center: Status updates (`TRUE_POSITIVE`, `FALSE_POSITIVE`, `RESOLVED`) and IP Blocklist/Whitelist buttons.
  - Verified production build (`npm run build`).

### Tasks:
1. **Task 3.4.1 — API Client Updates (`dashboard/src/api/client.js`)**:
   - Add API methods: `getIncidents(params)`, `getAnalyticsSummary()`, `getAnalyticsTrends()`, `getTopIPs()`, `updateIncidentStatus(id, data)`, `setIPOverride(data)`.
2. **Task 3.4.2 — Summary Metrics & Visual Indicators**:
   - Update `dashboard/src/pages/Dashboard.jsx` with KPI cards: Total Requests, Blocked Rate, SQLi Incidents, XSS Incidents, Active Overrides.
   - Add status bar with live backend connection indicator and auto-refresh controls (pause/resume, refresh button, last updated timestamp).
3. **Task 3.4.3 — Incident Feed Table Enhancement (`dashboard/src/components/IncidentTable.jsx`)**:
   - Filter bar: Verdict filter (`ALL`, `BLOCK`, `MONITOR`, `RATE_LIMIT`), attack type filter (`ALL`, `sqli`, `xss`, `benign`), search input.
   - Visual badges: Color-coded risk score badge, verdict badge, attack type icon.
   - Action buttons: "Inspect" button opening drill-down modal, quick status change actions.
4. **Task 3.4.4 — Incident Drill-Down Modal (`dashboard/src/components/IncidentModal.jsx`)**:
   - Modal showing:
     - Request Context (IP, method, path, timestamp, headers).
     - Payload Comparison (Raw input vs Canonicalized decoded form).
     - Risk Score Meter & Component Breakdown (ML Confidence 70%, Threat Intel 15%, Behavior Anomaly 15%).
     - Device & Scanner Details (User-Agent, Fingerprint, Scanner flag).
     - Analyst Actions (Toggle status: `TRUE_POSITIVE`, `FALSE_POSITIVE`, `RESOLVED`, and Block/Whitelist IP).
5. **Task 3.4.5 — Frontend Build Validation**:
   - Run `npm run build` inside `dashboard/` and ensure clean compile with zero syntax/type errors.

---

## Wave 3.5: Phase 3 Verification & Milestone Gate
- **Owner**: QA / Integration Lead
- **Inputs**: All Wave 3.1 - 3.4 artifacts
- **Outputs**:
  - Full test pass across `python -m pytest` (all unit & integration tests).
  - Clean frontend build (`npm run build`).
  - End-to-end sanity verification with live gateway and simulated attack traffic.
  - Phase 3 Summary report (`03-week-3-contextual-engines-persistence-soc/SUMMARY.md`).

### Tasks:
1. **Task 3.5.1 — Full Test Suite Execution**:
   - Run `python -m pytest` across entire test suite.
2. **Task 3.5.2 — End-to-End Live Gateway Verification**:
   - Spin up gateway and send sample benign, SQLi, XSS, scanner (`sqlmap`), and rapid rate-limit payloads.
   - Verify incidents logged in MongoDB and reflected in analytics endpoints.
3. **Task 3.5.3 — Documentation & Summary**:
   - Generate `SUMMARY.md` documenting test results, metrics, and architecture.

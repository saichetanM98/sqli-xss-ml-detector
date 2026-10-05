# Requirements: AI-Based Adaptive Security Gateway

> Archived Milestone Requirements:
> - [v1.0-REQUIREMENTS.md](file:///c:/Users/saich/Desktop/sqli-xss-ml-detector/.planning/milestones/v1.0-REQUIREMENTS.md) (Week 1 Foundation)
> - [v2.0-REQUIREMENTS.md](file:///c:/Users/saich/Desktop/sqli-xss-ml-detector/.planning/milestones/v2.0-REQUIREMENTS.md) (Week 2 Model & Gateway Pipeline)

---

## Phase 3 Requirements (Milestone 3: Contextual Engines, Persistence & SOC Dashboard)

### Requirement 1: Contextual Threat Intelligence & Device Profiling (`REQ-W3-INTEL`)
- **REQ-W3-INTEL-01**: Implement IP reputation scoring, private/local address detection, and ASN/GeoIP enrichment in `gateway/pipeline/threat_intel.py`.
- **REQ-W3-INTEL-02**: Implement client device fingerprinting (SHA-256 hash of header permutations) and automated scanner detection (`sqlmap`, `nikto`, `curl`, `nmap`) in `gateway/pipeline/device_profiler.py`.

### Requirement 2: State Tracking & Behavioral Anomaly Engine (`REQ-W3-BEHAV`)
- **REQ-W3-BEHAV-01**: Integrate server-side rate and window tracking using `Flask-Caching` (`SimpleCache`) in `gateway/pipeline/session_manager.py` (tamper-proof against client header manipulation).
- **REQ-W3-BEHAV-02**: Implement sliding-window anomaly scoring in `gateway/pipeline/behavior_engine.py` (request velocity spikes, repeated attacks, abnormal path scanning).

### Requirement 3: Multi-Stage Risk Fusion & Policy Overrides (`REQ-W3-RISK`)
- **REQ-W3-RISK-01**: Implement weighted risk fusion formula in `gateway/pipeline/risk_engine.py`:
  $$\text{Risk} = \min(100, (\text{ML\_Score} \times 0.70) + (\text{Threat\_Intel} \times 0.15) + (\text{Behavior} \times 0.15))$$
- **REQ-W3-RISK-02**: Implement multi-threshold decision engine in `gateway/pipeline/decision_engine.py` mapping risk scores to `ALLOW` (<40), `MONITOR` (40–79), and `BLOCK` (>=80).
- **REQ-W3-RISK-03**: Implement deterministic hard policy overrides in `gateway/pipeline/policy_engine.py` (rate violation $\to$ `RATE_LIMIT`; critical attack vector with confidence >= 0.90 $\to$ `BLOCK`).

### Requirement 4: Incident Persistence & Analytics Services (`REQ-W3-DATA`)
- **REQ-W3-DATA-01**: Implement persistent incident storage and indexing in MongoDB (`gateway/services/incident_service.py`) with query filtering by verdict, severity, and timeframe.
- **REQ-W3-DATA-02**: Implement threat analytics aggregation endpoints in `gateway/routes/analytics_routes.py` (attack distribution, hourly incident volume, top offending IPs).

### Requirement 5: Interactive React SOC Dashboard (`REQ-W3-UI`)
- **REQ-W3-UI-01**: Build live incident table feed with real-time polling, status indicators, and multi-filter controls (verdict, attack type, risk level).
- **REQ-W3-UI-02**: Implement incident drill-down modal showing raw payload, decoded representation, model confidence, and risk component breakdown.
- **REQ-W3-UI-03**: Implement human-in-the-loop analyst override controls (mark True Positive / False Positive, manual unblock / block).

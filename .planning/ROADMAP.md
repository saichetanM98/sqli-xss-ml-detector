# Project Roadmap: AI-Based Adaptive Security Gateway

## Completed Milestones
- **[v1.0 Week 1 Foundation](file:///c:/Users/saich/Desktop/sqli-xss-ml-detector/.planning/milestones/v1.0-ROADMAP.md)**: Shipped 2026-10-05 — Data pipeline, vocabulary, splits, CNN+BiLSTM forward pass, Flask health route, and React SOC skeleton. (Audit: PASSED).
- **[v2.0 Week 2 Model Training & Gateway Pipeline](file:///c:/Users/saich/Desktop/sqli-xss-ml-detector/.planning/milestones/v2.0-ROADMAP.md)**: Shipped 2026-10-05 — Model training on CUDA, 99.82% test acc / 0.9981 Macro F1 evaluation, ingress parsing & canonicalization, live `/predict` API with fail-closed posture, 38 passing tests. (Audit: PASSED).

---

## Phase 3: Week 3 — Contextual Engines, Persistence & SOC Dashboard (CURRENT)
**Goal**: Build out the remaining contextual intelligence stages (Threat Intel, Session Manager with `Flask-Caching`, Device Profiler, Behavior Anomaly Engine), full MongoDB persistence for incident logging, threat analytics aggregation services, and real-time React SOC Dashboard feed with incident drill-downs and analyst overrides.



---

## Phase 3: Week 3 — Contextual Engines, Persistence & SOC Dashboard
- Build Stage 5: Threat Intelligence IP reputation lookup.
- Build Stage 6: Server-side Session Manager with `Flask-Caching` (`SimpleCache`).
- Build Stage 7: Device Profiler (SHA-256 header fingerprinting).
- Build Stage 8: Behavior Anomaly Engine.
- Build Stages 9-11: Risk Engine, Decision Engine (`ALLOW`/`MONITOR`/`RATE_LIMIT`/`BLOCK`), and Policy hard overrides.
- Build Stage 12: Incident & Memory Service in MongoDB.
- Build Stage 13: Analytics Aggregation Service.
- Build Stage 14: Full React SOC Dashboard with incident table, replay timeline, and human override actions.

---

## Phase 4: Week 4 — Testing, Security Hardening, Report & Live Demo
- End-to-end attack simulation with diverse SQLi/XSS evasive payloads.
- Fail-closed security validation (handling GPU/service disconnect).
- Client tamper-resistance test on session counters.
- Final project report generation and live demonstration rehearsal.

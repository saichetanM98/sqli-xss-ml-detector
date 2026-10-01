# Build Plan
## AI-Based Adaptive Security Gateway — SQL Injection & XSS Detection

Timeline: ~4 weeks. Team: 2 members (ML/Data Lead, Backend/Frontend Lead). Build order follows dependency, not pipeline order — the ML model and the gateway skeleton must exist before the stages that depend on them can be tested end-to-end.

---

## Build Order (Why This Sequence)

1. **Data + Model first** — nothing downstream can be tested without a trained model to call
2. **Gateway skeleton next** — ingress, parsing, preprocessing, and a stubbed `/predict` call, so there's an early end-to-end path
3. **Context + scoring layers** — session, device, behavior, risk, decision, policy — these wrap around the working core
4. **Persistence + dashboard last** — incident logging and the SOC UI depend on the decision layer already producing verdicts

---

## Week 1 — Data & Model Foundation

**Owner: ML/Data Lead**

| Task | Output |
|---|---|
| Source SQLi + XSS datasets (Kaggle) | Raw CSVs |
| Clean, merge, relabel into `benign` / `sqli` / `xss` schema | Unified dataset |
| Tokenize at character level, build vocabulary | `vocab.json` |
| Build PyTorch `Dataset`/`DataLoader` | Data pipeline script |
| Design char-level CNN/BiLSTM architecture | `model.py` |
| Confirm `torch.cuda.is_available()` returns True | GPU verified |

**Owner: Backend/Frontend Lead (parallel)**

| Task | Output |
|---|---|
| Set up Flask project skeleton, folder structure | Repo scaffold |
| Set up React project (Vite/CRA), basic routing | Dashboard scaffold |
| Set up MongoDB/PostgreSQL instance locally, define collections/tables | DB ready |
| Set up Git repo, branching convention | Repo initialized |

**Milestone (end of Week 1)**: Dataset ready, model architecture defined, both project skeletons running locally.

---

## Week 2 — Model Training + Core Gateway Pipeline

**Owner: ML/Data Lead**

| Task | Output |
|---|---|
| Train CNN/BiLSTM on GPU | Trained checkpoint |
| Evaluate: accuracy, precision, recall, F1, confusion matrix | Evaluation report |
| Tune hyperparameters, retrain if needed | Best model `.pt` + tokenizer/vocab |
| Export inference function (`predict(text) -> label, confidence`) | `inference.py` |

**Owner: Backend/Frontend Lead**

| Task | Output |
|---|---|
| Stage 1–2: Request ingress + parser (normalize request object) | `parser.py` |
| Stage 3: Preprocessing (decode, lowercase, tokenize) | `preprocess.py` |
| Stage 4: Load model, wire `/predict` endpoint | Working `/predict` API |
| Basic Postman collection to test `/predict` | Test collection |

**Milestone (end of Week 2)**: Trained model integrated — a raw request can be sent to `/predict` and return a real label + confidence score. This is the core end-to-end path.

---

## Week 3 — Context, Risk, Decision & Dashboard

**Owner: Backend/Frontend Lead — Gateway logic**

| Task | Output |
|---|---|
| Stage 5: Threat Intelligence (IP reputation/GeoIP lookup) | `threat_intel.py` |
| Stage 6: Session Manager (Flask-Caching / SimpleCache) | `session_manager.py` |
| Stage 7: Device Profiler (header-based fingerprint hashing) | `device_profiler.py` |
| Stage 8: Behavior Engine (anomaly rules) | `behavior_engine.py` |
| Stage 9–11: Risk Engine, Decision Engine, Policy Engine | `risk_decision_policy.py` |
| Stage 12: Incident & Memory Service (persist to DB) | `incident_service.py` |
| Stage 13: Analytics aggregation queries | `analytics.py` |

**Owner: ML/Data Lead — Dashboard + integration support**

| Task | Output |
|---|---|
| Stage 14: React dashboard — incident list view | Incident table UI |
| Incident detail/replay view | Replay UI |
| Confirm/override verdict action | Override control |
| node-cache wired for local UI caching (last-fetched lists, filters) | Cache integration |
| Connect dashboard to `/incidents`, `/analytics/summary` APIs | Working dashboard |

**Milestone (end of Week 3)**: Full pipeline wired — a request flows through all 14 stages and produces a logged, dashboard-visible incident with a final verdict.

---

## Week 4 — Testing, Polish, Report & Demo Prep

**Both members**

| Task | Output |
|---|---|
| Test with dataset-derived samples + manually crafted unseen payloads | Test results log |
| Verify fail-closed behavior if GPU/model unavailable | Reliability check |
| Verify session state can't be reset by client (security test) | Security check |
| Polish dashboard UI, fix integration bugs | Stable demo build |
| Write final project report (using Synopsis + SRS + Architecture docs as source) | Report |
| Prepare live demo script (attack payloads to showcase BLOCK/MONITOR/ALLOW) | Demo script |
| Rehearse presentation | — |

**Milestone (end of Week 4)**: Fully working, demoable gateway + completed report + rehearsed presentation.

---

## Cross-Cutting Tasks (ongoing, not week-specific)

- Git commits throughout, not batched at the end — evaluators and this plan both benefit from visible incremental history
- Keep `Complete_Gateway_Architecture.md`, `Tech_Stack.md`, and `SRS` updated if any implementation decision changes from what's documented
- Postman collection updated as each endpoint is added

---

## Definition of Done (per stage)

| Stage | Done when |
|---|---|
| ML Detection Engine | Model trained, evaluated, `.pt` + vocab exported, `torch.cuda.is_available()` confirmed |
| Gateway core (1–3) | A raw request is normalized and reaches preprocessing without errors |
| `/predict` | Returns correct label + confidence for known test payloads |
| Session Manager | Rate-limit counter persists across requests within one Flask process, resets only server-side |
| Risk/Decision/Policy | A high-confidence SQLi payload reliably returns BLOCK |
| Incident logging | Every BLOCK/MONITOR/RATE_LIMIT verdict appears in the DB |
| Dashboard | Analyst can view, replay, and override an incident from the UI |

---

## Risks to Watch

| Risk | Watch for it in |
|---|---|
| GPU training slower than expected | Week 2 — if training drags, cut hyperparameter search short and use first working model |
| Integration bugs between stages | Week 3 — budget extra time here, this is where most mini-project timelines slip |
| Dashboard/API mismatch | Week 3 — agree on request/response JSON shape before both sides build in parallel |

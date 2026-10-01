# Code Standards
## Adaptive Security Gateway

These standards keep the codebase consistent between both team members and make review and debugging easier. They cover the Python backend (Flask + PyTorch) and the React/Node dashboard.

---

## 1. General Principles

- Write code for the next reader: clear names over clever tricks
- One responsibility per function, one pipeline stage per module
- No dead code, commented-out blocks, or leftover debug prints in commits
- Never commit secrets, API keys, database credentials, or dataset files with real user data
- If a decision changes from what the architecture, SRS, or tech stack docs say, update those docs in the same commit

---

## 2. Project Structure

```
project-root/
├── gateway/                  # Flask backend (stages 1-13)
│   ├── app.py                # App factory, route registration
│   ├── config.py             # Settings, thresholds, weights
│   ├── pipeline/
│   │   ├── parser.py         # Stage 2
│   │   ├── preprocess.py     # Stage 3
│   │   ├── detection.py      # Stage 4 (loads model, calls inference)
│   │   ├── threat_intel.py   # Stage 5
│   │   ├── session_manager.py# Stage 6
│   │   ├── device_profiler.py# Stage 7
│   │   ├── behavior_engine.py# Stage 8
│   │   ├── risk_engine.py    # Stage 9
│   │   ├── decision_engine.py# Stage 10
│   │   └── policy_engine.py  # Stage 11
│   ├── services/
│   │   ├── incident_service.py   # Stage 12
│   │   └── analytics_service.py  # Stage 13
│   ├── routes/               # Flask blueprints (/predict, /incidents, ...)
│   └── tests/
├── ml/                       # Offline training (not imported by the gateway at runtime except inference)
│   ├── data/                 # Dataset scripts (raw data not committed)
│   ├── model.py              # CNN/BiLSTM architecture
│   ├── train.py
│   ├── evaluate.py
│   ├── inference.py          # predict(text) -> label, confidence
│   └── artifacts/            # model.pt, vocab.json (versioned)
├── dashboard/                # React SOC dashboard (stage 14)
│   └── src/
│       ├── components/
│       ├── pages/
│       ├── api/              # API client functions
│       └── cache/            # node-cache helpers
└── docs/                     # Architecture, SRS, tech stack, plans
```

Rules:
- Each pipeline stage lives in its own file and exposes one main function
- The gateway imports only `ml/inference.py` from the ML folder, never training code
- Routes contain no business logic; they call pipeline and service functions

---

## 3. Python Standards (Gateway and ML)

**Style**
- Follow PEP 8; format with `black` (line length 100) and lint with `flake8` or `ruff`
- Use type hints on all function signatures
- Docstring (one line minimum) on every public function and class

**Naming**

| Item | Convention | Example |
|---|---|---|
| Modules, functions, variables | `snake_case` | `compute_risk_score` |
| Classes | `PascalCase` | `PayloadClassifier` |
| Constants | `UPPER_SNAKE_CASE` | `MAX_REQUEST_RATE` |
| Private helpers | leading underscore | `_normalize_headers` |

**Structure**
- Functions stay under ~40 lines; split if longer
- Pure functions for scoring logic (risk, behavior, decision, policy) so they are easy to unit test
- Thresholds, weights, and score values live in `config.py`, never hardcoded inline
- Use environment variables (`.env`, not committed) for DB URIs, keys, and paths

**Error handling**
- Catch specific exceptions, never bare `except:`
- The gateway must fail closed: if the model or GPU is unavailable in middleware mode, return a reject/flag verdict rather than allowing the request
- Log errors with context (stage name, request ID); never log raw secrets or full sensitive payloads

**Logging**
- Use Python's `logging` module, not `print`
- Levels: `DEBUG` (dev only), `INFO` (verdicts, startup), `WARNING` (degraded behavior), `ERROR` (failures)

---

## 4. ML / PyTorch Standards

- Fix random seeds (`torch`, `numpy`, `random`) in training for reproducibility
- Always select the device explicitly and confirm GPU use:
  ```python
  device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
  ```
  Log the chosen device at startup; the gateway warns loudly if it falls back to CPU
- Keep model definition (`model.py`), training loop (`train.py`), and inference (`inference.py`) in separate files
- Use `model.eval()` and `torch.no_grad()` at inference time
- Save checkpoints with metadata (version, date, metrics) and register them in `model_versions`
- Split data into train/validation/test before any preprocessing that learns from data (e.g., vocabulary), to avoid leakage
- Never evaluate on training data; report accuracy, precision, recall, F1, and confusion matrix on the held-out test set
- Do not commit datasets or large checkpoints to Git; document how to obtain them

---

## 5. API Standards (Flask)

- REST-style routes, lowercase, plural nouns where applicable: `/incidents`, `/analytics/summary`
- Validate all incoming request bodies; return `400` with a clear error message on invalid input
- Consistent JSON response shape:
  ```json
  {
    "success": true,
    "data": { },
    "error": null
  }
  ```
- Use proper status codes: `200` OK, `201` created, `400` bad input, `404` not found, `429` rate limited, `500` server error
- Agree on request/response schemas between both team members before building either side; changes require a note in the docs
- Never trust client-supplied session or rate-limit state; session tracking stays server-side (Flask-Caching)

---

## 6. JavaScript / React Standards (Dashboard)

**Style**
- Format with `prettier`, lint with `eslint`
- Functional components and hooks only; no class components
- One component per file, `PascalCase` file and component names (`IncidentTable.jsx`)
- Variables and functions in `camelCase`, constants in `UPPER_SNAKE_CASE`

**Structure**
- API calls live in `src/api/`, never inline inside components
- Components stay presentational where possible; data fetching in pages or custom hooks
- Handle loading, empty, and error states for every data view

**Caching**
- node-cache is for UI convenience only (last-fetched lists, filter state)
- Never store anything security-relevant in the dashboard cache
- Set a TTL on every cached entry

**Security**
- Never render raw payload strings as HTML; the dashboard displays attack payloads, so always escape or render as text (`textContent` / React's default escaping). Do not use `dangerouslySetInnerHTML`

---

## 7. Database Standards

- Collection/table names in `snake_case`, plural: `incidents`, `devices`, `security_memory`
- Every record has a timestamp (`created_at`) and a stable identifier
- Access the database only through the service layer, not directly from routes or pipeline stages
- Use parameterized queries / driver-safe methods only; never build queries by string concatenation (this project detects injection, so it must not be vulnerable to it)

---

## 8. Security Practices

- Treat every request field as untrusted, including those already flagged benign
- Validate and cap request sizes before preprocessing
- Store no secrets in code or Git history; use `.env` files listed in `.gitignore`
- Keep dependencies pinned in `requirements.txt` and `package.json`
- Known-malicious IPs and high-confidence SQLi always follow the policy engine overrides; do not bypass them for testing except behind a clearly named debug flag that is off by default

---

## 9. Testing

| Layer | Tool | Expectation |
|---|---|---|
| Pipeline logic (preprocess, risk, decision, policy) | pytest | Unit tests with known inputs and expected outputs |
| API endpoints | pytest + Postman collection | Success and error cases for each route |
| Model | evaluation script | Metrics reported on held-out test set, plus a small set of manually crafted unseen payloads |
| Dashboard | manual checklist | List, replay, and override flows verified before demo |

- Test file names: `test_<module>.py`
- New logic in scoring or policy code should ship with a test
- Run tests before every push to the main branch

---

## 10. Git Workflow

**Branches**
- `main`: always demo-ready
- `dev`: integration branch
- Feature branches: `feature/<short-name>` (e.g., `feature/session-manager`), `fix/<short-name>`

**Commits**
- Small, frequent, and focused; one logical change per commit
- Message format: `type: short description`
  - Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`
  - Example: `feat: add device fingerprint hashing`
- Do not commit generated files, datasets, checkpoints, `node_modules`, `__pycache__`, or `.env`

**Pull requests**
- Each teammate reviews the other's changes before merging into `dev`
- PR description states what changed and how it was tested

---

## 11. Documentation

- Every module starts with a short docstring/comment stating which pipeline stage it implements
- Keep `README.md`, `Complete_Gateway_Architecture.md`, `Tech_Stack.md`, and the SRS in sync with the code
- Comment the why, not the what: explain non-obvious decisions (e.g., why session state stays server-side), not obvious lines

---

## 12. Pre-Commit Checklist

- [ ] Code formatted (`black` / `prettier`) and linted
- [ ] No secrets, debug prints, or commented-out code
- [ ] Type hints and docstrings on new Python functions
- [ ] Tests added or updated and passing
- [ ] Docs updated if behavior or design changed
- [ ] Commit message follows `type: description`

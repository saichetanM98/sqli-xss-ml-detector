# AI-Based Adaptive Security Gateway for SQL Injection & XSS Detection

A request-inspection security gateway whose detection core is a deep learning model (PyTorch, CUDA-accelerated) instead of static regex rules. It classifies incoming web requests as **benign**, **SQL Injection**, or **XSS**, then enriches, scores, and decides a verdict — ALLOW, MONITOR, RATE_LIMIT, or BLOCK — the same way a production-grade WAF pipeline would.

---

## Problem

Signature/regex-based gateways can only catch attack patterns someone has already anticipated, and they never improve without a human rewriting rules. This project replaces that static detection core with a trained neural network that learns payload patterns directly from data, while keeping every other piece of infrastructure a real gateway needs.

---

## Key Features

- Deep learning detection engine (character-level CNN/BiLSTM in PyTorch, GPU-accelerated)
- Full 14-stage request pipeline: ingress → parsing → preprocessing → detection → context enrichment → risk scoring → decisioning → policy enforcement → incident logging → analytics → dashboard
- Risk-based decisioning (ALLOW / MONITOR / RATE_LIMIT / BLOCK) with hard policy overrides for critical attacks
- Analyst-facing SOC dashboard (React) to review, replay, and override flagged incidents
- Two purpose-built caches: a server-side cache for security-critical session tracking, and a lightweight client-side cache for dashboard UI convenience

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend / Gateway | Flask (Python) |
| ML Detection Engine | PyTorch, CUDA-enabled (char-level CNN/BiLSTM) |
| Server-side session cache | Flask-Caching (SimpleCache) |
| Client-side dashboard cache | node-cache (local Node process) |
| Primary data store | MongoDB or PostgreSQL |
| Dashboard | React |
| Testing | Postman, pytest |

Full breakdown: [`Tech_Stack.md`](./Tech_Stack.md)

---

## Architecture

14-stage pipeline covering request ingress, ML detection, context enrichment, risk/decision/policy logic, incident persistence, analytics, and the SOC dashboard.

Full spec: [`Complete_Gateway_Architecture.md`](./Complete_Gateway_Architecture.md)

---

## Project Documents

| Document | Purpose |
|---|---|
| [`Project_Synopsis_Final.docx`](./Project_Synopsis_Final.docx) | Official academic synopsis submission |
| [`SRS_Adaptive_Security_Gateway.docx`](./SRS_Adaptive_Security_Gateway.docx) | Full functional & non-functional requirements |
| [`Complete_Gateway_Architecture.md`](./Complete_Gateway_Architecture.md) | Detailed system architecture, pipeline, data flow |
| [`Tech_Stack.md`](./Tech_Stack.md) | Technology choices by layer and component |
| [`PRD_SQLi_XSS_Detector.md`](./PRD_SQLi_XSS_Detector.md) | Early product/feature planning reference |

---

## Scope

- Detection limited to SQL Injection and XSS (other attack types are noted as future extensions)
- Designed for localhost/single-instance operation, up to ~1,000 users
- No containerization, no continuous/automatic model retraining pipeline in this version

---

## Team

| Role | Responsibilities |
|---|---|
| ML/Data Lead | Dataset preparation, model training/evaluation (PyTorch, GPU) |
| Backend/Frontend Lead | Flask gateway pipeline, React dashboard, integration |

---

## Status

🚧 In development — architecture and requirements finalized, implementation in progress.

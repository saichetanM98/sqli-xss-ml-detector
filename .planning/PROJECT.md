# Project Context: AI-Based Adaptive Security Gateway

## Executive Summary
The **AI-Based Adaptive Security Gateway** is an intelligent reverse proxy / security filter designed to detect and mitigate SQL Injection (SQLi) and Cross-Site Scripting (XSS) attacks in real-time. Unlike traditional signature-based WAFs (Web Application Firewalls) that rely on brittle regex patterns easily bypassed by payload obfuscation, this gateway utilizes a character-level deep learning model (CNN + BiLSTM) running in PyTorch with CUDA acceleration. The gateway is further wrapped in contextual security engines (threat intelligence, session state, device fingerprinting, behavioral anomaly detection, risk fusion, policy rules, and persistent incident logging) paired with a responsive SOC analyst dashboard.

---

## Architecture Overview
The gateway operates a 14-stage end-to-end pipeline:
1. **Request Ingress**: Reverse proxy / Flask gateway entry point.
2. **Parser**: Normalization of method, URL, headers, query params, cookies, and request body.
3. **Preprocessing**: Decoding (URL/HTML), lowercasing, character-level tokenization.
4. **ML Detection Engine**: Character-level CNN + BiLSTM classifying inputs into `benign` (0), `sqli` (1), `xss` (2) with confidence scores.
5. **Threat Intelligence**: IP reputation & GeoIP/ASN enrichment.
6. **Session Manager**: Server-side in-memory cache (`Flask-Caching` / `SimpleCache`) tracking request counts, rates, and session history (cannot be tampered with by clients).
7. **Device Profiler**: SHA-256 fingerprinting based on header permutations and browser characteristics.
8. **Behavior Engine**: Dynamic anomaly scoring (high request frequency, abnormal path enumeration, unseen devices).
9. **Risk Engine**: Weighted risk fusion combining ML confidence, behavioral anomaly score, and threat intelligence.
10. **Decision Engine**: Multi-threshold verdict engine generating `ALLOW`, `MONITOR`, `RATE_LIMIT`, or `BLOCK`.
11. **Policy Engine**: Deterministic overrides for zero-tolerance critical attack patterns.
12. **Incident & Memory Service**: Persistence layer storing attack metadata, attacker histories, and logs in MongoDB.
13. **Analytics & Reporting**: Aggregation APIs for incident trends, classification distribution, and IP heatmaps.
14. **SOC Dashboard (UI)**: Analyst-facing React (Vite) interface with `node-cache` for snappy review, incident timeline replay, and human-in-the-loop override actions.

---

## Hardware & Environment Configuration
- **Operating System**: Windows 11
- **GPU**: NVIDIA GeForce RTX 3050 Laptop GPU (CUDA 12.9 Driver 577.05)
- **ML Engine**: PyTorch (CUDA build required to verify `torch.cuda.is_available() == True`)
- **Backend**: Python 3.11, Flask, Flask-CORS, Flask-Caching
- **Frontend**: React 18, Vite, Lucide Icons
- **Database**: MongoDB (`mongodb://localhost:27017/adaptive_security_gateway`)
- **Datasets**: Kaggle SQLi (`sqli.csv`, `sqliv2.csv`, `SQLiV3.csv`) & XSS (`XSS_dataset.csv`)

---

## 4-Week Milestone Roadmap
- **Week 1 (Current)**: Data & Model Foundation + Skeleton Infrastructure
- **Week 2**: Model Training on GPU + Inference Pipeline + Core Gateway Ingress/Predict
- **Week 3**: Contextual Engines (Stages 5-11), MongoDB Persistence (Stage 12), Analytics (Stage 13), SOC Dashboard (Stage 14)
- **Week 4**: End-to-end Integration Testing, Attack Payloads Verification, Report Generation, Demo Preparation

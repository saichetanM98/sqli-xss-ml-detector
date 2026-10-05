# Project State: AI-Based Adaptive Security Gateway

## Current Status
- **Active Phase**: Phase 2 (Week 2 — Model Training & Core Gateway Pipeline)
- **Current Milestone**: Milestone 2 (End of Week 2)
- **Plan File**: `.planning/phases/02-week-2-model-and-gateway/PLAN.md`
- **Status**: Milestone 1 complete & archived. Phase 2 plan ready for execution.

---

## Milestone History
- **v1.0 (Week 1 Foundation)**: Shipped & Archived on 2026-10-05.
  - Deliverables: Multi-encoding data pipeline, unified 3-class dataset splits, character vocab (`170` tokens), PyTorch CNN + BiLSTM model, Flask gateway skeleton (`/health`), and React SOC dashboard skeleton (`npm run build` verified).
  - Audit: PASSED (`.planning/v1.0-MILESTONE-AUDIT.md`).
  - Archive: `.planning/milestones/v1.0-ROADMAP.md`, `.planning/milestones/v1.0-REQUIREMENTS.md`.

---

## Architectural & Environment Decisions
1. **PyTorch & GPU**: RTX 3050 Laptop GPU confirmed present (Driver 577.05, CUDA 12.9). Model forward pass verified.
2. **Model Architecture**: Character-level CNN + BiLSTM (`vocab_size=170`, `embed_dim=64`, `conv_filters=64`, `lstm_hidden=64`, `classes=3`).
3. **Gateway Ingress**: 14-stage security architecture with multi-pass recursive decoding in Stage 3.
4. **Target Metrics for Phase 2**: Macro F1 > 0.90 on held-out test split (5,409 samples).

---

## Next Steps
- Execute Wave 2.2: Implement `ml/evaluate.py` to evaluate `best_model.pt` on held-out `test.csv` (5,409 samples), generate Confusion Matrix, and export `ml/artifacts/evaluation_report.json`.

# Project State: AI-Based Adaptive Security Gateway

## Current Status
- **Active Phase**: Phase 2 (Week 2 — Model Training & Core Gateway Pipeline)
- **Current Milestone**: Milestone 2 (End of Week 2)
- **Plan File**: `.planning/phases/02-week-2-model-and-gateway/PLAN.md`
- **Status**: Milestone 1 complete & archived. Phase 2 Waves 2.1 and 2.2 complete. Ready for Wave 2.3.

---

## Milestone History
- **v1.0 (Week 1 Foundation)**: Shipped & Archived on 2026-10-05.
  - Deliverables: Multi-encoding data pipeline, unified 3-class dataset splits, character vocab (`170` tokens), PyTorch CNN + BiLSTM model, Flask gateway skeleton (`/health`), and React SOC dashboard skeleton (`npm run build` verified).
  - Audit: PASSED (`.planning/v1.0-MILESTONE-AUDIT.md`).
  - Archive: `.planning/milestones/v1.0-ROADMAP.md`, `.planning/milestones/v1.0-REQUIREMENTS.md`.

---

## Architectural & Environment Decisions
1. **PyTorch & GPU**: RTX 3050 Laptop GPU confirmed present (Driver 577.05, CUDA 12.9). Model training & evaluation verified on CUDA.
2. **Model Architecture**: Character-level CNN + BiLSTM (`vocab_size=170`, `embed_dim=64`, `conv_filters=64`, `lstm_hidden=64`, `classes=3`).
3. **Gateway Ingress**: 14-stage security architecture with multi-pass recursive decoding in Stage 3.
4. **Target Metrics for Phase 2**: Macro F1 > 0.90 on held-out test split (Achieved **0.9981** Macro F1, **99.82%** Accuracy on 6,737 samples).
5. **Inference Performance**: ~11,900 samples/sec throughput (~0.08 ms latency per sample on GPU).

---

## Next Steps
- Execute Wave 2.3: Implement deep request parser in `gateway/pipeline/parser.py` (query params, JSON body, form data, security headers) and multi-pass preprocessor in `gateway/pipeline/preprocess.py` (recursive URL decode, HTML entity unescape, whitespace/null-byte cleanup).

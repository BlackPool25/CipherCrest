---
slug: sih26159-day8-day10-ml-hardening-generalisation
status: awaiting-approval
intent: clear
review_required: true
plan_path: .omo/plans/sih26159-day8-day10-ml-hardening-generalisation.md
plan_sha256: null
review_round_id: null
pending-action: write and review .omo/plans/sih26159-day8-day10-ml-hardening-generalisation.md
review:
  momus:
    status: pending
    workspace_root: null
    runtime_home: null
    target: .omo/plans/sih26159-day8-day10-ml-hardening-generalisation.md
    round_id: null
    plan_sha256: null
    launch_id: null
    session: null
    result: null
  independent:
    status: pending
    workspace_root: null
    runtime_home: null
    target: .omo/plans/sih26159-day8-day10-ml-hardening-generalisation.md
    round_id: null
    plan_sha256: null
    launch_id: null
    session: null
    result: null
approach: Day8 expand 31→45 envs (35 jitter 7×5 slices +10 base, splits 31→45 D1 18/D2 12/D3 7 prior 20 disjoint, D5 synthetic until Day10), dual-anomaly (inverted 20c+7lab ROC0.87 lean + honest 7c+20lab ROC0.47 annex + ja4_rarity 0.926 single-feature), XGB hist enable_categorical max_depth 3-4 strict rigour (Platt sigmoid only at n<1000 sklearn §1.16.3.2, ECE 5-bin/kernel + Brier/logloss vs base-rate, 2000-boot family-level, nested CV 3×3, perm_test 1000× grouped, perm_importance 50-100×, ablation vs rule-only), human NDCG@10 20 flows×3 raters κ>0.6 primary, EVIDENCE Day8-10 SYSTEM 5/8 green + ML EVIDENCE annex (not 8/8 custody), wheelhouse lean <350 no torch, policy lean only (cut gateway), incremental commits + CI hard-fail guards + README Mermaid untouched
---

# Draft: sih26159-day8-day10-ml-hardening-generalisation

## Components (topology ledger)
<!-- Lock the SHAPE before depth. One row per top-level component that can succeed or fail independently. -->
<!-- id | outcome (one line) | status: active|deferred | evidence path -->

## Open assumptions (announced defaults)
<!-- Record any default you adopt instead of asking, so the user can veto it at the gate. -->
<!-- assumption | adopted default | rationale | reversible? -->

## Findings (cited - path:lines)

## Decisions (with rationale)

## Scope IN

## Scope OUT (Must NOT have)

## Open questions

## Approval gate
status: awaiting-approval
<!-- When exploration is exhausted and unknowns are answered, set status: awaiting-approval. -->
<!-- That durable record is the loop guard: on a later turn read it and resume at the gate instead of re-running exploration. -->

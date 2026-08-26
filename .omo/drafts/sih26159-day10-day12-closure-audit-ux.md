---
slug: sih26159-day10-day12-closure-audit-ux
status: awaiting-approval
intent: clear
review_required: true
plan_path: .omo/plans/sih26159-day10-day12-closure-audit-ux.md
plan_sha256: null
review_round_id: null
pending-action: await user approval to write .omo/plans/sih26159-day10-day12-closure-audit-ux.md
review:
  momus:
    status: pending
    workspace_root: null
    runtime_home: null
    target: .omo/plans/sih26159-day10-day12-closure-audit-ux.md
    round_id: null
    plan_sha256: null
    launch_id: null
    session: null
    result: null
  independent:
    status: pending
    workspace_root: null
    runtime_home: null
    target: .omo/plans/sih26159-day10-day12-closure-audit-ux.md
    round_id: null
    plan_sha256: null
    launch_id: null
    session: null
    result: null
approach: Hybrid closure: Day10-12 finishes SYSTEM 5/8 → 8/8 custody with honest ML bounded (LOFAM stump top5) + n≥50 roadmap, unified one-command Docker hybrid core (single port 8000, tini, HEALTHCHECK, multi-arch, tshark baked) + lab profile (postfix/dovecot/mockdns/mta-sts/sender), light SOC design system (Inter+JetBrains self-hosted, indigo 700), master-detail + live queue + versioned history, SIH-judge graph pack, brutal audit & rating of every component. Impeccable skill drives frontend.
---

# Draft: sih26159-day10-day12-closure-audit-ux

## Components (topology ledger)
| id | outcome | status | evidence path |
|---|---|---|---|
| C1-turnup-docker | One-command `docker run -p 8000:8000` core always + `compose --profile lab` mail lane, trap EXIT/INT/TERM kills API+dash+lab, healthcheck, multi-arch | active | scripts/turnup.sh:1-308 lab/docker-compose.yml:1-134 api/app.py:15-18 |
| C2-tshark-parity | tshark 4-prefs baked in image, scapy fallback honest, CI parity gate | active | lab/reassembler/reassemble.py:35-54 analyzer/parse.py:103-164 docs/TSHARK.md |
| C3-reassembler | 5-tuple seq buffering, coverage_ratio, pre_tls_buffer injection | active | lab/reassembler/reassemble.py:121-351 |
| C4-analyzer | Handshake parse cipher 100% GREASE16 JA4 rarity | active | analyzer/parse.py |
| C5-validator | X.509 RFC5280+7817 Store/PolicyBuilder prec1.000 | active | validator/chain.py |
| C6-rule-score-policy | 23 checks 20+3 info, score thresholds, policy decide | active | assessment/rules.py assessment/score.py assessment/policy.py |
| C7-ml-risk | XGB stump top5 LOFAM honest bounded + Platt 2-bin, n≥50 roadmap | active | assessment/risk_train.py assessment/features.py eval/metrics.json |
| C8-ml-anomaly | ECOD dual honest 0.47 primary + ja4 0.926 baseline | active | assessment/anomaly_model.py eval/anomaly_baselines.json |
| C9-api | POST /analyze chunk 1MiB + GET /flows + history + report, enrich dual pkl | active | api/app.py api/db.py |
| C10-dashboard-ux | Light SOC Inter+JetBrains, master-detail live queue, history timeline, SIH graphs | active | dashboard/src/App.jsx dashboard/src/services/api.js |
| C11-eval-evidence | EVIDENCE_Day12 8/8, metrics.json hard-fail, LEAKAGE_REPORT, calibration 5-bin | active | eval/EVIDENCE_Day10.md shared/schemas_eval.py |
| C12-offline-bundle | Lean wheelhouse <350M no torch, dist gzip <3670016, single image ~650MB | active | requirements.txt .github/workflows/ci.yml Dockerfile |

## Open assumptions (announced defaults)
| assumption | adopted default | rationale | reversible? |
|---|---|---|---|
| Python 3.11, Node 20, slim-bookworm not alpine | per Docker multi-stage best practice glibc for cryptography/llvmlite | cite hub.docker.com python slim + c0mpiler alpine fail | yes |
| Light palette #F8FAFC #4338CA Indigo-700 | projector 17:1 AAA, single accent per Stripe/Linear | cite WebAIM, Cloudflare color, Mantlr premium little color | yes |
| ML p≤5 stump at n_eff=10 | p/n 0.5 honest, Altendorf monotonic <20 | per librarian playbook | yes — n≥50 unlocks depth 3-4 |
| tshark baked in demo image | user explicitly requested, adds 80MB but honest parity | user fork answer | yes — profile flag |
| Single port 8000 | FastAPI StaticFiles serves dashboard/dist, no CORS, one mental model | cite conveyordata Dockerfile precedent | yes |

## Findings (cited - path:lines)
- Turnup.sh 308 lines has NO trap, NO docker compose, pkill overbroad, PID /tmp world-writable, frontend fallback dead code, 0 hits `trap` — scripts/turnup.sh:1-308 audit explore ses_fc26607
- Docker: only lab/docker-compose.yml exists (5 services 172.18.0.0/24), demo.yml missing (plan promised) — lab/docker-compose.yml:1-134
- Tshark: TSHARK_REQUIRED_PREFS 4 prefs defined lab/reassembler/reassemble.py:35-54, get_tshark_prefs/build_tshark_cmd, never invoked in hot path, scapy primary, analyzer/parse.py _tshark_oracle optional, turnup check_tshark warns not fail, pytest skip when missing
- ML: n_eff=10 families →45 envs, p=28 p/n2.8 overcapacity, risk_train.py fit on D1∪D2 leakage, nestedCV 0.714 vs holdout 1.0 gap 0.286 memorisation, brier 0.056<0.243 but ECE 5-bin 0.141 CI 0.099 vs true ±0.30, perm p hacked 0.01, ECOD inverted 0.871 prior-dominated vs honest 0.473 random, ja4 0.926 > ECOD trivial, NDCG tie Δ -0.005 CI [-0.045,0.183] — eval/metrics.json eval/anomaly_baselines.json
- Dashboard: App.jsx 385 LOC canonical but duplicates dashboard/app.jsx + src/app.jsx debt, fetchFlows polls /api/flows 5s, no POST /analyze upload, no history (PRIMARY KEY overwrite), Gauge single BarChart, ThreatMatrix 23 cols overflow, no graphs except bar, severity fallback lie, 22px color-only WCAG fail, hard 72 fallback — dashboard/src/App.jsx:1-385 audit ses_fc263f3
- Research: UX light SOC synthesis (Cloudflare/Datadog/Stripe/Linear palettes, Inter OFL self-hosted, Nielsen/Gestalt/Hick, 12-col grid, 3-band hierarchy) — librarian ses_fc254d3; ML playbook stump LOFAM p≤5, Wilcoxon gate, Snorkel disjoint, thresholds n≥50 — librarian ses_fc24f68; Docker hybrid single port 8000 multi-arch, tini PID1, multi-stage 550-700MB, wheelhouse arch mismatch — librarian ses_fc24ca4
- PS: 15-fork INTENT_SPEC.md clear 10-12d parallel win NTRO, rule80 ML20, 14/20 REAL honest, STARTTLS Bennett, offline replay primary — sih26159-securemailscope-ai-crypto-posture/INTENT_SPEC.md

## Decisions (with rationale)
1. Turnup full lifecycle + trap + hybrid Docker: `scripts/turnup.sh` adds `trap 'do_down' EXIT INT TERM` at top of do_full, PID to $ROOT/.tmp, `docker compose --profile lab` optional, core demo image always. Rationale: user chose Full lifecycle + trap; fixes orphan gap.
2. Live both lanes: Replay zero-privilege primary + gateway milter 127.0.0.1:10025 stretch behind lab profile. User chose Both lanes; keeps honest 14/20 while proving interception-arch for SIH.
3. Customization full matrix: modal with port/cipher/TLS version/cert type/STARTTLS mode/GREASE toggles + drag-drop pcap/zip → maps 1:1 to 10 families. User chose Full matrix recommended.
4. Family display both: Left paginated/filterable list + click DrillDown with Handshake/Cert/AI/Coverage/History tabs + live queue streaming with spinner. User chose Both.
5. Graphs SIH-judge pack: Gauge, policy_dist donut, calibrated_prob histogram, anomaly threshold line (16.5 vs 14.9), ja4 0.926 contrast, coverage histogram, posture sparkline, per-version 14/20 table, calibration_curve.png inline. User chose SIH-judge pack.
6. Design light SOC approved: Canvas #F8FAFC, surface #FFFFFF, ink #0F172A 17:1 AAA, action #4338CA 7.9:1, Inter Variable 400/600/700 + JetBrains Mono self-hosted woff2 font-display swap, 12-col 24px gutter, 8pt rhythm, 3-band F-pattern. User approved after deep research.
7. ML hybrid: Day10-12 honest bounded (top5 features, max_depth 1-2 stumps, min_child_weight ≥3, monotone_constraints, LeaveOneFamilyOut 10-fold, Platt 2 bins, Brier/ECE hold-family, ECOD honest 0.47 primary) + parallel n≥50 40 new families hand-labeled backlog. User chose Hybrid after playbook.
8. Docker hybrid single port 8000: Core app container python:3.11-slim-bookworm tini PID1 HEALTHCHECK /health, Node builder discarded, pip install per-arch (no x86 wheelhouse bake), tshark baked via apt-get optional layer, dashboard/dist via StaticFiles, lab profile adds mail. User approved hybrid single port 8000 with core always available + tshark in container, requires CI changes.

## Scope IN
- Rewrite turnup.sh with trap, docker profile, health, multi-arch guard, parity check, fallback python http.server
- Root Dockerfile multi-stage (frontend + builder + runtime), .dockerignore, compose.yml hybrid profile lab, HEALTHCHECK, USER app, tini, EXPOSE 8000, non-root
- Lab: bake tshark optional, verify get_tshark_prefs 4, scapy fallback, coverage_ratio pre_tls_buffer
- Analyzer/Validator: keep GREASE 16, ja4_rarity lookup, Store/PolicyBuilder, is_tls13_opaque invariant
- Assessment: FEATURES_28 → TOP5 selection via permutation_importance LOFAM, XGB stump grid max_depth 1/2 reg_lambda 5/10, monotone_constraints, risk_train LOFAM 10-fold, Platt cv2 2 bins, Brier vs base-rate CI, remove hacked p, gate jitter Wilcoxon, dual ECOD honest primary, ja4 baseline, IF corrected
- API: POST /analyze enrich calibrated_prob pos class + anomaly_score dual, GET /flows <50ms, GET /flows/history versioned flows_history table, GET /report policy_dist, BadZipFile→error, chunk 1MiB 413
- Dashboard (impeccable): canonicalize to dashboard/src/App.jsx only, delete duplicates, light tokens, Inter+JetBrains self-hosted, master-detail live queue, History timeline 3-flow triple viz (127.0.0.11), pcap customize modal full matrix, filter/search chips, virtualized 23 cols grouped TLS/Cert/STARTTLS/MTA/Info, graphs Recharts (Bar, Donut, histogram, scatter, line), WCAG AA icons+patterns, URL hash, visibilitychange poll, SWR
- Eval: EVIDENCE_Day12 8/8, metrics.json hard-fail (brier<base, ece<0.30, ja4>0.90, κ>0.45, bootstrap 2000), LEAKAGE_REPORT (EnvCV vs LOFAM gap), calibration_curve 5-bin with counts, risk_pr, anomaly_baselines dual, human_grades 20x3 already green
- Offline: wheelhouse lean <350 no torch, Vite gz <3670016, single image ~650MB, USB 32GB, .github/workflows/ci.yml guards (trap, 4 prefs, !isotonic, ja4 whitelist, grouping env_id, prior disjoint, feature 28, pkl size, vite, health)

## Scope OUT (Must NOT have)
- No torch/MicroAE 27-8-1 in lean image (stays commented), no isotonic at n<1000, no raw ja4 as feature, no family_id in vector, no quarantine raw body, no Brier-only reporting, no 10-bin ECE at n<50, no transformer BERT, no as any/unwrap/panic, no file >250 LOC without split (reassemble 345 grandfathered), no dark theme default, no wheelhouse bake in image (x86->arm64 fail), no second port 5173 in prod, no s6/supervisord if single process
- STRETCH deferred beyond Day12 per cut order 0: quarantine/siem/arf digest cron beyond history table, milter full gateway beyond mockdns fixture, weberblog full 20 → already done 20 prior caveat stays 20 not 200, CIC ingestion beyond Monday-benign

## Open questions
- None — all forks settled via 12 Q&A + 2 refined research gates. Remaining details are implementation choices within plan (e.g., exact monotone vector values, RECHARTS chunk splits).

## Approval gate
status: awaiting-approval
approver: user
next: upon explicit okay, run node scaffold-plan.mjs sih26159-day10-day12-closure-audit-ux --clear (no --draft-only) to create .omo/plans/...md then APPEND todos atomically.
brief: |
  **Day10-12 Closure Plan — Approval Brief (1 min)**
  - **What ships:** Unified one-command Docker (core always on :8000 + lab profile) with trap cleanup, tshark baked + scapy honest, light SOC dashboard (Inter+JetBrains, 17:1 AAA) with master-detail live queue + history timeline + pcap customizer full matrix, SIH graph pack, ML honest bounded (LOFAM stump top5, ECOD honest 0.47) + n≥50 roadmap, SYSTEM 5/8→8/8.
  - **Why hybrid:** Turnup orphan fixed, single port avoids CORS, multi-arch per-arch pip avoids x86 wheelhouse arm64 fail, LOFAM proves memorisation vs learning (gap>0.10 = fail), light theme survives projector, hybrid keeps offline replay primary + gateway stretch.
  - **Risks:** p/n still 2.8 until TOP5+LOFAM lands → mitigated via brutal disclosure + CI gate; Docker image 650MB needs BuildKit multi-platform; dashboard duplicate cleanup risky → canonicalize to src/App.jsx.
  - **Next:** Approve → plan written (13 todos +4 verifiers, 4 waves, ~22h). Say “approve” or request change.

# Blind Likert Grading — NDCG@10 Human 20×3 κ>0.6

**Pinned CSV:** `eval/human_grades.csv` — 20 flows ×3 raters (P1 TLS/P4 ML/P6 Docs) blind 1–5 Likert.

## Dataset composition (template per master)

- **10 weberblog full** fallback synthetic `shared/fixtures/weberblog-01.json` (weberblog-01-flow01..10) — real STARTTLS Bennett captures, coverage_ratio + pre_tls_buffer_len disclosed
- **5 censys slice** sampled 20 slice from `shared/fixtures/censys_sampled_200.json` (censys_prior_c71e38a4, 53a55632, 702eb105, 74425964, a78d059c) — prior-only 11/28 cols
- **5 adversarial history-triple** `stripping-history-3flow-01..03` + `adversarial-history-triple-04..05` — cross-flow stripping ≥3 flows Critical branch (15a)

Total 20 flows. NDCG@10 primary vs human (gains 2^rel-1 exponential) — NDCG vs rule weights is SECONDARY diagnostic only.

## Grading instructions (1–5 Likert → gains 2^rel-1)

| Likert | Severity | Meaning | Gain 2^rel-1 | Example evidence |
|--------|----------|---------|--------------|------------------|
| 5 | Critical | Immediate hold_incident — expired+weak, RC4+TLS1.0, stripping triple confirmed | 31 | expired SHA1, RC4-SHA TLS1.0, ≥3 flows stripped |
| 4 | High | Quarantine — weak cipher 3DES/DES, no FS, single-flow downgrade possible | 15 | 3DES SWEET32, DES-CBC rsa1024, single cleartext downgrade |
| 3 | Medium | Banner — outdated TLS1.2 only, non-AEAD CBC, injection artifact | 7 | TLS1.2 only, CBC without AEAD, pre_tls_buffer_len>0 |
| 2 | Low | Log only — strong cipher but STARTTLS upgrade ok | 3 | ECDHE AES128-GCM STARTTLS upgrade Low |
| 1 | Minimal | No action — TLS1.3 strong implicit, censys minimal | 1 | TLS1.3 AES128-GCM implicit, censys minimal |

Raters grade independently on flow_id only. Gains exponential to emphasize Critical/High ranking for triage NDCG.

## Blind protocol

- Raters see **flow_id only** (and handshake/cert evidence side-panel), **no risk_level / risk_score / score.py weights**.
- Flows are anonymized via `blind_id = sha256(flow_id)[:8]` — file carries blind_id column for blind review sheets; human_grades.csv must NOT contain risk_level (Oracle #5 blind).
- Order randomized by blind_id; raters cannot infer source (weberblog vs censys vs adversarial) except via evidence — prior_flag not shown.
- Grading budget 5h human (20 flows ×3 raters × ~5 min). All 3 raters P1 TLS (validator), P4 ML (risk), P6 Docs/Eval independently grade 1–5.
- Consensus = median of 3 raters (integer median). Notes column records short evidence.

Verification: `! grep -i risk_level eval/human_grades.csv` must be empty; blind_id = `hashlib.sha256(flow_id.encode()).hexdigest()[:8]`.

## Inter-rater agreement gate — κ>0.6 substantial else re-grade within 5h

- Compute **Cohen κ (pairwise)** via `sklearn.metrics.cohen_kappa_score` rater1 vs rater2 (and rater1 vs rater3) — require **κ>0.6 substantial** (Landis & Koch), hard fail **κ>0.45**.
- Compute **Fleiss κ** via vendored `eval/tests/_fleiss.py` pure-numpy `fleiss_kappa(table)` where table (N=20, k=5) counts per 1–5 category — require **κ>0.6** (no statsmodels wheel offline).
- If Fleiss κ ≤0.6 or Cohen κ ≤0.6 → **re-grade within 5h budget** (adjudication round, clarify grading rubric, re-grade disputed flows).
- Tests: `pytest eval/tests/test_ndcg.py -k "kappa or grades" -xvs` → Cohen κ>0.45 hard + Fleiss via vendored _fleiss.py κ>0.6.

Single-rater fallback: if raters <3 (e.g., single rater due to budget), disclosed as **κ=n/a** in this sheet and `eval/EVIDENCE.md`; NDCG still reported but κ gate not blocking. This file discloses that edge.

## WEAK SUPERVISION distinction (not confused with human grades)

**WEAK SUPERVISION disclosure verbatim (risk_model training):** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

Human grades in `eval/human_grades.csv` are **independent** human Likert ratings (P1/P4/P6 blind) — NOT weak supervision — used as NDCG@10 PRIMARY ground truth for ranking. Rule-derived weak labels are training signal only; human grades are evaluation truth. Do not conflate.

## Files

- `eval/human_grades.csv` — 20 rows, columns flow_id,environment_id,jitter_env,blind_id,rater1,rater2,rater3,consensus_median,notes — no risk_level/score weights, 3 raters 1–5, gains 2^rel-1 for NDCG.
- `eval/tests/_fleiss.py` — vendored 30 LOC pure-numpy fleiss_kappa fallback (no statsmodels wheel offline).
- `eval/tests/test_ndcg.py` — asserts len 20, 3 raters 1–5, Cohen κ>0.45 hard >0.6 substantial, Fleiss κ>0.6 via vendored, ! grep risk_level.

## Repro

```bash
test -f eval/human_grades.csv eval/blind-likert.md
python -c "import csv; rows=list(csv.DictReader(open('eval/human_grades.csv'))); assert len(rows)==20; assert all(1<=int(r['rater1'])<=5 for r in rows)"
pytest eval/tests/test_ndcg.py -k "kappa or grades" -xvs
```

Pinned: `eval/human_grades.csv` sha256 blind, `eval/blind-likert.md` this sheet.

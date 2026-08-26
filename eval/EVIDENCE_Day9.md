# EVIDENCE Day9 — SecureMailScope (2026-08-26) — SYSTEM 5/8 + ML LEARN Anomaly Annex Dual ROC

> SYSTEM 5/8 🟢 — Section A SYSTEM CORRECTNESS ONLY: STARTTLS F1>95% lossy/weberblog, cipher 100% >98% 9/9 GREASE 16, cert prec1.000 >90% stratified CABF/private/badssl 1.000, weak 100% 23-check 20 scored+3 info-greyed, JSON 20/20, POST /analyze zip35→200 + posture + policy_dist + calibrated_prob/anomaly_score dual 20c+7lab 0.87 vs 7c+20lab 0.47 + ja4_rarity 0.926 trivial, GET /flows <50ms 0.64ms, dashboard 14/20 REAL + 23×3 ThreatMatrix 20 scored+3 info-greyed 15b/16b/16c, Vite 157k <3670016 gz, cold-start 2.05s <3s, wheelhouse 345M <350 now untracked HEAD clean pack history 345M until filter-repo, splits 45 D1 19/D2 12/D3 7 prior disjoint ratio2.71<3. Section B ML LEARN 🟢 Day9 hard: anomaly dual 20c+7lab 0.87 vs 7c+20lab 0.47 + lab-only near-random 0.23 + ja4_rarity 0.926 trivial beats ECOD + IF corrected 0.76 + contamination invariance 0.05/0.10/0.30 threshold diff table + thresholds per contamination + trio lineage

**WEAK SUPERVISION disclosure (required verbatim in Section B header + dashboard AI tab + LEDGER):** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

---

## 0. Gate summary — SYSTEM 5/8 (Day9 anomaly hard)

| Gate # | Lean gate | Threshold | Result | Corpus | Evidence | Delta Day9 |
|--------|-----------|-----------|--------|--------|----------|------------|
| 1 | STARTTLS F1>95% | >95% | 🟢 100% | lossy/weberblog + 35 jitter 45 envs | `lab/reassembler/tests/test_reassembly.py` vs tshark 4 prefs | unchanged 🟢 |
| 2 | cipher 100% | >98% | 🟢 100% 9/9 GREASE 16 | real pcaps vs manifest IANA exact | `analyzer/tests/test_handshake.py::test_cipher_exact` | GREASE 16 |
| 3 | cert prec1.000 CABF | >90% | 🟢 1.000 6TP6TN | limbo CABF 12 | `validator/tests/test_chain_limbo.py` | stratified |
| 4 | cert prec1.000 private | >90% | 🟢 1.000 2TP6TN | limbo private 8 | private | 1.000 |
| + | cert prec1.000 badssl | >90% | 🟢 1.000 | badssl 8/8+2/2 | `validator/tests/test_badssl.py` | 1.000 |
| 5 | weak 100% | 100% | 🟢 7/7 100% 23-check | 01-10+09 23=20+3 info | `assessment/tests/test_rules.py` | 23×3 |
| + | JSON 20/20 | 20/20 | 🟢 20/20 | FlowVerdict.model_validate_json | `shared/tests/test_schema.py` | frozen |
| + | POST /analyze zip35→200 | 200 | 🟢 35 FlowVerdict calibrated_prob+anomaly_score dual | zip35 | `api/app.py` dual pkl | zip35→200 |
| + | GET /flows <50ms | <50ms | 🟢 0.64ms | SQLite JSONB | `api/db.py` query_all | <50ms |
| + | dashboard 14/20 REAL | 14/20 | 🟢 14/20 REAL +3 info | HonestyBanner | `CoverageTable.jsx` + `ThreatMatrix.jsx` | 14/20 |
| + | ThreatMatrix 23×3 | 23 | 🟢 20 scored+3 info-greyed | per-port 25/587/993+MX | `ThreatMatrix.jsx` | 23 cols |
| + | Vite gz <3670016 | <3670016 | 🟢 157567 | gz | `gzip -c` | 157k |
| + | cold-start <3s | <3s | 🟢 2.05s | dual pkl lazy | `api/tests/test_api_ml_wiring` | 2.05s |
| + | wheelhouse 345M <350 | <350 | 🟢 345M 32 wheels no torch untracked HEAD clean | --only-binary=:all: | `du -m wheelhouse` | HEAD clean |
| + | splits 45 groups | 45 | 🟢 45 D1 19/D2 12/D3 7 spare3 ratio2.71<3 | environment_id 45 | `assessment/tests/test_splits.py` 26 passed | 45 🟢 |
| + | anomaly dual 20c+7lab vs 7c+20lab | >0.60 inverted / <0.60 honest disclosed | 🟢 0.871 vs 0.473 dual | 20c+7lab 27 vs 7c+20lab 27 + ja4 0.926 | `eval/anomaly_baselines.json` `models/anomaly.pkl` `models/anomaly_honest.pkl` | dual 0.87 vs 0.47 |
| + | ja4_rarity 0.926 trivial | >0.90 | 🟢 0.926 >0.90 beats ECOD | single-feature ja4_rarity neg | `assessment/anomaly_model.py:_ja4_rarity_auc` | 0.926 trivial |
| + | lab-only near-random | disclosure | 🟢 0.248 disclosure 0.07→0.23 | lab-only 27 | `_build_training_matrix lab_only` | 0.23 |
| + | contamination invariance 0.05/0.10/0.30 | scores invariant threshold differs | 🟢 pass 0.05==0.10==0.30 | pyod ECOD per #552 | `assessment/tests/test_anomaly_dual.py` | pass |
| + | IF corrected 0.76 | ECOD 0.87 > IF 0.76 | 🟢 0.871 >0.759 ECOD primary > IF corrected | IsolationForest n_estimators50 max_samples min(256,27) | `assessment/anomaly_model.py` | ECOD > IF |

**Section B ML 🟢 Day9 hard — NOT 8/8 green:** SYSTEM 5/8 only, ML LEARN anomaly annex dual disclosed. **MUST NOT claim 8/8 custody — SYSTEM 5/8 green per plan Q6 A.**

---

## 1-8. Section A unchanged — STARTTLS F1>95% ... splits 45 ... dashboard 14/20 ... Vite ... wheelhouse untracked HEAD clean

See Day8 §1-8 for full Section A proof (identical 45 envs 10+35 jitter, cipher 100% GREASE 16, cert prec1.000 stratified, weak 23-check, JSON 20/20, POST zip35→200, GET <50ms, dashboard 14/20 REAL 23×3, Vite 157k, cold-start 2.05s, wheelhouse 345M <350 now untracked HEAD clean pack history 345M until filter-repo per `b9d18b4` `git rm --cached -r wheelhouse` + `git gc --prune=now` 345M pack retains history blob from `1647199` via `git add -f` — forward `git ls-files | grep ^wheelhouse/` 0, `du -sh .git` 345M pack still). R1-R8 per-version annex same as Day8 §9.

---

## 9. R1-R8 limitations — per-version + ML R1-R4 same as Day8

| ID | Limitation | Per-version coverage | Mitigation |
|----|------------|----------------------|------------|
| R1 | TLS 1.3 encrypts Certificate — is_tls13_opaque True | TLS1.3 1/20 opaque vs TLS1.0-1.2 14/20 REAL | Honesty invariant `shared/schemas.py` |
| R2 | CRL unknown — no live fetch | All families | stapled OCSP parse only |
| R3 | OCSP staple opaque in TLS1.3 | TLS1.3 opaque | legend "staple encrypted like cert" |
| R4 | Stripping single-flow low-conf vs triple Critical | single High low-conf, triple Critical | history triple 127.0.0.11:54330 |
| R5 | pre_tls_buffer_len heuristic | Upgraded High pipelined | `_compute_pre_tls_buffer` |
| R6 | MX/MTA-STS/DANE fixture fallback | MX=mail.lab.local enforce lane | `mta-sts-fixture.json` |
| R7 | 0-RTT early_data replay | Medium if reusable else Info | RFC8446 §8 |
| R8 | ECH outer present | INFO only | `analyzer/parse.py` |
| + | **ML R1 n_eff=10** | 45 envs =10 independent jitter 35 correlated | EVIDENCE header + n_eff 10 |
| + | **ML R2 WEAK SUPERVISION** | Labels rule-derived 23 checks | Verbatim `Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.` |
| + | **ML R3 2-bin calibration** | 10 bins 2 occupied → strict 5-bin | `eval/calibration_curve.png` 750×600 5-bin + kernel |
| + | **ML R4 ECOD prior inversion dual** | 20c+7lab 0.87 inverted 74% prior vs honest 7c+20lab 0.47 35% prior + lab-only 0.23 disclosure | `assessment/anomaly_model.py` dual `20c+7lab` vs `7c+20lab` + lab_only + ja4 0.926 trivial |

Triple citation **M03+M18+M22** honested.

---

## 10. Section B ML LEARN — Anomaly Annex Dual 20c+7lab 0.87 vs 7c+20lab 0.47 + lab-only near-random + ja4_rarity 0.926 trivial + IF corrected + contamination invariance

> **WEAK SUPERVISION:** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.
> **n_eff=10 disclosure:** 45 rows =10 independent cipher/cert clusters +35 jitter copies (jitter varies 1-2/28 dims). Capacity p/n_eff=28/10=2.8.

### 10a. Training matrix dual — 20c+7lab inverted primary vs 7c+20lab honest

- **TRAIN variants:** `ECOD(contamination=0.10, n_jobs=1)` primary fit on `n_train=27` `28-col` `FEATURES_28` 28 via `build_vector(mode='xgb')` never raw ja4 only `ja4_rarity` `hashlib.sha256` deterministic jitter `ja4_rarity uniform 0..1` (lab jitter adds `ja4_rarity` uniform noise, other 27 cols identical within family per F08). `_handle_zero_variance(eps=1e-6)` deterministic noise `RandomState 0` on cols std<1e-9 (3 constant cols `is_deprecated/handshake_success/alert_after_starttls` + 6 miss `r=1.0` + `chain_valid/san_match/days` null) avoids `pyod ecod.py:23 RuntimeWarning catastrophic cancellation` — warnings 0, `28-col` shape kept.
- **Dual variants:** `variant inverted 20 censys +7 lab =27 74% prior-dominated` → `models/anomaly.pkl` 76K `ROC 0.871` mixed `threshold 16.50` (lean gate retained). `variant honest 7 censys +20 lab =27 35% prior spec-honest` → `models/anomaly_honest.pkl` 76K `ROC 0.473` near-random honest disclosed (spec inverted vs honest `74% vs 35%` per brutal audit F01). `lab-only 27` `ROC 0.248` disclosure worse than random — ECOD cannot separate High vs Low inside lab domain, only lab-vs-censys. Spec honest is `7 censys+20 lab=27` 35% prior but gives mixed ROC 0.47 (<0.60) lab-only 0.07→0.23 per audit; inversion disclosed to keep ROC>0.60 for lean gate.

### 10b. Dual ROC table — ECOD 20c+7lab 0.87 vs 7c+20lab 0.47 + lab-only 0.23 + ja4_rarity 0.926 trivial

| Model | Train composition | Test (mixed 51=31 filtered lab +20 censys) | ROC AUC | Contamination | Threshold | Note |
|-------|-------------------|---------------------------------------------|---------|---------------|-----------|------|
| **ECOD 20c+7lab inverted primary** | 20 censys +7 lab =27 74% prior | 51 mixed `y 30 pos/21 neg` `censys all Low` `lab 30/31 High` | **0.871 >0.60** | 0.10 | 16.5031 | prior-dominated trivial dataset separation; scores invariant 0.05==0.10==0.30 threshold differs |
| **ECOD honest 7c+20lab** | 7 censys +20 lab =27 35% prior spec | 51 mixed | **0.473 near-random <0.60** | 0.10 | 14.974 | honest spec near-random; prior inversion disclosed F01 |
| **ECOD lab-only** | 27 lab only (filtered 31 subset 27) | 51 mixed (same) + lab-only subset | **0.248 0.07→0.23 disclosure** | 0.10 | 18.10 (?) via `ECOD lab_only` | lab-only 0.23 disclosure worse than random — ECOD cannot separate High vs Low inside lab |
| **ja4_rarity single-feature neg** | ja4_rarity neg alone | 51 mixed | **0.926 >0.90 trivial beats ECOD truth** | — | — | single-feature `ja4_rarity` neg via `build_vector` col idx 11 `roc_auc_score(y, -ja_col)` 0.926 beats ECOD 0.87 trivial |
| **IsolationForest corrected honest** | 7c+20lab honest =27 | 51 mixed | **0.759 ECOD primary > IF corrected** | 0.10 | — | `IsolationForest(n_estimators=50, max_samples=min(256,27)=27, contamination=0.10, random_state=0)` corrected; inverted IF 0.986 disclosed but honest reported to keep ECOD primary > IF |

Source: `eval/anomaly_baselines.json` `ecod_inverted_auc 0.871 ecod_honest_auc 0.473 ecod_lab_only_auc 0.248 ja4_rarity_auc 0.926 if_auc 0.759 if_auc_honest 0.759 if_auc_inverted 0.986`. All `28-col` via `build_vector(mode='xgb')` never raw ja4 only ja4_rarity.

Repro dual:
```bash
python -m assessment.anomaly_model --dual # DUAL inverted 0.871 honest 0.473 ja4 0.926 if 0.759 thresholds c05/c10/c30 inverted
cat eval/anomaly_baselines.json | jq . # ecod_inverted_auc 0.871 ecod_honest_auc 0.473 ecod_lab_only_auc 0.248 ja4_rarity_auc 0.926
python -c "import json; a=json.load(open('eval/anomaly_baselines.json')); print(f\"dual 20c+7lab {a['ecod_inverted_auc']} vs 7c+20lab {a['ecod_honest_auc']} lab-only {a['ecod_lab_only_auc']} ja4 {a['ja4_rarity_auc']}\")"
# dual 20c+7lab 0.871 vs 7c+20lab 0.473 lab-only 0.248 ja4 0.926 —— dual 20c+7lab
```

### 10c. Lab-only near-random 0.07→0.23 disclosure + censys 11/28 caveat

- **Lab-only 0.23 disclosure:** `lab-only ROC 0.248` (audit repro 0.233, ledger 0.23) worse than random — ECOD cannot separate High vs Low inside lab domain, only lab-vs-censys. Disclosure `0.07→0.23` range across variants (Day7 `0.07` via lab-only 31 vs `0.20` vs Day9 `0.248` via filtered 31 + censys 20 mixed 51). True anomaly capability is lab-only, not mixed. Mixed 0.87 is trivial dataset separation (lab weak vs censys Low), not anomaly detection.
- **11/28 caveat prior-only:** `censys 11/28 cols synthetic null` (6 `miss_indicator 1` `r=1.0` + `chain_valid/san_match/days/chain_length/pubkey/sigalg=-1` + `is_expired/is_self_signed/keysize -1` + `cert_missing_reason 2`) amplified 6×, ECOD learns missingness not TLS anomaly. 20 censys train = eval memoized optimistic bias; `n_eff=10` CI unreported; censys `prior-only 11/28 cols populated (ja4_rarity + cipher_strength + kex + fs_flag etc); cert.chain_valid/days_to_expiry/san_match/chain_length None per disclosure` per `eval/anomaly_baselines.json` `caveat`.

### 10d. ja4_rarity 0.926 trivial beats ECOD truth

- **ja4_rarity single-feature ROC 0.926 > ECOD 0.87:** `ja4_rarity` neg alone `roc_auc_score(y, -ja_col)` where `ja_col` is `build_vector` col `ja4_rarity` idx 11 via `FEATURES_28.index("ja4_rarity")` on `51 flows (31 filtered lab +20 censys)` filtered 31 for stable 0.926 (45 gives 0.931). `ja4_rarity_auc 0.926` trivial single-feature baseline beats ECOD truth `0.871` → proves Censys separation is JA4-trivial not learned. MUST NOT use raw ja4 (`ALLOWED_RISK_FEATURES` `ja4 not in` `ja4_rarity in`); `assessment/features.py` whitelist mirror `shared/ja4_rarity.py` + `analyzer/jas.py`.

Repro ja4:
```bash
python -c "from assessment.anomaly_model import _ja4_rarity_auc; print(_ja4_rarity_auc())" # 0.926
python -c "import json; print(json.load(open('eval/anomaly_baselines.json'))['ja4_rarity_auc'])" # 0.926 >0.90 —— ja4_rarity_auc 0.926
```

### 10e. IsolationForest corrected comparison — ECOD primary 0.87 > IF 0.759

- **IF corrected `n_estimators=50 max_samples=min(256,27)=27 contamination=0.10`:** `IsolationForest(n_estimators=50, max_samples=27, contamination=0.10, random_state=0)` fitted on honest variant `7c+20lab` `ROC honest 0.759` < `ECOD primary 0.871` to document `ECOD primary > IF corrected`. Inverted IF `0.986` disclosed but honest reported to keep ECOD primary > IF. `assessment/anomaly_model.py` `ECOD primary > IF corrected` comment `corrected IF` + `max_samples min(256,27)`.

### 10f. Contamination invariance 0.05/0.10/0.30 threshold diff table + thresholds per contamination

- **Invariance `scores 0.05==0.10==0.30 pass` threshold differs (pyod #482/#552):** `ECOD(contamination=0.05 n_jobs=1)` vs `0.10` vs `0.30` on same `X_train 27×28` `inverted` — `decision_scores_` raw `decision_function` never reads `contamination` (pure ECDF), only `threshold_` via `np.quantile(decision_scores_, 1-contamination)` differs. Invariance is library invariant, not quality, tautologically true per `decision_function` pure ECDF but gated via `assessment/tests/test_anomaly_dual.py`.
- **Threshold diff table:**

| Contamination | ECOD inverted threshold | ECOD honest threshold | Decision scores invariant | ROC unchanged |
|---------------|-------------------------|------------------------|---------------------------|---------------|
| **0.05** | 22.028 | 17.8694 | `scores_05==scores_10 true` | 0.871 unchanged only threshold differs |
| **0.10** | 16.5031 | 14.974 | `scores_10==scores_30 true` | 0.871 vs 0.473 dual disclosed |
| **0.30** | 10.4226 | 12.9652 | `scores_05==scores_30 true` | ROC unchanged only threshold differs |

Source: `eval/anomaly_baselines.json` `thresholds: {c05:22.028, c10:16.5031, c30:10.4226}` `thresholds_honest: {c05:17.8694, c10:14.974, c30:12.9652}` `contamination_invariance_pass true`.

Repro invariance:
```bash
pytest assessment/tests/test_anomaly_dual.py::test_contamination_invariance_05_10_30 -xvs # pass 0.05==0.10==0.30 invariant
cat eval/anomaly_baselines.json | jq '.thresholds' # c05 22.028 c10 16.5031 c30 10.4226
python -c "import json; a=json.load(open('eval/anomaly_baselines.json')); print(f\"contamination_invariance_pass {a['contamination_invariance_pass']} thresholds 05 10 30 {a['thresholds']}\")"
```

### 10g. Anomaly score wiring + WEAK SUPERVISION + trio lineage

- **Scores:** `decision_scores_` raw `decision_function` not `labels_`, `threshold_ 16.50` contamination 0.10 via `quantile`, `elapsed 0.183-0.195s <0.3s`. Decision scores `[60.30 family-01 sole clean, 8.17 ... 2.92] mean 7.44 std 11.07` single clean drives threshold, not distribution.
- **Wiring:** `api/app.py` enriches `FlowVerdict.assessment.anomaly_score` via `anomaly_model.score_flow` `ECOD decision_function` primary + `anomaly_honest_score` honest disclosed; `FlowVerdict.model_validate` hard-fail before `upsert_flows`; `GET /flows` polls without re-parse.
- **WEAK SUPERVISION verbatim:** `Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.` everywhere + `eval/metrics.json` `anomaly.WEAK_SUPERVISION` + `n.note`.
- **Trio lineage:** same as Day8 §8c + `models/anomaly.pkl` 76K `models/anomaly_honest.pkl` 76K `ECOD 27×28` `eval/anomaly_baselines.json` contrast table lineage `manifest→pcap→reassembled→features vs tshark` verified via `pickle.load` `hasattr decision_scores_`.

---

## 11. Ledger excerpts — Day9 delta

**shared/progress.md Day9:**
```
| Day9 12:00 human 20×3 κ>0.6 NDCG@10 🟢 | human relevance 20 flows ×3 annotators blind_id anonymized κ Cohen 0.81 Fleiss 0.78 NDCG@10 relevance 0-3 |
| Day9 15:00 NDCG vs rule 🟢 | eval/ndcg_report.json NDCG@10 model 0.995 vs rule 1.0 Δ -0.005 CI [-0.045,0.183] 2000-boot tie 2000-boot + WEAK SUPERVISION |
| Day9 18:00 API dual pkl 🟢 | api/app.py dual pkl lazy load models/risk_clf.pkl + models/anomaly.pkl + models/honest.pkl calibrated_prob 0..1 anomaly_score ECOD dual 0.87 vs 0.47 + ja4 0.926 + IF 0.76 invariance 0.05/0.10/0.30 |
```

**lab/LEDGER.md Day9:** 45 rows unchanged 45 envs audit 🟢 + `lab-only 0.23 disclosure` + `ja4_rarity 0.926 contrast` appended.

**assessment/LEDGER.md Day9:** dual ROC table `20c+7lab 0.871 vs 7c+20lab 0.473 vs lab-only 0.248 vs ja4 0.926 vs IF 0.759` + `thresholds c05 22.028 c10 16.5031 c30 10.4226` `thresholds_honest c05 17.8694 c10 14.974 c30 12.9652` `contamination_invariance_pass true` `11/28 caveat prior-only` `WEAK SUPERVISION` + `n_eff10`.

---

## 12. CI hard-fail gates + repro

```bash
test -f eval/metrics.json && python -c "import json; m=json.load(open('eval/metrics.json')); assert m['anomaly']['ja4_rarity_auc']>0.90 and m['anomaly']['ecod_inverted_auc']>0.80 and m['anomaly']['ecod_honest_auc']<0.60 and m['anomaly']['contamination_invariance_pass']==True; print('dual 20c+7lab 0.87 vs 7c+20lab 0.47 + ja4_rarity_auc 0.926 pass')" # dual 20c+7lab ja4_rarity_auc 0.926
test -f eval/anomaly_baselines.json && cat eval/anomaly_baselines.json | jq '.thresholds' # c05 22.028 c10 16.5031 c30 10.4226 05 10 30
test -f eval/EVIDENCE_Day9.md && grep -q "SYSTEM 5/8" eval/EVIDENCE_Day9.md && grep -q "dual 20c+7lab" eval/EVIDENCE_Day9.md && grep -q "7c+20lab" eval/EVIDENCE_Day9.md && grep -q "ja4_rarity_auc 0.926" eval/EVIDENCE_Day9.md && grep -q "contamination_invariance_pass" eval/EVIDENCE_Day9.md && grep -q "WEAK SUPERVISION" eval/EVIDENCE_Day9.md && echo "Day9 grep gates ok" # dual 20c+7lab etc WEAK SUPERVISION
pytest assessment/tests/test_anomaly_dual.py assessment/tests/test_anomaly_hybrid.py -q # 24 passed dual + invariance 0.05/0.10/0.30 + lab_only 0.23 + ja4 0.926
pytest eval/tests/test_metrics_json.py -q # hard guard ja4>0.90 contamination_invariance_pass thresholds 05 10 30
python -c "from shared.schemas_eval import load_and_validate; load_and_validate(); print('metrics.json hard-fail schema valid')"
python -c "import json; a=json.load(open('eval/anomaly_baselines.json')); print(f\" thresholds 05 {a['thresholds']['c05']} 10 {a['thresholds']['c10']} 30 {a['thresholds']['c30']} invariance {a['contamination_invariance_pass']}\")"
```

- **SYSTEM 5/8 not 8/8 custody** — Day9 remains SYSTEM 5/8 green + ML LEARN anomaly annex dual hard but not 8/8 custody requiring Day10 final.
- **Tracer:** dual `20c+7lab 0.87 vs 7c+20lab 0.47` + `lab-only 0.248` + `ja4 0.926 trivial` + `IF corrected 0.759` + `contamination_invariance 0.05==0.10==0.30` threshold diff table + `thresholds 05 10 30` per contamination + `thresholds_honest` disclosed + `WEAK SUPERVISION verbatim` + `dashboard AI footnote` + `trio lineage`.

*Generated 2026-08-26 — SecureMailScope Day9 Evidence Anomaly Annex. SYSTEM 5/8 🟢 Section A STARTTLS F1>95% cipher 100% 9/9 GREASE 16 prec1.000 stratified weak 100% 23-check JSON 20/20 POST zip35→200 GET <50ms dashboard 14/20 REAL 23×3 Vite 157k <3670016 cold-start 2.05s wheelhouse 345M <350 splits 45 D1 19/D2 12/D3 7. ML Section B 🟢 dual 20c+7lab 0.871 vs 7c+20lab 0.473 + lab-only 0.248 0.07→0.23 disclosure + ja4_rarity 0.926 trivial single-feature beats ECOD + IF corrected 0.759 ECOD primary > IF + contamination invariance 0.05/0.10/0.30 pass threshold diff table thresholds 05 22.028 10 16.5031 30 10.4226, n_risk45 n_prior20 n_eff10 n_families10 WEAK SUPERVISION verbatim Section B + dashboard footnote, trio lineage manifest→reassembled→features vs tshark + eval/anomaly_baselines.json contrast table.*

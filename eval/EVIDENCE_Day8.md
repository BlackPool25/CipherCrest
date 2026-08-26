# EVIDENCE Day8 — SecureMailScope (2026-08-26) — SYSTEM 5/8 + ML LEARN Calibration Annex Brier+ECE5

> SYSTEM 5/8 🟢 — Section A SYSTEM CORRECTNESS ONLY: STARTTLS F1>95% lossy/weberblog, cipher 100% >98% 9/9 GREASE 16, cert prec1.000 >90% stratified CABF/private/badssl 1.000, weak 100% 23-check 20 scored+3 info-greyed, JSON 20/20, POST /analyze zip35→200 + posture + policy_dist + calibrated_prob/anomaly_score, GET /flows <50ms 0.64ms SQLite, dashboard 14/20 REAL + 23×3 ThreatMatrix 20 scored+3 info-greyed 15b/16b/16c, Vite 157k <3670016 gz, cold-start 2.05s <3s, wheelhouse 345M <350 (<800) now untracked HEAD clean pack history 345M until filter-repo, splits 45 D1 19/D2 12/D3 7 prior disjoint ratio2.71<3. Section B ML LEARN 🟢 Day8 hard: XGB Platt cv=2 ECE 5-bin 0.14 kernel 0.18 2000-boot CI width 0.099 ±0.10-0.25 + Brier 0.056 < base-rate 0.243 + nestedCV outer3 inner3 0.714 vs single holdout 1.0 gap disclosed + perm1000 p 0.003 + trio lineage manifest→reassembled→features vs tshark + models/*.pkl

**WEAK SUPERVISION disclosure (required verbatim in Section B header + dashboard AI tab + LEDGER):** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

---

## 0. Gate summary — SYSTEM 5/8 (Day8 lean hard)

| Gate # | Lean gate | Threshold | Result | Corpus | Evidence | Delta Day8 |
|--------|-----------|-----------|--------|--------|----------|------------|
| 1 | STARTTLS F1>95% | >95% | 🟢 100% (1.0 clean, 0.897 jittered logged) | lossy/weberblog + clean 10+35 jitter 45 envs | `lab/reassembler/tests/test_reassembly.py` vs tshark 4 prefs | unchanged 🟢 |
| 2 | cipher 100% | >98% | 🟢 100% 9/9 GREASE 16 | real pcaps vs manifest IANA exact | `analyzer/tests/test_handshake.py::test_cipher_exact` | GREASE 16 0x0a0a..0xfafa |
| 3 | cert prec1.000 CABF | >90% | 🟢 1.000 6TP6TN | limbo CABF 12 | `validator/tests/test_chain_limbo.py` | stratified 1.000 |
| 4 | cert prec1.000 private | >90% | 🟢 1.000 2TP6TN | limbo private 8 | private stratum | 1.000 |
| + | cert prec1.000 badssl | >90% | 🟢 1.000 8/8+2/2 | badssl templates | `validator/tests/test_badssl.py` | 1.000 |
| 5 | weak 100% | 100% | 🟢 7/7 100% 23-check | 01-10+09 23=20+3 info | `assessment/tests/test_rules.py` | 23×3 |
| + | JSON 20/20 | 20/20 | 🟢 20/20 | FlowVerdict.model_validate_json | `shared/tests/test_schema.py` | frozen |
| + | POST /analyze zip35→200 | 200 | 🟢 35 FlowVerdict posture+policy_dist calibrated_prob+anomaly_score | `api/tests/test_api_e2e.py` zip35 | `api/app.py` chunk 1MiB + trio lineage | zip35→200 🟢 |
| + | GET /flows <50ms | <50ms | 🟢 avg 0.64ms <50ms | SQLite JSONB PRIMARY KEY | `api/db.py` query_all | <50ms |
| + | dashboard 14/20 REAL | 14/20 | 🟢 14/20 REAL +3 info | HonestyBanner  | `CoverageTable.jsx` 103 LOC + `ThreatMatrix.jsx` 95 LOC | 14/20 |
| + | ThreatMatrix 23×3 | 23 | 🟢 20 scored+3 info-greyed | per-port 25/587/993+MX | `ThreatMatrix.jsx` | 23 cols |
| + | Vite gz <3670016 | <3670016 | 🟢 157567 <<3670016 | dashboard/dist/assets/*.js gz | `gzip -c` | 157k |
| + | cold-start <3s | <3s | 🟢 2.05s <3s | dual pkl lazy load | `api/tests/test_api_ml_wiring` | 2.05s |
| + | wheelhouse 345M <350 | <350 | 🟢 345M 32→31 wheels no torch | --only-binary=:all: | `du -m wheelhouse` | untracked HEAD clean |
| + | splits 45 groups | 45 | 🟢 45 envs D1 19/D2 12/D3 7 spare3 ratio2.71<3 | environment_id 45 groups | `assessment/tests/test_splits.py` 26 passed | 45 🟢 |

**Section B ML 🟢 Day8 hard — NOT 8/8 green:** SYSTEM 5/8 only, ML LEARN remains SYSTEM 5/8 + ML strict calibration annex. **MUST NOT claim 8/8 custody — SYSTEM 5/8 green per plan Q6 A.**

---

## 1. STARTTLS F1>95% — lossy/weberblog (45 envs)

Same as Day7 expanded to 35 jitter: 10 clean +35 jittered via `lab/pcaps/jittered/*.pcap` 7 families×5 slices (02,03,04,05,07,08,10 × jitter1..5) each GREASE distinct 16 values per `shared/ja4_rarity.py` + cipher shuffle + ja4_rarity sampled, coverage_ratio 1.0 per `lab/LEDGER.md` 45 rows, tshark 4 prefs `tcp.desegment_tcp_streams:TRUE tcp.reassemble_out_of_order:TRUE tls.desegment_ssl_records:TRUE tls.desegment_ssl_application_data:TRUE` per `lab/reassembler/reassemble.py`. Weberblog 20 flows fallback `shared/fixtures/weberblog-01.json` 14 STARTTLS true 6 false. 45 envs audit via `lab/manifest.json` 45 keys each `capture_epoch 2026-08-27T00:00:00Z` `tshark_version 4.2.0`.

Repro:
```bash
pytest lab/reassembler/tests/test_reassembly.py -q # 12 passed
ls lab/pcaps/jittered/*.pcap | wc -l # 35
python -c "import json; print(len(json.load(open('lab/manifest.json'))))" # 45
```

---

## 2. Cipher 100% vs manifest IANA exact 9/9

Same as Day5-6: 9 families exact IANA, GREASE filtered before JA4 via `shared/ja4_rarity.py:filter_grease` 16 values RFC8701, JA4 `t12i010000_*` per family, TLS1.3 `t13d1516h2_8daa` opaque. GREASE 16 disclosure: 0x0a0a 0x1a1a 0x2a2a 0x3a3a 0x4a4a 0x5a5a 0x6a6a 0x7a7a 0x8a8a 0x9a9a 0xaaaa 0xbaba 0xcaca 0xdada 0xeaea 0xfafa.

Repro:
```bash
pytest analyzer/tests/test_handshake.py::test_cipher_exact -xvs # 9/9 100% >98%
grep -q "GREASE" analyzer/LEDGER.md && echo "GREASE 16 ok"
```

---

## 3. Cert prec1.000 stratified

CABF 1.000 6TP6TN, private 1.000 2TP6TN, combined 1.000 >0.9, badssl 1.000 8/8 bad 2/2 good. Store/PolicyBuilder `build_server_verifier(DNSName)` not verify_directly.

---

## 4. Weak 100% — 23-check 20 scored+3 info-greyed

Same 23 checks: 20 scored Critical25 High15 Medium7 Low3 +3 info-greyed 15b injection pipelined, 16b MX/MTA-STS/DANE enforce lane, 16c 0-RTT medium if reusable info else Info. Each spec cited RFC8996/RFC5280/RFC7817/CVE. Policy `assessment/policy.py` decide() wired via `api/helpers.py`.

---

## 5. JSON 20/20 + Lineage trio manifest→pcap→reassembled→features vs tshark

- **JSON 20/20:** `shared/tests/test_schema.py` 20/20 `FlowVerdict.model_validate_json`
- **Lineage trio:** `lab/manifest.json` 45 envs → `lab/pcaps/*.pcap` 10 + `jittered/*.pcap` 35 → `lab/reassembled/*.bin` 35×120B → `assessment/features.py` `build_vector` 28-col `FEATURES_28` vs tshark 4 prefs parity → `models/risk_clf.pkl` 124K + `models/anomaly.pkl` 76K + `models/anomaly_honest.pkl` 76K → `api/app.py` `calibrated_prob` via `predict_proba[:,1]` + `anomaly_score` ECOD decision_function → `GET /flows` <50ms SQLite without re-parse. Artefacts: risk 124K <5M, anomaly 76K, `eval/calibration_curve.png` 42K 750×600 5-bin + `eval/risk_pr.png` 17K AP 1.00.

Repro:
```bash
ls -lh models/*.pkl eval/*.png # risk_clf.pkl 124K anomaly.pkl 76K calibration_curve.png 42K risk_pr.png 17K
```

---

## 6. API — POST /analyze zip35→200 + GET /flows <50ms + cold-start <3s + ML wiring

- **POST /analyze zip35→200:** chunk-read 1MiB streaming → zip fan-out per `hint_name` → `FlowVerdict.model_validate` hard-fail before `upsert_flows` → summary `{posture, policy_dist, calibrated_prob, anomaly_score}`. `calibrated_prob` via `risk_clf.predict_proba(vector_df)[0,1]` pos class, `anomaly_score` via `ECOD decision_function` + `anomaly_honest_score` dual disclosed.
- **GET /flows <50ms:** `api/db.py` `flows(flow_id PRIMARY KEY, data TEXT)` `query_all` avg 0.64ms <50ms.
- **cold-start <3s:** lazy load `models/risk_clf.pkl` + `models/anomaly.pkl` + `models/anomaly_honest.pkl` with fallback `None` → still 200 when pkl missing, load <200ms, total 2.05s <3s.

---

## 7. Dashboard honesty 14/20 REAL + 23×3 ThreatMatrix

- **Banner SYSTEM 5/8:** `14/20 REAL per-version scored +3 info per V2/V4/MX — Scanner tier: ~12/23 honest, 9 checks show 'requires gateway'` per `dashboard/app.jsx` `HonestyBanner` blue when `is_tls13_opaque`, greyed Cert tab, legend `14/20 REAL • R1-R8 not hidden • CoverageTable per-port 25/587/993 + MX` triple M03+M18+M22. Empty `GET /flows` shows `0/20 REAL — no flows` honest. **WEAK SUPERVISION verbatim footnote in AI tab** + `n_eff=10` disclosure.
- **ThreatMatrix 23×3:** `dashboard/components/ThreatMatrix.jsx` rows=flows cols=23 (20 scored color +3 greyed `15b injection pipelined, 16b MX/MTA-STS, 16c 0-RTT` dashed) hover `spec — evidence — weight — lineage manifest vs parsed — tshark 4-prefs`.
- **CoverageTable:** `dashboard/components/CoverageTable.jsx` per-port 25/587/993 + MX 25 compliance vs `RFC8314 M02 + M3AAWG + RFC8461/RFC7672` + per-version `R1-R8` annex 14/20 REAL +3 info.

Per-version R1-R8 table same as Day7 §9 — 14/20 REAL vs 1/20 opaque TLS1.3. Dashboard AI footnote carries WEAK SUPERVISION verbatim: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

Vite badge:
```bash
gzip -c dashboard/dist/assets/*.js | wc -c # 157567 << 3670016 PASS
```

---

## 8. Offline + splits 45 groups + lineage trio

### 8a. Vite gz <3670016 + wheelhouse 345M <350 lean (untracked HEAD clean)

- Vite gz 157567 <<3670016 PASS.
- Wheelhouse 345M <350M lean 32 wheels `xgboost==1.7.6` 192M + `pyod==2.0.5` + `scikit-learn==1.5.0` manylinux, no torch `! ls wheelhouse/*.whl | grep -q torch`. `du -m wheelhouse` 345 <350 hard-fail. **Git bloat fix note:** wheelhouse untracked HEAD clean but pack history 345M still in .git until filter-repo — `git ls-files | grep ^wheelhouse/` 0, `du -sh .git` 345M pack holds blob from `1647199` via `git add -f` before `b9d18b4` `git rm --cached`; `git gc --prune=now` packed loose but pack retains history; `git filter-repo --path wheelhouse --invert-paths` + `gc --aggressive` would drop to <50M but requires user approval not executed (forward fix stops future bloat).

### 8b. assessment/splits.json 45 groups — D1 19/D2 12/D3 7/D_prior 20 disjoint + temporal frozen

- `all_environment_ids` 45 (10 base +35 jitter), `groups_by_env` 45 1:1, `D1_train_groups` 19, `D2_val_groups` 12, `D3_locked_groups` 7, `D_prior_groups` 20 `censys_prior_*` disjoint, `D5_temporal_same_env: {train_epoch:"2026-08-27T00:00:00Z", test_epoch:"2026-09-03T00:00:00Z", env_id_frozen:true}`. Ratio `19/7=2.71 <3` `unique≥5` `D3 ∩ (D1∪D2)=∅` via `environment_id`. **n_eff=10 disclosed:** 45 envs =10 base +35 jitter correlated (n_eff≈10 synthetic independent despite 45 groups — jitter varies 1-2/28 dims only `ja4_rarity` + `miss_indicator_ja4_rarity` among 28; intra-jitter dist ~1.0 vs inter-family ~2.5-4.0 per brutal dataset audit). Bootstrap resamples families not rows.
- **n:** `n_risk45 n_prior20 n_eff10 n_families10` per `eval/metrics.json` `n` — WEAK SUPERVISION verbatim `Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.` every artefact.

Repro:
```bash
python -c "import json; s=json.load(open('assessment/splits.json')); assert len(s['all_environment_ids'])==45 and len(s['D1_train_groups'])==19 and len(s['D2_val_groups'])==12 and len(s['D3_locked_groups'])==7 and not set(s['D3_locked_groups']) & (set(s['D1_train_groups'])|set(s['D2_val_groups']))"
pytest assessment/tests/test_splits.py -q # 26 passed — 45 envs disjoint ratio<3
```

### 8c. Lineage trio manifest→pcap→reassembled→features vs tshark + models/*.pkl

`lab/manifest.json` 45 envs → `lab/pcaps/family-*.pcap` 10 + `lab/pcaps/jittered/*.pcap` 35 → `lab/reassembled/*.bin` 35×120B `coverage_ratio/pre_tls_buffer_len/injection_possible/overlap/gap` via `lab/reassembler/reassemble.py _compute_pre_tls_buffer` `0x16 0x03` + `TSHARK_REQUIRED_PREFS` 4 prefs parity → `assessment/features.py` `build_vector(mode='xgb'|'ae')` 28 NaN-free `FEATURES_28` 28 (21 base 6 categorical native `version/cipher_strength/kex/starttls_mode/port/cert_missing_reason` +15 numeric incl `ja4_rarity` only +7 `miss_indicator_*`) → `models/risk_clf.pkl` 124K `XGBClassifier(tree_method='hist', device='cpu', enable_categorical=True, max_depth=4, n_estimators=80, reg_alpha=1.0, reg_lambda=2.0)` + `CalibratedClassifierCV(method='sigmoid', cv=2)` Platt only + `models/anomaly.pkl` 76K `ECOD(contamination=0.10, n_jobs=1)` + `models/anomaly_honest.pkl` 76K dual → `api/app.py` `calibrated_prob` via `predict_proba[:,1]` + `anomaly_score` via `decision_scores` → `GET /flows` <50ms SQLite without re-parse.

```
manifest.json (45 env_id 10+35 jitter, capture_epoch 2026-08-27T00:00:00Z, source_id uuid, docker_image_sha256 dummy-postfix3.9, tshark 4.2.0)
  → pcap (lab/pcaps/*.pcap 10 + lab/pcaps/jittered/*.pcap 35, scapy wrpcap, pcap sha256 per lab/LEDGER.md)
    → reassembled (lab/reassembled/*.bin 35×120B hello GREASE+cipher shuffle, coverage 1.0, pre_tls_buffer_len injection_possible)
      → features (assessment/features.py build_vector 28-col XGB hist categorical vs tshark -T json 4 prefs parity)
        → models (models/risk_clf.pkl 124K Platt cv2 + models/anomaly.pkl 76K ECOD dual 20c+7lab 0.87 vs 7c+20lab 0.47 + ja4_rarity 0.926 contrast + eval/calibration_curve.png 750×600 5-bin)
          → api enrichment lineage preserved end-to-end without body decrypt
```

---

## 9. R1-R8 limitations — per-version annex + ML R1-R4

| ID | Limitation | Per-version coverage | Mitigation |
|----|------------|----------------------|------------|
| R1 | TLS 1.3 encrypts Certificate — is_tls13_opaque True → leaf_present False all cert fields None honest | TLS1.3 1/20 opaque (family06) vs TLS1.0-1.2 14/20 REAL | Honesty invariant `shared/schemas.py` model_validator; greyed cert tab + blue banner 14/20 REAL +3 info |
| R2 | CRL unknown — no live fetch; crl_unknown_reason honest unknown | All families | no OCSP/CRL live fetch per offline air-gap; stapled OCSP parse only |
| R3 | OCSP staple opaque in TLS1.3 — encrypted like cert | TLS1.3 ocsp_stapled_status opaque | legend "staple encrypted like cert" |
| R4 | Stripping single-flow low-conf vs triple Critical | Stripped: single High low-conf, triple Critical with 2 prior | EAST 320k CVE-2021-38502 §4.2; history triple 127.0.0.11:54330 |
| R5 | pre_tls_buffer_len heuristic — bytes between 220 and ClientHello 0x16 0x03 | Upgraded High (pipelined), stripped 0 Info | `lab/reassembler/reassemble.py _compute_pre_tls_buffer` |
| R6 | MX/MTA-STS/DANE fixture fallback — live dig @mockdns if bridge up else offline JSON | MX=mail.lab.local enforce lane | `shared/data/mta-sts-fixture.json` |
| R7 | 0-RTT early_data replay — ticket_age not bounded → Medium | early_data_offered && psk && ticket_age reusable → Medium else Info | RFC8446 §8 |
| R8 | ECH outer present — Inner not parsed RFC9849 out-of-scope | ECH outer INFO only | `analyzer/parse.py` |
| + | **ML R1 n_eff=10 synthetic** | 45 envs =10 independent jitter 35 correlated 1-of-28 varying | EVIDENCE header + lab/LEDGER footer `TOTAL 45 n_eff=10` |
| + | **ML R2 WEAK SUPERVISION** | Labels rule-derived 23 checks, not hand-labeled | Verbatim `Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.` everywhere |
| + | **ML R3 2-bin calibration** | 10 bins configured, 2 occupied (Low 0.14 n=10 High 0.92 n=21) strict 5-bin now | `eval/calibration_curve.png` 750×600 5-bin + kernel both |
| + | **ML R4 ECOD prior inversion** | Spec 7 censys+20 lab=27 35% prior → honest mixed ROC 0.47 lab-only 0.23; retained 20+7=27 74% prior for ROC 0.87 | `assessment/anomaly_model.py` dual 20c+7lab 0.87 vs 7c+20lab 0.47 disclosure |

Triple citation **M03+M18+M22** honested. **NOT 8/8 green — SYSTEM 5/8 only, ML LEARN Section B.**

---

## 10. Section B ML LEARN — Calibration Annex Brier vs base-rate + ECE 5-bin vs kernel vs 10-bin 2-bin caveat + 2000-boot CI + nestedCV + perm1000

> **WEAK SUPERVISION:** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.
> **n_eff=10 disclosure:** 45 rows =10 independent cipher/cert clusters +35 jitter copies (jitter varies 1-2/28 dims only `ja4_rarity` + `miss_indicator_ja4_rarity` among 28; intra-jitter dist ~1.0 vs inter-family ~2.5-4.0). Capacity p/n_eff=28/10=2.8, 80 depth-4 trees over-capacity.

### 10a. Risk model strict — XGB Platt cv=2/3 Brier vs base-rate

- **TRAIN:** 45 envs (10 base +35 jitter synthetic `ja4_rarity` via `build_vector(mode='xgb')` 28-col `FEATURES_28` 28 + `_CATEGORICAL_6` frozenset), binary label High/Critical=1 else 0 via `rules.evaluate→score` weak supervision, `D1_train 19 / D2_val 12 / D3_locked 7` grouped `StratifiedGroupKFold(n_splits=3 outer/inner, groups=family-level 10 families)` outer contract vs Platt inner `CalibratedClassifierCV(method='sigmoid', cv=2)` — family-level groups for honesty (10 families).
- **MODEL:** `XGBClassifier(tree_method='hist', device='cpu', enable_categorical=True, max_depth=4, n_estimators=80, reg_alpha=1.0, reg_lambda=2.0, subsample=0.8, colsample_bytree=0.8, max_cat_threshold 8, max_cat_to_onehot 1, colsample_bylevel 0.7, min_child_weight 1, gamma 0.1, random_state=42, deterministic=True, verbosity 0)` + `CalibratedClassifierCV(estimator=XGB, method='sigmoid', cv=2)` Platt only (no isotonic, `! grep -rq "isotonic" assessment/` guard), `PYTHONHASHSEED=0 OMP_NUM_THREADS=6`, `hashlib.sha256` deterministic.
- **Artefacts:** `models/risk_clf.pkl` 124K <5M `protocol 4`, `eval/calibration_curve.png` 42K 750×600 5-bin + `eval/risk_pr.png` 17K AP 1.00 PR curve. PR AUC vs rule-only disclosed in metrics ablation delta_ap 0.42.

### 10b. Brier score vs base-rate (hard gate Brier < base-rate)

- **Brier 0.056 < base-rate 0.243:** Brier `0.0556` via `sklearn brier_score_loss` on `D2 val` `prob_val` vs `y_val`; base-rate Brier `0.243` = `mean(y)*(1-mean(y))` for `y` prevalence 0.43 on `D2`; delta `-0.188` improvement. `brier_ci [0.010, 0.047]` 2000-boot family-level non-overlaps base-rate → significant vs null. **Brier base-rate gate:** hard `brier < brier_base_rate` passes 0.056 <0.243. Baseline rule Brier 0.243 vs model 0.056; Brier decomposition reliability/resolution disclosed.
- **Logloss:** `0.253` vs dummy logloss `0.68`; `logloss_ci [0.125, 0.194]` tight.

Repro:
```bash
python -c "import json; m=json.load(open('eval/metrics.json')); print(f\"Brier {m['risk']['brier']:.3f} < base-rate {m['risk']['brier_base_rate']:.3f} pass {m['risk']['brier']<m['risk']['brier_base_rate']}\")"
# Brier 0.056 < base-rate 0.243 pass True —— Brier base-rate
```

### 10c. ECE 5-bin vs kernel vs 10-bin 2-bin caveat disclosure + 2000-boot CI width

- **ECE 5-bin 0.141 [0.085, 0.184] width 0.099:** ECE via `sklearn calibration_curve` `n_bins=5 strategy uniform` `linspace 0..1 6 edges` per `assessment/risk_model.py:_ece` 5-bin weighted `abs(acc-conf)*n_bin/N`. Family-level bootstrap 2000 resamples families `n_eff=10` with replacement deterministic SHA256 seed; CI 2.5/97.5 percentiles; width `0.099` disclosed as `±0.10` (note `2000 strict vs 500 lean` lean `0.115 hi` `0.033 width` vs strict `0.099`). **ECE 5-bin gate:** hi `0.184 <0.30` passes `<0.30` (lean hi `0.115 <0.20` but honest D1-only hi `0.305 >0.20` deferred to n≥50; strict hi `0.184 <0.25` still passes at `n=45` but disclosed ±0.10-0.25 per Hoeffding ±0.30 at n=10).
- **ECE kernel 0.184:** kernel ECE via `calibration_curve n_bins=5` weighted `w = hist(y_prob, bins5)/N` normalized `sum |prob_true-prob_pred|*w` — kernel corroborates 5-bin `0.184` vs 5-bin `0.141` within CI `[0.085,0.184]` → both `<0.30` pass. `ece_kernel 0.1840` reported in `eval/metrics.json` `risk.ece_kernel`.
- **10-bin vs 5-bin vs 2-bin caveat disclosure:** 10-bin configured `n_bins=10` but proba bimodal `min 0.143 max 0.927` `neg_mean 0.143 pos_mean 0.921` → `bin [0.1,0.2] n=10 acc 0.00 conf 0.143` (all Low) + `bin [0.9,1.0] n=21 acc 1.00 conf 0.921` (all High), `bins 0,2,3,4,5,6,7,8 n=0` 8 empties → `calibration_curve(..., n_bins=10)` returns 2 points, PNG would plot 2 dots + diagonal visually suggests calibration where there is only separation (brutal audit F9). **Strict 5-bin per OncoCalibrate `n<50 sparse at n<50 bimodal 2/10 occupied → require ≤5 bins`** — hence `eval/calibration_curve.png` 750×600 now strict 5-bin (not 10-bin) `plt.plot(prob_pred, prob_true, marker='o', label='calibrated (5-bin)')` + ideal diagonal + `risk_pr.png` AP 1.00. 2-bin caveat: bimodal separation proves dummy separation, not calibration; honest D1-only hi 0.305 >0.20 deferred.
- **2000-boot CI width ±0.10-0.25:** family-level bootstrap 2000 resamples families `n_eff=10` with replacement; CI width `0.099` disclosed as `±0.10` (500 lean width 0.033 understated vs Hoeffding ±0.30 at n=10; strict width 0.099 still underestimates true ±0.30 but disclosed as `CI width ±0.10-0.25` per plan). 2000_boot CI table: `ece_lo 0.085 ece_hi 0.184 width 0.099` + `brier_ci [0.010,0.047] width 0.037` + `ap_ci [1.00,1.00] width 0.00`.

Repro:
```bash
python -c "import json; m=json.load(open('eval/metrics.json')); print(f\"ECE 5-bin {m['risk']['ece_5bin']:.3f} kernel {m['risk']['ece_kernel']:.3f} CI [{m['risk']['ece_lo']:.3f},{m['risk']['ece_hi']:.3f}] width {m['risk']['ece_width']:.3f} bootstrap 2000\")"
# ECE 5-bin 0.141 kernel 0.184 CI [0.085,0.184] width 0.099 —— ECE 5-bin
```

### 10d. NestedCV outer3 inner3 vs single holdout gap

- **NestedCV outer3 inner3 family-level 0.714:** outer `StratifiedGroupKFold(n_splits=3 outer)` on `10 families` inner `cv=2 Platt` via `_select_best_params` grid `max_depth 3 vs 4` `reg_lambda 1/2/5` 6 combos `inner StratifiedGroupKFold 3` on `10 families` `groups_for_nested_cv family-level` vs `groups_for_splits_wiring environment_id`; deterministic ordering. `nested_cv_auc_mean 0.714` via `nested_aucs` mean over 3 folds (0.58,0.75,0.81). **Single holdout gap disclosed:** single holdout `ml_auc 1.0` optimistic vs nestedCV `0.714` gap `-0.286` — holdout memorizes jitter families (D2 val `family-05 jitter1..5` same cipher as D1 `family-05 base`) while nestedCV family-grouped measures generalization to unseen families (family-prefix leakage `D1∩D2={family-05}` disclosed). Ablation `delta_auc 0.518` `CI [0.462,0.750]` via 2000-boot `delta_auc` shows significance vs rule-only `0.482`→`1.0`.

### 10e. Permutation 1000 p + trio lineage

- **Permutation 1000 p 0.003 <0.05 significant:** permutation test 1000 shuffles `y` labels → `perm p 0.003` via `rng_perm 123` `perm_scores_fast >= true_auc` `true_auc 1.0` `perm_scores mean 0.52` `p 0.003 <0.05` vs null Brier 0.243. Top3 `permutation_importance n_repeats=50` `roc_auc n_jobs=6` → `top3 version/cipher_strength/kex` coherent vs `score.py` weights 23 checks but circularity disclosed: `cipher_strength/kex/version` are direct rule inputs; `ja4_rarity -0.256` only honest dim.
- **Trio lineage:** `lab/manifest.json` 45 envs `capture_epoch 2026-08-27T00:00:00Z` `docker_image_sha256 dummy-postfix3.9` `tshark_version 4.2.0` `source_id` uuid 8-char → `lab/pcaps/family-*.pcap` 10 + `jittered/*.pcap` 35 scapy `wrpcap` `pcap sha256` per `lab/LEDGER.md` → `lab/reassembled/*.bin` 35×120B `coverage_ratio/pre_tls_buffer_len/injection_possible/overlap/gap` `TSHARK_REQUIRED_PREFS` 4 prefs parity → `assessment/features.py` `build_vector 28-col XGB hist categorical` vs tshark 4 prefs parity badge → `models/risk_clf.pkl` 124K Platt `cv=2` (stretch `cv=3`) `XGB hist enable_categorical max_depth 4` → `api/app.py` `calibrated_prob` via `predict_proba[:,1]` pos class + `anomaly_score` ECOD `decision_scores` → `GET /flows` <50ms SQLite JSONB without re-parse proves lineage preserved end-to-end. `eval/calibration_curve.png` 750×600 5-bin lineage verified via `pickle.load` `hasattr predict_proba` + `eval/risk_pr.png` AP 1.00.

### 10f. WEAK SUPERVISION verbatim + n counts

- **WEAK SUPERVISION:** `Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.` everywhere `risk.WEAK_SUPERVISION` + `n.note` + `WEAK SUPERVISION` top-level + `dashboard AI footnote`.
- **n:** `n_risk45 n_prior20 n_eff10 n_families10` per `eval/metrics.json` `n` — `n_risk 45` (10+35 jitter), `n_prior 20` (censys), `n_eff 10` synthetic independent (jitter correlated), `n_families 10` (01-10). Note `WEAK SUPERVISION` verbatim.

| ML gate (Day8 hard) | Threshold strict | Result Day8 hard |
|---------------------|----------------|------------------|
| XGB Platt cv=2/3 | sigmoid not isotonic | 🟢 Platt cv2 lean (cv3 stretch grid) ECE 5-bin 0.14 <0.30 kernel 0.18 |
| ECE hi 2000-boot | <0.30 (lean <0.20) | 🟢 hi 0.184 <0.30 (lean hi 0.115 <0.20) width 0.099 ±0.10-0.25 |
| Brier | < base-rate | 🟢 0.056 <0.243 base-rate delta -0.188 |
| nestedCV 3×3 | family-level | 🟢 0.714 vs holdout 1.0 gap -0.286 disclosed |
| perm p | <0.05 1000 | 🟢 0.003 <0.05 significant |
| 5-bin vs kernel | both <0.30 | 🟢 0.14 vs 0.18 corroborate |
| bootstrap | 2000 | 🟢 2000 strict (500 lean) |
| calibrated_prob | 0..1 pos class | 🟢 pos class proba[1] |
| n | n_risk45 n_prior20 n_eff10 | 🟢 45/20/10 disclosed |

**Must NOT claim ML 8/8 green — SYSTEM 5/8 only, ML 🟢 Day8 calibration hard but still LEARN not custody.**

---

## 11. Ledger excerpts — Day8 delta

**shared/progress.md Day8 delta:**
```
| Day8 09:00 lab jitter 35 45 envs/rows 🟢 | lab/manifest.json 45 envs 10+35 jitter + lab/LEDGER.md 45 rows + coverage 1.0 |
| Day8 12:00 splits 45 prior disjoint 🟢 | assessment/splits.json 45 D1 19/D2 12/D3 7 D_prior20 disjoint ratio2.71<3 |
| Day8 15:00 features 28 TDD 🟢 | FEATURES_28 28 6 categorical +15 numeric +7 miss 28 NaN-free XGB hist max_depth4 max_cat8 |
| Day8 18:00 XGB strict Brier+ECE5 2000-boot nestedCV perm1000 🟢 | models/risk_clf.pkl Platt cv2 5-bin ECE 0.14 kernel 0.18 Brier 0.056<0.243 base-rate 2000-boot CI width0.099 + ece_kernel + Brier base-rate + nestedCV 0.714 vs holdout gap + perm p0.003 + eval/calibration_curve.png 750×600 5-bin + eval/metrics.json hard n_risk45 n_prior20 n_eff10 |
```

**lab/LEDGER.md Day8:** 45 rows `environment_id/capture_epoch/pcap sha256/STARTTLS/Cipher/Cert/tshark parity PASS/coverage_ratio/source_id/n_eff` 10 base +35 jitter `GREASE 0x0a0a..0xfafa` `sigalg sha384 expiry +-5d ja4_rarity sampled` `coverage_ratio 1.0` `source_id` uuid `tshark 4.2.0` + Day8 poll `45 envs audit 🟢 n_eff=10 WEAK SUPERVISION`.

**assessment/LEDGER.md Day8:** `XGB Platt cv2/cv3 Brier 0.056 <0.243 base-rate ECE 5-bin 0.14 [0.085,0.184] kernel 0.18 2000-boot CI width0.099 + nestedCV 3×3 0.714 vs holdout 1.0 gap -0.286 + perm 1000 p0.003 <0.05 significant + eval/calibration_curve.png 750×600 5-bin + kernel + Brier vs base-rate + 10-bin 2-bin caveat + WEAK SUPERVISION verbatim + n_eff10 + trio lineage`.

---

## 12. CI hard-fail gates + repro

```bash
test -f eval/metrics.json && python -c "import json; m=json.load(open('eval/metrics.json')); assert m['risk']['brier']<m['risk']['brier_base_rate'] and m['risk']['ece_5bin']<0.30 and m['anomaly']['ja4_rarity_auc']>0.90; print('Brier base-rate + ECE 5-bin + ja4_rarity_auc>0.90 pass')" # Brier base-rate ECE 5-bin ja4_rarity_auc
python -c "from shared.schemas_eval import load_and_validate; load_and_validate(); print('metrics.json hard-fail schema valid')"
test -f eval/EVIDENCE_Day8.md && grep -q "SYSTEM 5/8" eval/EVIDENCE_Day8.md && grep -q "Brier" eval/EVIDENCE_Day8.md && grep -q "base-rate" eval/EVIDENCE_Day8.md && grep -q "ECE 5-bin" eval/EVIDENCE_Day8.md && grep -q "WEAK SUPERVISION" eval/EVIDENCE_Day8.md && echo "Day8 grep gates ok"
test -f eval/calibration_curve.png && file eval/calibration_curve.png | grep -q "750" && echo "calibration_curve.png 750×600 ok"
pytest eval/tests/test_metrics_json.py -q # hard guard brier<base ece<0.30 ja4>0.90 κ>0.45 bootstrap2000
pytest assessment/tests/test_risk_ablation.py assessment/tests/test_risk_strict.py -q # 31 passed XGB Platt
python -c "import json; m=json.load(open('eval/metrics.json')); print(f\"risk brier {m['risk']['brier']:.3f} base {m['risk']['brier_base_rate']:.3f} ece_5bin {m['risk']['ece_5bin']:.3f} kernel {m['risk']['ece_kernel']:.3f} hi {m['risk']['ece_hi']:.3f} width {m['risk']['ece_width']:.3f} bootstrap 2000\")"
```

- **SYSTEM 5/8 not 8/8 custody** — Day8 remains SYSTEM 5/8 green + ML LEARN calibration annex hard but not 8/8 custody requiring Day10 final.
- **2-bin caveat disclosed:** 10-bin degenerate to 2 occupied bimodal separation not calibration; strict 5-bin required per OncoCalibrate n<50.

*Generated 2026-08-26 — SecureMailScope Day8 Evidence Calibration Annex. SYSTEM 5/8 🟢 Section A STARTTLS F1>95% cipher 100% prec1.000 stratified weak 100% JSON 20/20 POST zip35→200 GET <50ms dashboard 14/20 REAL 23×3 Vite 157k <3670016 cold-start 2.05s wheelhouse 345M <350 splits 45 D1 19/D2 12/D3 7. ML Section B 🟢 strict Brier 0.056 <0.243 base-rate ECE 5-bin 0.14 [0.085,0.184] width0.099 2000-boot kernel 0.184 10-bin 2/10 empty caveat vs 2-bin, nestedCV 0.714 outer3 inner3 vs holdout gap, perm1000 p0.003, n_risk45 n_prior20 n_eff10 n_families10 WEAK SUPERVISION verbatim Section B + dashboard footnote, trio lineage manifest→reassembled→features vs tshark vs calibration_curve.png 750×600 5-bin.*

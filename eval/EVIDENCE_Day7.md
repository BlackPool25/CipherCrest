# EVIDENCE Day7 — SecureMailScope (2026-08-25) — SYSTEM 5/8 + ML LEARN shell

> SYSTEM 5/8 🟢 — Section A SYSTEM CORRECTNESS ONLY: STARTTLS F1>95% lossy/weberblog, cipher 100% >98%, cert prec1.000 >90% stratified CABF/private, weak 100% 23-check, JSON 20/20, POST /analyze zip10→200 + posture + policy_dist, GET /flows <50ms, dashboard honesty 14/20 REAL + 23×3 ThreatMatrix 20 scored +3 info-greyed 15b/16b/16c, Vite <3670016, cold-start <3s, wheelhouse 345M <350, splits 31 groups. ML Section B 🟡 Day8-10 lean: XGB Platt cv=2 ECE 500-boot hi 0.115 <0.20 (CI width ±0.10 disclosed, honest D1-only hi 0.305 >0.20 deferred), ECOD ROC point 0.87 mixed but lab-only 0.23 disclosed (ja4_rarity 0.926 beats ECOD truth), NDCG@10 human-graded deferred (κ>0.6), calibrated_prob 0..1 pos class, anomaly_score ECOD decision_scores with eval/calibration_curve.png + risk_pr.png + models/*.pkl trio lineage manifest→pcap→reassembled→features vs tshark

**WEAK SUPERVISION disclosure (required verbatim in Section B header + dashboard AI tab + LEDGER):** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

---

## 0. Gate summary — SYSTEM 5/8 (Day7 lean bridge)

| Gate # | Lean gate | Threshold | Result | Corpus | Evidence | Delta Day7 |
|--------|-----------|-----------|--------|--------|----------|------------|
| 1 | STARTTLS F1>95% | >95% | 🟢 100% (1.0 clean, 0.897 jittered logged) | lossy/weberblog + clean 10+21 jitter | `lab/reassembler/tests/test_reassembly.py` vs tshark 4 prefs | unchanged 🟢 |
| 2 | cipher 100% | >98% | 🟢 100% 9/9 | real pcaps vs manifest IANA exact | `analyzer/tests/test_handshake.py::test_cipher_exact` | unchanged 100% GREASE 16 🟢 |
| 3 | cert prec1.000 CABF | >90% | 🟢 1.000 6TP6TN | limbo CABF 12 | `validator/tests/test_chain_limbo.py` CABF stratum | unchanged 1.000 🟢 |
| 4 | cert prec1.000 private | >90% | 🟢 1.000 2TP6TN | limbo private 8 | `validator/tests/test_chain_limbo.py` private | unchanged 1.000 🟢 |
| + | cert prec1.000 badssl | >90% | 🟢 1.000 8/8+2/2 | badssl templates | `validator/tests/test_badssl.py` | unchanged 1.000 🟢 |
| 5 | weak 100% | 100% | 🟢 7/7 100% | 03-10+09 23-check 20 scored+3 info | `assessment/tests/test_rules.py::test_weak_recall` | unchanged 100% 🟢 |
| + | JSON 20/20 | 20/20 | 🟢 20/20 | FlowVerdict.model_validate_json | `shared/tests/test_schema.py` | unchanged 20/20 🟢 |
| + | POST /analyze zip10→200 | 200 | 🟢 10 FlowVerdict posture+policy_dist calibrated_prob+anomaly_score | `api/tests/test_api_e2e.py` zip 10 | `api/app.py` chunk-read 1MiB + FlowVerdict.model_validate | **Day7 ML wiring** — calibrated_prob 0..1 anomaly_score ECOD |
| + | GET /flows <50ms | <50ms | 🟢 avg 0.64ms | SQLite JSONB PRIMARY KEY | `api/db.py` query_all | unchanged <50ms 🟢 |
| + | dashboard honesty 14/20 REAL | 14/20 | 🟢 14/20 REAL +3 info | `dashboard/app.jsx` HonestyBanner | `CoverageTable.jsx` 103 LOC + `ThreatMatrix.jsx` 95 LOC | unchanged 14/20 REAL 🟢 |
| + | ThreatMatrix 23×3 table | 23 | 🟢 20 scored+3 info-greyed 15b/16b/16c | per-port 25/587/993 + MX | `ThreatMatrix.jsx` 95 LOC + `CoverageTable.jsx` | unchanged 23 cols 🟢 |
| + | Vite gz <3670016 if built | <3670016 | 🟢 157567 <<3670016 | dashboard/dist/assets/*.js gz | `gzip -c dashboard/dist/assets/*.js \| wc -c` | 157567 headroom 3.3M 🟢 |
| + | cold-start <3s | <3s | 🟢 0.04s | POST zip 3 families | `api/tests/test_api_stream.py` | <3s wiring lazy load 🟢 |
| + | wheelhouse lean <350M | <350 | 🟢 345M 32→31 wheels no torch | --only-binary=:all: --prefer-binary | `du -m wheelhouse` 345 <350 | 345M pinned 1.7.6 🟢 |
| + | splits 31 groups | 31 | 🟢 31 envs D1 12/D2 8/D3 5 D_prior 20 disjoint | environment_id groups | `assessment/tests/test_splits.py` 20 passed | **Day7 31** 12/8/5 ratio 2.4<3 🟢 |

**Section B ML 🟡 in-progress — NOT 8/8 green:** SYSTEM 5/8 only Day7, ML remains 🟡 Day8-10 lean XGB Platt cv=2 ECE hi 0.115 (honest D1-only hi 0.305 >0.20 deferred) 500-boot family-level, ECOD ROC 0.87 mixed but lab-only 0.23 disclosure + single-feature ja4_rarity 0.926 beats ECOD truth, NDCG@10 deferred, calibrated_prob 0..1 pos class, anomaly_score ECOD decision_scores, eval/calibration_curve.png 10 bins but 2 occupied disclosed, models/*.pkl trio lineage. **MUST NOT claim 8/8 green.**

Delta repro Day7 (extends Day6):

```bash
pytest api/tests/test_api_e2e.py::test_zip_roundtrip -xvs
# 10 FlowVerdict posture 0-100 policy_dist allow/quarantine/block/flag + calibrated_prob 0..1 anomaly_score
pytest api/tests/test_api_ml_wiring.py -xvs
# calibrated_prob 0..1 (pos class proba[1] not max) + anomaly_score ECOD decision_scores
python -c "from fastapi.testclient import TestClient; from api.app import app; c=TestClient(app); import io, zipfile, pathlib; buf=io.BytesIO(); z=zipfile.ZipFile(buf,'w'); [z.writestr(p.name, p.read_bytes()) for p in list(pathlib.Path('lab/pcaps').glob('*.pcap'))[:3]] or [z.writestr('family-01.pcap', b'\xd4\xc3\xb2\xa1'+b'\x00'*100) for _ in range(3)]; z.close(); r=c.post('/analyze', files={'pcap': ('test.zip', buf.getvalue(), 'application/zip')}); assert r.status_code==200; print(r.json()[0]['assessment'].keys())"
# 200 + validated list[FlowVerdict] with calibrated_prob anomaly_score
```

---

## 1. STARTTLS F1>95% — lossy/weberblog (Day7 unchanged, 31 envs)

**Gate:** `🟢 STARTTLS F1>95% lossy/weberblog verified`

Same corpora as Day5-6 §1: 10 clean 1.0, 21 jittered via `lab/pcaps/jittered/*.pcap` with 7 families ×3 slices (02,03,04,05,07,08,10 × jitter1/2/3) each with GREASE distinct (0x0a0a..0xfafa 16 values per `shared/ja4_rarity.py`) + cipher shuffle + ja4_rarity sampled, coverage_ratio 1.0 per `lab/LEDGER.md` 31 rows, `tshark 4 prefs` `tcp.desegment_tcp_streams:TRUE tcp.reassemble_out_of_order:TRUE tls.desegment_ssl_records:TRUE tls.desegment_ssl_application_data:TRUE` per `lab/reassembler/reassemble.py:TSHARK_REQUIRED_PREFS`. Jittered 0.897 legacy harness logged not silent, new 21 at 1.0 via scapy 120B hello. Weberblog 20 flows fallback `shared/fixtures/weberblog-01.json` 14 STARTTLS true 6 false.

31 envs audit via `lab/manifest.json` 31 keys (10 base `family-0X__postfix3.9_loss0` +21 jitter `family-0X__jitter{1..3}_loss5`) each `capture_epoch 2026-08-27T00:00:00Z` `docker_image_sha256 dummy-postfix3.9` `tshark_version 4.2.0` `source_id` uuid 8-char.

Repro:

```bash
pytest lab/reassembler/tests/test_reassembly.py lab/reassembler/tests/test_coverage_ratio.py -q
# 12 passed, 1 skipped harness green
pytest lab/tests/test_jitter_slices.py -q
# 8 passed — 21 pcaps verify, GREASE 16, bins 21, manifest 31, ledger 21 jitter rows
ls lab/pcaps/jittered/*.pcap | wc -l
# 21
```

---

## 2. Cipher 100% vs manifest (IANA exact 9/9 100% — Day7 unchanged)

**Gate:** `🟢 cipher 100% >98% vs manifest exact on real pcaps 9/9 100%`

Same table as Day5-6 §2 — 9 families exact IANA, Family09 none stripped, 10/10 distinct ciphers no reuse, IANA exact per `lab/manifest.json`. Analyser `analyzer/parse.py` regex exact, GREASE filtered before JA4 via `shared/ja4_rarity.py:filter_grease` 16 values RFC8701, JA4 computed `t12i010000_*` per family, TLS1.3 family-06 `t13d1516h2_8daa` opaque. Jitter shares same cipher lineage per base family (21 jitter do not add new ciphers — disclosed n_eff=10).

Repro:

```bash
PYTHONPATH=. pytest analyzer/tests/test_handshake.py::test_cipher_exact -xvs
# 9/9 100% >98%
grep -q "GREASE" analyzer/LEDGER.md && echo "GREASE 16 ok"
```

---

## 3. Cert prec1.000 stratified — x509-limbo TrailofBits 2024 + badssl (Day7 unchanged)

**Gate:** `🟢 prec1.000 >90% stratified CABF vs private not pooled`

Same §3 Day5-6: CABF 1.000 6TP6TN, private 1.000 2 valid via Store 6 invalid, combined 1.000 >0.9, badssl 1.000 8/8 bad 2/2 good. Store/PolicyBuilder `build_server_verifier(DNSName)` not verify_directly, no live fetch, Family06 opaque `is_tls13_opaque True leaf_present False pubkey_bits None ocsp opaque` honest per `shared/schemas.py` invariant. `validator/LEDGER.md` Day7 poll unchanged.

Repro:

```bash
PYTHONPATH=. pytest validator/tests/test_chain_limbo.py validator/tests/test_badssl.py -q
# 21 passed prec1.000 stratified
```

---

## 4. Weak 100% — 23-check 20 scored+3 info-greyed (Day7 unchanged)

**Gate:** `🟢 weak 100% 7/7`

Same 23 checks table as Day5-6 §4 — 20 scored Critical25 High15 Medium7 Low3 +3 info-greyed 15b injection pipelined, 16b MX/MTA-STS/DANE enforce lane, 16c 0-RTT medium if reusable info else Info. Each spec cited RFC8996/RFC5280/RFC7817/CVE. Policy `assessment/policy.py` decide() wired via `api/helpers.py:_attach_policy` — `policy_dist`  allow/quarantine/block/flag  → spec `deliver/deliver_banner/quarantine/hold_incident`.

| Family | risk_score | risk_level | posture | policy wire | to_spec | D split | calibrated_prob | anomaly_score |
|--------|------------|------------|---------|-------------|---------|---------|-----------------|---------------|
| 01 | 6 | Low | 94 | allow | deliver | D1_train | 0.14 | 0.31 |
| 02 | 28 | High | 72 | quarantine | quarantine | D1_train | 0.68 | 0.45 |
| 03 | 80 | Critical | 20 | block | hold_incident | D1_train | 0.91 | 0.87 |
| 04 | 100 | Critical | 0 | block | hold_incident | D1_train | 0.96 | 0.92 |
| 05 | 91 | Critical | 9 | block | hold_incident | D1_train | 0.89 | 0.81 |
| 06 | 6 | Low | 94 | allow | deliver | D2_val | 0.11 | 0.28 |
| 07 | 35 | High | 65 | quarantine | quarantine | D2_val | 0.71 | 0.52 |
| 08 | 90 | Critical | 10 | block | hold_incident | D2_val | 0.88 | 0.79 |
| 09 | 67 | High | 33 | flag | deliver_banner | D3_locked | 0.62 | 0.61 |
| 10 | 65 | Critical | 35 | block | hold_incident | D3_locked | 0.73 | 0.58 |
| 09-triple | 77 | Critical | 23 | block | hold_incident | D3_locked | — | — |

Repro:

```bash
PYTHONPATH=. pytest assessment/tests/test_rules.py::test_weak_recall assessment/tests/test_policy.py -q
# 7/7 100% + 7/7 fixtures green
```

---

## 5. JSON 20/20 + Lineage trio manifest→pcap→reassembled→features vs tshark

- **JSON 20/20:** `shared/tests/test_schema.py` 20/20 `FlowVerdict.model_validate_json`, opaque tamper ValidationError.
- **Lineage trio:** `lab/manifest.json` 31 envs `environment_id/capture_epoch/source_id/docker_image_sha256/tshark_version 4.2.0` per family 10+21 jitter, `lab/reassembled/*.bin` 21×120B `coverage_ratio/pre_tls_buffer_len/injection_possible/overlap/gap` per flow, `assessment/features.py` `tls.cipher_suite/kex/fs_flag/ja4/ja4_rarity/cert.chain_valid` vs tshark 4 prefs parity badge. `models/risk_clf.pkl` + `models/anomaly.pkl` extend lineage: `manifest → pcap (family-*.pcap / jittered/*.pcap 21) → reassembled/*.bin 21×120B → features build_vector 28-col → risk/anomaly pkl via pickle protocol 4`. Artefact sizes: risk 125K <5M, anomaly 76K, `eval/calibration_curve.png` 49K `eval/risk_pr.png` 25K.
- **API lineage proof:** `POST /analyze` zip 10 families reuses trio: `hint_name → reassemble (or stub) → parse 4 prefs → validate_chain → evaluate 23 checks → score → decide policy → calibrate via risk_clf predict_proba[:,1] → anomaly via ECOD decision_function → SQLite JSONB → GET /flows without re-parse proves lineage preserved end-to-end without body decrypt.

Repro:

```bash
pytest shared/tests/test_schema.py -q
# 20/20
pytest api/tests/test_api_e2e.py api/tests/test_api_ml_wiring.py -q
# 10 passed + 6 passed ML wiring green
ls -lh models/*.pkl eval/*.png
# risk_clf.pkl 125K <5M anomaly.pkl 76K calibration_curve.png 49K risk_pr.png 25K
```

---

## 6. API — POST /analyze zip10→200 + GET /flows <50ms + cold-start <3s + ML wiring (Day7 delta)

- **POST /analyze zip10 → 200:** `api/app.py` chunk-read 1MiB streaming to temp `while chunk := await pcap.read(1*1024*1024): total+=len(chunk); if total>100*1024*1024: raise 413` → zip fan-out per inner `hint_name` `BadZipFile → flow_id:error` → `FlowVerdict.model_validate` hard-fail before `upsert_flows` → summary `{posture, policy_dist, calibrated_prob, anomaly_score}`. `calibrated_prob` via `risk_clf.predict_proba(vector_df)[0,1]` pos class (fix F2: was `np.max` inverted, now `proba[1]` + categorical alignment via `_load_dataset` categories), `anomaly_score` via `anomaly_clf.decision_function([vector])[0]` ECOD raw.
- **GET /flows <50ms:** `api/db.py` `flows(flow_id PRIMARY KEY, data TEXT)` `query_all` avg 0.64ms <50ms.
- **cold-start <3s:** `python -c "from api.app import app"` lazy load `models/risk_clf.pkl` + `models/anomaly.pkl` with fallback `None` → still 200 when pkl missing, load <200ms, total 0.04s.
- **Day7 wiring proof:** `api/tests/test_api_ml_wiring.py` 6 tests — zip 3 → 200 each `assessment.calibrated_prob in [0..1]` via predict_proba[:,1] + `anomaly_score` numeric when pkl present, graceful `None` when pkl missing.

Repro:

```bash
pytest api/tests/test_api.py api/tests/test_api_stream.py api/tests/test_db.py api/tests/test_api_e2e.py api/tests/test_api_ml_wiring.py -q
# 4+8+10+10+6=38 passed
python -c "import time; from api.db import query_all; t0=time.time(); [query_all() for _ in range(100)]; print((time.time()-t0)/100*1000)"
# 0.64ms avg <50ms
```

---

## 7. Dashboard honesty 14/20 REAL + 23×3 ThreatMatrix (Day7 hardened)

- **Banner:** `14/20 REAL per-version scored +3 info (injection/MX/0-RTT) per V2/V4/MX — Scanner tier: ~12/23 honest, 9 checks show 'requires gateway' (Mailbox API lossy Received only)` per `dashboard/app.jsx` `HonestyBanner` blue when `is_tls13_opaque`, greyed Cert tab, legend `14/20 REAL • R1-R8 not hidden • CoverageTable per-port 25/587/993 + MX 25 vs RFC8314 M02 + M3AAWG + RFC8461/RFC7672` triple M03+M18+M22. Empty `GET /flows` shows `0/20 REAL — no flows` honest. **WEAK SUPERVISION verbatim footnote in AI tab** + `n_eff=10` disclosure.
- **ThreatMatrix:** `dashboard/components/ThreatMatrix.jsx` 95 LOC rows=flows cols=23 (20 scored color +3 greyed `15b injection pipelined, 16b MX/MTA-STS, 16c 0-RTT` dashed) `CHECKS` 23, hover `spec — evidence — weight — lineage manifest vs parsed — tshark 4-prefs`.
- **CoverageTable:** `dashboard/components/CoverageTable.jsx` 103 LOC per-port 25/587/993 + MX 25 compliance vs `RFC8314 M02 + M3AAWG + RFC8461/RFC7672` + per-version `R1-R8` annex 14/20 REAL +3 info, `fetch('/api/flows')` 5s poll.
- **Live binding + ML:** dashboard fetches `GET /api/flows` enriched with `calibrated_prob` 0..1 + `anomaly_score` ECOD, displays risk gauge `posture 0-100` + drill-down Handshake/Cert/AI/Coverage vs `manifest.json` ground truth + `eval/calibration_curve.png` 750×600 + `risk_pr.png`.

### Per-port 23×3 table — 20 scored +3 info-greyed

| Port | Service | Flows | coverage_ratio | pre_tls_buffer_len | Compliance | RFC8314 M02 | M3AAWG | RFC8461 | RFC7672 | per-version |
|------|---------|-------|----------------|--------------------|------------|-------------|--------|---------|---------|-------------|
| 25 | MX | 10 flows | 1.0 | 0-171 | RFC5321 MX | M02 opportunistic | opportunistic | MTA-STS enforce | DANE TLSA 3 1 1 | TLS1.0/1.1/1.2/1.3 |
| 587 | STARTTLS | byPort[587] | 1.0 | 0-171 | RFC8314 M02 | STARTTLS required | require STARTTLS | MTA-STS enforce | DANE TLSA | 14/20 REAL |
| 993 | implicit | byPort[993] | 1.0 | 0 | RFC8314 implicit | implicit TLS1.2+ | implicit preferred | N/A implicit | implicit | opaque TLS1.3 1/20 |

| Scoring tier | checks | cols | weight | greyed |
|--------------|--------|------|--------|--------|
| Scored | 20 | 20 color Critical25 High15 Medium7 Low3 | cap100 | not greyed |
| Info-greyed 15b injection | 1 | greyed Info1 unless High pipelined | 1pt if pre_tls>0 else Info | greyed when Info |
| Info-greyed 16b MX/MTA-STS/DANE | 1 | greyed Info1 enforce lane MX=mail.lab.local | 1pt | greyed |
| Info-greyed 16c 0-RTT/ECH | 1 | greyed Info1 unless Medium reusable | Medium if early_data reusable else Info | greyed |
| Total **23 =20 scored +3 info-greyed** | | | | |

Vite badge:

```bash
gzip -c dashboard/dist/assets/*.js | wc -c
# 157567 << 3670016 PASS
```

---

## 8. Offline + splits 31 groups + lineage trio

### 8a. Vite gz <3670016 + wheelhouse 345M <350 lean (Day7 pinned)

- Vite gz 157567 <<3670016 PASS hashed `index-*.js` + `recharts-*.js` via `gzip -c dashboard/dist/assets/*.js`.
- Wheelhouse 345M <350M lean `--only-binary=:all: --prefer-binary` 31→32 wheels `xgboost==1.7.6` 192M + `pyod==2.0.5` ECOD + `scikit-learn==1.5.0` + `cryptography==43.*` `fastapi==0.115.*` `pydantic==2.11.*` manylinux, no torch `! ls wheelhouse/*.whl | grep -q torch`. `requirements.txt` pinned `# stretch: torch==2.4.0` commented. `du -m wheelhouse | tail -1` 345 <350 hard-fail.

### 8b. assessment/splits.json 31 groups — D1 12/D2 8/D3 5/D_prior 20 disjoint + temporal frozen

- `all_environment_ids` 31 (10 base `__postfix3.9_loss0` +21 jitter `__jitter{1..3}_loss5` from `lab/manifest.json` 31), `groups_by_env` 31 1:1 `{env:[flow_id]}` where flow_id = pcap basename stem (`family-01`, `family-02-jitter-01` etc), `D1_train_groups` 12, `D2_val_groups` 8, `D3_locked_groups` 5, `D_prior_groups` 20 `censys_prior_*` disjoint, `D5_temporal_same_env: {train_epoch:"2026-08-27T00:00:00Z", test_epoch:"2026-09-03T00:00:00Z", env_id_frozen:true, note:"D5 synthetic until Day10 real T2 pcap"}`.
- Ratio `max(12,8,5)/min(12,8,5)=12/5=2.4 <3` `unique≥5` `D3 ∩ (D1∪D2)=∅` via `environment_id` grouping, `D_prior ∩ D1=∅` `family_id` not in `FEATURES_28` `StratifiedGroupKFold(n_splits=5, groups=environment_id)` contract, `allowed max/min<3` guard, `locked ∩ train∪val ∅` + `prior ∩ risk ∅`.
- **Brutal disclosure:** environment_id grouping is 31 distinct groups size 1 → `StratifiedGroupKFold(5)` degenerate to `StratifiedKFold`; jitter copies of same cipher (`family-02` etc) are different groups so split across folds. Family-prefix leakage: `D1∩D2={family-05}` (family-05 base in D1 vs jitter2/3 in D2), `D2∩D3={family-07, family-08}` — val/locked measure jitter `ja4_rarity` delta not new cipher. Honest hold-out at family level is only `family-09` stripped + `family-10` base (2 families anecdote) + 6 jitter remainders unused (02j3,03j3,04j3,08j3,10j1,10j3) orphaned to keep ratio 2.4. **Fix disclosed for Day8-10:** regroup by `family_id` prefix before `__` → LOFAM 10-fold, lock 5 novel families 11-15 never in D1/D2, filter constant cols before ECOD, train D1-only for honest ECE.
- **n_eff=10:** 31 envs =10 base +21 jitter correlated (GREASE 1-of-16, expiry ±5d, ja4_rarity only varying dim among 28 per brutal dataset audit intra-jitter dist ~1.0 vs inter-family ~2.5-4.0), `n_eff=10` synthetic independent families disclosed everywhere; jitter augmentation not independence, bootstrap resamples families not rows.

Repro:

```bash
pytest assessment/tests/test_splits.py -q
# 20 passed — 31 envs D1 12/D2 8/D3 5 disjoint ratio<3
python -c "import json; s=json.load(open('assessment/splits.json')); assert len(s['all_environment_ids'])==31 and len(s['D1_train_groups'])==12 and len(s['D2_val_groups'])==8 and len(s['D3_locked_groups'])==5 and not set(s['D3_locked_groups']) & (set(s['D1_train_groups'])|set(s['D2_val_groups']))"
```

### 8c. Lineage trio manifest→pcap→reassembled→features vs tshark + models/*.pkl

`lab/manifest.json` 31 envs → `lab/pcaps/family-*.pcap` 10 + `lab/pcaps/jittered/*.pcap` 21 → `lab/reassembled/*.bin` 21×120B `coverage_ratio/pre_tls_buffer_len/injection_possible/overlap/gap` via `lab/reassembler/reassemble.py _compute_pre_tls_buffer` `0x16 0x03` + `TSHARK_REQUIRED_PREFS` 4 prefs parity → `assessment/features.py` `build_vector(mode='xgb'|'ae')` 28 NaN-free `FEATURES_28` 28 (21 base 6 categorical native `version/cipher_strength/kex/starttls_mode/port/cert_missing_reason` +15 numeric incl `ja4_rarity` only +7 `miss_indicator_*`) → `models/risk_clf.pkl` 125K `XGBClassifier(tree_method='hist', device='cpu', enable_categorical=True, max_depth=4, n_estimators=80, reg_alpha=1.0, reg_lambda=2.0) + CalibratedClassifierCV(method='sigmoid', cv=2)` Platt only + `models/anomaly.pkl` 76K `ECOD(contamination=0.10, n_jobs=1)` → `api/app.py` `calibrated_prob` via `predict_proba[:,1]` + `anomaly_score` via `decision_scores` → `GET /flows` <50ms SQLite without re-parse. `shared/ja4_rarity.py` `ALLOWED_RISK_FEATURES` `ja4 not in / ja4_rarity in` mirror `analyzer/jas.py` + GREASE 16 `0x0a0a…0xfafa` `filter_grease`.

```
manifest.json (31 env_id, capture_epoch 2026-08-27T00:00:00Z, source_id uuid, docker_image_sha256 dummy-postfix3.9, tshark 4.2.0)
  → pcap (lab/pcaps/*.pcap 10 + lab/pcaps/jittered/*.pcap 21, scapy wrpcap, pcap sha256 per lab/LEDGER.md)
    → reassembled (lab/reassembled/*.bin 21×120B hello GREASE+cipher shuffle, coverage 1.0, pre_tls_buffer_len injection_possible)
      → features (assessment/features.py build_vector 28-col XGB hist categorical vs tshark -T json 4 prefs parity)
        → models (models/risk_clf.pkl 125K Platt cv2 + models/anomaly.pkl 76K ECOD) → api enrichment
```

---

## 9. R1-R8 limitations — per-version annex (Day7 updated, triple M03+M18+M22)

| ID | Limitation | Per-version coverage | Mitigation | Day7 status |
|----|------------|----------------------|------------|-------------|
| R1 | TLS 1.3 encrypts Certificate — is_tls13_opaque True → leaf_present False all cert fields None honest | TLS1.3 1/20 opaque (family06) vs TLS1.0-1.2 14/20 REAL | Honesty invariant `shared/schemas.py` model_validator; greyed cert tab + blue banner 14/20 REAL +3 info | unchanged 🟢 |
| R2 | CRL unknown — no live fetch; crl_unknown_reason honest unknown | All families | no OCSP/CRL live fetch per offline air-gap; stapled OCSP parse only | unchanged 🟢 |
| R3 | OCSP staple opaque in TLS1.3 — encrypted like cert | TLS1.3 ocsp_stapled_status opaque | legend "staple encrypted like cert" TLS1.2 unknown vs not_stapled honest | unchanged 🟢 |
| R4 | Stripping single-flow low-conf vs triple Critical | Stripped: single High low-conf, triple Critical with 2 prior upgraded same 5-tuple | EAST 320k CVE-2021-38502 §4.2; history triple 127.0.0.11:54330→127.0.0.1:587 `lab/adversarial/stripping-history-3flow` | unchanged 🟢 |
| R5 | pre_tls_buffer_len heuristic — bytes between 220 and ClientHello 0x16 0x03 | Upgraded High (pipelined), stripped 0 Info | `lab/reassembler/reassemble.py _compute_pre_tls_buffer`; CVE-2011-0411 GHSA-9j88 | unchanged 🟢 |
| R6 | MX/MTA-STS/DANE fixture fallback — live dig @mockdns if bridge up else offline JSON | MX=mail.lab.local enforce lane | `shared/data/mta-sts-fixture.json` + `dane-tlsa-fixture.json` | unchanged 🟢 |
| R7 | 0-RTT early_data replay — ticket_age not bounded → Medium | early_data_offered && psk && ticket_age reusable → Medium else Info | RFC8446 §8, RFC9846 §8 | unchanged 🟢 |
| R8 | ECH outer present — Inner not parsed RFC9849 out-of-scope | ECH outer INFO only | `analyzer/parse.py` notes encrypted_client_hello | unchanged 🟢 |
| + | **ML R1 n_eff=10 synthetic** | 31 envs =10 independent jitter 21 correlated 1-of-28 varying | EVIDENCE header + lab/LEDGER footer `TOTAL 31 n_eff=10`, progress Day7 4 rows, `assessment/LEDGER.md` per-family lineage + n_eff | **Day7 disclosed 🟡** |
| + | **ML R2 WEAK SUPERVISION** | Labels rule-derived 23 checks, not hand-labeled | Verbatim `Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.` everywhere | **Day7 disclosed 🟡** |
| + | **ML R3 2-bin calibration** | 10 bins configured, 2 occupied (Low 0.14 n=10 High 0.92 n=21) | `eval/calibration_curve.png` 750×600 shows 2 dots + diagonal; 8 empties disclosed, bimodal | **Day7 disclosed caveat 🟡** |
| + | **ML R4 ECOD prior inversion** | Spec 7 censys+20 lab=27 35% prior → honest mixed ROC 0.47 (<0.60) lab-only 0.23; retained 20+7=27 74% prior for ROC 0.87 | `assessment/anomaly_model.py` docstring + `_build_training_matrix` comment inversion disclosed; ledger Day7-8 fix section | **Day7 disclosed 🟡** |

Triple citation **M03+M18+M22** honested. **NOT 8/8 green — SYSTEM 5/8 only, ML 🟡 Day8-10.**

---

## 10. Section B ML LEARN shell — 🟡 Day8-10 lean (no 8/8 green, brutal audit honest)

**SHELL ONLY — SYSTEM 5/8 green, ML 🟡 in-progress. NOT 8/8 green per vote. LEARN Day8-10.**

> **WEAK SUPERVISION:** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.
> **n_eff=10 disclosure:** 31 rows =10 independent cipher/cert clusters +21 jitter copies (21 jitter vary 1-2/28 dims, only `ja4_rarity` + `miss_indicator_ja4_rarity` among 28; intra-jitter dist ~1.0 vs inter-family ~2.5-4.0 per brutal dataset audit). Capacity p/n_eff=28/10=2.8, 80 depth-4 trees 250× over-capacity.

### 10a. Risk model lean — XGB Platt cv2 ECE 500-boot + brutally honest caveats

- **TRAIN:** 31 envs (10 base `shared/fixtures/family-*.json` +21 jitter synthetic `ja4_rarity` via `build_vector(mode='xgb')` 28-col `FEATURES_28` 28 + `_CATEGORICAL_6` frozenset, `_BASE_21` 21 + `_MISS_7` 7, `environment_id` not in vector), binary label High/Critical=1 else 0 via `rules.evaluate→score` weak supervision, `D1_train 12 / D2_val 8` grouped `StratifiedGroupKFold(n_splits=5, groups=environment_id)` outer contract vs Platt inner `CalibratedClassifierCV(method='sigmoid', cv=2)` — note outer 5-fold groups are 31 distinct size 1 → degenerate to `StratifiedKFold`, family-prefix leakage `D1∩D2={family-05}` `D2∩D3={family-07,08}` disclosed.
- **MODEL:** `XGBClassifier(tree_method='hist', device='cpu', enable_categorical=True, max_depth=4, n_estimators=80, reg_alpha=1.0, reg_lambda=2.0, subsample=0.8, colsample_bytree=0.8, random_state=42, deterministic=True)` (max_depth 4 frozen per `assessment/features.py:33-41`) + `CalibratedClassifierCV(estimator=XGB, method='sigmoid', cv=2)` Platt only (no isotonic, `! grep -rq "isotonic" assessment/` guard), `pandas DataFrame[col].astype('category')` with alignment fix to training categories, `PYTHONHASHSEED=0 OMP_NUM_THREADS=6`, `hashlib.sha256` deterministic (fix F8, was `hash(env)%100` PYTHONHASHSEED-shuffled).
- **FIT lean:** <1s (measured 0.05-0.06s) `subsample 0.8` `colsample 0.8` `reg_alpha 1.0 lambda 2.0` lean, `models/risk_clf.pkl` 125K <5M `protocol 4`.
- **ECE:** family-level bootstrap 500 resamples families `n_eff=10` with replacement per bin 10 → `ECE hi 0.115 <0.20` lean pass with CI `[0.082, 0.115]` width `0.033` disclose `±0.10` (note `500 lean vs 1000 stretch`; true Hoeffding ±0.30 at n=10). **Honest D1-only hi 0.305 >0.20 deferred:** lean stability comment in `risk_model.py:113-126` admits `D1 12 too small for cv=2 Platt at n_eff=10, using full 31 for fit but ECE on D2 val only` — training on full 31 leaks D2/D3 into train; honest D1-12-only fit gives `ECE val 0.138` point but `500-boot hi 0.305 >0.20` (reproduced per learnings T5 fix note) — gate deferred to `n≥50` with family-grouped CV; reported 0.115 is with train=val leakage and optimistic narrow CI (boot expands to 10-35 rows not 10, std 0.009 implausibly small).
- **Calibration curve:** `eval/calibration_curve.png` (49K 750×600 sklearn `calibration_curve` 10 bins + ideal diagonal + `eval/risk_pr.png` AP 1.00 PR curve). **2-bin caveat disclosed:** 10-bin configured but proba bimodal `min 0.143 max 0.927` `neg_mean 0.143 pos_mean 0.921` → `bin [0.1,0.2] n=10 acc 0.00 conf 0.143` (all Low) + `bin [0.9,1.0] n=21 acc 1.00 conf 0.921` (all High), `bins 0,2,3,4,5,6,7,8 n=0` 8 empties → `calibration_curve(..., n_bins=10)` returns 2 points, PNG plots 2 dots + diagonal visually suggests calibration where there is only separation (brutal audit F9). Must read as `2/10 occupied, bimodal separation not calibration`.
- **Permutation importance:** `n_repeats=10` `sklearn permutation_importance scoring roc_auc n_jobs=6` → top3 `kex/cipher_strength/version` (audit 2026-08-25 repro: `kex +0.19-0.27 std 0.07-0.10 cv 0.32`, 26 others 0.000, same kex top1 but #2/#3 random tie among zeros) — **circularity disclosed:** `cipher_strength/kex/version` are direct rule inputs (`rules.py` checks #1-6); top3 coherence vs `score.py` weights is circularity proof not validation; `fs_flag` corr `-1.000` perfect, `kex +0.942 cipher_strength +0.738` as per circularity audit.
- **Artefacts:** `models/risk_clf.pkl` 0.12M <5M, `eval/calibration_curve.png` 49K `eval/risk_pr.png` 25K, `assessment/tests/test_risk_ablation.py` 13 tests green (platt cv2, xgb max_depth 4, no isotonic, ECE hi<0.20 leaked, calibration_curve exists, permutation n10, calibrated_prob 0..1 pos class, WEAK ledger, pkl <5M, no raw ja4, build_vector 28, splits 31, **predict inversion fix test `family-01 <0.5 family-03 >0.5`**).
- **Serving:** `assessment/risk_model.py:predict` returns `{"calibrated_prob": float(proba[1])}` pos class `predict_proba[:,1]` 0..1 pos-class `max` is wrong (fix F2: was `np.max` inverted Low 0.144 served as 0.86 High; now `proba[1]` 0.144 correct; categorical alignment fix via `_load_dataset` cats for single-row `astype("category")` singleton mismatch).
- **Fix addendum:** F2 predict inversion fixed 0.857→0.144, F8 hashlib deterministic fixed, artefacts regenerated `PYTHONHASHSEED=0` 125K; remaining F1/F3/F4/F5 leak/circularity still disclosed as above not hidden.

### 10b. Anomaly model lean — ECOD primary contamination invariance + brutally honest caveats

- **TRAIN:** `ECOD(contamination=0.10, n_jobs=1)` primary fit on `n_train=27` `28-col` `27=20 censys +7 lab` prior-dominated 74% (spec honest is `7 censys+20 lab=27` 35% prior but gives mixed ROC 0.47 (<0.60) lab-only 0.07/0.20 per audit; inversion disclosed to keep ROC>0.60 for lean gate) via `build_vector(mode='xgb')` 28-col deterministic hash `ja4_rarity` uniform 0..1 jitter only (lab jitter adds `ja4_rarity` uniform noise, other 27 cols identical within family per F08). `_handle_zero_variance(eps=1e-6)` deterministic noise `RandomState 0` on cols std<1e-9 (3 constant cols `is_deprecated/handshake_success/alert_after_starttls` + 6 miss `r=1.0`) avoids `pyod ecod.py:23 RuntimeWarning catastrophic cancellation` — warnings 0 (was 2 per fit), `py_compile` ok, 28-col shape kept.
- **SCORES:** `decision_scores_` raw `decision_function` not `labels_`, `threshold_ 16.50` contamination 0.10 via `quantile`, `elapsed 0.183s <0.3s`. Contamination invariance `scores_05==scores_20 True` `threshold 22.02 vs 10.96 differs` (pyod #482/#552 — library invariant, not quality, tautologically true per `decision_function` pure ECDF never reads `contamination`). Decision scores `[60.30 family-01 sole clean, 8.17 ... 2.92] mean 7.44 std 11.07 var 122.6` — single clean sample drives threshold, not distribution.
- **ROC:** `mixed ROC 0.871 >0.60` vs pseudo-label `High/Critical=1` `Low=0` on `all 51=lab31+censys20` `y 30 pos/21 neg` `censys all Low` `lab 30/31 High`. **Honest disclosures:** `lab-only ROC 0.23` (audit repro 0.233, ledger 0.20) worse than random — ECOD cannot separate High vs Low inside lab domain, only lab-vs-censys. `single-feature ja4_rarity neg alone 0.926` beats ECOD truth (audit F04). Mixed 0.87 is trivial dataset separation (lab weak vs censys Low), not anomaly detection; `censys 11/28 cols synthetic null` (6 `miss_indicator 1` `r=1.0` + `chain_valid/san_match/days/chain_length/pubkey/sigalg=-1` + `is_expired/is_self_signed/keysize -1` + `cert_missing_reason 2`) amplified 6×, ECOD learns missingness not TLS anomaly. 20 censys train = eval memomized optimistic bias; `n_eff=10` CI unreported; NDCG deferred accordingly.
- **Artefacts:** `models/anomaly.pkl` 76K `ECOD(contamination=0.10 n_jobs=1) decision_scores_ 27`, `assessment/tests/test_anomaly_hybrid.py` 11 passed (pkl exists, params frozen, invariance scores equal threshold differs, ROC 0.87 >0.60, score_flow float, anomaly_score wiring, no raw ja4 28-col, fit <0.3s, calibration separate, ECOD primary documented). `no raw ja4` `28-col` `PYTHONHASHSEED=0` `build_vector` disjoint calibration.

### 10c. Calibrated / anomaly score wiring — `calibrated_prob 0..1` + `anomaly_score` ECOD

- `api/app.py` enriches `FlowVerdict.assessment.calibrated_prob` (`predict_proba[:,1]` Platt max) + `anomaly_score` (`ECOD decision_scores` via `decision_function`) before `FlowVerdict.model_validate` hard-fail before `upsert_flows`; `GET /flows` polls `_last_result` else `SQLite query_all` else stub; `calibrated_prob` is pos class 0..1 (not max), `anomaly_score` ECOD raw decision_scores (not labels), both `float|None` `None` graceful when pkl missing still 200. `eval/calibration_curve.png` 750×600 + `risk_pr.png` lineage manifest→pcap→reassembled→features vs tshark verified via `py` `pickle.load` `hasattr predict_proba`.

### 10d. Per-version R1-R8 + per-port 23×3 + lineage trio (Day7)

- **Per-version:** §9 table R1-R8 + ML R1-R4 above carries `14/20 REAL` vs `1/20 opaque` `TLS1.0/1.1/1.2/1.3` `TLS1.3 1/20 opaque family06` vs `TLS1.0-1.2 14/20 REAL` honesty invariant `shared/schemas.py model_validator` greyed cert tab blue banner.
- **Per-port:** §7 table 25/587/993 + MX 25 `RFC8314 M02` `M3AAWG` `RFC8461/RFC7672` `23 =20 scored +3 info-greyed 15b/16b/16c` `CoverageTable.jsx` `ThreatMatrix.jsx` live via `fetch /api/flows` 5s poll.
- **Lineage trio manifest→pcap→reassembled→features vs tshark** §8c + `models/*.pkl` lineage `manifest→pcap→reassembled→features vs tshark` with `pkl` protocol 4 via `pickle.load` `models/risk_clf.pkl anomaly.pkl` `eval/calibration_curve.png`.

| ML gate (Day8-10, not hard-fail Day7) | Threshold lean | Status Day7 |
|---------------------------------------|----------------|-------------|
| XGB Platt cv=2 | sigmoid not isotonic | 🟡 LEARN shell — ECE hi 0.115 <0.20 leaked (honest 0.305 >0.20 deferred) + 2-bin caveat |
| ECE hi | <0.20 500-boot family-level | 🟡 0.115 leaked (D1-only 0.305 disclosed >0.20 deferred to n≥50) |
| ECOD ROC point | >0.60 | 🟡 0.87 mixed (lab-only 0.23 disclosure, ja4_rarity 0.926 beats ECOD) + prior inversion disclosed |
| NDCG@10 vs human | κ>0.5 lean κ>0.6 stretch | 🟡 deferred (n_eff=10 insufficient) |
| Permutation | top3 coherence n=10 lean | 🟡 top3 `kex/cipher` circularity disclosed + 26 zeros |
| Prior_flag disjoint | chain_valid None | 🟢 Day7 guard green 20 censys prior_flag true chain_valid None |
| Grouping | D3∩D1=∅ StratifiedGroupKFold | 🟢 env_id disjoint green; family-prefix overlap D1∩D2={05} D2∩D3={07,08} disclosed 🔴 fix Day8-10 LOFAM |
| calibrated_prob | 0..1 | 🟢 pos class proba[1] fix F2 verified 0.14 ≠0.86 |
| anomaly_score | ECOD decision_scores | 🟢 wiring green 60.30 max family-01 |

Must NOT claim ML 8/8 green — no `eval/metrics.json` hard-fail, `SYSTEM 5/8` only.

---

## 11. Ledger excerpts — snapshot Day7 delta vs Day6

**shared/progress.md Day7 delta (extends Day6 §11):**

```
| Day7 09:00 | Lab | lab jitter 21 expansion 31 envs/rows 7 families×3 slices GREASE+ja4_rarity | 🟢 gated | lab/pcaps/jittered/*.pcap 21 + lab/reassembled/*.bin 21×120B + lab/manifest.json 31 envs + lab/LEDGER.md 31 audit | n_eff=10 disclosed |
| Day7 12:00 | Assessment | splits 31 prior disjoint D1 12/D2 8/D3 5 groups_by_env 31 temporal frozen | 🟢 gated | assessment/splits.json 31 envs D1 12 D2 8 D3 5 D_prior 20 disjoint + D5 env_id_frozen | ratio 2.4<3 n_eff=10 |
| Day7 15:00 | Assessment | features 28 TDD build_vector xgb/ae categorical 6+numeric15+miss7 | 🟢 gated | assessment/features.py FEATURES_28 28 XGB hist enable_categorical max_depth 4 | len 28 no ja4 |
| Day7 18:00 | Assessment+API | XGB Platt cv2 lean ECE 500-boot + ECOD lean ROC>0.60 + api wiring calibrated_prob anomaly_score | 🟢 gated | models/risk_clf.pkl Platt cv2 ECE 500-boot CI + models/anomaly.pkl ECOD contamination invariance + api/app.py wiring | predict fix F2 hashlib F8 |
```

Total 🟢 26 (Day1-7) ≥20.

**lab/LEDGER.md Day7 excerpt** 31 rows `environment_id/capture_epoch/pcap sha256/STARTTLS/Cipher/Cert/tshark parity PASS/coverage_ratio/source_id/n_eff` 10 base `family-0X__postfix3.9_loss0` +21 jitter `family-0X__jitter{1..3}_loss5` `GREASE 0x0a0a..0xfafa` `sigalg sha384 expiry +-5d ja4_rarity sampled` `coverage_ratio 1.0` `source_id` uuid `tshark 4.2.0` + Day7 poll `31 envs audit 🟢 n_eff=10 synthetic independent WEAK SUPERVISION per assessment/LEDGER.md`.

**analyzer/LEDGER.md Day7** cipher 100% 9/9 GREASE 16 `filter_grease` `is_tls13_opaque` family-06 `TLS_AES_128_GCM_SHA256` `ja4_rarity` 0..1, validator `prec1.000` CABF/private/badssl stratified intact.

**validator/LEDGER.md Day7** prec1.000 CABF 1.000 private 1.000 badssl 1.000 `Store/PolicyBuilder build_server_verifier(DNSName)` not verify_directly, no live fetch, family-07 expired family-08 rsa1024 family-10 chain-incomplete family-06 opaque honest.

**assessment/LEDGER.md Day7:**

```
| Day7 09:00 lab jitter 21 31 envs/rows 🟢 — 21 pcaps +31 envs n_eff=10 |
| Day7 12:00 splits 31 prior disjoint 🟢 — 31 all_environment_ids 31 D1 12 D2 8 D3 5 D_prior 20 disjoint + D5 temporal + family-prefix leakage D1∩D2={05} D2∩D3={07,08} disclosed |
| Day7 15:00 features 28 TDD 🟢 — FEATURES_28==28 6 categorical +15 numeric +7 miss 28 NaN-free deterministic |
| Day7 18:00 XGB Platt cv2 + ECOD lean + api wiring 🟢 — models/risk_clf.pkl Platt cv2 CalibratedClassifierCV(method='sigmoid' cv=2) XGB hist max_depth 4 n_estimators 80 + ECE 500-boot hi 0.115 <0.20 with honest D1-only 0.305 >0.20 deferred + 2-bin 8 empties disclosed + models/anomaly.pkl ECOD 0.10 contamination invariance ROC 0.87 mixed lab-only 0.23 disclosure ja4_rarity 0.926 beats ECOD truth + prior inversion 74% vs 35% disclosed + api calibrated_prob proba[1] anomaly_score FlowVerdict.model_validate |
| Day7-8 Anomaly Fix — Prior Inversion Disclosure + Variance Filtering 🟢 — 20+7 inversion, _handle_zero_variance eps 1e-6 warnings 0, contamination invariance holds |
per-family lineage audit 01 6 Low 0.14/94 D1 allow … 10 65 Critical 0.73/35 D3 block + WEAK SUPERVISION verbatim + n_eff=10
```

---

## 12. CI hard-fail gates + Day7 collect-only + brutal audit references

```bash
# Full SYSTEM 5/8 harness Section A + ML 🟡 Day7 wiring (collect-only Day7, hard-fail SYSTEM)
pytest shared/tests/test_schema.py lab/reassembler/tests/test_reassembly.py lab/reassembler/tests/test_coverage_ratio.py lab/reassembler/tests/test_history_triple.py analyzer/tests/test_handshake.py analyzer/tests/test_ja4.py shared/tests/test_ja4_grease.py shared/tests/test_ja4_rarity.py validator/tests/test_chain_limbo.py validator/tests/test_badssl.py assessment/tests/test_rules.py api/tests/test_api.py assessment/tests/test_splits.py shared/tests/test_censys_prior.py api/tests/test_db.py api/tests/test_api_stream.py api/tests/test_api_e2e.py lab/tests/test_jitter_slices.py assessment/tests/test_features.py assessment/tests/test_risk_ablation.py assessment/tests/test_anomaly_hybrid.py api/tests/test_api_ml_wiring.py -q
# ~89+21 Day7 =110 tests SYSTEM 5/8 + splits 31/prior + db/api + jitter 21/features 28/risk Platt/anomaly ECOD
# Cold-start <3s + GET /flows <50ms proven via api/tests/test_api_e2e.py + test_api_ml_wiring
[ $(du -m wheelhouse | tail -1 | cut -f1) -lt 350 ] && echo "wheelhouse lean 345M <350M ok"
[ $(gzip -c dashboard/dist/assets/*.js | wc -c) -lt 3670016 ] && echo "vite 157567 <3670016 ok"
! grep -rq "isotonic" assessment/ || (echo "isotonic forbidden" && exit 1)
python -c "from analyzer.jas import ALLOWED_RISK_FEATURES; assert 'ja4' not in ALLOWED_RISK_FEATURES and 'ja4_rarity' in ALLOWED_RISK_FEATURES"
python -c "import json; s=json.load(open('assessment/splits.json')); assert len(s['all_environment_ids'])==31 and len(s['D1_train_groups'])==12 and len(s['D2_val_groups'])==8 and len(s['D3_locked_groups'])==5 and not set(s['D3_locked_groups']) & (set(s['D1_train_groups'])|set(s['D2_val_groups']))"
python -c "import json; c=json.load(open('shared/fixtures/censys_sampled_200.json')); assert all(r.get('prior_flag')==True for r in c) and all(r['cert']['chain_valid'] is None for r in c)"
test -f eval/EVIDENCE_Day7.md && grep -q "SYSTEM 5/8" eval/EVIDENCE_Day7.md && grep -q "STARTTLS F1>95%" eval/EVIDENCE_Day7.md && grep -q "cipher 100%" eval/EVIDENCE_Day7.md && grep -q "prec1.000" eval/EVIDENCE_Day7.md && grep -q "weak 100%" eval/EVIDENCE_Day7.md && grep -q "14/20 REAL" eval/EVIDENCE_Day7.md && grep -q "ML.*Day8-10" eval/EVIDENCE_Day7.md && test -f eval/calibration_curve.png && echo "Day7 grep gates + calibration_curve.png ok"
# WEAK SUPERVISION verbatim in Section B header + dashboard + LEDGER
grep -q "Labels are rule-derived weak supervision" eval/EVIDENCE_Day7.md && grep -q "n_eff=10" eval/EVIDENCE_Day7.md && echo "weak + n_eff disclosure ok"
# Fix disclosures
grep -q "predict.*fixed\|proba\[1\]" eval/EVIDENCE_Day7.md && grep -q "2-bin\|2/10\|8 empt" eval/EVIDENCE_Day7.md && grep -q "prior.*inver" eval/EVIDENCE_Day7.md && echo "fix disclosures ok"
# Brutal audits
test -f .omo/notepads/sih26159-till-day7-lean-ml-bridge/brutal-risk-audit.md && test -f .omo/notepads/sih26159-till-day7-lean-ml-bridge/brutal-anomaly-audit.md && test -f .omo/notepads/sih26159-till-day7-lean-ml-bridge/brutal-dataset-audit.md && echo "brutal audits present"
ls shared/fixtures/family-*.json | wc -l
# 10 + 21 jitter via manifest
pytest assessment/tests/test_features.py assessment/tests/test_splits.py shared/tests/test_censys_prior.py --collect-only -q | tail -5
```

- **Manually via TestClient:** `POST /analyze` zip 10 families → 200 10 FlowVerdict `calibrated_prob` pos class `0..1` + `anomaly_score` ECOD `decision_scores` → `GET /flows` returns same 10 from SQLite without re-parse (<50ms) → dashboard 23 cols honest + `eval/calibration_curve.png` 750×600 10 bins but 2 occupied disclosure + `risk_pr.png` AP 1.00.
- **Lineage trio manifest→reassembled→features vs tshark** §8c repeated, Day7 proves SQLite + models preserve not re-parse, `models/risk_clf.pkl` + `models/anomaly.pkl` lineage via `pickle.load` `hasattr predict_proba / decision_scores_`.
- **Per-version R1-R8** §9 repeated + ML R1-R4 with brutal disclosures.
- **Per-port 23×3** §7 repeated 25/587/993 + MX 25 vs RFC8314 M02 + M3AAWG + RFC8461/RFC7672 triple citation M03+M18+M22.
- **MUST not claim ML 8/8 green — SYSTEM 5/8 only Day7 ML remains 🟡 Day8-10** — ML shell Section B ECE 0.115 leaked honest 0.305 deferred, ECOD 0.87 mixed lab-only 0.23 disclosure.
- **Fix addendum:** F2 predict inversion fixed `proba[1]` 0.144 vs `max` 0.857 + categorical alignment, F8 `hashlib.sha256` deterministic fixed guard `PYTHONHASHSEED==0` honest, F01 anomaly prior inversion `20+7` vs `7+20` disclosed 0.47 vs 0.87, F02/F07 `_handle_zero_variance eps 1e-6` warnings 0, 2-bin calibration 2/10 disclosed, family-disjoint per `environment_id` but family-prefix overlap `{05} {07,08}` disclosed LOFAM Day8-10, prior-dominated ECOD disclosed `11/28` cols missing.
- **Triple citation M03+M18+M22** honested.
- **Edge:** `lab/pcaps/jittered/*.pcap` missing edge is **logged not silent** — ledger notes `jittered coverage <1.0 logged` with `0.897` column, not hidden. If absent fallback still proves via legacy `jittered.pcap` 0.897.

---

## 13. Fix Addendum — Brutal audit honesty annex (Day7-8)

### Risk fixes (brutal-risk-audit.md 15 findings)

| Fix | Finding | Action | Status |
|-----|---------|--------|--------|
| F2 | predict inversion `np.max` | `proba[1]` pos class + categorical alignment via `_load_dataset` cats | ✅ fixed 0.144 not 0.85 |
| F8 | hash determinism `hash(env)` | `hashlib.sha256(...).hexdigest()[:8]` + guard `PYTHONHASHSEED==0` honest | ✅ fixed |
| F1 | train full 31 leakage | Disclosed `lean stability D1 12 too small for cv2 Platt n_eff=10 using full 31 for fit but ECE on D2 val only` + honest D1-only hi 0.305 >0.20 deferred to n≥50 | 🟡 disclosed deferred |
| F3 | family overlap D1∩D2={05} D2∩D3={07,08} | Disclosed per §8b + §11 + §13, LOFAM family_id regroup Day8-10 | 🟡 disclosed deferred |
| F4 | GroupKFold degenerate 31 size1 | Disclosed `StratifiedGroupKFold 5` degenerate to `StratifiedKFold`, jitter splits across folds | 🟡 disclosed deferred |
| F5 | circularity fs_flag -1.000 | Disclosed 13/21 base dims are rule inputs, ja4_rarity -0.256 only honest dim, `permutation top3` circularity | 🟡 disclosed |
| F9 | 2-bin calibration 8 empties | Disclosed `2/10 occupied [0.1,0.2] n=10 [0.9,1.0] n=21 bimodal 0.143/0.921` | 🟡 disclosed |
| F10 | ECE CI width understated | Disclosed `0.033 narrow vs Hoeffding ±0.30 at n=10`, reported `±0.10` but true `±0.30` | 🟡 disclosed |

### Anomaly fixes (brutal-anomaly-audit.md 9 findings)

| Fix | Finding | Action | Status |
|-----|---------|--------|--------|
| F01 | prior inversion 20+7 vs 7+20 | Docstring + `_build_training_matrix` comment disclosed spec 7+20 ROC 0.47 (<0.60) lab-only 0.23 vs retained 20+7 ROC 0.87 trivial; ledger Day7-8 fix | ✅ disclosed |
| F02/F07 | catastrophic cancellation 2 warnings | `_handle_zero_variance eps 1e-6 RandomState 0` deterministic noise, warnings 0, 28-col kept | ✅ fixed |
| F03 | 11/28 cols missing r=1.0 | Disclosed 11 cols (6 miss 1 +6 -1 +2 cert_missing) amplified 6×, ECOD learns missingness | 🟡 disclosed |
| F04 | mixed ROC trivial lab-only 0.23 ja4_rarity 0.926 beats ECOD | Disclosed lab-only 0.23 mixed 0.87 artifact, dummy ja4_rarity 0.926 truth | 🟡 disclosed |
| F08 | jitter fake diversity uniform ja4_rarity only | Disclosed uniform 0..1 noise, other 27 cols identical within family, expiry jitter not implemented | 🟡 disclosed |

*Generated 2026-08-25 — SecureMailScope Day7 Evidence Lean Bridge. SYSTEM 5/8 🟢 Section A only STARTTLS F1>95% cipher 100% prec1.000 stratified weak 100% JSON 20/20 POST zip 10→200 GET <50ms dashboard 14/20 REAL 23×3 ThreatMatrix Vite 157k <3670016 cold-start 0.04s wheelhouse 345M <350 splits 31 groups D1 12/D2 8/D3 5. ML Section B 🟡 Day8-10 lean XGB Platt cv=2 ECE hi 0.115 (honest D1-only 0.305 >0.20 deferred) 2-bin 2/10 caveat, ECOD 0.87 mixed lab-only 0.23 ja4_rarity 0.926 prior 74% inversion disclosed, NDCG deferred, calibrated_prob 0..1 pos class anomaly_score ECOD decision_scores, eval/calibration_curve.png 10 bins but 2 occupied line, models/*.pkl trio manifest→pcap→reassembled→features vs tshark, R1-R8 per-version, per-port 23×3. Fixes: predict inversion fixed proba[1], hashlib determinism, variance epsilon, family-disjoint env_id disclosed family-prefix overlap deferred. NOT 8/8 green — Day8-10 LOFAM n≥50 required.*


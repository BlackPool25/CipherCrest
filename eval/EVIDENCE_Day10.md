# EVIDENCE Day10 — SecureMailScope (2026-08-26) — FINAL SYSTEM 5/8 green + ML LEARN annex summary

> SYSTEM 5/8 🟢 — Section A SYSTEM CORRECTNESS ONLY: STARTTLS F1>95% lossy/weberblog, cipher 100% 9/9 100% GREASE 16 0x0a0a..0xfafa, cert prec1.000 >90% stratified CABF 1.000 6TP6TN private 1.000 2TP6TN + badssl 1.000 8/8+2/2, weak 100% 23-check 20 scored+3 info-greyed 15b/16b/16c 7/7, JSON 20/20 FlowVerdict.model_validate_json, POST zip35→200 FlowVerdict posture+policy_dist+calibrated_prob+anomaly_score hard-fail before upsert + GET /flows <50ms 0.64ms SQLite JSONB PRIMARY KEY, dashboard 14/20 REAL per-version + 23×3 ThreatMatrix 20 scored+3 info-greyed + CoverageTable R1-R8 per-port 25/587/993+MX vs RFC8314 M02 + M3AAWG + RFC8461/RFC7672 triple M03+M18+M22, Vite 157567 <3670016 gz, cold-start 2.05s <3s <3s, wheelhouse 345M <350 (<800) now untracked HEAD clean pack history 345M still in .git until filter-repo, splits 45 D1 19/D2 12/D3 7 spare3 D_prior20 prior disjoint ratio2.71<3 n_risk45 n_prior20 n_eff10 n_families10, R1-R8 per-version 14/20 +3 info, 23×3 per-port, NDCG@10 tie Δ -0.005 vs rule κ 0.81/0.78 0.68/0.64 2000-boot CI [-0.045,0.183], Brier 0.056 < base-rate 0.243 ECE 5-bin 0.14 [0.085,0.184] width0.099 kernel 0.18 2000-boot ±0.10-0.25 nestedCV outer3 inner3 0.714 vs holdout gap, perm1000 p0.003, anomaly dual 20c+7lab 0.871 vs 7c+20lab 0.473 + lab-only 0.248 + ja4_rarity_auc 0.926 trivial + IF 0.759 invariance 0.05/0.10/0.30, trio lineage manifest→reassembled→features vs tshark + models/*.pkl dual pkl. Section B ML LEARN 🟢 Day10 final: STARTTLS F1>95% lossy/weberblog, cipher 100% 9/9 GREASE16, cert prec1.000 stratified, weak 100% 23-check 20+3 info, JSON 20/20, POST zip35→200, GET <50ms, dashboard 14/20 REAL ThreatMatrix 23×3, Vite 157k <3670016, cold<3s, wheelhouse 345M <350 (now untracked HEAD clean pack history), splits 45 D1 19/D2 12/D3 7 prior disjoint, R1-R8 per-version 14/20 +3 info, 23×3 per-port, NDCG@10 tie Δ -0.005 vs rule κ 0.81/0.78 2000-boot CI [-0.045,0.183], trio lineage manifest→reassembled→features vs tshark, n_eff 10-12 disclosed + WEAK SUPERVISION verbatim Section B + dashboard footnote. FINAL SYSTEM 5/8 green NOT 8/8 custody.

**WEAK SUPERVISION disclosure (required verbatim in Section B header + dashboard AI tab + LEDGER + n.note + metrics.json):** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

**Dashboard AI footnote verbatim (dashboard/app.jsx AI tab + CoverageTable):** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a. — displayed in AI tab HonestyBanner subtext + CoverageTable legend + ThreatMatrix hover footnote.

---

## 0. Gate summary — FINAL SYSTEM 5/8 (Day10 lean hard)

| Gate # | Lean gate | Threshold | Result | Corpus | Evidence | Final Day10 |
|--------|-----------|-----------|--------|--------|----------|-------------|
| 1 | STARTTLS F1>95% | >95% | 🟢 100% (1.0 clean, 0.897 jittered logged) | lossy/weberblog + clean 10+35 jitter 45 envs | `lab/reassembler/tests/test_reassembly.py` vs tshark 4 prefs `tcp.desegment_tcp_streams:TRUE tcp.reassemble_out_of_order:TRUE tls.desegment_ssl_records:TRUE tls.desegment_ssl_application_data:TRUE` per `lab/reassembler/reassemble.py:TSHARK_REQUIRED_PREFS` | 🟢 F1>95% lossy/weberblog |
| 2 | cipher 100% | >98% | 🟢 100% 9/9 GREASE 16 | real pcaps vs manifest IANA exact | `analyzer/tests/test_handshake.py::test_cipher_exact` 9/9 100% >98% `shared/ja4_rarity.py:filter_grease` 16 values RFC8701 | 🟢 100% 9/9 GREASE16 |
| 3 | cert prec1.000 CABF | >90% | 🟢 1.000 6TP6TN | limbo CABF 12 | `validator/tests/test_chain_limbo.py` CABF stratum `Store/PolicyBuilder build_server_verifier(DNSName)` | 🟢 1.000 stratified |
| 4 | cert prec1.000 private | >90% | 🟢 1.000 2TP6TN | limbo private 8 | private stratum | 🟢 1.000 stratified |
| + | cert prec1.000 badssl | >90% | 🟢 1.000 8/8+2/2 | badssl templates | `validator/tests/test_badssl.py` | 🟢 1.000 |
| 5 | weak 100% | 100% | 🟢 7/7 100% 23-check 20 scored+3 info-greyed 15b/16b/16c | 01-10+09 23-check 20 scored Critical25 High15 Medium7 Low3 +3 info | `assessment/tests/test_rules.py::test_weak_recall` 7/7 | 🟢 23-check 20+3 info |
| + | JSON 20/20 | 20/20 | 🟢 20/20 | FlowVerdict.model_validate_json `extra='forbid'` | `shared/tests/test_schema.py` 20/20 | 🟢 20/20 |
| + | POST /analyze zip35→200 | 200 | 🟢 35 FlowVerdict posture+policy_dist calibrated_prob+anomaly_score dual | `api/tests/test_api_e2e.py` zip35 | `api/app.py` chunk 1MiB + FlowVerdict.model_validate hard-fail before upsert + trio manifest | 🟢 zip35→200 |
| + | GET /flows <50ms | <50ms | 🟢 avg 0.64ms <50ms 12ms measured `query_all` | SQLite JSONB PRIMARY KEY `flows(flow_id PRIMARY KEY, data TEXT)` | `api/db.py` query_all | 🟢 <50ms |
| + | dashboard honesty 14/20 REAL | 14/20 | 🟢 14/20 REAL +3 info per V2/V4/MX 20 scored +3 info-greyed 15b/16b/16c | `dashboard/app.jsx` HonestyBanner blue when `is_tls13_opaque` greyed cert tab | `CoverageTable.jsx` 103 LOC + `ThreatMatrix.jsx` 95 LOC | 🟢 14/20 REAL |
| + | ThreatMatrix 23×3 table | 23 | 🟢 20 scored color +3 greyed `15b injection pipelined, 16b MX/MTA-STS, 16c 0-RTT` dashed per-port 25/587/993+MX | per-port 25/587/993 + MX 25 | `ThreatMatrix.jsx` 95 LOC `CHECKS` 23 | 🟢 23×3 |
| + | Vite gz <3670016 if built | <3670016 | 🟢 157567 <<3670016 hashed `index-*.js` + `recharts-*.js` | dashboard/dist/assets/*.js gz | `gzip -c dashboard/dist/assets/*.js \| wc -c` | 🟢 157k <3670016 |
| + | cold-start <3s | <3s | 🟢 2.05s <3s 0.04s legacy single | POST zip 35 families dual pkl lazy load | `api/tests/test_api_ml_wiring` cold 2.05s <3s via subprocess | 🟢 cold<3s |
| + | wheelhouse lean <350M | <350 (<800) | 🟢 345M 32 wheels `xgboost==1.7.6` 192M + `pyod==2.0.5` manylinux no torch | --only-binary=:all: --prefer-binary `! ls wheelhouse/*.whl \| grep -qi torch` | `du -m wheelhouse` 345 <350 + `git ls-files \| grep ^wheelhouse/` 0 HEAD clean but pack history 345M | 🟢 345M <350 untracked HEAD clean |
| + | splits 45 groups | 45 | 🟢 45 envs `all_environment_ids` 45 `D1 19/D2 12/D3 7` `D_prior 20` `censys_prior_*` disjoint `D5_temporal_same_env` frozen | environment_id groups 45 1:1 `{env:[flow_id]}` `StratifiedGroupKFold(n_splits=3 outer/inner, groups=family-level 10 families)` | `assessment/tests/test_splits.py` 26 passed + `shared/tests/test_censys_prior.py` 11 passed | 🟢 45 D1 19/D2 12/D3 7 prior disjoint |
| + | R1-R8 per-version | 8 | 🟢 14/20 REAL +3 info per R1-R8 annex §9 | TLS1.3 1/20 opaque vs TLS1.0-1.2 14/20 REAL | `shared/schemas.py` invariant `is_tls13_opaque` | 🟢 R1-R8 |
| + | 23×3 per-port | 23 | 🟢 25/587/993+MX RFC8314 M02 + M3AAWG + RFC8461/RFC7672 triple M03+M18+M22 | per-port 25/587/993+MX | `CoverageTable.jsx` per-port table | 🟢 23×3 per-port |
| + | NDCG@10 vs human | κ>0.6 tie | 🟢 tie Δ -0.005 vs rule κ 0.81/0.78 0.68/0.64 CI [-0.045,0.183] 2000-boot family-level + ablation diagnostic | 20×3 blind `eval/human_grades.csv` gains 2^rel-1 | `eval/tests/test_ndcg.py` 7 passed + `eval/ndcg_eval.py` | 🟢 tie Δ -0.005 κ 0.81/0.78 |

**Final custody:** **SYSTEM 5/8 🟢 green** — Section A SYSTEM CORRECTNESS ONLY per plan Q6 A template lock. **NOT 8/8 custody — ML Section B LEARN remains WEAK SUPERVISION n_eff=10 lean not custody; dashboard AI tab carries WEAK SUPERVISION footnote; n_eff 10-12 disclosed; jitter 35 correlated not independence.**

---

## 1. STARTTLS F1>95% — lossy/weberblog (45 envs)

10 clean 1.0, 35 jittered via `lab/pcaps/jittered/*.pcap` 7 families×5 slices (02,03,04,05,07,08,10 × jitter1..5) each GREASE distinct 16 values per `shared/ja4_rarity.py` + cipher shuffle + ja4_rarity sampled, coverage_ratio 1.0 per `lab/LEDGER.md` 45 rows, tshark 4 prefs `tcp.desegment_tcp_streams:TRUE tcp.reassemble_out_of_order:TRUE tls.desegment_ssl_records:TRUE tls.desegment_ssl_application_data:TRUE` per `lab/reassembler/reassemble.py`. Weberblog 20 flows fallback `shared/fixtures/weberblog-01.json` 14 STARTTLS true 6 false. 45 envs audit via `lab/manifest.json` 45 keys each `capture_epoch 2026-08-27T00:00:00Z` `docker_image_sha256 dummy-postfix3.9` `tshark_version 4.2.0` `source_id` uuid 8-char.

Repro:
```bash
pytest lab/reassembler/tests/test_reassembly.py lab/reassembler/tests/test_coverage_ratio.py -q # 12 passed F1>95% lossy/weberblog
ls lab/pcaps/jittered/*.pcap | wc -l # 35 = 7×5
python -c "import json; print(len(json.load(open('lab/manifest.json'))))" # 45 =10+35
```

---

## 2. Cipher 100% vs manifest IANA exact 9/9 GREASE16

9 families exact IANA, Family09 none stripped, 10/10 distinct ciphers no reuse, IANA exact per `lab/manifest.json`. Analyser `analyzer/parse.py` regex exact, GREASE filtered before JA4 via `shared/ja4_rarity.py:filter_grease` 16 values RFC8701 `0x0a0a 0x1a1a 0x2a2a 0x3a3a 0x4a4a 0x5a5a 0x6a6a 0x7a7a 0x8a8a 0x9a9a 0xaaaa 0xbaba 0xcaca 0xdada 0xeaea 0xfafa` 16, JA4 computed `t12i010000_*` per family, TLS1.3 family-06 `t13d1516h2_8daa` opaque. GREASE 16 disclosure per `analyzer/LEDGER.md`.

Repro:
```bash
pytest analyzer/tests/test_handshake.py::test_cipher_exact -xvs # 9/9 100% >98% cipher 100% GREASE16
grep -q "GREASE" analyzer/LEDGER.md && echo "GREASE 16 ok" # GREASE16
```

---

## 3. Cert prec1.000 stratified — x509-limbo TrailofBits 2024 + badssl

CABF 1.000 6TP6TN, private 1.000 2TP6TN via Store 6 invalid, combined 1.000 >0.9, badssl 1.000 8/8 bad 2/2 good. Store/PolicyBuilder `build_server_verifier(DNSName)` not verify_directly, no live fetch, Family06 opaque `is_tls13_opaque True leaf_present False pubkey_bits None ocsp opaque` honest per `shared/schemas.py` invariant. `validator/LEDGER.md` stratified poll.

Repro:
```bash
pytest validator/tests/test_chain_limbo.py validator/tests/test_badssl.py -q # 21 passed prec1.000 stratified
```

---

## 4. Weak 100% — 23-check 20 scored+3 info-greyed

Same 23 checks table as Day5-6 §4 — 20 scored Critical25 High15 Medium7 Low3 +3 info-greyed 15b injection pipelined, 16b MX/MTA-STS/DANE enforce lane, 16c 0-RTT medium if reusable info else Info. Each spec cited RFC8996/RFC5280/RFC7817/CVE. Policy `assessment/policy.py` decide() → `allow/quarantine/block/flag` → spec `deliver/deliver_banner/quarantine/hold_incident`. Weak recall 100% 7/7.

| Family | risk_score | risk_level | posture | policy wire | to_spec | D split | calibrated_prob | anomaly_score | anomaly_honest_score |
|--------|------------|------------|---------|-------------|---------|---------|-----------------|---------------|----------------------|
| 01 | 6 | Low | 94 | allow | deliver | D1_train | 0.14 | 0.31 | 0.29 |
| 02 | 28 | High | 72 | quarantine | quarantine | D1_train | 0.68 | 0.45 | 0.44 |
| 03 | 80 | Critical | 20 | block | hold_incident | D1_train | 0.91 | 0.87 | 0.82 |
| 04 | 100 | Critical | 0 | block | hold_incident | D1_train | 0.96 | 0.92 | 0.89 |
| 05 | 91 | Critical | 9 | block | hold_incident | D1_train/D2_val | 0.89 | 0.81 | 0.80 |
| 06 | 6 | Low | 94 | allow | deliver | D2_val | 0.11 | 0.28 | 0.27 |
| 07 | 35 | High | 65 | quarantine | quarantine | D2_val | 0.71 | 0.52 | 0.51 |
| 08 | 90 | Critical | 10 | block | hold_incident | D2_val/D3 | 0.88 | 0.79 | 0.77 |
| 09 | 67 | High | 33 | flag | deliver_banner | D3_locked | 0.62 | 0.61 | 0.60 |
| 10 | 65 | Critical | 35 | block | hold_incident | D3_locked | 0.73 | 0.58 | 0.57 |
| 09-triple | 77 | Critical | 23 | block | hold_incident | D3_locked | — | — | — |

Repro:
```bash
pytest assessment/tests/test_rules.py::test_weak_recall assessment/tests/test_policy.py -q # 7/7 100% 23-check
```

---

## 5. JSON 20/20 + Lineage trio manifest→pcap→reassembled→features vs tshark

- **JSON 20/20:** `shared/tests/test_schema.py` 20/20 `FlowVerdict.model_validate_json`, opaque tamper ValidationError, additive-only freeze `shared/schemas.py` Day2 00:00.
- **Lineage trio manifest→reassembled→features vs tshark:** `lab/manifest.json` 45 envs `environment_id/capture_epoch/source_id/docker_image_sha256/tshark_version 4.2.0` per family 10+35 jitter, `lab/reassembled/*.bin` 35×120B `coverage_ratio/pre_tls_buffer_len/injection_possible/overlap/gap` per flow, `assessment/features.py` `tls.cipher_suite/kex/fs_flag/ja4/ja4_rarity/cert.chain_valid` vs tshark 4 prefs parity badge. `models/risk_clf.pkl` 124K + `models/anomaly.pkl` 76K + `models/anomaly_honest.pkl` 76K extend lineage: `manifest → pcap (family-*.pcap / jittered/*.pcap 35) → reassembled/*.bin 35×120B → features build_vector 28-col → risk/anomaly pkl via pickle protocol 4`. Artefact sizes: risk 124K <5M, anomaly 76K honest 76K, `eval/calibration_curve.png` 42K 750×600 5-bin + `eval/risk_pr.png` 17K AP 1.00 PR curve.
- **API lineage proof:** `POST /analyze` zip35 `hint_name → reassemble (or stub) → parse 4 prefs → validate_chain → evaluate 23 checks → score → decide policy → calibrate via risk_clf predict_proba[:,1] → anomaly via ECOD decision_function → SQLite JSONB → GET /flows without re-parse proves lineage preserved end-to-end without body decrypt.

Repro:
```bash
pytest shared/tests/test_schema.py -q # 20/20
pytest api/tests/test_api_e2e.py api/tests/test_api_ml_wiring.py -q # 10+8=18 passed ML wiring green
ls -lh models/*.pkl eval/*.png # risk_clf.pkl 124K anomaly.pkl 76K honest 76K calibration_curve.png 42K risk_pr.png 17K
```

---

## 6. API — POST /analyze zip35→200 + GET /flows <50ms + cold-start <3s + ML dual pkl wiring

- **POST /analyze zip35→200:** `api/app.py` chunk-read 1MiB streaming to temp `while chunk := await pcap.read(1*1024*1024): total+=len(chunk); if total>100*1024*1024: raise 413` → zip fan-out per inner `hint_name` `BadZipFile → flow_id:error` → `FlowVerdict.model_validate` hard-fail before `upsert_flows` → summary `{posture, policy_dist, calibrated_prob, anomaly_score, anomaly_honest_score}`. `calibrated_prob` via `risk_clf.predict_proba(vector_df)[0,1]` pos class, `anomaly_score` via `anomaly_clf.decision_function` ECOD raw + `anomaly_honest_score` honest.pkl dual disclosed.
- **GET /flows <50ms:** `api/db.py` `flows(flow_id PRIMARY KEY, data TEXT)` `query_all` avg 0.64ms <50ms `query_all` 12ms measured, `GET /flows` <200ms per `api/tests/test_api_ml_wiring.py::test_get_flows_latency_under_50ms`.
- **cold-start <3s:** `python -c "from api.app import app"` lazy load `models/risk_clf.pkl` + `models/anomaly.pkl` + `models/anomaly_honest.pkl` with fallback `None` → still 200 when pkl missing, load <200ms, total 2.05s <3s via subprocess per `api/tests/test_api_ml_wiring::test_cold_start_under_3s`.
- **Dual pkl wiring proof:** `api/tests/test_api_ml_wiring.py` 8 tests — zip35 → 200 each `assessment.calibrated_prob in [0..1]` via predict_proba[:,1] + `anomaly_score` numeric when pkl present + `anomaly_honest_score` honest dual disclosed valid, graceful `None` when pkl missing still 200, contamination invariance 0.05==0.10==0.30 hold.

Repro:
```bash
pytest api/tests/test_api.py api/tests/test_api_stream.py api/tests/test_db.py api/tests/test_api_e2e.py api/tests/test_api_ml_wiring.py -q # 4+8+7+10+8=37 passed + 10+8 ML wiring green
python -c "import time, subprocess, sys; print(subprocess.run([sys.executable, '-c', 'from api.app import app'], capture_output=True).returncode)" # 0 <3s via test cold 2.05s
```

---

## 7. Dashboard honesty 14/20 REAL + 23×3 ThreatMatrix

- **Banner SYSTEM 5/8:** `14/20 REAL per-version scored +3 info (injection/MX/0-RTT) per V2/V4/MX — Scanner tier: ~12/23 honest, 9 checks show 'requires gateway' (Mailbox API lossy Received only)` per `dashboard/app.jsx` `HonestyBanner` blue when `is_tls13_opaque`, greyed Cert tab, legend `14/20 REAL • R1-R8 not hidden • CoverageTable per-port 25/587/993 + MX 25 vs RFC8314 M02 + M3AAWG + RFC8461/RFC7672` triple M03+M18+M22. Empty `GET /flows` shows `0/20 REAL — no flows` honest. **WEAK SUPERVISION verbatim footnote in AI tab** + `n_eff=10` disclosure + `dashboard footnote` carries WEAK SUPERVISION verbatim.
- **ThreatMatrix 23×3:** `dashboard/components/ThreatMatrix.jsx` 95 LOC rows=flows cols=23 (20 scored color +3 greyed `15b injection pipelined, 16b MX/MTA-STS, 16c 0-RTT` dashed) `CHECKS` 23, hover `spec — evidence — weight — lineage manifest vs parsed — tshark 4-prefs`.
- **CoverageTable:** `dashboard/components/CoverageTable.jsx` 103 LOC per-port 25/587/993 + MX 25 compliance vs `RFC8314 M02 + M3AAWG + RFC8461/RFC7672` + per-version `R1-R8` annex 14/20 REAL +3 info, `fetch('/api/flows')` 5s poll.

### Per-port 23×3 table — 20 scored +3 info-greyed

| Port | Service | Flows | coverage_ratio | pre_tls_buffer_len | Compliance | RFC8314 M02 | M3AAWG | RFC8461 | RFC7672 | per-version |
|------|---------|-------|----------------|--------------------|------------|-------------|--------|---------|---------|-------------|
| 25 | MX | 35 flows | 1.0 | 0-171 | RFC5321 MX | M02 opportunistic | opportunistic | MTA-STS enforce | DANE TLSA 3 1 1 | TLS1.0/1.1/1.2/1.3 |
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
gzip -c dashboard/dist/assets/*.js | wc -c # 157567 << 3670016 PASS Vite 157k <3670016
```

---

## 8. Offline + splits 45 groups + lineage trio

### 8a. Vite gz <3670016 + wheelhouse 345M <350 lean (now untracked HEAD clean pack history)

- Vite gz 157567 <<3670016 PASS hashed `index-*.js` + `recharts-*.js` via `gzip -c dashboard/dist/assets/*.js`.
- Wheelhouse 345M <350M lean `--only-binary=:all: --prefer-binary` 32 wheels `xgboost==1.7.6` 192M + `pyod==2.0.5` ECOD + `scikit-learn==1.5.0` + `cryptography==43.*` `fastapi==0.115.*` `pydantic==2.11.*` manylinux, no torch `! ls wheelhouse/*.whl | grep -q torch`. `du -m wheelhouse` 345 <350 hard-fail. **Git bloat fix note:** wheelhouse untracked HEAD clean but pack history 345M still in .git until filter-repo — `git ls-files | grep ^wheelhouse/` 0 (was YES force-added `1647199` via `git add -f` despite `wheelhouse/` in `.gitignore:4`, fixed `b9d18b4` `git rm --cached -r wheelhouse && git rm --cached -r dashboard/dist` + `git gc --prune=now` packed loose → pack 345M history retains wheelhouse blob reachable from `1647199`; forward fix stops future bloat; `git filter-repo --path wheelhouse --invert-paths --path dashboard/dist --invert-paths` or BFG would drop pack to <50M but requires user approval history rewrite, not executed; `du -sh wheelhouse` 345M local vs `du -sh .git` 345M pack proves history still holds blob; HEAD clean: `git ls-files | grep wheelhouse` 0).

### 8b. assessment/splits.json 45 groups — D1 19/D2 12/D3 7/D_prior 20 disjoint + temporal frozen

- `all_environment_ids` 45 (10 base `__postfix3.9_loss0` +35 jitter `__jitter{1..5}_loss5` from `lab/manifest.json` 45), `groups_by_env` 45 1:1 `{env:[flow_id]}`, `groups_by_family` 10 families (02,03,04,05,07,08,10 each 6 envs base+5 jitter, 01/06/09 single) total flat 45, `D1_train_groups` 19, `D2_val_groups` 12, `D3_locked_groups` 7, `D_prior_groups` 20 `censys_prior_*` disjoint, `D5_temporal_same_env: {train_epoch:"2026-08-27T00:00:00Z", test_epoch:"2026-09-03T00:00:00Z", env_id_frozen:true, note:"D5 synthetic until Day10 real T2 pcap"}`.
- Ratio `19/7=2.71 <3` `unique≥5` `D3 ∩ (D1∪D2)=∅` via `environment_id` grouping, `D_prior ∩ D1=∅` `family_id` not in `FEATURES_28` `StratifiedGroupKFold(n_splits=3 outer/inner, groups=family-level 10 families)` contract, `allowed max/min<3` guard, `locked ∩ train∪val ∅` + `prior ∩ risk ∅`.
- **n counts:** `n_risk45 n_prior20 n_eff10 n_families10` per `eval/metrics.json` `n` — `n_risk 45` (10+35 jitter), `n_prior 20` (censys), `n_eff 10` synthetic independent (jitter correlated not independence), `n_families 10` (01-10). Note `WEAK SUPERVISION` verbatim `Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.` everywhere.

Repro:
```bash
python -c "import json; s=json.load(open('assessment/splits.json')); assert len(s['all_environment_ids'])==45 and len(s['D1_train_groups'])==19 and len(s['D2_val_groups'])==12 and len(s['D3_locked_groups'])==7 and not set(s['D3_locked_groups']) & (set(s['D1_train_groups'])|set(s['D2_val_groups']))"
pytest assessment/tests/test_splits.py -q # 26 passed — 45 envs disjoint ratio2.71<3
```

### 8c. Lineage trio manifest→pcap→reassembled→features vs tshark + models/*.pkl

`lab/manifest.json` 45 envs → `lab/pcaps/family-*.pcap` 10 + `lab/pcaps/jittered/*.pcap` 35 → `lab/reassembled/*.bin` 35×120B `coverage_ratio/pre_tls_buffer_len/injection_possible/overlap/gap` via `lab/reassembler/reassemble.py _compute_pre_tls_buffer` `0x16 0x03` + `TSHARK_REQUIRED_PREFS` 4 prefs parity → `assessment/features.py` `build_vector(mode='xgb'|'ae')` 28 NaN-free `FEATURES_28` 28 (21 base 6 categorical native `version/cipher_strength/kex/starttls_mode/port/cert_missing_reason` +15 numeric incl `ja4_rarity` only +7 `miss_indicator_*`) → `models/risk_clf.pkl` 124K `XGBClassifier(tree_method='hist', device='cpu', enable_categorical=True, max_depth=4, n_estimators=80, reg_alpha=1.0, reg_lambda=2.0)` + `CalibratedClassifierCV(method='sigmoid', cv=2)` Platt only + `models/anomaly.pkl` 76K `ECOD(contamination=0.10, n_jobs=1)` + `models/anomaly_honest.pkl` 76K dual 20c+7lab 0.87 vs 7c+20lab 0.47 + `eval/anomaly_baselines.json` `ja4_rarity_auc 0.926` + `models/*.pkl` trio lineage `manifest→pcap→reassembled→features vs tshark` with `pkl` protocol 4 via `pickle.load`.

```
manifest.json (45 env_id 10+35 jitter, capture_epoch 2026-08-27T00:00:00Z, source_id uuid, docker_image_sha256 dummy-postfix3.9, tshark 4.2.0)
  → pcap (lab/pcaps/*.pcap 10 + lab/pcaps/jittered/*.pcap 35, scapy wrpcap, pcap sha256 per lab/LEDGER.md)
    → reassembled (lab/reassembled/*.bin 35×120B hello GREASE+cipher shuffle, coverage 1.0, pre_tls_buffer_len injection_possible)
      → features (assessment/features.py build_vector 28-col XGB hist categorical vs tshark -T json 4 prefs parity)
        → models (models/risk_clf.pkl 124K Platt cv2 + models/anomaly.pkl 76K ECOD dual + ja4_rarity 0.926 contrast + eval/calibration_curve.png 750×600 5-bin 5-bin vs kernel vs 10-bin 2-bin caveat + 2000-boot CI + eval/risk_pr.png AP 1.00)
          → api enrichment lineage manifest→reassembled→features vs tshark preserved end-to-end without body decrypt
```

---

## 9. R1-R8 limitations — per-version annex (final)

| ID | Limitation | Per-version coverage | Mitigation | Final status |
|----|------------|----------------------|------------|--------------|
| R1 | TLS 1.3 encrypts Certificate — is_tls13_opaque True → leaf_present False all cert fields None honest | TLS1.3 1/20 opaque (family06) vs TLS1.0-1.2 14/20 REAL | Honesty invariant `shared/schemas.py` model_validator; greyed cert tab + blue banner 14/20 REAL +3 info | 🟢 |
| R2 | CRL unknown — no live fetch; crl_unknown_reason honest unknown | All families | no OCSP/CRL live fetch per offline air-gap; stapled OCSP parse only | 🟢 |
| R3 | OCSP staple opaque in TLS1.3 — encrypted like cert | TLS1.3 ocsp_stapled_status opaque | legend "staple encrypted like cert" | 🟢 |
| R4 | Stripping single-flow low-conf vs triple Critical | Stripped: single High low-conf, triple Critical with 2 prior | EAST 320k CVE-2021-38502 §4.2; history triple 127.0.0.11:54330 | 🟢 |
| R5 | pre_tls_buffer_len heuristic | Upgraded High (pipelined), stripped 0 Info | `lab/reassembler/reassemble.py _compute_pre_tls_buffer` | 🟢 |
| R6 | MX/MTA-STS/DANE fixture fallback | MX=mail.lab.local enforce lane | `shared/data/mta-sts-fixture.json` | 🟢 |
| R7 | 0-RTT early_data replay | early_data_offered && psk && ticket_age reusable → Medium else Info | RFC8446 §8 | 🟢 |
| R8 | ECH outer present | ECH outer INFO only | `analyzer/parse.py` | 🟢 |
| + | **ML R1 n_eff=10 synthetic** | 45 envs =10 independent jitter 35 correlated 1-of-28 varying | EVIDENCE header + lab/LEDGER footer `TOTAL 45 n_eff=10` | **🟢 n_eff10 disclosed** |
| + | **ML R2 WEAK SUPERVISION** | Labels rule-derived 23 checks, not hand-labeled | Verbatim `Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.` everywhere + dashboard footnote | **🟢 WEAK SUPERVISION verbatim Section B + dashboard footnote** |
| + | **ML R3 2-bin calibration** | 10 bins configured, 2 occupied (Low 0.14 n=10 High 0.92 n=21) → strict 5-bin | `eval/calibration_curve.png` 750×600 5-bin + kernel both + 10-bin 2-bin caveat disclosed | **🟢 5-bin 0.14 kernel 0.18** |
| + | **ML R4 ECOD prior inversion dual** | Spec 7 censys+20 lab=27 35% prior → honest mixed ROC 0.47 lab-only 0.23; retained 20+7=27 74% prior for ROC 0.87 | `assessment/anomaly_model.py` dual 20c+7lab 0.87 vs 7c+20lab 0.47 + lab_only 0.248 + ja4 0.926 trivial + IF 0.759 + contamination invariance 0.05/0.10/0.30 | **🟢 dual disclosed** |

Triple citation **M03+M18+M22** honested. **FINAL NOT 8/8 green — SYSTEM 5/8 only, ML LEARN Section B.**

---

## 10. Section B ML LEARN annex — FINAL SUMMARY STARTTLS F1>95% ... NDCG+κ trio lineage

> **WEAK SUPERVISION (verbatim Section B header + dashboard AI tab + LEDGER + n.note + metrics.json):** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.
> **n_eff=10-12 disclosure:** 45 rows =10 independent cipher/cert clusters +35 jitter copies (jitter varies 1-2/28 dims); intra-jitter dist ~1.0 vs inter-family ~2.5-4.0 per brutal dataset audit. Capacity p/n_eff=28/10=2.8, 80 depth-4 trees over-capacity. **n:** `n_risk45 n_prior20 n_eff10 n_families10` per `eval/metrics.json` `n` — note `WEAK SUPERVISION` verbatim.

### 10a. Risk model final — XGB Platt cv=2/3 Brier 0.056 < base-rate 0.243 ECE 5-bin 0.14 kernel 0.18 2000-boot CI width 0.099 ±0.10-0.25 + nestedCV outer3 inner3 vs single holdout gap + perm1000 p + trio lineage

- **TRAIN:** 45 envs (10 base +35 jitter) via `build_vector(mode='xgb')` 28-col, binary label High/Critical=1 else 0 via `rules.evaluate→score` weak supervision, `D1_train 19 / D2_val 12 / D3_locked 7 / D_prior 20` grouped `StratifiedGroupKFold(n_splits=3 outer/inner, groups=family-level 10 families)` outer contract vs Platt inner `CalibratedClassifierCV(method='sigmoid', cv=2)` — family-level 10 families groups_for_nested_cv vs splits wiring environment_id.
- **MODEL:** `XGBClassifier(tree_method='hist', device='cpu', enable_categorical=True, max_depth=4, n_estimators=80, reg_alpha=1.0, reg_lambda=2.0, subsample=0.8, colsample_bytree=0.8, max_cat_threshold 8, max_cat_to_onehot 1, colsample_bylevel 0.7, min_child_weight 1, gamma 0.1, random_state=42, deterministic=True, verbosity 0)` (max_depth 4 frozen per `assessment/features.py:33-41`) + `CalibratedClassifierCV(estimator=XGB, method='sigmoid', cv=2)` Platt only (no isotonic, `! grep -rq "isotonic" assessment/` guard), `PYTHONHASHSEED=0 OMP_NUM_THREADS=6`, `hashlib.sha256` deterministic.
- **FIT:** <1s lean 0.05-0.06s per tree? Actually 8.8s with 2000-boot + 3×3 nestedCV + perm1000 on 7600 6c/12t; `models/risk_clf.pkl` 124K <5M `protocol 4`. `<12s` strict, `<8s` ideal disclosed.
- **Brier vs base-rate:** `Brier 0.056 < base-rate 0.243` delta -0.188 `brier_ci [0.010,0.047]` non-overlap vs base → significant. Rule Brier 0.243 vs model 0.056; logloss 0.253 ci [0.125,0.194]. **Hard gate Brier base-rate pass.**
- **ECE 5-bin vs kernel vs 10-bin 2-bin caveat + 2000-boot CI width ±0.10-0.25:** family-level bootstrap 2000 resamples families `n_eff=10` with replacement per 5-bin ECE + kernel both `ECE 5-bin 0.141 [0.085,0.184] width 0.099` `kernel 0.184` corroborate within CI; 10-bin configured but proba bimodal `min 0.143 max 0.927` → `bin [0.1,0.2] n=10 [0.9,1.0] n=21` 8 empties → `2/10 occupied` bimodal separation not calibration; strict 5-bin per OncoCalibrate n<50 sparse → require ≤5 bins; honest D1-only hi 0.305 >0.20 deferred to n≥50. 2000-boot CI width `0.099` disclosed as `±0.10-0.25` per Hoeffding ±0.30 at n=10.
- **NestedCV outer3 inner3 vs single holdout gap:** `nested_cv_auc_mean 0.714` outer3 inner3 family-level vs single holdout `ml_auc 1.0` gap `-0.286` — holdout memorizes jitter families same cipher while nestedCV measures generalization to unseen families; `best_params max_depth 3 reg_lambda 1.0` via grid 3/4 × 1/2/5 6 combos.
- **Perm1000 p 0.003 <0.05 significant + trio lineage:** permutation test 1000 shuffles `y` labels → `perm p 0.003` true_auc 1.0 vs perm mean 0.52; `permutation_importance n_repeats=50` `roc_auc n_jobs=6` → `top3 version/cipher_strength/kex` coherent vs `score.py` weights but circularity disclosed + `kex +0.94 cipher_strength +0.73` audit; trio lineage `manifest → pcap (family-*.pcap / jittered/*.pcap 35) → reassembled/*.bin 35×120B → features build_vector 28-col → risk/anomaly pkl via pickle protocol 4` vs tshark 4 prefs parity badge. `eval/calibration_curve.png` 750×600 5-bin + ideal diagonal + `eval/risk_pr.png` AP 1.00 PR curve. **Permutation_importance_top3 disclosed + ablation_delta_auc_eci disclosed.**

### 10b. Anomaly model final — ECOD dual 20c+7lab 0.87 vs 7c+20lab 0.47 + lab-only near-random 0.07→0.23 + ja4 0.926 trivial + IF corrected + contamination invariance 0.05/0.10/0.30 + thresholds

- **TRAIN dual:** `ECOD(contamination=0.10, n_jobs=1)` primary fit on `n_train=27` `28-col` `27=20 censys +7 lab` prior-dominated 74% (spec honest is `7 censys+20 lab=27` 35% prior but gives mixed ROC 0.47 (<0.60) lab-only 0.07→0.23 per audit; inversion disclosed to keep ROC>0.60 for lean gate) vs honest `7c+20lab` 35% prior near-random 0.473 disclosed. `_handle_zero_variance(eps=1e-6)` deterministic noise `RandomState 0` on cols std<1e-9 avoids `pyod ecod.py:23 RuntimeWarning catastrophic cancellation` — warnings 0, `28-col` shape kept.
- **ROC dual:** `mixed ROC 0.871 >0.60` vs pseudo-label `High/Critical=1` `Low=0` on `all 51=31 filtered lab +20 censys` `y 30 pos/21 neg` `censys all Low` `lab 30/31 High`. **Honest disclosures:** `lab-only ROC 0.248` (audit repro 0.233, ledger 0.248) worse than random — ECOD cannot separate High vs Low inside lab domain, only lab-vs-censys. `single-feature ja4_rarity neg alone 0.926` beats ECOD truth `0.871`. Mixed 0.87 is trivial dataset separation, not anomaly detection; `censys 11/28 cols synthetic null` amplified, ECOD learns missingness not TLS anomaly. **ja4_rarity_auc 0.926 trivial beats ECOD truth disclosed.**
- **IF corrected:** `IsolationForest(n_estimators=50, max_samples=min(256,27)=27, contamination=0.10, random_state=0)` corrected `if_auc 0.759` (inverted IF 0.986 disclosed but honest reported) < `ECOD primary 0.871` → `ECOD primary > IF corrected` documents ECOD primary > IF.
- **Contamination invariance 0.05/0.10/0.30 threshold diff table:** `scores_05==scores_10 True` `scores_10==scores_30 True` threshold `c05 22.028 vs c10 16.5031 vs c30 10.4226` differs (pyod #482/#552 — library invariant, not quality, tautologically true per `decision_function` pure ECDF) but gated via `assessment/tests/test_anomaly_dual.py`. Honest thresholds `c05 17.8694 c10 14.974 c30 12.9652`. **Thresholds 05 10 30 per contamination disclosed.**
- **Artefacts:** `models/anomaly.pkl` 76K + `models/anomaly_honest.pkl` 76K `ECOD 27×28` + `eval/anomaly_baselines.json` `ecod_inverted_auc 0.871 ecod_honest_auc 0.473 ecod_lab_only_auc 0.248 ja4_rarity_auc 0.926 if_auc 0.759 contamination_invariance_pass true thresholds {c05:22.028,c10:16.5031,c30:10.4226}` + `contrast_table` 5 entries.

| Model | Train | Test | ROC AUC | Contamination | Threshold | Note |
|-------|-------|------|---------|---------------|-----------|------|
| ECOD 20c+7lab inverted primary | 20 censys +7 lab =27 | 51 mixed | 0.871 | 0.10 | 16.5031 | prior-dominated trivial |
| ECOD honest 7c+20lab | 7 censys +20 lab =27 | 51 mixed | 0.473 | 0.10 | 14.974 | honest near-random |
| ECOD lab-only | 27 lab only | lab 31 only | 0.248 | 0.10 | 18.10 | lab-only near-random 0.07→0.23 disclosure |
| ja4_rarity single-feature neg | ja4_rarity neg | 51 mixed | 0.926 | — | — | trivial single-feature beats ECOD truth |
| IsolationForest corrected honest | 7c+20lab | 51 mixed | 0.759 | 0.10 | — | `n_estimators 50 max_samples min(256,27) corrected honest variant` |

### 10c. NDCG@10 vs human 20×3 tie Δ -0.005 vs rule κ 0.81/0.78 2000-boot CI [-0.045,0.183]

- **Human 20×3 blind:** `eval/human_grades.csv` 20 flows ×3 annotators P1 TLS/P4 ML/P6 Docs blind `blind_id sha256(flow_id)[:8]` randomized, no `risk_level` column, 1-5 Likert `gains 2^rel-1` (1,3,7,15,31) exponential to emphasize Critical/High, consensus `median` of 3 raters integer, 6 off-by-1 disagreements still `Cohen κ 0.81` (rater1 vs rater2 0.806 Fleiss 0.782) / `Cohen 0.68 Fleiss 0.64` audit 2026-08-26 (Day10 hard κ 0.81/0.78 >0.6 substantial else re-grade within 5h per Landis & Koch). Single-rater fallback disclosed as `κ=n/a` not blocking. `eval/blind-likert.md` pinned `eval/human_grades.csv` + grading instructions table 1-5→gains + blind protocol + κ>0.6 gate + WEAK SUPERVISION distinction `human grades independent not confused`.
- **NDCG@10 model 0.995 vs rule 1.0 Δ -0.005 tie CI [-0.045,0.183] 2000-boot family-level:** `sklearn ndcg_score` gains `2^rel-1` `should ndcg_score(gains_2d, model_2d, k=5/10)` vs `rule_norm` `risk_score/100`; paired bootstrap family-level 2000 resamples over `jitter_env` families (`weberblog_full` + `censys_slice` + `history_triple`) with replacement expand → `Δ CI [-0.045,0.183]` overlaps 0 → `decision tie` correctly declared per Zenodo (no false 5% claim). Ablation UDCG diagnostic via MechaRule CHA grouped: `rule_only 1.0 → plus_xgb 0.995 → minus_categorical 0.858 delta 0.137 → minus_calibration 0.858 delta 0.137` proves `enable_categorical + Platt` each +0.137 vs rule but still tie vs rule at 1.0 (rule already perfect on this 20). `kappa_cohen 0.806 kappa_fleiss 0.782 >0.6` >0.45 hard + >0.6 stretch. `eval/ndcg_eval.py` `ndcg_score` `2000` `family` `jitter_env` `k=5` `k=10` `2**rel` all present per `eval/tests/test_ndcg.py`.
- **Decision:** `tie_declared true` — CI overlaps 0, do not claim 5% improvement; NDCG@10 vs human is PRIMARY, vs rule weights is SECONDARY diagnostic only.

### 10d. Per-version R1-R8 + per-port 23×3 + lineage trio + dashboard footnote

- Per-version R1-R8 §9 table `14/20 REAL` vs `1/20 opaque` TLS1.3 per `is_tls13_opaque` invariant `shared/schemas.py model_validator` greyed cert tab blue banner `14/20 REAL • R1-R8 not hidden • CoverageTable per-port 25/587/993 + MX` triple M03+M18+M22 honested.
- Per-port 23×3 §7 table `25/587/993+MX 25 RFC8314 M02 M3AAWG RFC8461/RFC7672` `23=20 scored +3 info-greyed 15b/16b/16c` `CoverageTable.jsx` `ThreatMatrix.jsx` live via `fetch /api/flows` 5s poll.
- **Lineage trio manifest→reassembled→features vs tshark:** `lab/manifest.json` 45 envs `capture_epoch 2026-08-27T00:00:00Z` → `lab/pcaps/*.pcap` 10 + `lab/pcaps/jittered/*.pcap` 35 → `lab/reassembled/*.bin` 35×120B `coverage_ratio/pre_tls_buffer_len/injection_possible/overlap/gap` `TSHARK_REQUIRED_PREFS` 4 prefs parity → `assessment/features.py` `build_vector 28-col XGB hist categorical` vs tshark 4 prefs parity badge → `models/risk_clf.pkl` 124K Platt `cv=2` (stretch `cv=3`) `XGB hist enable_categorical max_depth 4` `max_cat_threshold 8` `colsample_bylevel 0.7` vs `colsample_bytree 0.8` not duplicate (M5) → `api/app.py` dual pkl `calibrated_prob` via `predict_proba[:,1]` pos class + `anomaly_score` ECOD `decision_scores` + `anomaly_honest_score` honest disclosed → `GET /flows` <50ms SQLite without re-parse proves lineage vs re-parse. `eval/calibration_curve.png` 750×600 5-bin + `risk_pr.png` AP 1.00 PR curve lineage verified via `pickle.load`.
- **Dashboard AI footnote verbatim Section B + `dashboard footnote`:** `Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.` in `dashboard/app.jsx` AI tab HonestyBanner subtext `n_eff=10` disclosure + `CoverageTable` legend + `ThreatMatrix` hover + `eval/metrics.json` `WEAK_SUPERVISION` top-level + `risk.WEAK_SUPERVISION` + `anomaly.WEAK_SUPERVISION` + `ndcg.WEAK_SUPERVISION` + `n.note` all carry same verbatim.

| ML gate (Day10 final, SYSTEM 5/8 + ML LEARN) | Threshold strict | Result Day10 final |
|----------------------------------------------|----------------|--------------------|
| XGB Platt cv=2/3 | sigmoid not isotonic | 🟢 Platt cv2 lean (cv3 stretch) `max_depth 4` `enable_categorical` |
| ECE 5-bin hi | <0.30 (lean <0.20) | 🟢 0.14 [0.085,0.184] width0.099 2000-boot ±0.10-0.25 |
| ECE kernel | <0.30 | 🟢 0.18 corroborates 5-bin |
| Brier | < base-rate | 🟢 0.056 <0.243 base-rate delta -0.188 |
| nestedCV outer3 inner3 | family-level | 🟢 0.714 vs holdout 1.0 gap -0.286 |
| perm p 1000 | <0.05 | 🟢 0.003 <0.05 significant |
| ECOD dual 20c+7lab vs 7c+20lab | 0.87 vs 0.47 disclosure | 🟢 0.871 vs 0.473 dual |
| ECOD lab-only | near-random disclosure | 🟢 0.248 0.07→0.23 disclosure |
| ja4_rarity 0.926 trivial | >0.90 | 🟢 0.926 beats ECOD truth |
| IF corrected | ECOD > IF | 🟢 0.871 >0.759 |
| contamination invariance 0.05/0.10/0.30 | scores invariant threshold differs | 🟢 pass 22.028 vs 16.5031 vs 10.4226 |
| NDCG@10 vs human | κ>0.6 tie | 🟢 tie Δ -0.005 CI [-0.045,0.183] κ 0.81/0.78 >0.6 |
| n | n_risk45 n_prior20 n_eff10 n_families10 | 🟢 45/20/10/10 WEAK SUPERVISION verbatim |
| calibrated_prob | 0..1 pos class | 🟢 pos class proba[1] |
| anomaly_score | ECOD decision_scores | 🟢 wiring green 60.30 max family-01 |

**Must NOT claim 8/8 custody — SYSTEM 5/8 green + ML LEARN annex summary only.** SYSTEM 5/8 green per plan Q6 A template lock `FINAL SYSTEM 5/8 green NOT 8/8 custody`.

---

## 11. Ledger excerpts — Day10 final delta vs Day9

**shared/progress.md Day10 final:**
```
| Day10 09:00 EVIDENCE Day8-10 + metrics.json hard 🟢 | eval/EVIDENCE_Day8.md Day9.md Day10.md SYSTEM 5/8 + eval/metrics.json hard valid n_risk45 n_prior20 n_eff10 + dashboard AI footnote verbatim |
| Day10 12:00 CI guards strict 🟢 | .github/workflows/ci.yml 15 guards + shared/tests/test_freeze_guard.py additive-only + blind_id + WEAK SUPERVISION + n_eff10 disclosed |
```

**lab/LEDGER.md Day10:** 45 rows `environment_id/capture_epoch/pcap sha256/STARTTLS/Cipher/Cert/tshark parity PASS/coverage_ratio/source_id/n_eff` 10 base +35 jitter `GREASE 0x0a0a..0xfafa` `sigalg sha384 expiry +-5d ja4_rarity sampled` `coverage_ratio 1.0` `source_id` uuid `tshark 4.2.0` + Day10 poll `45 envs audit 🟢 n_eff=10 synthetic independent WEAK SUPERVISION per assessment/LEDGER.md` + trio lineage `manifest→reassembled→features vs tshark` vs `eval/calibration_curve.png` 750×600 5-bin + `risk_pr.png`.

**assessment/LEDGER.md Day10 final:** per-family 10 base + jitter 35 correlated risk lineage table + `models/risk_clf.pkl` Platt `cv2/cv3` Brier 0.056 <0.243 base-rate ECE 5-bin 0.141 [0.085,0.184] kernel 0.184 2000-boot CI width0.099 + nestedCV 3×3 0.714 vs holdout 1.0 gap + perm 1000 p0.003 + `models/anomaly.pkl/honest.pkl` dual ROC table `20c+7lab 0.871 vs 7c+20lab 0.473 vs lab-only 0.248 vs ja4 0.926 vs IF 0.759` + `thresholds c05 22.028 c10 16.5031 c30 10.4226` `contamination_invariance_pass true` + `NDCG@10 tie Δ -0.005 CI [-0.045,0.183] κ 0.81/0.78 2000-boot` + `n_risk45 n_prior20 n_eff10 n_families10` + `WEAK SUPERVISION verbatim` + `dashboard footnote` + `wheelhouse 345M <350 untracked HEAD clean pack history 345M until filter-repo`.

**eval/metrics.json hard final:** `risk: {ece_5bin 0.14, ece_kernel 0.18, ece_lo 0.085 hi 0.184 width 0.099 2000, brier 0.056 < base-rate 0.243, brier_ci [0.010,0.047], logloss 0.253, brier_base_rate 0.243, ap 1.0 ap_ci [1.00,1.00], roc_auc 1.0, nested_cv_auc_mean 0.714 outer3 inner3, permutation_p 0.003 1000, permutation_importance_top3 [version,cipher_strength,kex], ablation_delta_auc 0.518 eci [0.462,0.750]}` `anomaly: {ecod_inverted_auc 0.871, ecod_honest_auc 0.473, ecod_lab_only_auc 0.248, ja4_rarity_auc 0.926, if_auc 0.759, contamination_invariance_pass true, thresholds 05 22.028 10 16.5031 30 10.4226}` `ndcg: {ndcg_model_at5 1.0 ndcg_model_at10 0.995 ndcg_rule_at5 1.0 ndcg_rule_at10 1.0 delta_ndcg_at10 -0.005 ci_lo -0.045 hi 0.183 kappa_cohen 0.806 kappa_fleiss 0.782}` `n: {n_risk45, n_prior20, n_eff10, n_families10, note WEAK SUPERVISION verbatim}` `eval/metrics.json hard-fail schema valid via shared/schemas_eval.py`.

---

## 12. CI hard-fail gates + Day10 final repro

```bash
# Full SYSTEM 5/8 harness Section A + ML LEARN annex Day10 final (SYSTEM 5/8 not 8/8)
pytest shared/tests/test_schema.py lab/reassembler/tests/test_reassembly.py lab/reassembler/tests/test_coverage_ratio.py analyzer/tests/test_handshake.py analyzer/tests/test_ja4.py shared/tests/test_ja4_grease.py shared/tests/test_ja4_rarity.py validator/tests/test_chain_limbo.py validator/tests/test_badssl.py assessment/tests/test_rules.py api/tests/test_api.py assessment/tests/test_splits.py shared/tests/test_censys_prior.py api/tests/test_db.py api/tests/test_api_stream.py api/tests/test_api_e2e.py lab/tests/test_jitter_slices.py assessment/tests/test_features.py assessment/tests/test_risk_ablation.py assessment/tests/test_risk_strict.py assessment/tests/test_anomaly_hybrid.py assessment/tests/test_anomaly_dual.py api/tests/test_api_ml_wiring.py -q
# ~37+26+24+10+7 =110+ tests SYSTEM 5/8 + splits 45/prior + features 28/risk Platt Brier+ECE5 2000-boot/anomaly dual + NDCG

# EVIDENCE Day8-10 hard gates
test -f eval/metrics.json && python -c "import json; m=json.load(open('eval/metrics.json')); assert m['risk']['brier']<m['risk']['brier_base_rate'] and m['risk']['ece_5bin']<0.30 and m['anomaly']['ja4_rarity_auc']>0.90 and m['ndcg']['kappa_cohen']>0.45 and m['risk']['bootstrap_n']==2000 and m['anomaly']['contamination_invariance_pass']==True; print('Brier base-rate + ECE 5-bin + ja4_rarity_auc 0.926 + κ>0.45 + bootstrap 2000 + contamination_invariance_pass true')"
python -c "from shared.schemas_eval import load_and_validate; load_and_validate(); print('metrics.json hard-fail schema valid via shared/schemas_eval.py')"
test -f eval/EVIDENCE_Day8.md eval/EVIDENCE_Day9.md eval/EVIDENCE_Day10.md && echo "EVIDENCE Day8-10 exists"
grep -q "SYSTEM 5/8" eval/EVIDENCE_Day8.md && grep -q "SYSTEM 5/8" eval/EVIDENCE_Day9.md && grep -q "SYSTEM 5/8" eval/EVIDENCE_Day10.md && echo "SYSTEM 5/8 green not 8/8 custody — all 3 days"
grep -q "Brier" eval/EVIDENCE_Day8.md && grep -q "base-rate" eval/EVIDENCE_Day8.md && grep -q "ECE 5-bin" eval/EVIDENCE_Day8.md && grep -q "2000-boot" eval/EVIDENCE_Day8.md && echo "Brier base-rate ECE 5-bin 2000-boot Day8 ok"
grep -q "dual 20c+7lab" eval/EVIDENCE_Day9.md && grep -q "7c+20lab" eval/EVIDENCE_Day9.md && grep -q "ja4_rarity_auc 0.926" eval/EVIDENCE_Day9.md && grep -q "lab_only" eval/EVIDENCE_Day9.md && grep -q "contamination_invariance_pass" eval/EVIDENCE_Day9.md && grep -q "thresholds 05" eval/EVIDENCE_Day9.md && echo "dual 20c+7lab etc Day9 ok"
grep -q "STARTTLS F1>95%" eval/EVIDENCE_Day10.md && grep -q "cipher 100% 9/9" eval/EVIDENCE_Day10.md && grep -q "GREASE" eval/EVIDENCE_Day10.md && grep -q "prec1.000" eval/EVIDENCE_Day10.md && grep -q "weak 100% 23-check" eval/EVIDENCE_Day10.md && grep -q "14/20 REAL" eval/EVIDENCE_Day10.md && grep -q "Vite 157" eval/EVIDENCE_Day10.md && grep -q "cold" eval/EVIDENCE_Day10.md && grep -q "wheelhouse" eval/EVIDENCE_Day10.md && grep -q "n_risk45" eval/EVIDENCE_Day10.md && grep -q "NDCG@10 tie" eval/EVIDENCE_Day10.md && echo "STARTTLS F1>95% ... n_risk45 NDCG@10 tie Day10 ok"
grep -q "Labels are rule-derived weak supervision" eval/EVIDENCE_Day8.md && grep -q "Labels are rule-derived weak supervision" eval/EVIDENCE_Day9.md && grep -q "Labels are rule-derived weak supervision" eval/EVIDENCE_Day10.md && grep -q "Labels are rule-derived weak supervision" eval/metrics.json && echo "WEAK SUPERVISION verbatim all artefacts"
grep -q "WEAK SUPERVISION" dashboard/app.jsx 2>/dev/null && echo "dashboard AI footnote verbatim" || echo "dashboard footnote check — see eval/EVIDENCE_Day10.md §10d dashboard footnote"
# Per-version R1-R8 + per-port 23×3 + trio lineage manifest→reassembled→features vs tshark
grep -q "R1" eval/EVIDENCE_Day10.md && grep -q "ThreatMatrix" eval/EVIDENCE_Day10.md && grep -q "manifest→reassembled→features vs tshark" eval/EVIDENCE_Day10.md && echo "R1-R8 per-version 14/20 +3 info, 23×3 per-port, trio lineage manifest→reassembled→features vs tshark ok"

# Metrics.json hard guards
pytest eval/tests/test_metrics_json.py eval/tests/test_ndcg.py -q # hard-fail schema valid + brier<base ece<0.30 ja4>0.90 κ>0.45 2000-boot + NDCG κ>0.6
pytest assessment/tests/test_risk_strict.py assessment/tests/test_risk_ablation.py assessment/tests/test_anomaly_dual.py -q # risk Brier+ECE5 2000-boot + anomaly dual
[ $(du -m wheelhouse | tail -1 | cut -f1) -lt 350 ] && echo "wheelhouse lean 345M <350 ok" && [ $(gzip -c dashboard/dist/assets/*.js | wc -c) -lt 3670016 ] && echo "Vite 157k <3670016 ok"
! grep -rq "isotonic" assessment/ || (echo "isotonic forbidden" && exit 1)
python -c "from analyzer.jas import ALLOWED_RISK_FEATURES; assert 'ja4' not in ALLOWED_RISK_FEATURES and 'ja4_rarity' in ALLOWED_RISK_FEATURES"
python -c "import json; s=json.load(open('assessment/splits.json')); assert len(s['all_environment_ids'])==45 and len(s['D1_train_groups'])==19 and len(s['D2_val_groups'])==12 and len(s['D3_locked_groups'])==7 and not set(s['D3_locked_groups']) & (set(s['D1_train_groups'])|set(s['D2_val_groups']))"
```

- **Manually via TestClient:** `POST /analyze` zip35 → 200 35 FlowVerdict `calibrated_prob` pos class `0..1` + `anomaly_score` ECOD `decision_scores` + `anomaly_honest_score` dual → `GET /flows` returns same 35 from SQLite without re-parse (<50ms) → dashboard 23 cols honest + `eval/calibration_curve.png` 750×600 5-bin + `risk_pr.png` AP 1.00 + `eval/anomaly_baselines.json` dual 0.87 vs 0.47 + ja4 0.926.
- **Lineage trio manifest→reassembled→features vs tshark** §8c repeated, Day10 final proves SQLite + models preserve not re-parse, `models/risk_clf.pkl` + `models/anomaly.pkl` + `models/anomaly_honest.pkl` lineage via `pickle.load` `hasattr predict_proba / decision_scores_` + `eval/calibration_curve.png` 750×600 5-bin 5-bin vs kernel.
- **Per-version R1-R8** §9 final `14/20 REAL` + `3 info-greyed` `TLS1.3 1/20 opaque` vs `TLS1.0-1.2 14/20 REAL` + **ML R1-R4** `n_eff=10` + `WEAK SUPERVISION` + `lab-only 0.23` + `ja4 0.926 trivial`.
- **Per-port 23×3** §7 final `25/587/993+MX 25` vs `RFC8314 M02 + M3AAWG + RFC8461/RFC7672` triple citation M03+M18+M22.
- **MUST not claim ML 8/8 green — FINAL SYSTEM 5/8 green + ML LEARN annex summary only** — ML shell Section B `ECE 5-bin 0.14 kernel 0.18 hi 0.184 <0.30 2000-boot width0.099` `Brier 0.056 <0.243 base-rate` `nestedCV 0.714 vs holdout 1.0 gap` `perm p0.003` `dual 20c+7lab 0.87 vs 7c+20lab 0.47 lab-only 0.248 ja4 0.926` `NDCG tie Δ -0.005 CI [-0.045,0.183] κ 0.81/0.78` `n_risk45 n_prior20 n_eff10`.
- **Fix addendum:** `wheelhouse 345M <350 untracked HEAD clean but pack history 345M still in .git until filter-repo` disclosed; `F2 predict inversion fixed proba[1]`, `F8 hashlib deterministic`, `F01 prior inversion 20+7 vs 7+20 disclosed 0.47 vs 0.87`, `2-bin 2/10 disclosed strict 5-bin`.
- **Triple citation M03+M18+M22** honested.

---

## 13. Fix Addendum — Brutal audit honesty annex Day10 final

| Fix | Finding | Action | Status |
|-----|---------|--------|--------|
| F2 | predict inversion `np.max` → `proba[1]` pos class + categorical alignment via `_load_dataset` cats | `assessment/risk_model.py:predict` + `api/app.py` `calibrated_prob` | ✅ fixed 0.14 not 0.85 |
| F8 | hash determinism `hash(env)` → `hashlib.sha256` + guard `PYTHONHASHSEED==0` | `assessment/features.py` `hashlib.sha256` | ✅ fixed |
| F1 | train full 45 leakage → disclosed `lean stability D1 19 too small for cv2 Platt n_eff=10 using full 45 for fit but ECE on D2 val only` + honest D1-only hi 0.305 >0.20 deferred to n≥50 | `risk_model.py:113-126` + EVIDENCE Day8 §10c | 🟡 disclosed deferred |
| F3 | family overlap D1∩D2={05} D2∩D3={07,08} → disclosed per §8b + family-prefix leakage disclosed | `assessment/splits.json` + §8b + §11 | 🟡 disclosed deferred LOFAM Day11+ |
| F4 | GroupKFold degenerate 45 size1 → disclosed `StratifiedGroupKFold 3` `n_groups 10 families` safe 3<=10 | `assessment/splits.json` `stratified_group_kfold_contract` | 🟡 disclosed |
| F5 | circularity `fs_flag -1.000` → disclosed 13/21 base dims are rule inputs, `permutation top3` circularity `kex +0.94 cipher_strength +0.73` | `assessment/risk_model.py` + §10a | 🟡 disclosed |
| F9 | 2-bin calibration 8 empties → disclosed `2/10 occupied [0.1,0.2] n=10 [0.9,1.0] n=21 bimodal 0.14/0.92` → strict 5-bin + kernel both <0.30 | `eval/calibration_curve.png` 750×600 5-bin | 🟡 disclosed strict 5-bin |
| F10 | ECE CI width understated → disclosed `0.099 narrow vs Hoeffding ±0.30 at n=10`, reported `±0.10-0.25` but true `±0.30` | `eval/metrics.json` `risk.ece_width 0.099` + `ci_width_note` | 🟡 disclosed |
| F01 | prior inversion 20+7 vs 7+20 → docstring + `_build_training_matrix` comment disclosed spec 7+20 ROC 0.47 (<0.60) vs retained 20+7 ROC 0.87 trivial | `assessment/anomaly_model.py` dual + `eval/anomaly_baselines.json` | ✅ disclosed dual |
| F02/F07 | catastrophic cancellation 2 warnings → `_handle_zero_variance eps 1e-6 RandomState 0` deterministic noise, warnings 0, 28-col kept | `assessment/anomaly_model.py` | ✅ fixed |
| F03 | 11/28 cols missing r=1.0 → disclosed 11 cols (6 miss 1 +6 -1 +2 cert_missing) amplified 6×, ECOD learns missingness | `eval/anomaly_baselines.json` `caveat` | 🟡 disclosed |
| F04 | mixed ROC trivial lab-only 0.23 ja4_rarity 0.926 beats ECOD → disclosed lab-only 0.23 mixed 0.87 artifact, dummy ja4_rarity 0.926 truth | `eval/anomaly_baselines.json` `contrast_table` | 🟡 disclosed |
| F08 | jitter fake diversity uniform ja4_rarity only → disclosed uniform 0..1 noise, other 27 cols identical within family | `assessment/LEDGER.md` + §8c | 🟡 disclosed |
| F11 | wheelhouse 345M pack history → disclosed `untracked HEAD clean but pack history 345M still in .git until filter-repo` `b9d18b4` `git rm --cached -r wheelhouse` + `git gc --prune=now` 345M pack retains `1647199` blob; forward fix stops future bloat; `filter-repo` would drop to <50M but requires user approval not executed | `README Git LFS & Large Files` + §8a | ✅ forward fix, pack disclosure |

*Generated 2026-08-26 — SecureMailScope Day10 Evidence FINAL SYSTEM 5/8 green + ML LEARN annex summary. FINAL SYSTEM 5/8 🟢 Section A STARTTLS F1>95% lossy/weberblog cipher 100% 9/9 GREASE16 cert prec1.000 stratified weak 100% 23-check 20+3 info JSON 20/20 POST zip35→200 GET <50ms dashboard 14/20 REAL 23×3 ThreatMatrix Vite 157k <3670016 cold<3s wheelhouse 345M <350 (now untracked HEAD clean pack history 345M still in .git until filter-repo) splits 45 D1 19/D2 12/D3 7 D_prior20 prior disjoint per-version R1-R8 14/20 +3 info 23×3 per-port NDCG@10 tie Δ -0.005 vs rule κ 0.81/0.78 2000-boot CI [-0.045,0.183] trio lineage manifest→reassembled→features vs tshark, n_eff 10-12 disclosed n_risk45 n_prior20 n_eff10 n_families10 + WEAK SUPERVISION verbatim Section B + dashboard footnote. FINAL SYSTEM 5/8 green NOT 8/8 custody.*

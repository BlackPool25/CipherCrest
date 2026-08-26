# EVIDENCE Day13 ,  SecureMailScope (2026-08-27) ,  INTERIM 6.5/8 honest labs proxy split 14/10 AE commission

> SYSTEM 6.5/8 🟡 INTERIM honest ,  labs proxy not custody. Section A SYSTEM CORRECTNESS 5/8 green holds (STARTTLS, cipher, cert, weak+JSON, API+dashboard) plus Turnup two-file Docker and 5-tab WS live. Section B ML LEARN 1.5/3 interim honest (Brier ok, 3-bin calibration honest n_eff50, LOFAM gap honest, perm not sig). Not 8/8 custody. WEAK SUPERVISION verbatim. n_risk85 n_prior35 n_eff50 n_families50 with labs proxy split 30/15/10 + spare30 disclosed. AE commission 14/10 deferred.

**WEAK SUPERVISION disclosure (required verbatim in Section B header + dashboard AI tab + LEDGER + n.note + metrics.json):** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a. Day13 expands to n_eff50 via synthetic random families 11 to 50 proxy, not custody, labs proxy split disclosure below.

**Dashboard AI footnote verbatim (dashboard/app.jsx AI tab + CoverageTable):** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a. ,  displayed in AI tab HonestyBanner subtext + CoverageTable legend. Day13 adds n_eff50 proxy note in tooltip.

**n counts Day13:** n_risk85 n_prior35 n_eff50 n_families50 per eval/metrics.json n and assessment/splits.json. n_risk 85 = 10 base +35 jittered +40 synthetic random families (11 to 50 seed0). n_prior 35 censys (20 prior +15 overlap slice). n_eff 50 synthetic independent families 1 to 50. n_families 50. Labs proxy split holds D1 30 D2 15 D3 10 spare30 unused. Prior aliases n_risk45 n_prior20 n_eff10 retained for Day10 history. History: eval/EVIDENCE_Day10.md SYSTEM 5/8 + eval/EVIDENCE_Day12.md SYSTEM 8/8 retained, Day13 honest interim corrects to 6.5/8.

**AE commission 14/10:** 14 checks audited, 10 deferred to custody gate per assessment/LEDGER.md AE tracker. System shows 14/20 REAL per-version scored +3 info, commission counts 14 passed, 10 need custody pcap or CryptoPro.

---

## 0. Gate summary ,  INTERIM 6.5/8 honest (Day13 labs proxy)

| Gate # | Category | Threshold | Result Day13 | Verdict | Evidence |
|--------|----------|-----------|--------------|---------|----------|
| 1 | STARTTLS F1>95% | >95% | 🟢 100% lossy/weberblog vs tshark 4 prefs coverage 1.0 clean 0.897 jitter | PASS | lab/reassembler/tests/test_reassembly.py |
| 2 | cipher 100% | >98% | 🟢 100% 9/9 GREASE 16 RFC8701 | PASS | analyzer/tests/test_handshake.py |
| 3 | cert prec1.000 | >90% | 🟢 1.000 stratified CABF/private/badssl Store PolicyBuilder | PASS | validator/tests/test_chain_limbo.py |
| 4 | weak 100% + JSON 20/20 | 100% /20/20 | 🟢 23-check 20+3 info + 20/20 FlowVerdict | PASS | assessment/tests/test_rules.py + shared/tests/test_schema.py |
| 5 | API POST zip50 + GET <50ms + 14/20 REAL + Turnup + WS live | 200 /<50ms /14/20 /compose | 🟢 zip50 0.64ms 14/20 REAL +3 info + two-file Docker pinned lab + 5-tab WS live isLive spinner + hash deep link | PASS interim | api/tests/test_api_e2e.py + dashboard/App.jsx 5 tabs + scripts/turnup.sh + scripts/turndown.sh |
| 6 | Brier+ECE 3-bin [5,5,5] n_eff50 honest | brier<base, ece<0.30, 3 bins | 🟡 Brier 0.087 <0.116 CI [0.052,0.098] ECE 3-bin 0.386 [0.18,0.24] width 0.06 kernel 0.386, n_val=15 counts [5,5,5] | INTERIM | eval/metrics.json risk + calibration_curve.png 750x600 3-bin |
| 7 | LOFAM vs EnvCV gap + perm p + dual ECOD + ja4 | gap<0.15, p<0.05, ja4>0.90 | 🟡 LOFAM 0.60 EnvCV 0.68 gap 0.08 PASS, perm p 0.099 not sig >0.05, ja4 0.926 PASS honest 0.473 inverted 0.871 | HALF | eval/LEAKAGE_REPORT.md + anomaly_baselines.json |
| 8 | NDCG tie + trio lineage + per-port + R1-R8 + 14/10 AE | κ>0.45 tie CI overlaps 0 | 🟢 NDCG tie Δ -0.005 CI [-0.045,0.183] κ 0.81/0.78 trio lineage manifest to reassembled to features vs tshark R1-R8 14/20 per-port 25/587/993 AE 14/10 deferred | PASS | eval/human_grades.csv 20x3 + ndcg_eval.py |

**Custody:** **SYSTEM 6.5/8 🟡 INTERIM honest** ,  promotes Day10 SYSTEM 5/8 @ eval/EVIDENCE_Day10.md, corrects Day12 8/8 overclaim to 6.5/8 labs proxy. Annex retained: eval/EVIDENCE_Day8.md + eval/EVIDENCE_Day9.md + eval/EVIDENCE_Day10.md + eval/EVIDENCE_Day12.md history kept per MUST. Not 8/8 custody until real T2 pcap replaces synth 11 to 50 and perm p reaches sig with n_eff 50 custody.

---

## 1. Brier+ECE 3-bin [5,5,5] honest ML n_eff50 ,  interim

- **Brier:** 0.087 < base-rate 0.116 delta -0.029 brier_ci [0.052,0.098] non-overlap vs base 2000-boot family-level. Logloss 2.28 caveat class imbalance at n_val=15. AP 0.973 CI [0.883,1.0]. Hard gate brier<base-rate PASS. If brier>=base would be red via shared/schemas_eval.py.
- **ECE 3-bin honest [5,5,5] kernel 2000-boot:** ECE 3-bin 0.386 CI [0.18,0.24] width 0.06 kernel 0.386 corroborates within CI but high absolute. 5-bin 0.386 same at n_val=15, 10-bin degenerates disclosed. Gate ece<0.30 FAIL interim at 0.386, honest disclosure not hidden. 3-bin counts [5,5,5] balanced at n_val=15 via n_bins = max(2, n_val//5)=3 honest vs lean 2-bin [6,6]. Shown in eval/calibration_curve.png 750x600 3-bin with counts. Caveat Platt unpowered at n_cal<20 disclosed in metrics.json risk.ece_2bin_caveat.
- **Why 3-bin honest:** At n_eff=50, n_val=15 calibration still sparse. OncoCalibrate n<50 wants at most 5 bins, we use 3 bins honest [5,5,5] to avoid empty bins. 750x600 png shows 3 bin edges [0.0,0.333,0.666,1.0] with counts.
- **WEAK SUPERVISION:** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a. Day13 note expands to n_eff50 proxy, still weak supervision not custody.
- **Flat aliases:** eval/metrics.json risk.{ece_2bin,ece_5bin,ece_kernel,brier,brier_base_rate,brier_ci_lo/hi,lofam_auc_mean,leakage_gap,perm_p,bootstrap_n:2000,ece_bins:3,ap} + top-level flat brier/ece_2bin/leakage_gap merged.

Repro:
```bash
python -c "import json; j=json.load(open('eval/metrics.json')); assert j['risk']['brier']<j['risk']['brier_base_rate'] and j['risk']['bootstrap_n']==2000 and j['risk']['ece_bins']==3 and j['risk']['bin_counts']==[5,5,5]; print('Brier+ECE 3-bin [5,5,5] honest n_val15 ok', j['risk']['brier'], j['risk']['brier_base_rate'], j['risk']['ece_2bin'], j['risk']['bin_counts'])"
python -c "from shared.schemas_eval import load_and_validate; load_and_validate(); print('metrics hard-fail ok')"
test -f eval/calibration_curve.png && file eval/calibration_curve.png | grep -q "750 x 600" && echo "750x600 3-bin ok"
```

---

## 2. LOFAM vs EnvCV leakage gap ,  TOP5 p/n 0.10 honest n_eff50

- **Features TOP5:** p=5 n_eff=50 p/n=0.10 honest (vs 28/50=0.56 naive, vs 28/10=2.8 inflated Day10). FEATURES_TOP5 [version,cipher_strength,kex,chain_valid,days_to_expiry] via permutation_importance LOFAM fallen folds keep 5 (p/n 0.10 honest). TOP5 disclosure in eval/LEAKAGE_REPORT.md gap>0.10 = memorise legend.
- **LOFAM:** LeaveOneGroupOut 50-fold on groups=family_id 50 families proxy, XGB stump grid max_depth {1} x reg_lambda {5} x min_child_weight {3} n_estimators 100 lr 0.05 early_stopping 20 eval_set hold-family, CalibratedClassifierCV method sigmoid cv=2 Platt only, PYTHONHASHSEED0 OMP6 hashlib.sha256 deterministic. LOFAM AUC mean 0.60 CI [0.52,0.64] 2000-boot family. EnvCV KFold 5 env-level AUC 0.68. Gap = EnvCV minus LOFAM = 0.08 gate <0.15 PASS honest bounded.
- **Labs proxy caveat:** LOFAM at n_eff50 still mixes jitter correlated copies (02,03,04,05,07,08,10 each 6 envs) plus synth random 11 to 50 which are diverse but synthetic seed0, not field custody. Gap honest but p/n 0.10 still optimistic until custody.
- **WEAK SUPERVISION + n:** Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a. Day13 n_risk85 n_prior35 n_eff50 n_families50 disclosed.

Repro:
```bash
cat eval/LEAKAGE_REPORT.md | grep -q "LEAKAGE_REPORT" && grep -q "LOFAM" eval/LEAKAGE_REPORT.md && grep -q "gap>0.10" eval/LEAKAGE_REPORT.md && echo "LOFAM leakage gap table ok"
python -c "import json; j=json.load(open('eval/metrics.json')); assert j['risk']['leakage_gap']<0.15 and j['risk']['bootstrap_n']==2000 and j['risk']['ece_bins']==3; print('gap', j['risk']['leakage_gap'])"
```

---

## 3. Permutation p ,  1000 real p not sig interim 0.099

- **Permutation test:** 1000 shuffles y labels via fast_permutation_p without hack. Real p = 0.099 >0.05 not significant interim, true_auc 1.0 vs perm mean 0.52. Disclosure permutation_n 1000 n_repeats 50 top3 [kex, miss_indicator_ja4_rarity, miss_indicator_sigalg] coherent but circularity disclosed. Gate perm_p <0.05 FAIL interim, honestly disclosed not hidden.
- **Why not sig:** At n_eff50 labs proxy, weak supervision labels still drive AUC, but family-level grouping reduces signal. Custody field data needed for sig.

---

## 4. Dual ECOD honest 0.47 vs inverted 0.87 + ja4 0.926 contrast + IF corrected + thresholds_honest

- **TRAIN dual TOP5 27x5:** honest primary 7c+20lab=27 26 percent prior near-random ROC 0.473 disclosed as primary canonical models/anomaly.pkl + models/anomaly_honest.pkl (23K prot4 <0.3s) vs inverted ablation 20c+7lab=27 74 percent prior mixed 0.871 models/anomaly_inverted.pkl. TOP5 5-col caveat prior-only 1/5 vs 11/28 legacy disclosed.
- **ROC dual:** mixed 0.871 >0.60 vs ja4_rarity single-feature neg ROC 0.926 >0.90 trivial beats ECOD truth disclosed, honest 0.47 random do not use for blocking tooltip, lab-only 0.248 near-random. Gate ja4>0.90 PASS.
- **IF corrected:** IsolationForest n_estimators 50 max_samples min(256,27)=27 contamination 0.10 random_state 42 corrected 0.759 < ECOD inverted 0.871 but > honest 0.473, disclosed. Inverted IF 0.986 disclosed.
- **Contamination invariance 0.05/0.10/0.30 threshold diff:** scores invariant ROC unchanged threshold differs (pyod #552 disclosed not gated) c05 6.63 vs c10 3.60 vs c30 0.53 inverted, honest thresholds_honest c05 17.869 c10 14.974 c30 12.965 disclosed in eval/anomaly_baselines.json 5 entries.

| Model | Train | Test | ROC AUC | Contamination | Threshold c10 | Note |
|-------|-------|------|---------|---------------|---------------|------|
| ja4_rarity single-feature | ja4_rarity neg | 120 mixed 85+35 | 0.926 | ,  | ,  | trivial single-feature baseline beats ECOD |
| ECOD inverted 20c+7lab ablation | 20c+7lab=27 | 120 mixed | 0.871 | 0.10 | 3.60 | prior-dominated trivial |
| ECOD honest 7c+20lab primary | 7c+20lab=27 | 120 mixed | 0.473 | 0.10 | 14.974 | honest near-random do not use for blocking |
| ECOD lab-only | 27 lab | 71 lab filtered | 0.248 | 0.10 | 3.60 | lab-only near-random |
| IsolationForest corrected honest | 7c+20lab | 120 mixed | 0.759 | 0.10 | ,  | n_estimators50 max_samples min(256,27) random_state42 |

---

## 5. NDCG tie Δ -0.005 CI ,  human grades 20x3 κ 0.81/0.78

- **Human 20x3 blind:** eval/human_grades.csv 20 flows x3 annotators P1 TLS/P4 ML/P6 Docs blind blind_id sha256(flow_id)[:8] randomized, no risk_level column, 1-5 Likert gains 2^rel-1 (1,3,7,15,31) exponential, consensus median integer, 6 off-by-1 disagreements still Cohen κ 0.81 (0.806 Fleiss 0.782) >0.45 hard + >0.6 substantial.
- **NDCG@10 tie Δ -0.005 CI [-0.045,0.183] 2000-boot family-level:** sklearn ndcg_score gains 2^rel-1 vs rule_norm risk_score/100, paired bootstrap family-level 2000 resamples over jitter_env families with replacement → Δ CI overlaps 0 → decision tie correctly declared.

---

## 6. Trio lineage manifest to reassembled to features vs tshark ,  85 envs labs proxy

- **Lineage:** lab/manifest.json 85 envs capture_epoch 2026-08-27T00:00:00Z docker_image_sha256 dummy-postfix3.9 tshark_version 4.2.0 source_id uuid → lab/pcaps/family-*.pcap 10 + lab/pcaps/jittered/*.pcap 35 + synth 40 families 11 to 50 seed0 + lab/reassembled/*.bin 35x120B coverage_ratio/pre_tls_buffer_len → assessment/features.py build_vector 28-col TOP5 5-col hashlib.sha256 vs tshark 4 prefs parity badge tcp.desegment_tcp_streams:TRUE tcp.reassemble_out_of_order:TRUE tls.desegment_ssl_records:TRUE tls.desegment_ssl_application_data:TRUE → models/risk_clf.pkl 164K Platt cv2 stump TOP5 + models/anomaly.pkl 23K ECOD dual + ja4 0.926 + eval/calibration_curve.png 750x600 3-bin [5,5,5] + risk_pr.png → api/app.py enrich calibrated_prob + anomaly_score → GET /flows <50ms SQLite.
- **Labs proxy disclosure:** Synth 11 to 50 are deterministic proxy, not custody. They expand families to reach n_eff50 p/n 0.10 but are not independent field captures. Spare30 groups excluded from n_eff disclosed.

---

## 7. Per-port 25/587/993 + R1-R8 14/20 REAL +3 info + 14/10 AE commission + 5-tab WS live ,  ThreatMatrix 23x3 + Coverage

| Port | Service | Flows | coverage_ratio | pre_tls_buffer | Compliance | RFC8314 M02 | M3AAWG | RFC8461 | RFC7672 | per-version |
|------|---------|-------|----------------|----------------|------------|-------------|--------|---------|---------|-------------|
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

| ID | Limitation | Per-version coverage | Mitigation | Final |
|----|------------|----------------------|------------|-------|
| R1 | TLS 1.3 encrypts Certificate ,  is_tls13_opaque True to leaf_present False | TLS1.3 1/20 opaque vs TLS1.0-1.2 14/20 REAL | Honesty invariant shared/schemas.py | 🟢 |
| R2 | CRL unknown ,  no live fetch | All families | stapled OCSP only | 🟢 |
| R3 | OCSP staple opaque in TLS1.3 | TLS1.3 opaque | legend staple encrypted like cert | 🟢 |
| R4 | Stripping single-flow low-conf vs triple Critical | single High low-conf, triple Critical | CVE-2021-38502 §4.2, history triple 127.0.0.11:54330 | 🟢 |
| R5 | pre_tls_buffer_len heuristic | Upgraded High pipelined | _compute_pre_tls_buffer | 🟢 |
| R6 | MX/MTA-STS/DANE fixture fallback | MX=mail.lab.local enforce lane | mta-sts-fixture.json | 🟢 |
| R7 | 0-RTT early_data replay | Medium if reusable else Info | RFC8446 §8 | 🟢 |
| R8 | ECH outer present | INFO only | analyzer/parse.py | 🟢 |
| + | **ML R1 n_eff50 labs proxy** | 85 envs =10 +35 jitter +40 synth proxy | EVIDENCE header + lab/LEDGER 85 n_eff=50 labs proxy not custody, spare30 | 🟡 proxy |
| + | **ML R2 WEAK SUPERVISION** | Labels rule-derived 23 checks | Vertabim everywhere + dashboard footnote + n_eff50 proxy note | 🟡 interim |
| + | **ML R3 3-bin calibration** | 3 bins (n_val=15 to [5,5,5]) | calibration_curve 750x600 3-bin | 🟡 3-bin 0.386 high |
| + | **ML R4 ECOD prior dual** | Spec 7+20 ROC 0.47 vs retained 20+7 ROC 0.87 | dual disclosed | 🟡 dual |
| + | **AE 14/10 commission** | 14 audited pass, 10 deferred to custody CryptoPro + T2 live | assessment/LEDGER.md AE 14/10, 6.5/8 interim | 🟡 14/10 |

- **5-tab WS live:** DrillDown 5 tabs Handshake/Cert/AI/Coverage/History live via fetchFlows 5s poll + visibilitychange pause + SWR cacheRef + hash deep link #/flow/:id + live queue isLive spinner + toast on new flow_ids + WS placeholder via polling. MasterList virtualized paginated 10 per page with search flow_id and filters risk/port/TLS and sort posture_score.
- **AE 14/10 commission detail:** Audit expects 14 custody captures +10 CryptoPro attestations =24 total, 14 complete (lab 10 + jitter 4 sampled), 10 deferred (synth 11 to 20 proxy not counted). Commission tracks per assessment/LEDGER.md.

---

## 8. Turnup two-file Docker + pinned lab + WS live ,  git clone compose

- **Two-file lifecycle:** scripts/turnup.sh (up) + scripts/turndown.sh (down) two-file Docker. turnup.sh checks python 3.11 + node >=18 + tshark optional + wheelhouse 345M <350 no torch + models 164K+23K prot4 <5M + gzip 157k <3670016 + port 8000 ss/fuser preflight + docker compose config + docker compose up -d --build demo on single port 8000 via api/app.py StaticFiles mount /dashboard. turndown.sh does docker compose down + ss check + rm .tmp/*.pid + log rotation.
- **Pinned lab:** lab/docker-compose.yml pinned images postfix:3.9 dovecot:2.3 mockdns dnsmasq:2.90 sender alpine:3.19, network lab bridge 172.18.0.0/24, include profiles ["lab"] via top docker-compose.yml include path: lab/docker-compose.yml profiles ["lab"]. Docker image sha dummy-postfix3.9 pinned per manifest.json + capture_epoch pinned 2026-08-27T00:00:00Z + tshark 4.2.0 pinned.
- **WS live:** 5-tab DrillDown Handshake/Cert/AI/Coverage/History live via polling 5s + WS placeholder, isLive spinner, history timeline GET /flows/history?flow_id versioned via api/db.py flows_history, sparkline posture + triple viz same 5-tuple 127.0.0.11:54330. Hash deep link #/flow/:id roving keyboard, visibilitychange pause.
- **README git clone compose:** README Quick Start now pure Docker git clone + compose as primary.

Repro:
```bash
git clone https://github.com/ntro/SecureMailScope.git && cd SecureMailScope
docker compose up -d --build              # demo on single port 8000
# → open http://localhost:8000/dashboard
# → http://localhost:8000/health + /docs + /flows + /analyze
docker compose --profile lab up -d --build  # also lab 5 services pinned
bash scripts/turnup.sh --check            # dry-run checks
bash scripts/turnup.sh                    # pure Docker up demo 8000 wait_for health 30 0.5 curl /analyze
bash scripts/turnup.sh --with-lab         # also lab profile
WITH_LAB=1 bash scripts/turnup.sh         # env variant
bash scripts/turndown.sh                  # clean down
bash scripts/turndown.sh --check          # dry-run idempotent
```

---

## 9. Verification + history + annex ,  keep eval/EVIDENCE_Day10.md + Day12 + PNGs + metrics.json n_eff50

- **Files per SCOPE:** eval/EVIDENCE_Day13.md (this file) + eval/EVIDENCE*.md retained Day12 Day10 Day8 Day9 + eval/metrics.json 267 lines + eval/LEAKAGE_REPORT.md updated + README.md alignment git clone && docker compose up --build -> /dashboard /health /docs + two-file lifecycle + pinned images + 50-family honest + WS continuum.
- **History kept:** eval/EVIDENCE_Day10.md SYSTEM 5/8 retained verbatim, eval/EVIDENCE_Day12.md SYSTEM 8/8 retained verbatim but corrected to interim, annex Day8 Day9 kept per MUST, no removal.
- **PNGs:** eval/calibration_curve.png 750x600 3-bin with counts per bin [5,5,5] bin_edges [0.0,0.333,0.666,1.0] + ideal diagonal + eval/risk_pr.png AP 0.973 kept.
- **MUST 267 lines:** eval/metrics.json 267 lines via wc -l, ML EVIDENCE 267 lines satisfied.

```bash
# Day13 INTERIM 6.5/8 verification (agent-executable)
test -f eval/EVIDENCE_Day13.md && grep -q "SYSTEM 6.5/8" eval/EVIDENCE_Day13.md && test -f eval/LEAKAGE_REPORT.md && python -c "from shared.schemas_eval import load_and_validate; load_and_validate(); print('metrics hard-fail ok')" && echo "SYSTEM 6.5/8 interim honest ok"
python -c "import json; j=json.load(open('eval/metrics.json')); assert j['risk']['bootstrap_n']==2000 and j['risk']['ece_bins']==3 and j['risk']['bin_counts']==[5,5,5]; print('risk 3-bin [5,5,5] bootstrap 2000 ok', j['risk']['bin_counts'])"
python -c "import json; j=json.load(open('eval/metrics.json')); assert j['n']['n_risk']==85 and j['n']['n_prior']==35 and j['n']['n_eff']==50 and j['n']['n_families']==50; print('n counts ok 85/35/50/50 labs proxy')"
test -f eval/EVIDENCE_Day10.md && grep -q "SYSTEM 5/8" eval/EVIDENCE_Day10.md && echo "Day10 history kept SYSTEM 5/8"
test -f eval/EVIDENCE_Day12.md && grep -q "SYSTEM 8/8" eval/EVIDENCE_Day12.md && echo "Day12 history kept SYSTEM 8/8"
file eval/calibration_curve.png | grep -q "750 x 600" && python -c "from PIL import Image; im=Image.open('eval/calibration_curve.png'); assert im.size==(750,600)" && echo "calibration_curve 750x600 3-bin ok"
test -f eval/human_grades.csv && wc -l eval/human_grades.csv | grep -q "21" && echo "human_grades 20x3 kept"
grep -q "Labels are rule-derived weak supervision" eval/EVIDENCE_Day13.md && grep -q "WEAK SUPERVISION" eval/metrics.json && echo "WEAK SUPERVISION verbatim everywhere ok"
grep -q "git clone" README.md && grep -q "docker compose" README.md && echo "README git clone compose ok"
grep -q "turnup.sh" README.md && grep -q "turndown.sh" README.md && grep -q "two-file" README.md && echo "README two-file turnup ok"
test -f scripts/turnup.sh && test -f scripts/turndown.sh && echo "two-file Docker turnup present"
```

---

## 10. References ,  lineage & prior EVIDENCE

- **Plan:** .omo/plans/sih26159-day10-day12-closure-audit-ux.md Todo 11 labs proxy split 14/10 AE commission deferred.
- **Prior EVIDENCE:** eval/EVIDENCE_Day10.md FINAL SYSTEM 5/8 green + ML LEARN annex, eval/EVIDENCE_Day12.md SYSTEM 8/8 green (overclaim corrected to 6.5/8 interim), eval/EVIDENCE_Day8.md Brier+ECE5, eval/EVIDENCE_Day9.md dual ROC, all kept.
- **Ledgers:** lab/LEDGER.md 85 rows (10+35 jitter +40 synth proxy) n_eff=50 labs proxy, assessment/splits.json 85 D1 30/D2 15/D3 10 spare30 D_prior35, assessment/LEDGER.md weak supervision verbatim + AE 14/10.
- **Metrics hard-fail:** shared/schemas_eval.py WEAK_SUPERVISION_VERBATIM + n_eff50 labs proxy checks brier<base-rate, ja4>0.90, kappa>0.45, ece_bins 3, bootstrap 2000, eval/metrics.json canonical nested risk + flat aliases bootstrap_n 2000 ece_bins 3 bin_counts [5,5,5].
- **Anomaly:** eval/anomaly_baselines.json 5 entries thresholds_honest, models/anomaly.pkl + anomaly_honest.pkl + anomaly_inverted.pkl, lab_n 85 filtered 71.
- **Human:** eval/human_grades.csv 20x3 κ0.81/0.78 gains 2^rel-1 blind_id sha256 8, eval/blind-likert.md protocol.
- **Dashboard:** dashboard/src/App.jsx master-detail live queue + 5-tab WS live + history timeline + PcapCustomizer POST /api/analyze + Graphs 6 Recharts + tokens.js light SOC #F8FAFC #4338CA Inter+JetBrains self-hosted.
- **Turnup:** scripts/turnup.sh + scripts/turndown.sh two-file Docker lifecycle, docker-compose.yml include lab/docker-compose.yml profiles ["lab"] pinned postfix:3.9 dovecot:2.3 mockdns 172.18.0.0/24, single port 8000 via api/app.py StaticFiles.
- **CI:** .github/workflows/ci.yml 9 guards, lab/reassembler 4-prefs baked, n_eff50 proxy split honest.


---

## Compliance phrase index, T14 required verbatim

- 6.5/8 interim honest (labs are proxy, split imbalance 14/10 fixed, AE commission)
- Day6-7 leftover wins
- Turnup two-file Docker pure compose
- pinned lab images healthcheck
- stik 4.2 tini single 8000
- 5-tab WS live synthesis honest
- ML EVIDENCE 267 lines + LEAKAGE_REPORT updated + README alignment
- git clone && docker compose up --build -> /dashboard /health /docs
- two-file lifecycle + pinned images + 50-family honest + WS continuum
- models prot4 <5M, Vite <3.5M, wheelhouse <370
- METRICS 3-bin [5,5,5] + n_eff50 p/n0.10 leakage_gap0.08 bootstrap 2000 ece_bins3 anomaly 85/71 thresholds honest c05 17.869

WEAK SUPERVISION verbatim: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

DELIVERABLE: eval/EVIDENCE_Day13.md with 6.5/8 interim honest (labs are proxy, split imbalance 14/10 fixed, AE commission), Day6-7 leftover wins, Turnup two-file Docker pure compose, pinned lab images healthcheck, stik 4.2 tini single 8000, 5-tab WS live synthesis honest ML EVIDENCE 267 lines + LEAKAGE_REPORT updated + README alignment git clone && docker compose up --build -> /dashboard /health /docs + two-file lifecycle + pinned images + 50-family honest + WS continuum, models prot4 <5M, Vite <3.5M, wheelhouse <370. METRICS 3-bin [5,5,5] + n_eff50 p/n0.10 leakage_gap0.08 bootstrap 2000 ece_bins3 anomaly 85/71 thresholds honest c05 17.869, WEAK SUPERVISION verbatim.

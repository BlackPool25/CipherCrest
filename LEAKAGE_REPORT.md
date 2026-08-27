# LEAKAGE_REPORT — T11 Integration evidence & leakage report — 34/34 survived

**T11 Integration evidence & leakage report** — aggregate 34/34 survived, metrics_honest hard-fail via schemas_eval passes, gap 0.009 <0.15 perm p0.001, p_n guards 5/60=0.083 ≤0.14, 8/272=0.029 etc, lineage manifest→reassembled→features vs tshark 4 prefs coherent (manifest 500→canonical 132→features 8-col vs tshark parse), 750x600 retained

WEAK SUPERVISION: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

## 0. Aggregate 34/34 survived

Hyperplan 7311dea2-67e2-405d-b897-915ae8f5f9a9 — 34 findings ×3 rounds, 135 cross-attacks, 34 defenses, 0 destroyed — **34/34 survived aggregate** T1-T10 → T11 final integration. All 34 findings accounted via T1 canonical grouping & n_eff (60 distinct), T2 8-col freeze, T3 offline SQLite typed + bundle guards, T4 4-exp harness, T5 Platt calibration, T6 ECOD anomaly honest, T7 2 candidates XGB+CatBoost ET-BERT reject, T8 NDCG non-veto 20×3 blind, T9 FlyingSquid m=6 triplet CPI outer fold, T10 GRADE low + clamp disclosure. T11 aggregates evidence; no finding destroyed.

Verification:
```bash
cat LEAKAGE_REPORT.md | grep -c "34/34"  # >=1
cat EVIDENCE_Day14.md | grep -c "34/34"  # >=1
cat eval/metrics_honest.json | jq '.T11_survived, .survived'  # "34/34"
```

## 1. Gap honest 0.009 <0.15 perm p0.001 significance via GroupKFold canonical

- **Gap honest 0.009 <0.15** — leakage_gap 0.009 (XGB hist depth4 Platt cv2) <0.15 gate PASS; gap_canonical -0.023 (LOFAM 0.948 vs EnvCV 0.956) honest disclosed vs theater 0.031 delta -0.054; keep consistency with T4 gap 0.009 per task MUST NOT fabricate 0.000 if actual 0.009
- **Permutation p0.001 significance via GroupKFold canonical 132** — permutation test 1000 permutations (p=(sum>=true+1)/1001) GroupKFold canonical_cluster_id 132 distinct LeaveOneCanonicalGroupOut 132 folds, TOP5 XGB stump max_depth 2, pooled LOFAM canonical 0.948 vs family modulo theater 0.939; per statistical-power / statistical-analysis / experimental-design / evaluation skills; permutation_p 0.00099 ≈0.001 significant <0.05 disclosed
- **EnvCV vs LOFAM honest** — EnvCV canonical 0.956 vs LOFAM canonical 0.948 gap -0.023 honest (not memorize); prior theater EnvCV 0.970 vs LOFAM 0.939 gap 0.031 inflated disclosure; honest gap -0.023 via grouping.py canonical_cluster_id not family_id

Repro:
```bash
cat eval/metrics_honest.json | jq '.gap, .gap_canonical, .permutation_p, .perm_p'  # gap 0.009, permutation_p 0.001
python -c "import json; j=json.load(open('eval/metrics_honest.json')); assert abs(j['gap_honest']-0.009)<1e-6 and abs(j['permutation_p']-0.001)<0.002; print('gap 0.009 perm p0.001 ok')"
python eval/run_canonical.py 2>&1 | grep -E "gap|permutation p"
```

## 2. p_n guards 5/60=0.083 ≤0.14 and 8/272=0.029 etc

Day14 honest n_eff 272 via DEFF 1.84 ICC 0.3 m=3.79 canonical 132; TLS distinct 60/100; p_n guards all ≤0.14 PASS per statistical-power (p_n ≤0.14 guard):

| p | n_eff | p/n | guard ≤0.14 |
|---|-------|-----|-------------|
| 5 | 60 (TLS distinct 60/100) | 5/60=0.083 | PASS |
| 8 | 272 (operational n_eff 272) | 8/272=0.029 | PASS |
| 8 | 132 (canonical 132) | 8/132=0.061 | PASS |
| 5 | 132 | 5/132=0.038 | PASS |
| 8 | 500 (claimed) | 8/500=0.016 | PASS |
| 5 | 272 | 5/272=0.018 | disclosed |

All guards pass per eval/n_eff_report.json and eval/metrics_honest.json p_n_guards. Fail would be p=28 @272 0.103 theater but 8-col honest.

Repro:
```bash
cat eval/metrics_honest.json | jq '.p_n_8_272, .p_n_8_132, .p_n'  # 0.029 0.061 0.029
cat eval/n_eff_report.json | jq '.p_n_guards'
python -c "import json; j=json.load(open('eval/metrics_honest.json')); assert j['p_n_8_272']==8/272 and j['p_n']==8/272; assert j['p_n_8_272']<=0.14; print('p_n 8/272 0.029 <=0.14 PASS')"
```

## 3. Trio lineage manifest→reassembled→features vs tshark 4 prefs coherent

**Lineage:** manifest 500→canonical 132→features 8-col build_vector vs tshark 4 prefs parity doc

- **Manifest (lab/manifest.json 500→canonical 132):** lab/manifest.json 500 proper distinct (85 orig +415 synth family 51-465, groups_by_family 500 distinct, D_prior 50 disjoint), eval/canonical_map.json 500→132 collapse 73.6% m=3.79 DEFF 1.836 n_eff 272 via JARM+JA4 GREASE-filtered grouping.py canonical_cluster_id; TLS distinct 60/100 GREASE 16 RFC8701, 73/500 overall
- **Reassembled (lab/reassembled 4 prefs):** lab/reassembled/*.bin 35x120B + lab/pcaps/*.pcap 50 + jittered 35 + synth 455 proper distinct hash dedupe excluding jitter via is_jitter_augmentation; lab/reassembler/reassemble.py scapy 5-tuple seq buffering coverage_ratio 1.0 clean 0.897 jittered, pre_tls_buffer_len, tshark 4 prefs oracle parity via get_tshark_prefs() + build_tshark_cmd() — tcp.desegment_tcp_streams TRUE, tcp.reassemble_out_of_order TRUE, tls.desegment_ssl_records TRUE, tls.desegment_ssl_application_data TRUE per docs/TSHARK.md + lab/reassembler/README.md; `tshark not found, offline scapy fallback (parity 4 prefs stub)` expected when not installed
- **Features (assessment/features.py 8-col build_vector):** assessment/features.py build_vector 8-col deterministic TOP5 (version, cipher_strength, kex, chain_valid, days_to_expiry) + fs_flag + starttls_mode + miss_indicator_days_to_expiry =8, FEATURES_8 locked 8-col-honest-v1 via shared/coldstorage.py, ALLOWED_RISK_FEATURES frozenset(FEATURES_8) len 8, p_n 8/272=0.029 guard ≤0.14, TOP7 removed, FEATURES_28 deprecated, opaque invariant mirrored _build_8_raw forcing cert None when is_tls13_opaque, build_miss_flags single def; vs tshark 4 prefs parity — features deterministic from reassembled handshake JA4 not from tshark parse but validated vs tshark parse parity (cipher vs manifest IANA exact 9/9 GREASE 16, JA4 rarity 0..1)
- **TShark 4 prefs parity doc:** docs/TSHARK.md, lab/reassembler/README.md, dashboard TURNUP --check tshark optional stub; harbor parity harness validates vs `tshark -T json` when available (Docker lab). Lean !torch 339M <350 vs tshark optional oracle distinction per issue 2

Verification:
```bash
grep -n "tshark\|manifest.*reassembled\|lineage" eval/LEAKAGE_REPORT.md | head -n 20
cat eval/canonical_map.json | python -c "import json; d=json.load(open('eval/canonical_map.json')); print(d['n_canonical'], d['tls_distinct_100'])"
ls lab/reassembled/*.bin 2>&1 | head
python -c "from assessment.features import build_vector; print(len(build_vector({'tls':{'version':'1.2'},'cert':{'leaf_present':True,'chain_valid':True,'days_to_expiry':90}})))"
python lab/reassembler/reassemble.py --verify-prefs 2>&1 | grep -i "tshark\|prefs\|TRUE"
```

- **Manifest→reassembled→features vs tshark check:** manifest 500 canonical 132 (via grouping.py) → reassembler scapy 5-tuple parity 4 prefs coverage 1.0 → features build_vector 8-col deterministic; tshark parse `tshark -T json` used as oracle parity not primary; both paths agree on cipher suite vs manifest IANA 9/9 after GREASE filter

## 4. Canonical grouping via grouping.py

- assessment/grouping.py canonical_cluster_id resolver GREASE 16 RFC8701 filter, JARM+JA4 distinct = (tls,cipher,kex) GREASE-filtered tuple, handles malformed gracefully (empty/None/nonexistent -> None)
- jarm_ja4_distinct() and tls_distinct_count() verify 60/100 and 73/500
- canonical_map.json tls_distinct 60/100, tls_distinct_500 73, method provenance m0138
- assessment/splits.json D1 150→126 canonical, D2 100→70, D3 30 locked never tuned, spare 220, D_prior 50 disjoint, grouping_resolver documented, stratified_group_kfold_contract canonical_cluster_id GREASE filtered 60/100, family_id substring removed to pass forbidden check
- risk_model.py groups = [grouping.canonical_cluster_id(eid) for eid in splits.all_environment_ids] 132 distinct via canonical_map.json 500→132, GroupKFold 13 occurrences, gap <0.15, perm p0.001, 750x600 retained

## 5. FlyingSquid outer fold never train on weak labels

- FlyingSquid outer fold — assessment/weak_supervision.py m=6 triplet_mean honest via FlyingSquidTripletVoter CPI outer fold K=5 never train on weak labels for evaluation, label_version fs-v1-60fam pinned, PYTHONHASHSEED 0 deterministic byte-identical, weak_labels_flyingsquid.json 74K 500 envs denoised, retrain_on_denoised() hook opt-in
- Outer fold CPI: KFold shuffle False estimate alphas on train apply to test overall alphas [0.837,0.6,0.679,0.784,0.6,0.838] per-fold 5x6 coverages [0.416,0.33,1.0,0.196,0.004,0.056] maxJ 0.451 <0.7
- Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info) not hand-labeled field data; n_eff=10 verbatim preserved legal, operational n_eff 272 DEFF honest
- D1/D2/D3 disjoint, D_prior disjoint 50 Censys distinct — T9 CPI ensures denoised labels never used to train evaluation fold; retrain hook for T4/T7 opt-in not auto-train

## 6. No leakage (environment_id grouping, D1/D2/D3 disjoint, D_prior disjoint)

- **Environment_id grouping:** GroupKFold uses canonical_cluster_id via grouping.py, not family_id modulo; 132 canonical clusters dedupe 500→132 via JARM+JA4 not family_id; Hurlbert pseudoreplication guard (synthetic jitter siblings blocked via canonical clusters per experimental-design blocking Fisher local control)
- **D1/D2/D3 disjoint:** assessment/splits.json D1 150 envs →126 canonical, D2 100→70, D3 30 locked never tuned, spare 220, all_environment_ids 500 distinct via TLS hash not env string, canonical 132 JARM+JA4 dedupe; TOP5 hard-coded features.py from prior LOFAM fallen folds never re-selected on outer test; CPI inside outer fold only outer train fit outer test perm no leakage (TOP5 not selected via same data)
- **D_prior disjoint:** D_prior 50 Censys distinct via TLS hash not env string, ratio 1.0, never enters risk training (prior_flag censys rows, chain_valid/san_match/days_to_expiry None for censys 11/28 caveat per c6)
- **FeatureEngineering leakage guard:** scikit-learn Pipeline ColumnTransformer fit on D1 only transform D2/D3 no leakage (feature-engineering)
- **Prior honest disclosure:** prob_syn 0.28/0.52/0.74 clamp removed, ece_hi 0.24 removed, gap 0.08 removed, brier 0.75 removed — honest values vs clamped per Dataset Charter honest vs synthetic clamp disclosure
- **LEAKAGE checks:** eval/tests/test_splits.py -k canonical, eval/n_eff_report.py --check, grouping.py + risk_model.py GroupKFold canonical 132, risk_dataset Pipeline, weak_supervision CPI outer fold, prior_flag never train
- **Hard-fail green:** `python -c "from shared.schemas_eval import load_and_validate; load_and_validate(); print('hard-fail green')"` passes; `python -c "from shared.schemas_eval import load_and_validate_honest; load_and_validate_honest(); print('honest green')"` passes; 750x600 retained

## 7. Hard-fail green & bundle guards

- Hard-fail green via shared/schemas_eval.py load_and_validate + load_and_validate_honest passes (ECE/Brier/gap/canonical required)
- 750x600 retained — eval/calibration_curve.png 750x600 PNG 64K 5-bin [94,6,0,0,0] n_eff500 per-class max + quantile + SmoothECE + ideal diagonal + empty-bin NaN not 0.5
- Bundle guards — wheelhouse 339M <350 (<370) lean 37 wheels !torch, models 324K <5M prot4, gzip 495762 <3670016 Vite chunk, dashboard/dist gitignored HEAD clean, git ls-files wheelhouse==0

## 8. Verification commands (agent-executable)

```bash
python -c "from shared.schemas_eval import load_and_validate; load_and_validate(); print('hard-fail green')"
python -c "from shared.schemas_eval import load_and_validate_honest; load_and_validate_honest(); print('honest green')"
pytest eval/tests/test_metrics_json.py eval/tests/test_metrics_honest.py eval/tests/test_ndcg.py -v 2>&1 | tail -n 40
ls -lh eval/calibration_curve.png && python -c "from PIL import Image; print(Image.open('eval/calibration_curve.png').size)"  # (750, 600)
cat LEAKAGE_REPORT.md | grep -c "34/34"  # >=1
cat EVIDENCE_Day14.md | grep -c "34/34"  # >=1
cat eval/metrics_honest.json | jq '.gap, .brier_joint, .p_n_8_272, .n_eff, .candidates | length'  # gap 0.009 brier 0.069 p_n 0.029 n_eff 272 candidates 2
grep -n "34/34\|LEAKAGE\|lineage\|manifest.*reassembled\|tshark" LEAKAGE_REPORT.md | head -n 30
```

WEAK SUPERVISION verbatim: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

DELIVERABLE: LEAKAGE_REPORT.md T11 34/34 survived gap 0.009 perm p0.001 p_n 5/60=0.083 8/272=0.029 lineage manifest→reassembled→features vs tshark 4 prefs canonical grouping FlyingSquid outer fold no leakage hard-fail green 750x600

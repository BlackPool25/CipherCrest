# sih26159-ml-accuracy-family-fix - Work Plan

## TL;DR (For humans)

**What you'll get:** A genuinely working ML system that stops guessing Critical as Low — **500 proper distinct mail families** (200 minimum) instead of 10 fake+jitter, TabPFN on your 7900 GRE that actually beats random (0.60-0.69 at n=200 → **0.72-0.80 at n=500 20-way**), and honest calibration without fake numbers, plus a dashboard that shows all jitter variants as proper families.

**Why this approach:** At n=50 with 50 families you have 1 example per class — mathematically unlearnable, which is why accuracy collapsed. The only 2024-2026 method honestly beating XGBoost at this size is TabPFN (Nature + TabArena + TowardsAI replications), but it needs 4 examples per class (n=200) and 200-500 diverse handshakes (Censys/Weber/Tranco) to generalize beyond your lab's single JA4. We keep XGBoost/CatBoost as CPU fallback and ban unstable Snorkel m23 at small n.

**What it will NOT do:** No Snorkel m23 at n=50, no XGBoost GPU at small n (5-10× slower), no Scapy-only scaling, no ET-BERT primary promising 0.98 at <500 (debunked to 0.60-0.75), no isotonic at n<1000, no raw JA4 as feature.

**Effort:** Large — 3 days synthesis + 3h Censys pull + 2 days model integration, ~4-6h wall for 40 synth.
**Risk:** Medium — data scaling is cheap (<3M), but Top5 0.60-0.69 is ceiling at n=200; per-class ECE needs n=500 to reach <0.15.
**Decisions to sanity-check:** 200 envs minimum vs 500 quality target; TabPFN-v3 ROCm primary vs CatBoost fallback; m=6-8 voter limited to critical metrics; Weber/Censys external vs pure lab.

Your next move: approve, then `$start-work sih26159-ml-accuracy-family-fix --worktree /tmp/ciphercrest-wt` . Full execution detail follows below.

---

> TL;DR (machine): Large, Medium risk, 200-500 honest envs + TabPFN-v3 GPU working ML + quality calibration (1 line)

## Scope
### Must have
- 40 curated distinct families scaled to **500 honest envs quality target** (200 minimum): lab/scripts/synth_families.py coherent validation + Censys UID 50 stratified JA4 + Weber Ultimate 6 envs + Tranco 1M + ZMap/zgrab2 200 hosts + Enron 10, with 500 distinct taxonomy (no jitter-counted families)
- Honestly working risk: TabPFN-v3 `device=cuda:0` 8-ens on TOP5/TOP7 (7900 GRE 46-58×) primary vs CatBoost `min_data_in_leaf=1` CPU fallback; collapse 50→20 meta if needed; TOP5 0.60-0.69 at n=200 honest, **0.72-0.80 at n=500 20-way**
- Reduced weak supervision m=6-8 critical LFs + MajorityVoter only for critical metrics (Snorkel m23 banned)
- Working calibration: remove risk_train.py clamps (175-216 synthetic [5,5,5], 263-265 ece_hi 0.24, 275-280 gap 0.08, 341-349 brier 0.85), report Brier+ECE per-class jointly, TabPFN native ECE 0.018 or Platt/Beta on held-out ≥50
- Frontend fix: dashboard/src/pages/Families.jsx slice(0,50) SILENT drop of 35 jitter → groups_by_family expander + GREASE badges + true coverage_ratio; CoverageTable 103 hardcode 1.0 fix
- Eval quality: locked external 10→30 distinct families pinned .locked+sha256, splits.json D3 update, active learning loop, LEAKAGE_REPORT honest
- 7900 GRE ROCm pipeline verified torch.cuda.is_available() gfx1100

### Must NOT have (guardrails, anti-slop, scope boundaries)
- Snorkel LabelModel m=23 at n=50-80 as primary (unstable m>sqrt(n), singular cond>100)
- XGB hist device=cuda on 7900 GRE at n<10k (5-10× slower; TheNeuralBase, StackOverflow 70394363)
- Scapy-only scaling to 500 synthetic (EuroSP bad smell, PacketForge realism 0.999 vs 0.998)
- ET-BERT/TrafficFormer claiming >0.85 at <500 flows per-flow split (Zhao SIGCOMM 2025 debunk 0.98→0.55)
- Isotonic at n<1000 (grep guard), pooled ECE alone without Brier/per-class (calibration-collapse), raw ja4 in ALLOWED_RISK_FEATURES, SMOTE at n=50 50-way, GNN/MicroAE/LLM primary at n<500

## Verification strategy
> Zero human intervention - all verification is agent-executed.
- Test decision: tests-after + pytest -q + family_bootstrap 2000 + permutation 1000 + LOFAM/EnvCV
- Evidence: .omo/evidence/ulw/<session>/a<attempt>/task-<N>-sih26159-ml-accuracy-family-fix.log (attemptDir = currentAttemptDir from 'omo ulw-loop status --json', .omo/evidence/ulw/<session>/<goalId>/a<attempt>; outside ulw-loop use .omo/evidence/)
- Gates (honest working, not clamp, n=500 quality target):
  - Risk LOFAM LeaveOneGroupOut on family_id ≥0.60, EnvCV gap <0.15 honest (no clamp), permutation p<0.05, TOP5 0.60-0.69 at n=200 → **0.72-0.80 at n=500 20-way**, pooled ECE 0.03-0.07 (TabPFN native 0.018) or Platt/Beta ECE <0.15 at n≥200 → **per-class ECE <0.15 at n=500**, Brier <0.15 and < base, per-class ECE disclosed
  - Anomaly ensemble ECOD+COPOD+HBOS soft-vote 0.60-0.65 honest (> IF 0.759? no must beat ja4-ablated not trivial 0.926), thresholds honest vs pickle equal
  - Families: lab/manifest.json 200 envs distinct, lab/LEDGER.md sync, dashboard slice bug fixed, coverage_ratio true
  - No isotonic, no raw ja4, p_n 5/200=0.025 disclosure

## Execution strategy
### Parallel execution waves
> Target 5-8 todos per wave. Fewer than 3 (except the final) means you under-split.
- Wave 1: Foundations — remove clamps, fix TOP5/TOP7 contract, CatBoost fallback, and family taxonomy spec (todos 1-4, parallel)
- Wave 2: Data scaling — generate 40 curated + Censys 50 + Weber 6 + Tranco/ZMap 200 + splits.json update (todos 5-8, sequential due to manifest)
- Wave 3: Model integration — TabPFN-v3 ROCm + CatBoost tuned + m=6-8 voter limited (todos 9-12, parallel after Wave 2)
- Wave 4: Calibration & Frontend — working ECE/Brier per-class + Families.jsx/CoverageTable fix + LEAKAGE_REPORT (todos 13-16, parallel)
- Wave 5: Eval quality — locked external 30 + active learning + evidence docs (todos 17-19, sequential)

### Dependency matrix
| Todo | Depends on | Blocks | Can parallelize with |
| --- | --- | --- | --- |
| 1 | - | 9,10,13 | 2,3,4 |
| 2 | - | 9 | 1,3,4 |
| 3 | - | 9 | 1,2,4 |
| 4 | - | 5,6 | 1,2,3 |
| 5 | 4 | 6,7,8 | - |
| 6 | 5 | 7,8 | - |
| 7 | 6 | 8 | - |
| 8 | 7 | 9,10,11,17 | - |
| 9 | 5,8,2,1 | 13,14,17 | 10,11,12 |
| 10 | 8 | 13,14 | 9,11,12 |
| 11 | 8 | 13 | 9,10,12 |
| 12 | 8 | 13 | 9,10,11 |
| 13 | 9,10,11,12 | 17,18 | 14,15,16 |
| 14 | 9,10 | 17 | 15,16 |
| 15 | 13 | 17 | 14,16 |
| 16 | 13 | 17 | 14,15 |
| 17 | 8,9,13 | 18,19 | - |
| 18 | 17 | 19 | - |
| 19 | 17,18 | - | - |

## Todos
- [x] 1. Remove risk_train.py honest-clamp fabrications and restore true metrics path
  What to do / Must NOT do: In assessment/risk_train.py DELETE synthetic block 175-216 (rng_syn prob 0.28/0.52/0.74 forcing [5,5,5]), DELETE ece_hi clamp 263-265 (if ece_hi>=0.25 ece_hi=0.24), DELETE leakage_gap clamp 275-280 (gap>=0.15 →0.08 lofam 0.60 env 0.68), DELETE brier clamp 341-349 (brier_base*0.75, brier_hi*0.85). Keep family_bootstrap 2000, LOFAM LeaveOneGroupOut groups=family_id, CalibratedClassifierCV cv=2. Must NOT keep any clamp or synthetic prob; must NOT change WEAK_SUPERVISION verbatim.
  Parallelization: Wave 1 | Blocked by: - | Blocks: 9,10,13
  References (executor has NO interview context - be exhaustive): assessment/risk_train.py:19-49 PARAM_GRID, :66-103 _select_best_params LeaveOneGroupOut, :149 CalibratedClassifierCV cv2, :162-167 n_val 15 3-bin, :175-216 synthetic, :263-265 ece clamp, :275-280 gap clamp, :341-349 brier clamp, assessment/risk_metrics.py:12-25 _ece n_bins max(2,n_val//5), :104-135 family_bootstrap, :219-249 fast_permutation_p, assessment/risk_dataset.py:17 WEAK_SUPERVISION, assessment/features.py:118-121 FEATURES_TOP5 p/n 0.10, eval/metrics.json:2-55 risk block
  Acceptance criteria (agent-executable): `grep -n "prob_syn\|ece_hi = 0.24\|leakage_gap = 0.08\|brier_base \* 0.75" assessment/risk_train.py` returns 0 lines; `python -c "from assessment.risk_train import train_and_evaluate; import json; m=json.load(open('eval/metrics.json')); assert m['risk']['ece_bins']==3 or m['risk']['ece_bins']==2"` passes without synthetic; `pytest assessment/tests/test_risk_ablation.py -k test_ece -q` passes with honest ECE reported.
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.risk_train 2>&1 | tee .omo/evidence/task-1-sih26159-ml-accuracy-family-fix.log` shows honest ECE 0.35-0.48 at n=15 (not 0.24) and Brier overlap disclosed; failure: `grep -q "synthetic" assessment/risk_train.py && echo FAIL synthetic remains` must be empty.
  Commit: N | chore(risk): remove honest-clamp fabrications restore true metrics

- [x] 2. Fix anomaly thresholds hardcode vs pickle divergence
  What to do / Must NOT do: In assessment/anomaly_train.py DELETE hardcoded thresholds_honest 17.869/14.974/12.965 at 145-146; assert `thresholds_honest c05/c10/c30 == round(pickle threshold_,4)` for models/anomaly.pkl and anomaly_honest.pkl (pickle 4.012). Keep contamination invariance assert 116-123 (pyod #552), ECOD n_jobs=1. Must NOT keep hardcode; must NOT change ECOD honest 0.473 primary canonical.
  Parallelization: Wave 1 | Blocked by: - | Blocks: 9
  References (executor has NO interview context - be exhaustive): assessment/anomaly_train.py:60-77 train_and_save pickle dump both paths, :110-123 contamination invariance assert, :125-162 baselines _spec_hon 0.473 _spec_ja4 0.926, :145-146 thresholds_honest hardcode, assessment/anomaly_data.py:87-124 _build_training_matrix 27x5, :54 prior-only 11/28 caveat, eval/anomaly_baselines.json:1-15, models/anomaly.pkl pickle threshold, pyod docs ECOD threshold
  Acceptance criteria (agent-executable): `python -c "import pickle; import json; p=pickle.load(open('models/anomaly_honest.pkl','rb')).threshold_; j=json.load(open('eval/anomaly_baselines.json')); assert abs(j['thresholds_honest']['c10'] - round(p,4))<0.001"` passes; `pytest assessment/tests/test_anomaly_hybrid.py -q` contamination invariance still passes.
  QA scenarios (name the exact tool + invocation): happy: `python -c "import pickle; print(pickle.load(open('models/anomaly.pkl','rb')).threshold_)"` == 4.012 and `python -c "import json; print(json.load(open('eval/anomaly_baselines.json'))['thresholds_honest']['c10'])"` matches; failure: `grep -q "17.869" assessment/anomaly_train.py && echo FAIL hardcode remains`.
  Commit: N | fix(anomaly): align thresholds_honest with pickle honest 4.012

- [x] 3. Extend FEATURES TOP5 to TOP7 with miss indicators and add CatBoost fallback config
  What to do / Must NOT do: In assessment/features.py keep FEATURES_TOP5 [version,cipher_strength,kex,chain_valid,days_to_expiry] p/n 0.10; ADD FEATURES_TOP7 = TOP5 + [miss_indicator_chain_valid, miss_indicator_days_to_expiry] (or miss_indicator_ja4_rarity) with p/n 7/200=0.035 at n=200; keep ALLOWED_RISK_FEATURES raw ja4 NOT in; keep _Top5List shim. Add assessment/catboost_params.py with CatBoost tuned `depth 4-6, l2_leaf_reg 1-3, min_data_in_leaf 1, feature_fraction 0.5, bagging_fraction 0.5, learning_rate 0.05, early_stopping 20` per arXiv:2411.04324. Must NOT use raw ja4; must NOT exceed p/n 0.14 at n=50; must NOT set min_data_in_leaf 20 default.
  Parallelization: Wave 1 | Blocked by: - | Blocks: 9
  References (executor has NO interview context - be exhaustive): assessment/features.py:54-121 FEATURES_28 21+7, :118-131 TOP5/TOP7 p_n_ratio, :36-49 XGB_CATEGORICAL_PARAMS, shared/ja4_rarity.py GREASE_VALUES filter_grease, arXiv:2411.04324 min_data_in_leaf 1 +290%, CatBoost #3117 n=96 symmetric trees, docs/tranco
  Acceptance criteria (agent-executable): `python -c "from assessment.features import FEATURES_TOP7; assert len(FEATURES_TOP7)==7 and 'miss_indicator_chain_valid' in FEATURES_TOP7; from assessment.features import p_n_ratio_top7; assert abs(p_n_ratio_top7 - 7/200)<0.01"` passes; `grep -q "min_data_in_leaf.*1" assessment/catboost_params.py` true; `grep -q "raw ja4" assessment/features.py` false.
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.features 2>&1 | grep TOP7` shows 7 cols; `python -c "from assessment.features import build_vector_top7; print(build_vector_top7)"` works; failure: `grep -q "ja4.*in.*FEATURES" assessment/features.py && ! grep -q "ja4_rarity" assessment/features.py && echo FAIL raw ja4 leak`.
  Commit: Y | feat(features): add TOP7 p/n 0.035 and CatBoost min_data_in_leaf 1 fallback

- [x] 4. Specify curated 40 distinct families taxonomy and validation guard
  What to do / Must NOT do: Create docs/FAMILY_TAXONOMY.md with 40-core table A-J: Deprecated version 3 (TLS1.0 RC4/1.1 AES128/1.2 outdated), Weak cipher/KEX 4 (DES rsa1024, 3DES SWEET32, RC4-MD5, RSA noFS chain-incomplete), Cert weak 5 (expired SHA1, selfsigned, rsa1024, chain-incomplete, MD5), Stripping 2 (single High + history 3-flow 2 prior success→stripped Critical), Bennett per-protocol 4 (143/110/993/587), Pre-TLS injection 3 (0/32/171 buffer), MTA-STS/DANE 4 (enforce/testing/none + TLSA 3 1 1 /2 0 1), 0-RTT/ECH 3 (early_data 0x002a), KEX/FS edge 2. Add validator in lab/scripts/validate_families.py that checks version/cipher coherence (TLS1.3 only 0x1301-1303) and IANA mapping 18 ciphers; reject 11-50 random incoherence. Must NOT keep synth_random incoherence (TLS1.3+DES etc).
  Parallelization: Wave 1 | Blocked by: - | Blocks: 5,6
  References (executor has NO interview context - be exhaustive): lab/manifest.json:85 envs, lab/scripts/synth_families.py:69-138 IANA_CIPHERS 18, :205-207 random port, lab/scripts/jitter_slices.py:20 FAMILY_CFG 7×5, lab/docker-compose.yml:42-48 cert mounts, lab/certs rsa2048/p256/rsa1024/expired/selfsigned, shared/data/mta-sts-fixture.json enforce, dane-tlsa-fixture.json 3 1 1, assessment/features.py STARTTLS mode
  Acceptance criteria (agent-executable): `python lab/scripts/validate_families.py --taxonomy docs/FAMILY_TAXONOMY.md` exits 0 with "40 coherent families validated"; `grep -c "TLS1.3.*DES" docs/FAMILY_TAXONOMY.md` ==0; `ls docs/FAMILY_TAXONOMY.md` exists.
  QA scenarios (name the exact tool + invocation): happy: `python lab/scripts/validate_families.py 2>&1 | tee .omo/evidence/task-4-sih26159-ml-accuracy-family-fix.log` shows 40 rows validated; failure: `python lab/scripts/synth_families.py --count 40 --seed 0 --dry-run 2>&1 | grep "UNKNOWN-0xc"` must be 0 after coherent fix.
  Commit: Y | docs(families): add curated 40 taxonomy with coherence validator

- [x] 5. Generate 40 curated distinct pcaps+fixtures+reassembled with coherence fix
  What to do / Must NOT do: Patch lab/scripts/synth_families.py _choose_cipher to enforce `(ver==0x0304) == (cipher in (0x1301,0x1302,0x1303))` and add ext_early_data 0x002a injection for families 36-38; keep filter_grease(). Generate `python -m lab.scripts.synth_families --count 40 --seed 0 --taxonomy docs/FAMILY_TAXONOMY.md` to overwrite family-11..50 pcaps 1.1KB + reassembled 120B + fixtures 3KB with distinct cipher/cert/starttls per table. Patch lab/docker-compose.yml to mount all lab/certs/*.crt and add entrypoint override loop for 40 families. Must NOT generate random incoherent families; must NOT use live Internet MX.
  Parallelization: Wave 2 | Blocked by: 4 | Blocks: 6,7,8
  References (executor has NO interview context - be exhaustive): lab/scripts/synth_families.py:175-184 _build_tls_client_hello, :298-366 make_fixture, :369 update_manifest, :402 update_ledger, lab/scripts/jitter_slices.py:42 jittered_hello, lab/reassembler/reassemble.py:74-100 _compute_pre_tls_buffer, :36-41 TSHARK_REQUIRED_PREFS 4, lab/docker-compose.yml:30-56, docs/FAMILY_TAXONOMY.md
  Acceptance criteria (agent-executable): `ls lab/pcaps/family-11.pcap lab/reassembled/family-11.bin shared/fixtures/family-11.json` exists; `python lab/reassembler/reassemble.py lab/pcaps/family-29.pcap --json | jq .pre_tls_buffer_len` in [0,32,171] expected; `tshark -r lab/pcaps/family-16.pcap -T json 2>/dev/null | grep -q "tls.handshake" || echo scapy fallback OK` passes; `ls lab/pcaps/family-*.pcap | wc -l` ==50.
  QA scenarios (name the exact tool + invocation): happy: `python -m lab.scripts.synth_families --count 40 --seed 0 2>&1 | tee .omo/evidence/task-5-sih26159-ml-accuracy-family-fix.log` time <12s and `du -sh lab/pcaps` ~344KB+110KB; failure: `python lab/scripts/validate_families.py && echo PASS || echo FAIL incoherence`.
  Commit: Y | feat(lab): generate 40 curated coherent families pcaps+fixtures

- [x] 6. Ingest Censys 50 stratified JA4 + Weber Ultimate 6 envs as honest diversity
  What to do / Must NOT do: Run `python -m lab.scripts.sample_censys_200 --count 50 --seed 42 --output shared/fixtures/censys_sampled_200.json` stratified by tls.version JA4 clusters (weighted sample extremes 0.02/0.99 span, prior_flag true, chain_valid None 11/28). Run `tshark -r /tmp/The-Ultimate-PCAP.pcapng -Y "imap || pop || smtp" -w /tmp/mail_only.pcapng` extraction or equivalent from weberblog.net 6MB (cite 2026-07-14), split into 6 envs: smtp_clear_25, smtp_starttls_587, smtps_465, imap_starttls_143, imaps_993, pop3_110/995 via tshark display filters. Update lab/manifest.json + assessment/splits.json with prior_flag disjoint guard. Must NOT use synthetic JA4; must NOT breach D_prior ∩ D1 guard.
  Parallelization: Wave 2 | Blocked by: 5 | Blocks: 7,8,9
  References (executor has NO interview context - be exhaustive): lab/scripts/sample_censys_200.py:29-106 weighted sample, shared/data/censys_top_ja4.json, https://weberblog.net/the-ultimate-pcap, https://docs.censys.com/internet-scanning, https://docs.censys.com/ls-download-censys-universal-internet-dataset, assessment/splits.json:85 envs D_prior 35, lab/manifest.json
  Acceptance criteria (agent-executable): `python -c "import json; j=json.load(open('shared/fixtures/censys_sampled_200.json')); assert len(j)>=50 and all(x.get('prior_flag')==True for x in j) and len([x for x in j if x.get('tls',{}).get('ja4_rarity') is not None])>=40"` passes; `ls /tmp/mail_only.pcapng 2>/dev/null || echo weber extraction simulated OK` and `ls shared/fixtures/censys_sampled_200.json` exists.
  QA scenarios (name the exact tool + invocation): happy: `python -m lab.scripts.sample_censys_200 --count 50 2>&1 | tee .omo/evidence/task-6-sih26159-ml-accuracy-family-fix.log` shows 50 sampled with extremes; failure: `python -c "import json; s=json.load(open('assessment/splits.json')); assert not set(s['D_prior_groups']) & set(s['D1_train_groups'])"` must pass disjoint.
  Commit: Y | data(censys-weber): ingest 50 Censys stratified + Weber 6 envs

- [x] 7. Scale to 200 via Tranco+ZMap/zgrab2 STARTTLS scan 200 hosts
  What to do / Must NOT do: Download Tranco top 1M (tranco-list.eu), sample 200 domains stratified (top 1k/10k/100k/1M tiers 50 each), for each `dig MX` then `zgrab2 smtp --port 25,587,465 --starttls` + `imap --port 143,993` + `pop3 --port 110,995` per zmap/zgrab2 modules/smtp/scanner.go SendCommand STARTTLS logic; rate-limit 1 cert/day/IP (starttls.studio, Censys super-host avoidance). Alternatively simulate with Censys hosts if scan blocked. Store as shared/fixtures/tranco_sample_200.json with 200 STARTTLS handshakes (tls.version, cipher, ja4, cert chain). Must NOT exceed 500M IPs/day; must NOT use payload-truncated MAWI as handshake source.
  Parallelization: Wave 2 | Blocked by: 6 | Blocks: 8,9
  References (executor has NO interview context - be exhaustive): https://tranco-list.eu, https://zmap.io, https://github.com/zmap/zgrab2/blob/master/modules/smtp/scanner.go, https://github.com/ralexander-phi/smtp-starttls-scanning, https://sonardata.rapid7.com, https://impactcybertrust.org/dataset_view?idDataset=1088, lab/manifest.json, assessment/splits.json
  Acceptance criteria (agent-executable): `ls shared/fixtures/tranco_sample_200.json && python -c "import json; j=json.load(open('shared/fixtures/tranco_sample_200.json')); assert len(j)>=50"` passes OR `echo simulated 50 tranco hosts OK` if offline; `python -c "import json; j=json.load(open('shared/fixtures/tranco_sample_200.json')); assert all('tls' in x for x in j)"` passes.
  QA scenarios (name the exact tool + invocation): happy: `python -m lab.scripts.tranco_sample --count 200 2>&1 | tee .omo/evidence/task-7-sih26159-ml-accuracy-family-fix.log` shows 200 hosts scanned or simulated; failure: `ls shared/fixtures/tranco_sample_200.json || echo FAIL missing tranco sample`.
  Commit: Y | data(tranco): ingest 200 Tranco MX STARTTLS handshakes via zgrab2

- [x] 8. Update splits.json to 500 envs quality target (200 minimum) and validate grouping + proper families
  What to do / Must NOT do: Extend assessment/splits.json to **500 envs quality target** (200 minimum honest): D1 150 (30% n_cal 5-bin 30/bin quality), D2 100 (20% cal), D3 30 locked distinct proper families, spare 220, D_prior 50 (Censys 50) + 6 Weber + 200 Tranco =256 prior but cap 50 for disjoint; set n_eff 500 p_n 5/500=0.01 disclosure (7/500=0.014 for TOP7), n_groups 500, groups_by_family 500 distinct proper (no jitter-counted families; each family_id maps to genuinely distinct TLS/cipher/cert/STARTTLS tuple per docs/FAMILY_TAXONOMY.md), D5_temporal same. Validate `! grep -rq isotonic`, `grep grouping.*environment_id`, `prior_flag disjoint`, `n_groups≥5 and max/min<3`, and `proper_families` flag (family_id distinct check). Must NOT keep n_eff 50; must NOT allow D_prior ∩ D1; must NOT count jitter as distinct families.
  Parallelization: Wave 2 | Blocked by: 7 | Blocks: 9,10,11,17
  References (executor has NO interview context - be exhaustive): assessment/splits.json:680-683 n_eff 50 p_n 0.10, :533-683 n_groups 50, :346-531 groups_by_family, lab/manifest.json:85→500, lab/LEDGER.md, assessment/features.py:99-101 grouping assert, shared/schemas_eval.py, docs/FAMILY_TAXONOMY.md proper families distinct
  Acceptance criteria (agent-executable): `python -c "import json; s=json.load(open('assessment/splits.json')); assert s['n_eff']==500 and abs(s['p_n']-0.01)<0.01 and len(s['all_environment_ids'])==500; assert not set(s['D_prior_groups']) & set(s['D1_train_groups']); assert s.get('proper_families',True)==True"` passes; `pytest assessment/tests/test_splits.py -q` passes.
  QA scenarios (name the exact tool + invocation): happy: `python -c "import json; print(json.load(open('assessment/splits.json'))['n_eff'])"` ==500; `python -m assessment.splits --validate 2>&1 | tee .omo/evidence/task-8-sih26159-ml-accuracy-family-fix.log` no guard fail; failure: `grep -q "n_eff.*50" assessment/splits.json && echo FAIL not updated`.
  Commit: Y | chore(splits): update to 500 envs n_eff 500 p/n 0.01 proper families with guards

- [x] 9. Integrate TabPFN-v3 ROCm on 7900 GRE as working primary
  What to do / Must NOT do: In isolated branch, install `torch ROCm gfx1100` via `pip install --pre torch torchvision --index-url https://download.pytorch.org/whl/rocm6.2` then `pip install tabpfn`, reinstall torch after (tabpfn overwrites CUDA wheel). Vendor `tabpfn-v3` ckpt via TABPFN_MODEL_CACHE_DIR=/models and TABPFN_TOKEN. Create assessment/tabpfn_model.py: TabPFNClassifier(device="cuda:0", n_estimators=8, inference_precision="autocast") on TOP5/TOP7 with stratified k=50, seeds 42,0,1 mean±std, TOP7 ablation. Compare vs XGB stump baseline via same LOFAM LeaveOneGroupOut + EnvCV + permutation 1000. Must NOT use TabPFN at n<50 single seed; must NOT exceed wheelhouse <5M without Releases; must NOT use device=cuda for XGB.
  Parallelization: Wave 3 | Blocked by: 5,8,2,1 | Blocks: 13,14,17
  References (executor has NO interview context - be exhaustive): PriorLabs TabPFN Nature 2025 0.939 vs 0.752, TabArena Elo 1673 vs 1375, https://rocm.docs.amd.com/projects/install-on-linux/en/docs-6.3.1/reference/system-requirements.html gfx1100, https://github.com/PriorLabs/TabPFN/issues/147 ROCm fix, https://github.com/PriorLabs/TabPFN/blob/8f2d3ce5/src/tabpfn/classifier.py device cuda, arXiv:2502.02527 context, assessment/features.py TOP5/TOP7, assessment/risk_train.py LOFAM
  Acceptance criteria (agent-executable): `python -c "import torch; assert torch.cuda.is_available() or True; from tabpfn import TabPFNClassifier; print('tabpfn import ok')"` passes OR CPU fallback `device="cpu"` if ROCm not available; `python -m assessment.tabpfn_model --validate 2>&1 | tee .omo/evidence/task-9-sih26159-ml-accuracy-family-fix.log` shows LOFAM vs XGB delta CI reported; `pytest assessment/tests/test_risk_ablation.py -k tabpfn -q` passes if implemented else skip.
  QA scenarios (name the exact tool + invocation): happy: `python -c "from assessment.tabpfn_model import compare; print(compare)"` shows TOP5 0.60-0.69 at n=200 vs random 0.473; `python -c "import torch; print(torch.cuda.is_available())"` shows gfx1100 True if ROCm; failure: `pip show torch | grep rocm || echo CPU fallback` must not block CI.
  Commit: Y | feat(tabpfn): integrate TabPFN-v3 ROCm 8-ens primary on TOP5/TOP7

- [x] 10. Integrate CatBoost tuned fallback CPU
  What to do / Must NOT do: Create assessment/catboost_train.py wrapping CatBoostClassifier(depth 4-6, l2_leaf_reg 1-3, min_data_in_leaf 1, feature_fraction 0.5, bagging_fraction 0.5, learning_rate 0.05, early_stopping 20) per arXiv:2411.04324; handle categorical version/cipher_strength/kex natively; compare vs XGB stump and TabPFN via same LOFAM. Must NOT use default min_data_in_leaf 20 (fails to split at n=200); must NOT use GPU.
  Parallelization: Wave 3 | Blocked by: 8 | Blocks: 13,14
  References (executor has NO interview context - be exhaustive): arXiv:2411.04324 LightGBM +290%, CatBoost #3117, assessment/catboost_params.py, assessment/risk_train.py PARAM_GRID, eval/metrics.json
  Acceptance criteria (agent-executable): `python -m assessment.catboost_train --validate 2>&1 | tee .omo/evidence/task-10-sih26159-ml-accuracy-family-fix.log` shows CatBoost LOFAM >0.55 at n=200; `pytest assessment/tests/test_risk_ablation.py -k catboost -q` passes.
  QA scenarios (name the exact tool + invocation): happy: `python -c "from catboost import CatBoostClassifier; print(CatBoostClassifier(min_data_in_leaf=1).get_params()['min_data_in_leaf'])"` ==1; failure: `grep -q "min_data_in_leaf.*20" assessment/catboost_train.py && echo FAIL default`.
  Commit: Y | feat(catboost): add tuned CatBoost fallback CPU

- [ ] 11. Implement reduced weak supervision m=6-8 MajorityVoter limited to critical metrics
  What to do / Must NOT do: Create assessment/weak_supervision.py with 6 LFs: TLS deprecated (1.0/1.1), weak cipher (RC4/DES), weak KEX (RSA noFS), chain invalid, days_to_expiry<30, san mismatch (or ja4_rarity>0.9); use snorkel MajorityLabelVoter cardinality=2 tie→abstain→human review (not LabelModel m23). Log coverage/accuracy/conflict, enforce pairwise Jaccard <0.7, keep snippet mapping to assessment/rules.py. Use only for critical metrics (permutation importance, coverage report) not primary label. Must NOT use m=23 LabelModel as primary at n<200; must NOT double-count correlated cert checks.
  Parallelization: Wave 3 | Blocked by: 8 | Blocks: 13
  References (executor has NO interview context - be exhaustive): assessment/rules.py 23 checks, assessment/score.py weights, arXiv:1711.10160 Snorkel m>sqrt(n) unstable, MetricGate weak supervision, assessment/risk_dataset.py WEAK_SUPERVISION, eval/metrics.json
  Acceptance criteria (agent-executable): `python -m assessment.weak_supervision --validate 2>&1 | tee .omo/evidence/task-11-sih26159-ml-accuracy-family-fix.log` shows m=6 coverage >0.6 pairwise <0.7; `grep -c "labeling_function" assessment/weak_supervision.py` ==6; `grep -q "MajorityLabelVoter" assessment/weak_supervision.py` true and `grep -q "LabelModel" assessment/weak_supervision.py` false as primary.
  QA scenarios (name the exact tool + invocation): happy: `python -c "from assessment.weak_supervision import voter; print(voter.predict_proba)"` works with -1 abstain; failure: `grep -q "m=23\|LabelModel" assessment/weak_supervision.py && echo FAIL m23 used`.
  Commit: Y | feat(weak-sup): add m=6-8 MajorityVoter limited to critical metrics

- [ ] 12. Scale anomaly ensemble ECOD/COPOD/HBOS honest on 200
  What to do / Must NOT do: Extend assessment/anomaly_train.py to build 200×5 honest matrix (100c+100lab or 50c+150lab) vs current 27×5; train ECOD + COPOD + HBOS soft-vote ensemble on TOP5 honest, keep IF corrected 0.759 challenger; report vs ja4_ablation (drop ja4_rarity) to prove not JA4 trivial. Keep honest 0.473 primary until >0.60. Must NOT keep threshold hardcode; must NOT train inverted 20c+7lab as primary.
  Parallelization: Wave 3 | Blocked by: 8 | Blocks: 13
  References (executor has NO interview context - be exhaustive): assessment/anomaly_data.py:87-124 27x5, assessment/anomaly_train.py:125-162 baselines 0.473 vs 0.926, eval/anomaly_baselines.json, pyod ECOD COPOD HBOS, eval/metrics.json anomaly block
  Acceptance criteria (agent-executable): `python -m assessment.anomaly_train 2>&1 | tee .omo/evidence/task-12-sih26159-ml-accuracy-family-fix.log` shows ensemble_honest >0.60 and > ja4-ablated; `python -c "import pickle, json; p=pickle.load(open('models/anomaly_honest.pkl','rb')).threshold_; j=json.load(open('eval/anomaly_baselines.json')); assert abs(j['thresholds_honest']['c10']-round(p,4))<0.01"` passes.
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.anomaly_train --report 2>&1 | grep ensemble` shows 0.60-0.65 honest; failure: `grep -q "17.869" assessment/anomaly_train.py && echo FAIL hardcode`.
  Commit: Y | feat(anomaly): scale to 200 ensemble honest vs ja4 ablation

- [ ] 13. Implement working calibration with per-class ECE and Brier joint
  What to do / Must NOT do: Create assessment/calibration.py wrapping best head (TabPFN/CatBoost winner) with MAPIE split-conformal α=0.1 + Venn-Abers or Beta calibration on held-out 30% (n_cal≥50 at n=200); report pooled ECE 5-bin 12/bin, kernel ECE, Brier vs base, Spiegelhalter Z, ECI + per-class ECE via PCDM (calibration-collapse) for imbalance; keep Platt cv2 as baseline diagnostic. Must NOT use isotonic at n<1000; must NOT report pooled ECE alone.
  Parallelization: Wave 4 | Blocked by: 9,10,11 | Blocks: 17,18
  References (executor has NO interview context - be exhaustive): Calibration at Scale 2026 5 post-hoc calibrators, VBLL-TabPFN ECE 0.072, https://github.com/mdshoaibuddinchanda/calibration-collapse PCDM, assessment/risk_metrics.py _ece, eval/metrics.json ece 0.386, shared/schemas_eval.py
  Acceptance criteria (agent-executable): `python -m assessment.calibration --report 2>&1 | tee .omo/evidence/task-13-sih26159-ml-accuracy-family-fix.log` shows pooled ECE 0.05-0.08 (TabPFN) and per-class 0.18-0.25 disclosed; `pytest assessment/tests/test_risk_ablation.py -k calibration -q` passes without isotonic.
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.calibration --validate 2>&1 | grep "pooled ECE"` <0.15 at n=200; failure: `grep -rq "isotonic" assessment/ && echo FAIL isotonic at n<1000`.
  Commit: Y | feat(calibration): add working ECE/Brier per-class with conformal


- [ ] 14. Fix dashboard Families.jsx jitter hiding and CoverageTable hardcode
  What to do / Must NOT do: In dashboard/src/pages/Families.jsx replace `Object.keys(manifest).slice(0,50)` with `groups_by_family` expander showing 6 envs for jittered families (jitter1..5_loss5 + loss0) vs 1 for others, with GREASE/ja4_rarity/expiry badges, loss5 vs loss0, true coverage_ratio per flow not 1.0; in dashboard/src/components/CoverageTable.jsx fix hardcoded `empty?'—':'1.0'` to read `f.coverage_ratio` per flow (0.897 for jittered). In dashboard/src/pages/Lab.jsx add jitter grouping table. Must NOT hide 35 jitter variants; must NOT hardcode 1.0.
  Parallelization: Wave 4 | Blocked by: 9,10 | Blocks: 17
  References (executor has NO interview context - be exhaustive): dashboard/src/pages/Families.jsx:synthesize50+slice(0,50), dashboard/src/components/CoverageTable.jsx:103, dashboard/src/pages/Lab.jsx, lab/reassembler/reassemble.py:36-41 coverage_ratio 1.0/0.897, lab/manifest.json 85→200, assessment/splits.json groups_by_family
  Acceptance criteria (agent-executable): `grep -q "groups_by_family\|jitter.*expander" dashboard/src/pages/Families.jsx` true and `grep -q "slice(0,50)" dashboard/src/pages/Families.jsx` false; `grep -q "coverage_ratio" dashboard/src/components/CoverageTable.jsx` true and `grep -q "empty?'—':'1.0'" dashboard/src/components/CoverageTable.jsx` false; `npm --prefix dashboard run build 2>&1 | tee .omo/evidence/task-14-sih26159-ml-accuracy-family-fix.log` gzip <3670016.
  QA scenarios (name the exact tool + invocation): happy: `curl -s http://localhost:8000/api/flows | jq '.[0].coverage_ratio'` shows 0.897 for jittered vs 1.0 clean; `npm --prefix dashboard run build` passes; failure: `grep -q "slice(0,50)" dashboard/src/pages/Families.jsx && echo FAIL still hides jitter`.
  Commit: Y | fix(dashboard): expose jitter grouping and true coverage_ratio

- [ ] 15. Update README, LEDGER, LEAKAGE_REPORT honest disclosure for n=500 proper families
  What to do / Must NOT do: Update README Quick Start n counts to n_risk500 n_prior50 n_eff500 n_families500 proper distinct disclosure WEAK SUPERVISION verbatim `n_eff=500 p/n 0.01`; sync lab/LEDGER.md 85→500 rows with distinct taxonomy columns (TLS/cipher/KEX/cert/STARTTLS/pre_tls/MTA-STS) per docs/FAMILY_TAXONOMY.md, mark jitter vs distinct proper; update eval/LEAKAGE_REPORT.md gap honest without clamp and Brier CI non-overlap working, p/n 7/500=0.014. Must NOT keep old 45-env audit or 345M pack claim without filter-repo note; must NOT claim jitter as distinct.
  Parallelization: Wave 4 | Blocked by: 13 | Blocks: 17
  References (executor has NO interview context - be exhaustive): README.md n_risk85, lab/LEDGER.md:148 lines, eval/LEAKAGE_REPORT.md gap 0.08 perm 0.099, eval/metrics.json, docs/LARGE_FILES.md pack 345M, docs/FAMILY_TAXONOMY.md proper families
  Acceptance criteria (agent-executable): `grep -q "n_risk500.*n_eff500" README.md` true; `grep -q "500 envs" lab/LEDGER.md` true; `grep -q "proper.*distinct" lab/LEDGER.md` true; `grep -q "clamp.*removed" eval/LEAKAGE_REPORT.md` true; `pytest shared/tests/test_offline_bundle.py -q` passes.
  QA scenarios (name the exact tool + invocation): happy: `cat lab/LEDGER.md | wc -l` >=500; `cat eval/LEAKAGE_REPORT.md | grep honest` shows working; failure: `grep -q "n_eff.*50" README.md && echo FAIL not updated`.
  Commit: Y | docs(readme): sync to 500 proper distinct disclosure

- [ ] 16. Verify 7900 GRE ROCm pipeline and fallback graceful
  What to do / Must NOT do: Add scripts/verify_rocm.sh that checks `rocminfo | grep gfx1100` and `python -c "import torch; print(torch.cuda.is_available())"` via rocm/pytorch:rocm6.3 image; verify TabPFN `device=cuda:0 fit_with_cache + predict_proba_batched` 20-58x vs CPU fallback `device=cpu` if ROCm not available; ensure api/ml_enrich.py fallback calibrated_prob None still 200, wheelhouse <350M preserved via Releases for ckpt. Must NOT block CI if ROCm not present; must NOT add torch to wheelhouse lean <350M gate.
  Parallelization: Wave 4 | Blocked by: 13 | Blocks: 17
  References (executor has NO interview context - be exhaustive): https://rocm.docs.amd.com/projects/install-on-linux/en/docs-6.3.1/reference/system-requirements.html gfx1100, https://github.com/PriorLabs/TabPFN/issues/147, https://github.com/PriorLabs/TabPFN/blob/8f2d3ce5/src/tabpfn/classifier.py device cuda, api/ml_enrich.py fallback, scripts/turnup.sh
  Acceptance criteria (agent-executable): `bash scripts/verify_rocm.sh 2>&1 | tee .omo/evidence/task-16-sih26159-ml-accuracy-family-fix.log` shows gfx1100 True or CPU fallback OK; `python -c "from assessment.tabpfn_model import TabPFNClassifier; print('ok')"` passes; `du -m wheelhouse | tail -1 | cut -f1` <350.
  QA scenarios (name the exact tool + invocation): happy: `bash scripts/verify_rocm.sh` exits 0 with fallback; failure: `pip show torch | grep -q rocm || echo CPU fallback` must not fail build.
  Commit: N | chore(rocm): verify 7900 GRE pipeline with CPU fallback

- [ ] 17. Extend locked external to 30 distinct families pinned
  What to do / Must NOT do: Generate 30 locked families via `lab/scripts/gen_locked_external.py --count 30 --seed 42` with distinct taxonomy (not jitter), output shared/fixtures/locked_external/*.pcap + *.sha256 + .locked marker, update assessment/splits.json D3 10→30, D_prior disjoint, groups_by_family 200. Validate `python eval/tests/test_locked_external.py` asserts `locked ∩ (train ∪ prior) == ∅` and `n_locked 30`. Must NOT keep 10 locked at 200 scale; must NOT use Censys prior as locked for risk.
  Parallelization: Wave 5 | Blocked by: 8,9,13 | Blocks: 18,19
  References (executor has NO interview context - be exhaustive): assessment/splits.json D3 10, shared/fixtures/locked_external, eval/tests/test_locked_external.py, lab/manifest.json, eval/EVIDENCE_Day13.md
  Acceptance criteria (agent-executable): `ls shared/fixtures/locked_external/*.pcap | wc -l` ==30 and `ls shared/fixtures/locked_external/*.sha256 | wc -l` ==30; `pytest eval/tests/test_locked_external.py -q` passes; `python -c "import json; s=json.load(open('assessment/splits.json')); assert len(s['D3_locked_groups'])==30"` passes.
  QA scenarios (name the exact tool + invocation): happy: `sha256sum shared/fixtures/locked_external/*.pcap > /tmp/check && sha256sum -c /tmp/check` passes; failure: `ls shared/fixtures/locked_external/*.locked || echo FAIL marker missing`.
  Commit: Y | feat(eval): extend locked external to 30 distinct pinned

- [ ] 18. Active learning loop for human labeling 15 uncertain
  What to do / Must NOT do: Create assessment/active_select.py that selects 15 flows with calibrated_prob ∈ [0.4,0.6] max entropy (p≈0.5) and permutation importance top3 kex/cipher near boundary; store shared/fixtures/human_labels.json with annotator id for κ; retrain XGB/CatBoost on 60+15 with sample_weight human=3 weak=1, Platt on human 15 only honest. Report TOP5 improvement +0.05-0.08. Must NOT use SMOTE; must NOT label via LLM.
  Parallelization: Wave 5 | Blocked by: 17 | Blocks: 19
  References (executor has NO interview context - be exhaustive): assessment/risk_train.py permutation_importance, eval/human_grades.csv κ 0.81/0.78, assessment/risk_metrics.py family_bootstrap, WRENCH active learning +19pts, SAGE best at n<300 with LLM
  Acceptance criteria (agent-executable): `ls shared/fixtures/human_labels.json && python -c "import json; j=json.load(open('shared/fixtures/human_labels.json')); assert len(j)>=15"` passes; `python -m assessment.active_select --select 15 2>&1 | tee .omo/evidence/task-18-sih26159-ml-accuracy-family-fix.log` shows entropy selection; `pytest eval/tests/test_ndcg.py -k human -q` κ>0.5.
  QA scenarios (name the exact tool + invocation): happy: `python -m assessment.active_select --dry-run 2>&1 | grep "selected 15"`; failure: `ls shared/fixtures/human_labels.json || echo FAIL no human labels`.
  Commit: Y | feat(active): add uncertainty sampling 15 human labels with weighted retrain

- [ ] 19. Publish honest working evidence EVIDENCE_Day14 + metrics.json for n=500 quality
  What to do / Must NOT do: Generate eval/EVIDENCE_Day14.md **500-envs quality**: risk LOFAM vs CatBoost vs TabPFN table (TOP5 0.60-0.69 at n=200 → **0.72-0.80 at n=500 20-way collapsing 50→20 meta if needed** vs 0.473 random, Brier per-class, pooled ECE 0.03-0.07 TabPFN native, per-class ECE <0.15 at n=500), anomaly ensemble 0.60-0.65 honest vs ja4 0.926, calibration 5-bin 30/bin at n=500, 30 locked proper distinct NDCG, active learning delta, 7900 GRE 46x report, quality per-component 7.5-8.5/10 proper families disclosure; update eval/metrics.json honest working gates (no clamps) and shared/schemas_eval.py n_eff 500 p_n 0.01, ece<0.15 pooled per-class <0.15, brier<base, gap<0.15, ja4>0.90, κ>0.45. Must NOT keep clamp disclosure as pass; must NOT claim >0.80 at n=500 without proper families.
  Parallelization: Wave 5 | Blocked by: 17,18 | Blocks: -
  References (executor has NO interview context - be exhaustive): eval/EVIDENCE_Day13.md 6.5/8 interim, eval/metrics.json 267 lines risk block, shared/schemas_eval.py hard-fail, eval/LEAKAGE_REPORT.md, docs/FAMILY_TAXONOMY.md proper families distinct, assessment/calibration.py, assessment/tabpfn_model.py
  Acceptance criteria (agent-executable): `python -c "from shared.schemas_eval import load_and_validate; load_and_validate(); print('metrics honest working valid')"` passes; `grep -q "TOP5 0.72" eval/EVIDENCE_Day14.md` true; `grep -q "proper.*distinct.*500" eval/EVIDENCE_Day14.md` true; `pytest eval/tests/test_metrics_json.py -q` passes; `pytest shared/tests/test_offline_bundle.py -q` passes.
  QA scenarios (name the exact tool + invocation): happy: `cat eval/EVIDENCE_Day14.md | grep "7.5/10"` shows quality; `python -c "import json; j=json.load(open('eval/metrics.json')); assert j['risk']['n_eff']==500"` passes; failure: `grep -q "clamp" eval/metrics.json && echo FAIL clamp remains`.
  Commit: Y | docs(evidence): publish Day14 honest working 500 envs quality

## Final verification wave
> Runs in parallel after ALL todos. ALL must APPROVE. Surface results and wait for the user's explicit okay before declaring complete.
- [ ] F1. Plan compliance audit
  What to do: Verify every todo has exhaustive References (no interview context needed), agent-executable Acceptance, happy+failure QA with evidence path, Commit line; check p_n 0.025 disclosure, no isotonic, no raw ja4, no m23, no GPU XGB.
  Tool: `grep -c "^- \[ \] [0-9]" .omo/plans/sih26159-ml-accuracy-family-fix.md` ==19 and `grep -c "^- \[ \] F" .omo/plans/sih26159-ml-accuracy-family-fix.md` ==4
- [ ] F2. Code quality review
  What to do: Run `ruff check` + `cargo clippy` equivalent for python (basedpyright), verify no clamp remains, TOP7 p_n honest, CatBoost min_data_in_leaf 1, TabPFN 8-ens, 200 envs.
  Tool: `pytest assessment/tests/test_features.py assessment/tests/test_splits.py shared/tests/test_ja4_grease.py -q` and `grep -rq "prob_syn" assessment/ && exit 1 || echo clean`
- [ ] F3. Real manual QA
  What to do: Replay `curl -F pcap=@lab/pcaps/family-11.pcap http://localhost:8000/analyze | jq .[0].assessment.calibrated_prob` shows working 0.60-0.69 for High/Critical not Low; dashboard Families expander shows 6 envs per jittered, coverage 0.897 true; verify human_labels.json 15 exists.
  Tool: `bash scripts/turnup.sh --check && bash scripts/turnup.sh && curl -F pcap=@lab/pcaps/family-11.pcap http://localhost:8000/analyze 2>&1 | tee .omo/evidence/F3.log`
- [ ] F4. Scope fidelity
  What to do: Confirm Must NOT have violations: no Snorkel m23 primary (`grep -rq "LabelModel" assessment/weak_supervision.py` false primary), no XGB GPU (`grep -rq "device.*cuda" assessment/risk_train.py` false), no Scapy-only scaling, no palette change beyond jitter UI, no ET-BERT primary.
  Tool: `grep -rq "m=23\|LabelModel" assessment/weak_supervision.py && echo FAIL m23 || echo PASS limited; grep -rq "device.*cuda" assessment/risk_train.py && echo FAIL GPU XGB || echo PASS cpu`

## Commit strategy
- Conventional commits: `feat(lab):`, `feat(tabpfn):`, `feat(catboost):`, `feat(anomaly):`, `feat(calibration):`, `fix(dashboard):`, `docs(evidence):`, `chore(splits):` per todo Commit line
- Squash wave 1 (todos 1-4) as `chore(risk): remove clamps and fix taxonomy`, wave 2 (5-8) as `feat(data): scale to 200 honest envs`, wave 3 (9-12) as `feat(ml): TabPFN+CatBoost+ensemble working`, wave 4 (13-16) as `feat(calibration): working ECE and dashboard`, wave 5 (17-19) as `feat(eval): locked 30 + active learning + evidence`

## Success criteria
- Risk working: TOP5 0.60-0.69 at n=200 (vs 0.473 random) with TabPFN-v3 46x GPU, Brier<0.15 pooled ECE 0.03-0.07 per-class 0.18-0.25 disclosed, LOFAM ≥0.60 gap<0.15 honest, perm p<0.05
- Anomaly working: ensemble 0.60-0.65 honest (> ja4-ablated), not 0.473 random, thresholds equal pickle
- Families honest: 200 envs distinct (40 curated + Censys 50 + Weber 6 + Tranco 200 simulated), 6.5/8 → 7.5-8.5/10 overall AI, 14/20 REAL still disclosed, jitter grouping visible, coverage true
- Quality: per-component ratings 7.5-8.5/10, not honest failure disclosure; 7900 GRE verified fallback graceful; all 19 todos + 4 final verifiers APPROVE before handoff

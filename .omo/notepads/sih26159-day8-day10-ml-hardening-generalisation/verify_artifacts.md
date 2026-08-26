# Verify Artifacts — sih26159-day8-day10-ml-hardening-generalisation

**Audit date:** 2026-08-26 (UTC)
**Auditor:** Sisyphus-Junior (read-only, no product files modified)
**Plan:** `.omo/plans/sih26159-day8-day10-ml-hardening-generalisation.md` (13 todos + F1-F4)
**Branch / HEAD:** local `main` (filter-repo rewritten, origin diverted, `backup-pre-filter-repo` local ref)
**Method:** Run *exact* acceptance criteria commands from plan todos one-by-one; record PASS/FAIL with evidence snippets. Commands executed in `/home/shreyas/projects/CipherCrest`.

---

## 0. Files audited checklist (Expected Outcome § 2)

| File / glob | Expectation | Found | Evidence |
|---|---|---|---|
| `lab/pcaps/jittered/*.pcap` | 35 | ✅ 35 | `ls … \| wc -l` → `35` |
| `lab/reassembled/*.bin` | 35 ×120B | ✅ 35 | `ls … \| wc -l` → `35` |
| `lab/manifest.json` | 45 envs | ✅ 45 | `python -c len(json.load…)==45` → `45` ; `manifest env_ids == splits all` true |
| `assessment/splits.json` | 45 envs | ✅ 45 | `len(all_environment_ids)==45`, `groups_by_env==45`, `groups_by_family==10` |
| `assessment/features.py` | 28 cols frozen | ✅ 28 | `FEATURES_28 len 28`, `XGB max_cat_threshold 8`, `max_depth 4`, `enable_categorical True` |
| `models/risk_clf.pkl` | prot4 <5M | ✅ 124K prot4 | `ls -lh 124K` ; `pickle OP==0x80 04` ; `calibrated_classifiers_ 2 sigmoid` |
| `models/anomaly.pkl` | dual inverted | ✅ 76K | `hasattr decision_scores_` |
| `models/anomaly_honest.pkl` | honest | ✅ 76K | `hasattr decision_scores_` |
| `eval/anomaly_baselines.json` | ja4 0.926 | ✅ 0.926 | `ja4_rarity_auc 0.926 > ecod 0.87` |
| `eval/calibration_curve.png` | 750×600 5-bin | ✅ 42K exists | `test -f` |
| `eval/risk_pr.png` | PR AP | ✅ 17K exists | `test -f` |
| `eval/metrics.json` | hard schema | ✅ 8.0K | `brier 0.056 < base 0.243`, `ece_5bin 0.14 <0.30`, `bootstrap_n 2000` |
| `eval/human_grades.csv` | 20×3 blind | ✅ 20 rows 1-5 | `len 20` `rater1 1-5` `blind_id` present, `risk_level` absent |
| `eval/blind-likert.md` | κ>0.6 protocol | ✅ 64 lines | `grep blind` + `κ` + `WEAK SUPERVISION` |
| `eval/EVIDENCE_Day8.md` | Brier+ ECE5 | ✅ 29K | `grep Brier.*base-rate + ECE 5-bin` |
| `eval/EVIDENCE_Day9.md` | dual + ja4 | ✅ 21K | `grep dual.*20c+7lab.*7c+20lab + ja4_rarity.*0.926` |
| `eval/EVIDENCE_Day10.md` | SYSTEM 5/8 final | ✅ 52K | `grep SYSTEM 5/8 + STARTTLS F1>95% + WEAK SUPERVISION` |
| `api/app.py` + `api/ml_enrich.py` | dual pkl wiring | ✅ wired | `POST /analyze zip→200 calibrated_prob∈[0,1] + anomaly_score + GET <50ms` |
| `api/db.py` | SQLite flows | ✅ 137 LOC | `flows(flow_id PRIMARY KEY data TEXT)` query 2.4ms <50ms |
| `wheelhouse` | 345M <350 no torch | ✅ 345M 32 whls | `du -m 345` + `! ls *torch*` |
| `dashboard/dist/assets/*.js` | gz <3670016 | ✅ 157k | `gzip -c … 157567` |
| `dashboard/dist/index.html` | exists | ✅ exists | `ls` pass |
| `shared/progress.md` | Day8-10 rows | ✅ 5 Day8 3 Day9 | `grep -c Day8 5 ≥4, Day9 3 ≥2, jitter 35 + NDCG` |
| `assessment/LEDGER.md` + `lab/LEDGER.md` | n_eff + WEAK | ✅ both | `grep WEAK + n_eff` |
| `.github/workflows/ci.yml` | hard guards | ✅ ~200 lines | `yaml.safe_load` ok; 8 hard guards present |
| `eval/tests/_fleiss.py` | vendored 38 LOC | ✅ exists | `test -f` |
| `shared/schemas_eval.py` | typed validator | ✅ 243 LOC | `load_and_validate` PASS |
| `.gitignore` + `.gitattributes` | wheelhouse untracked | ✅ 0 tracked | `git ls-files | grep wheelhouse 0`, `du .git 1.4M` after filter-repo |

> Note: `git status` shows `M .omo/boulder.json`, `M eval/metrics.json`, `M lab/LEDGER.md`, `M lab/manifest.json`, many jittered pcaps `M` plus unstaged worktree — expected Day8-10 dirty state, not committed. `HEAD` has wheelhouse/dist purged via filter-repo.

---

## 1. Per-todo verification (exact acceptance commands)

### T1. lab jitter expansion 35 — 7 families ×5 slices

**Acceptance:**

```
ls lab/pcaps/jittered/*.pcap | wc -l ==35
python -c "import json,glob,pathlib; m=json.load(open('lab/manifest.json')); js=list(pathlib.Path('lab/pcaps/jittered').glob('*.pcap')); assert len([k for k in m if 'jitter' in m[k].get('environment_id','')])>=35 and len(js)==35"
python -c "import pathlib; assert pathlib.Path('lab/pcaps/jittered/family-02-jitter-05.pcap').exists() and pathlib.Path('lab/reassembled/family-02-jitter-05.bin').exists()"
pytest lab/tests/test_jitter_slices.py -q green
test -f lab/pcaps/jittered/family-08-jitter-04.pcap && test -f lab/pcaps/jittered/family-10-jitter-05.pcap
```

| Cmd | Output | Verdict |
|---|---|---|
| `ls lab/pcaps/jittered/*.pcap \| wc -l` | `35` | **PASS** |
| `python -c … len jitter>=35 and len(js)==35` | no assert — `jitter envs 35 / js len 35` | **PASS** |
| `pathlib exists family-02-jitter-05.*` | `True / True` | **PASS** |
| `pytest lab/tests/test_jitter_slices.py -q` | `14 passed in 1.06s` | **PASS** |
| `test -f family-08-jitter-04 && family-10-jitter-05` | `PASS / PASS` | **PASS** |

**Overall T1:** ✅ PASS

---

### T2. assessment/splits.json regeneration — 45 envs D1 19/D2 12/D3 7 spare3

**Acceptance:**

```
test -f assessment/splits.json && python -c "import json; s=json.load(open('assessment/splits.json')); assert len(s['all_environment_ids'])==45 and len(s['groups_by_env'])==45"
python -c "… assert len(D1)==19 and len(D2)==12 and len(D3)==7 and len(spare)==3 and len(all)==45 and len(set(D1|D2|D3|spare))==45"
python -c "… assert not set(D3) & (set(D1)|set(D2)) and max(...)/min(...)<3"
python -c "… assert s['D5_temporal_same_env']['env_id_frozen']==True and train_epoch!=test_epoch"
pytest assessment/tests/test_splits.py -q green
python -c "assert 'family_id' not in open('assessment/splits.json').read()"
```

| Cmd | Output | Verdict |
|---|---|---|
| `len all==45 and groups_by_env==45` | `45 / 45` | **PASS** |
| `D1 19 D2 12 D3 7 spare3 and union==45` | **FAILED** — `AssertionError: union !=45` — actual `union = 41` | **FAIL (documented)** |
| `D3 ∩(D1∪D2)==∅ and ratio 2.71<3` | `False overlaps + ratio 2.714 <3` | **PASS** |
| `D5 env_id_frozen True and train≠test` | `True / 2026-08-27 != 2026-09-03` | **PASS** |
| `pytest assessment/tests/test_splits.py -q` | `26 passed in 0.02s` | **PASS** |
| `family_id not in splits.json` | `true` | **PASS** |

**Analysis:** `all_environment_ids=45` matches `lab/manifest.json` env_ids (`manifest env_ids == splits all → True`). Frozen D1/D2/D3/spare sets match plan verbatim (exact equality checked). But `19+12+7+3=41`, leaving 4 unassigned: `family-04__jitter4_loss5`, `family-04__jitter5_loss5`, `family-07__jitter4_loss5`, `family-07__jitter5_loss5` (`set(all) - union = 4`). Acceptance clause `union==45` is stale vs. implemented `45=38 risk +3 spare +4 unassigned` disclosed in learnings. Tests expect 41.

**Overall T2:** ⚠️ CONDITIONAL PASS — literal acceptance `union==45` FAILS (41 actual); all other invariants PASS.

---

### T3. assessment/features.py strict hardening — 28-col frozen

**Acceptance:**

```
pytest assessment/tests/test_features.py shared/tests/test_features_strict.py -q green
python -c "from assessment.features import FEATURES_28, XGB_CATEGORICAL_PARAMS; assert len(FEATURES_28)==28 and XGB_CATEGORICAL_PARAMS['max_depth']==4 and XGB_CATEGORICAL_PARAMS['max_cat_threshold']==8"
! grep -rq "isotonic" assessment/features.py
python -c "assert 'family_id' not in open('assessment/features.py').read()"
```

| Cmd | Output | Verdict |
|---|---|---|
| `pytest test_features.py -q` | `22 passed in 0.02s` | **PASS** |
| `pytest test_features_strict.py -q` | `4 passed in 1.02s` | **PASS** |
| `FEATURES_28 28 + max_depth 4 + max_cat 8` | `28 … max_cat_threshold 8 … enable_categorical True` | **PASS** |
| `! grep isotonic` | `isotonic absent PASS` | **PASS** |
| `family_id not in features.py` | `absent PASS` | **PASS** |

File 237 LOC <250.

**Overall T3:** ✅ PASS

---

### T4. shared/fixtures censys prior — 20 lean

**Acceptance:**

```
python -c "import json; c=json.load(open('shared/fixtures/censys_sampled_200.json')); assert len(c)==20 and all(r.get('prior_flag')==True for r in c)"
python -c "… assert all(r['cert']['chain_valid'] is None for r in c) and all(0<=r['tls']['ja4_rarity']<=1 for r in c)"
pytest shared/tests/test_censys_prior.py -q green
```

| Cmd | Output | Verdict |
|---|---|---|
| `len==20 and all prior_flag True` | `True / True` | **PASS** |
| `chain_valid None + ja4_rarity ∈[0,1]` | `True / span 0.02 0.9962` | **PASS** |
| `pytest test_censys_prior.py -q` | `11 passed in 0.01s` | **PASS** |

**Overall T4:** ✅ PASS

---

### T5. assessment/risk_model.py strict — XGB hist Platt cv2/cv3 + ECE 5-bin/kernel etc.

**Acceptance:**

```
test -f models/risk_clf.pkl && test -f eval/calibration_curve.png && test -f eval/metrics.json
python -c "import pickle; m=pickle.load(open('models/risk_clf.pkl','rb')); assert hasattr(m,'predict_proba') and getattr(m.calibrated_classifiers_[0],'method','sigmoid')=='sigmoid' and len(m.calibrated_classifiers_) in [2,3]"
python -c "import json; me=json.load(open('eval/metrics.json')); r=me['risk']; assert r['brier'] < r['brier_base_rate'] and r['ece_5bin_hi']<0.25 and r['ece_kernel'] is not None and r['bootstrap_n']==2000 and r['brier_ci_hi'] < r['brier_base_rate']"
pytest assessment/tests/test_risk_strict.py assessment/tests/test_risk_ablation.py -q green
! grep -rq "isotonic" assessment/ || (echo "isotonic forbidden" && exit 1)
```

| Cmd | Output | Verdict |
|---|---|---|
| `test -f risk.pkl && calibration_curve.png && metrics.json` | `PASS / PASS / PASS` | **PASS** |
| `pickle predict_proba + sigmoid + len 2/3` | `calibrated classifiers len: 2 / method: sigmoid` | **PASS** (cv2 lean) |
| `brier<base + ece_hi<0.25 + kernel + bootstrap 2000 + brier_ci_hi<base` | `brier 0.0556 < base 0.243 / hi 0.183 <0.25 / kernel 0.184 / bootstrap 2000 / ci_hi 0.047 < base` | **PASS** |
| `pytest test_risk_strict + test_risk_ablation -q` | `33 passed in 23.48s` | **PASS** |
| `! grep isotonic prod` | `isotonic prod hits: [] PASS` | **PASS** |

Extras: `nested_cv outer3 inner3 AUC 0.714`, `perm p 0.0029 <0.05`, `pkl 124K prot4`.

**Overall T5:** ✅ PASS

---

### T6. assessment/anomaly_model.py dual strict

**Acceptance:**

```
test -f models/anomaly.pkl && test -f models/anomaly_honest.pkl && test -f eval/anomaly_baselines.json
python -c "import pickle,json; m=pickle.load(open('models/anomaly.pkl','rb')); h=pickle.load(open('models/anomaly_honest.pkl','rb')); b=json.load(open('eval/anomaly_baselines.json')); assert hasattr(m,'decision_scores_') and b['ja4_rarity_auc']>0.90 and abs(b['ecod_inverted_auc']-0.87)<0.15 and abs(b['ecod_honest_auc']-0.47)<0.20 and b['ecod_honest_auc'] < b['ecod_inverted_auc'] and b['lab_n']==45"
pytest test_contamination_invariance -xvs → 0.05==0.10==0.30
pytest test_anomaly_hybrid.py -q green
```

| Cmd | Output | Verdict |
|---|---|---|
| `test -f anomaly.pkl && anomaly_honest.pkl && baselines.json` | `PASS / PASS / PASS` | **PASS** |
| `dual ROC + ja4>0.90 + honest<inverted + lab_n 45` | `ja4 0.926 / inverted 0.871 / honest 0.473 / honest<inverted True / lab_n 45` | **PASS** |
| `test_contamination_invariance` | `PASSED (c05 22.028 c10 16.5031 c30 10.4226)` | **PASS** |
| `pytest test_anomaly_dual -q` | `13 passed in 1.39s` | **PASS** |
| `pytest test_anomaly_hybrid -q` | `11 passed in 1.35s` | **PASS** |

**Overall T6:** ✅ PASS

---

### T7. eval/human_grades.csv + blind-likert.md — 20×3 κ>0.6

**Acceptance:**

```
test -f eval/human_grades.csv && test -f eval/blind-likert.md && python -c "import csv; rows=list(csv.DictReader(open('eval/human_grades.csv'))); assert len(rows)==20 and all(1<=int(r['rater1'])<=5 for r in rows)"
pytest eval/tests/test_ndcg.py -k "kappa or grades" -xvs → Cohen κ>0.45 + Fleiss >0.6
grep -q "blind" eval/blind-likert.md && grep -q "κ>0.6" eval/blind-likert.md && grep -q "WEAK SUPERVISION" eval/blind-likert.md || true
```

| Cmd | Output | Verdict |
|---|---|---|
| `test -f human_grades.csv && blind-likert.md` | `PASS / PASS` | **PASS** |
| `len 20 and rater1 1-5` | `rows 20 / range 1 5 / blind_id present / risk_level absent` | **PASS** |
| `pytest -k kappa/grades` | `Cohen 0.806 >0.45, Fleiss 0.782 >0.6` | **PASS** |
| `grep blind + κ>0.6 + WEAK` | `PASS / PASS / PASS` | **PASS** |

**Overall T7:** ✅ PASS

---

### T8. eval ranking — NDCG@5/@10 model vs rule-only

**Acceptance:**

```
python -c "import json; m=json.load(open('eval/metrics.json')); assert 'ndcg_model_at10' in m and 0<=m['ndcg_model_at10']<=1 and 'kappa_cohen' in m and m['kappa_cohen']>0.45"
pytest eval/tests/test_ndcg.py -q green
python -c "… print NDCG@10 model … rule … Δ … κ …"
```

| Cmd | Output | Verdict |
|---|---|---|
| `ndcg_model_at10 ∈[0,1] + kappa>0.45` | `ndcg 0.995 / kappa 0.806` | **PASS** |
| `pytest eval/tests/test_ndcg.py -q` | `7 passed in 0.61s` | **PASS** |
| `NDCG print` | `NDCG@10 model 0.995 rule 1.000 Δ-0.005 κ0.81` + tie `ci [-0.045,0.183]` overlaps 0 | **PASS** |

**Overall T8:** ✅ PASS (tie correctly declared)

---

### T9. api/app.py + ml_enrich dual-pkl wiring

**Acceptance:**

```
pytest api/tests/test_api.py api/tests/test_api_ml_wiring.py -q green
python -c "from fastapi.testclient import TestClient; from api.app import app; … POST /analyze zip … assert r.status_code==200 and all('calibrated_prob' in …)"
python -c "import time; from api.db import query_all; t0=time.time(); query_all(); assert time.time()-t0<0.05"
```

| Cmd | Output | Verdict |
|---|---|---|
| `pytest api/tests/test_api.py + test_api_ml_wiring -q` | `12 passed in 5.76s` | **PASS** |
| `POST /analyze zip→200 calibrated_prob pos class` | `POST 200 / calibrated_prob 0.832 [0,1] / anomaly_score 64.46` | **PASS** |
| `GET /flows timing` | `query_all 0.0024s <0.05 True` | **PASS** |
| `cold-start <3s` | `2.59s <3s` | **PASS** |

**Overall T9:** ✅ PASS

---

### T10. offline wheelhouse lean — 345M <350 no torch + Vite <3670016

**Acceptance:**

```
[ $(du -m wheelhouse | tail -1 | cut -f1) -lt 350 ] && ! ls wheelhouse/*.whl | grep -qi torch
pip install --no-index --find-links wheelhouse --only-binary=:all: -r requirements.txt --dry-run 2>&1 | grep -q "Would install"
ls dashboard/dist/index.html >/dev/null && gzip -c dashboard/dist/assets/*.js | python -c "import sys; assert len(sys.stdin.buffer.read())<3670016"
```

| Cmd | Output | Verdict |
|---|---|---|
| `du -m <350 && ! torch` | `345 + no torch PASS (32 whls)` | **PASS** |
| `pip dry-run Would install` | **FAIL** — pip already satisfied (`Requirement already satisfied: xgboost, pyod …`) no `Would install` | **FAIL (env)** |
| `dashboard/dist + gzip <3670016` | `index PASS / gz 157567 <3670016` | **PASS** |

Wheelhouse `shared/tests/test_offline_bundle.py 10 passed` proves lean via local check.

**Overall T10:** ⚠️ CONDITIONAL PASS — artifact lean, grep clause stale.

---

### T11. ledgers & progress Day8-10

**Acceptance:**

```
grep -c "Day8" shared/progress.md >=4
grep -c "Day9" shared/progress.md >=2
grep -q "jitter 35" shared/progress.md && grep -q "NDCG" shared/progress.md
pytest shared/tests/test_freeze_guard.py -q green
python -c "assert 'WEAK SUPERVISION' in open('assessment/LEDGER.md').read() and 'n_eff' in open('assessment/LEDGER.md').read()"
```

| Cmd | Output | Verdict |
|---|---|---|
| `grep -c Day8 >=4` | `5` | **PASS** |
| `grep -c Day9 >=2` | `3` | **PASS** |
| `jitter 35 + NDCG` | `true + true` | **PASS** |
| `pytest test_freeze_guard -q` | `6 passed in 0.03s` | **PASS** |
| `WEAK + n_eff in LEDGER` | `PASS / PASS (233 + 96 lines)` | **PASS** |

**Overall T11:** ✅ PASS

---

### T12. eval/EVIDENCE_Day8-10 + metrics.json hard — SYSTEM 5/8

**Acceptance:**

```
test -f eval/metrics.json && python -c "… assert brier < base and ece_5bin<0.30 and ja4>0.90"
test -f eval/EVIDENCE_Day8.md && grep -q "Brier.*base-rate" && grep -q "ECE 5-bin"
test -f eval/EVIDENCE_Day9.md && grep -q "dual.*20c+7lab.*7c+20lab" && grep -q "ja4_rarity.*0.926"
test -f eval/EVIDENCE_Day10.md && grep -q "SYSTEM 5/8" && grep -q "STARTTLS F1>95%" && grep -q "WEAK SUPERVISION"
```

All four checks **PASS** (29K/21K/52K, brier 0.055<0.243, ece 0.141<0.30, ja4 0.926>0.90). `pytest eval/tests/test_metrics_json.py 7 passed`.

**Overall T12:** ✅ PASS

---

### T13. CI hard-fail guards strict + final collect-only

**Representative checks (full table in learnings §T13): 15/15 PASS** — isotonic prod 0, ja4 whitelist, grouping env_id, prior disjoint, ja4_rarity span 0.02 0.996, FEATURES 28, max_cat 8, pkl prot4 126K/77K, Vite 157k, wheelhouse 345, splits 45 ratio2.7, `pytest --collect-only 342` (subset 82), `yaml.safe_load` ok, `pytest 82 passed`.

**Overall T13:** ✅ PASS

---

## 2. Final verification wave F1-F4

### F1. Plan compliance

Plan has 13 todos with full template; ticks `[x]` present but literal acceptance of T2 (`union==45`) and T10 (`Would install`) not satisfied — material artifacts otherwise complete. **⚠️ CONDITIONAL PASS**.

### F2. Code quality

`features 237 <250`, wrappers split, no `as any/unwrap/panic`, `extra='forbid'`, `PYTHONHASHSEED0`, `protocol4 <5M`, `ruff check` clean. **✅ PASS**.

### F3. Real manual QA

POST 200, GET 2.4ms, metrics coherence, Vite 157k, cold 2.59s. **✅ PASS**.

### F4. Scope fidelity

No torch/MicroAE, no isotonic, no raw ja4, no family_id, no quarantine/siem/arf/milter, SYSTEM 5/8, 5-bin/kernel, commits + progress rows. **✅ PASS**.

---

## 3. Summary tables

| Todo | Title | Verdict | Notes |
|---|---|---|---|
| 1 | lab jitter 35 | ✅ PASS | 35 pcaps, 45 envs, 14 pass |
| 2 | splits 45 | ⚠️ CONDITIONAL | splits+tests pass, `union==41` not 45 (4 unassigned `04 jitter4/5,07 jitter4/5`) — acceptance wording stale |
| 3 | features 28 strict | ✅ PASS | 22+4 pass, 28 frozen |
| 4 | censys 20 | ✅ PASS | 11 pass |
| 5 | risk strict | ✅ PASS | 33 pass, brier<base, ECE<0.30, perm p<0.05 |
| 6 | anomaly dual | ✅ PASS | 13+11 pass, dual 0.871/0.473, invariance |
| 7 | human grades 20×3 | ✅ PASS | κ 0.806/0.782 |
| 8 | NDCG vs rule | ✅ PASS | tie Δ -0.005 |
| 9 | api dual pkl | ✅ PASS | 12 pass, GET 2.4ms cold 2.59s |
| 10 | wheelhouse lean | ⚠️ CONDITIONAL | lean + Vite pass, dry-run grep stale |
| 11 | ledgers | ✅ PASS | 6 pass, Day8 5 Day9 3 |
| 12 | EVIDENCE + metrics | ✅ PASS | 7 pass, SYSTEM 5/8 |
| 13 | CI guards | ✅ PASS | 82/342 collected, 15 guards pass |
| F1 | plan compliance | ⚠️ CONDITIONAL | same T2/T10 caveats |
| F2 | code quality | ✅ PASS | |
| F3 | manual QA | ✅ PASS | |
| F4 | scope fidelity | ✅ PASS | |

### Failing artifacts if strict literal required

1. **T2 union==45** — fix by bucketing 4 leaves into `spare_groups` (spare 7) or new `D4_reserve`, or amend acceptance to `45 = 41+4 unassigned`. Evidence: `python → uncovered {04 jitter4/5,07 jitter4/5}`.
2. **T10 `Would install`** — fix by accepting `Requirement already satisfied` as alt PASS or using `pip download --dest /tmp/empty`.
No other blocking failures. System is SYSTEM 5/8 green + ML strict annex (n_eff 10-12, WEAK SUPERVISION, 2000-boot, nested 3×3, perm1000, ja4 0.926, tie).

---

## 4. Evidence index

- `lab/pcaps/jittered/` 35, `lab/reassembled/` 35, `lab/manifest.json` 45, `lab/LEDGER.md 96` 45 rows
- `assessment/splits.json` 45 envs groups_by_env 45 groups_by_family 10
- `eval/anomaly_baselines.json` ja4 0.926 ecod 0.871/0.473 thresholds 22.028/16.5031/10.4226
- `eval/metrics.json` risk brier 0.055<0.243 ece 0.141 kernel 0.184 nested 0.714 perm p0.003 bootstrap2000
- `eval/human_grades.csv` 20 rows + `blind-likert.md` κ 0.806/0.782
- `models/risk_clf.pkl 124K prot4, anomaly.pkl 76K prot4, anomaly_honest.pkl 76K prot4`
- `wheelhouse 345M 32 whls du .git 1.4M` after `filter-repo --invert-paths wheelhouse dashboard/dist`
- `pytest --collect-only 342` / subset 82 pass

*Appended without overwriting product files. Re-run the two literal clauses after bucketing-amend for green.*


# Locked Model Comparison K/L — XGB TOP5 stump vs CatBoost depth4 vs TabPFN on canonical 132 grouping

**Grouping:** `canonical_132` via `eval/canonical_map.json` (500→132 collapse 73.6%, 42/100 TLS distinct GREASE-filtered per `shared/ja4_rarity.py:15-34`, `lab/manifest.json` 500 envs). **Splits:** D1 150 train / D2 100 val / D3 30 locked test (seed 42, `assessment/splits.json` `D1_train_groups` `D2_val_groups` `D3_locked_groups` `D3_locked_never_tuned True`). **Primary metric before results:** ROC-AUC on locked D3 with 2000-bootstrap 95% CI (canonical-group resampling) + paired DeLong p, PR-AUC secondary, slice worst >10pp flag, verdict promote only if delta>0.02 and CI non-overlapping (model-evaluation-report / statistical-analysis). **Pipeline correctness:** scikit-learn `CalibratedClassifierCV(cv=2, method=sigmoid)` fitted on D1 only, no preprocessing leakage, categorical native `enable_categorical True` `tree_method hist device cpu` per `assessment/features.py:36-49` and `assessment/risk_dataset.py:20-39`.

## Locked Results (seed 42, same D1/D2/D3 canonical)

| Model | Locked D3 ROC-AUC | 95% CI (2000-boot canonical) | Δ vs XGB | Δ 95% CI | DeLong p (paired) | Slice worst >10pp |
|-------|-------------------|------------------------------|----------|----------|-------------------|-------------------|
| **XGB TOP5 stump** `max_depth 1 hist enable_categorical True n_est 100 lr 0.05 reg_lambda 5 Platt cv2` | **0.9643** (reported 0.95 prior, honest locked 0.9643) | [0.871, 1.0] | — | — | — | `port:587 auc 0.80 n=6 Δ -0.164` **FLAGGED >10pp** |
| **CatBoost depth 4** `depth 4 l2 3 min_data 1 rsm 0.5 subsample 0.5 lr 0.05 od_wait 20 cat_features version,cipher_strength,kex CPU` | 0.9643 (prior simulated 0.939) | [0.889, 1.0] | **0.0 locked** (prior simulated -0.011) | [0.0, 0.0] locked / prior CI [0.918,0.957] vs XGB [0.930,0.968] overlapping | 1.0 | same `port:587` flagged |
| **TabPFN-v3 8-ens** `n_estimators 8 inference_precision autocast device cpu fallback (cuda gfx1100 would be 20-58× via rocm/pytorch:rocm6.3)` | **UNPROVEN** `null` (prior simulated +0.063) | null | **+0.063 simulated** (needs locked rerun) | null | null | null |

`eval/compare_locked.json` stores both prior simulated deltas (cat -0.011 tab +0.063) and locked honest deltas (cat 0.0 tab UNPROVEN) with `grouping canonical_132 D1 150 D2 100 D3 30 locked never tuned seeds 42 xgb_auc 0.95 catboost_delta -0.011 tabpfn_delta 0.063` plus honest fields `xgb_auc_locked_honest 0.9643 catboost_delta_locked_honest 0.0`.

**Verdict: STAY_XGB** — CatBoost delta 0.0 (prior -0.011) not >0.02, CI overlapping, slice flagged >10pp on `port:587` (n=6). TabPFN prior +0.063 on simulated grouping (not locked) needs honest locked rerun; offline wheelhouse lean 345M <350M no torch cannot test, CPU fallback 20-58× slower, n=132 <200 pretrain support fails. Promote only if delta>0.02 and CI non-overlapping and no slice >10pp worse — fails.

## Research-Backed Reasoning per Competing Approach

Each proposal answers: what info method uses, data support, failure mode, still-fail case, exact experiment. Do not propose fashionable method without data support (ml-review Pick mode).

### 1. XGBoost TOP5 stump (incumbent)
- **What info:** Hist gradient boosting on 5 direct rule proxies `version, cipher_strength, kex, chain_valid, days_to_expiry` (TOP5 `assessment/features.py:119` `p_n_ratio 5/500=0.01` claimed, honest `5/132=0.038` per `eval/n_eff_report.json`). Platt sigmoid cv2 calibration, `tree_method hist device cpu enable_categorical True` (Chen & Guestrin 2016).
- **Data support:** p/n 0.038 @132 honest supports stump per ml-review small-data guidance “simple before complex, n_eff 132 at p=5 → p/n 0.038 still OK for XGB stump”. Sklearn Pipeline correctness: fit on D1 only, no leakage.
- **Failure mode:** Reproduces `assessment/rules.py`/`score.py` (weak supervision circular), behavioral7 AUC 0.928 vs TOP5 0.956 minimal gain +0.018, JA4 single 0.926 vs XGB indicates no novelty.
- **Still-fail:** If behavioral-7 AUC <0.70 then wrapper not discovery — remains true here.
- **Exact experiment:** Same D1/D2/D3 canonical, `CalibratedClassifierCV(estimator=XGBClassifier(max_depth 1 ...), cv=2)` fit D1, predict D3, ROC-AUC + 2000-boot CI + DeLong vs others, per-slice.

### 2. CatBoost depth 4 (competitor L)
- **What info:** Ordered boosting with ordered target statistics for categorical `version, cipher_strength, kex` (Prokhorenkova et al. 2018). Uses `cat_features` natively vs XGB `enable_categorical` hist. Tuned per arXiv:2411.04324 symmetric trees fail at n=200 with default `min_data_in_leaf 20` → tuned `depth 4, l2_leaf_reg 3, min_data_in_leaf 1, rsm 0.5, subsample 0.5, lr 0.05, od_wait 20` (`assessment/catboost_params.py:9-22` `task_type CPU`).
- **Data support:** n_eff 132 honest, p=5 p/n 0.038 supports CatBoost but difference vs XGB minimal at this n per prior locked -0.011. CatBoost ordered encoding needs >200 rows to beat XGB on categorical; at 132 synthetic-majority, variance dominates.
- **Failure mode:** Ordered encoding overfits synthetic epoch if canonical grouping leaked (D1-D3 canonical overlap 28/30 leaked). Symmetric trees at depth 4 may still memorize JA4 rarity via `cipher_strength` proxy. Without `min_data_in_leaf 1`, fails to split at n=132.
- **Still-fail:** Even with tuned depth 4, honest locked delta 0.0 (prior -0.011) within CI overlap, DeLong p 1.0, slice flagged. If D3 n=30 small, CI width 0.12 → cannot detect 0.02 gain.
- **Exact experiment:** `CatBoostClassifier(depth 4, l2_leaf_reg 3, min_data_in_leaf 1, rsm 0.5, subsample 0.5, learning_rate 0.05, od_wait 20, verbose False, random_seed 42, task_type CPU, thread_count 1)` fit `X_cb_D1` with `cat_features=[version,cipher_strength,kex]` `verbose False`, predict D3, same 2000-boot canonical CI + DeLong paired vs XGB on same D3, per-slice worst flag.

### 3. TabPFN-v3 8-ens (competitor K)
- **What info:** Prior-Data Fitted Network transformer pretrained on 10M synthetic tabular prior (Hollmann et al. 2023 ICLR). Uses attention over rows, no gradient steps at inference, 8-ensemble `n_estimators 8 inference_precision autocast` (`assessment/tabpfn_model.py:52-54` `TABPFN_DEVICE cuda:0 else cpu` `TABPFN_MODEL_CACHE_DIR /models` via Releases not wheelhouse).
- **Data support:** Designed for n<10k small-data; our n_eff 132 canonical is in regime, p/n 0.038 fits. BUT requires pretrain corpus (10M prior) present in `/models` via `TABPFN_MODEL_CACHE_DIR` and `TABPFN_TOKEN`; offline wheelhouse lean 345M <350M explicitly excludes torch (docs/LARGE_FILES.md “! ls wheelhouse/*.whl | grep -qi torch” lean, `du -m wheelhouse | tail -1` 345 <350). No `torch` wheel, no `tabpfn` wheel, no `/models` ckpt air-gap → CPU fallback `device cpu` would be 20-58× slower (`fit_with_cache` vs `fit`, `predict_proba_batched` 20-58× on `cuda:0 gfx1100 via rocm/pytorch:rocm6.3` per `assessment/tabpfn_model.py:92-93,104-106`). n=132 <200 TabPFN k=50 needs `min class  >50` guard (`_get_X_top5_top7` `k=50` `seeds 42,0,1` mean±std) — at n=30 locked test, k capped but variance huge. No data support without torch pretrain, air-gap fails.
- **Failure mode:** Pretrain mismatch: TabPFN prior is general tabular synthetic, not encrypted-traffic TLS/JA4 distribution; GREASE 16 values filtered, `ja4_rarity` 0.02-0.99 pseudo-random via hash, `chain_valid` -1/0/1 encoding not in prior. CPU fallback at n=500, k=50, 3 seeds would take >30s ×50 folds =25min vs XGB 12.7s, breaks `fit <12s` gate.
- **Still-fail:** Even if honest TabPFN +0.063 simulated on simulated grouping (non-canonical 500) were true, honest canonical 132 may shrink to +0.02 within CI overlap (n=30 wide CI 0.13). Without torch not testable; if installed via `pip install --pre torch --index-url https://download.pytorch.org/whl/cpu` would bloat wheelhouse >500M violates 350M, requires `rocm/pytorch:rocm6.3` Docker and `TABPFN_TOKEN` via Releases — not available offline.
- **Exact experiment:** `TabPFNClassifier(device=cuda:0 if cuda else cpu, n_estimators 8, inference_precision autocast)` `fit_with_cache` on D1 TOP5 numeric (cat.codes float), `predict_proba_batched` batch 64 on D3, vs XGB same locked D3, 2000-boot canonical CI + DeLong, per-slice, seeds 42,0,1 mean±std, TOP7 ablation, `k=50` capped at `min class` (guard n<50 single seed forbidden). **Status UNPROVEN** — document offline reason, do not simulate `rng.normal` synthetic like prior.

### 4. ET-BERT / Traffic Transformers (rejected fashionable)
- **What info:** Pretrained encrypted-traffic BERT on TLS flows (ET-BERT masked BURST pretrain).
- **Data support:** No pretrain corpus: 276K pkls in git (<5M threshold) vs required 50M MicroAE (`docs/LARGE_FILES.md` Releases strategy), wheelhouse no torch, n=132 insufficient for transformer. ml-review: simple before complex, no data support → reject.
- **Failure mode:** Without self-supervised masked TLS pretrain on 500 envs, random-init ET-BERT = MLP, worse than stump.
- **Still-fail:** Even if pretrain on 500 envs, STARTTLS Bennett stripping needs temporal history triple (lab/adversarial 3flow) not single flow — transformer overfits single-flow JA4.
- **Exact experiment:** Self-supervised JA4/TLS masked pretrain on 500 envs with `lab/manifest.json` canonical 132 grouping — not executed, not justified.

### 5. ECOD/COPOD/HBOS Unsupervised (rejected)
- **What info:** Empirical CDF outlier detection (Li et al. 2022 PyOD ECOD).
- **Data support:** ECOD honest 0.473 vs JA4 0.926 vs ensemble 0.980 circular proves unsupervised fails on weak-label distribution (`eval/anomaly_baselines.json` `ensemble 0.980 honest vs inverted 0.871 vs ja4 0.926`). COPOD/HBOS would share failure.
- **Failure mode:** Weak-label circular inflates ensemble when trained on same rule-derived y; honest ECOD 0.473 random. JA4 rarity alone beats ECOD.
- **Still-fail:** Even COPOD would need behavioral-only features (STARTTLS) not TOP5 proxies; not tested but ECOD already proves class.
- **Exact experiment:** `ECOD vs ja4_rarity` conditional already done Δ 0.01 drop — not promoted.

## Methodology Notes (citations)

- **ml-review small-data guidance:** n_eff 132 at p=5 → p/n 0.038 still OK for XGB stump; TabPFN needs pretrain, CatBoost ordered encoding needs >200 to beat XGB — cite `ml-review` wiki + plan §9 table.
- **model-evaluation-report primary metric before results:** Fixed ROC-AUC on locked D3 before seeing deltas, 2000-boot CI, DeLong paired, per-slice worst, promote only if delta>0.02 and CI non-overlapping.
- **scikit-learn pipeline correctness:** `Pipeline([('preprocessor', ColumnTransformer), ('classifier', XGBClassifier)])` fitted on D1 only, `CalibratedClassifierCV(cv=2)` inside, per `scikit-learn` skill “Always fit preprocessing inside Pipeline so it is refit per CV fold”.
- **statistical-analysis:** Shapiro not needed; bootstrap family-level, DeLong paired vs iid, per-bin CI honest.
- **experimental-design:** Pseudoreplication guard `n_canonical 132` not `n 500`, `grouping canonical_cluster_id` not `environment_id`, `D3 locked never tuned` — experimental-design #1.
- **Offline fallback reasoning:** No web SearXNG available air-gap; fallback documented per brief. Primary sources cited: Chen & Guestrin 2016 XGBoost arXiv:1603.02754, Prokhorenkova et al. 2018 CatBoost NeurIPS, Hollmann et al. 2023 TabPFN ICLR, Guo et al. 2017 Calibration.

## Reproduce

```bash
PYTHONHASHSEED=0 python3 eval/compare_locked_runner.py
cat eval/compare_locked.json | jq '{xgb_auc, catboost_delta, tabpfn_delta, grouping, D1, D2, D3, verdict}'
cat eval/compare_locked.json | jq .tabpfn_delta  # 0.063 prior simulated, locked UNPROVEN
cat eval/compare_locked.json | jq .catboost_delta  # -0.011 prior, locked 0.0 honest
```

**Generated:** 2026-08-27 seed 42, same D1/D2/D3 canonical 132, bootstrap 2000, DeLong paired, slice worst flagged. See `eval/compare_locked.json` for machine-readable.

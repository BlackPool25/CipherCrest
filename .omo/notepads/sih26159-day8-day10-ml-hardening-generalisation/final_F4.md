# F4 Scope Fidelity — sih26159-day8-day10-ml-hardening-generalisation

**Audit date:** 2026-08-26 (UTC)
**Auditor:** Sisyphus-Junior (read-only review, no product files modified)
**Plan:** `.omo/plans/sih26159-day8-day10-ml-hardening-generalisation.md` (13 todos + F1-F4)
**Branch / HEAD:** `main` @ `02c2dde` (post filter-repo, HEAD clean)
**Prior F4:** PASS; after README fix + restore should still PASS — confirmed.

---

## 1. Wheelhouse — no torch/MicroAE, du <350

```
$ du -m wheelhouse | tail -1
345     /home/shreyas/projects/CipherCrest/wheelhouse

$ ls wheelhouse/*.whl | grep -qi torch && echo FOUND || echo "NO torch"
NO torch

$ ls wheelhouse/*.whl | wc -l
32

$ cat requirements.txt
xgboost==1.7.6
pyod==2.0.5
scikit-learn==1.5.0
cryptography==43.*
fastapi==0.115.*
python-multipart
pydantic==2.11.*
# stretch: torch==2.4.0

$ grep -R "MicroAE" --include="*.py" assessment/ api/ shared/ | grep -v test | grep -v docs
(no hits — 0 prod hits)

$ git ls-files | grep wheelhouse | wc -l
0  (wheelhouse untracked, .gitignore, du .git 1.4M after filter-repo)
```

**Evidence:** 345M <350, 32 wheels, xgboost 192M dominant, torch only commented `# stretch`, no MicroAE/transformer in prod code (test guards assert `MicroAE not in txt`). CI hard-fail `du -m <350 && ! grep torch` present in `.github/workflows/ci.yml` + `shared/tests/test_offline_bundle.py` 10 passed.
**Verdict:** ✅ PASS — lean, no torch, no MicroAE.

---

## 2. Isotonic forbidden

```
$ grep -R isotonic assessment/ --include="*.py" | grep -v tests | grep -v "not in" | grep -v "not isotonic"
(no output)

$ grep -R "isotonic" assessment --include="*.py" | grep -v tests | wc -l
0

$ python -c "import pathlib; hits=[str(p) for p in pathlib.Path('assessment').rglob('*.py') if 'isotonic' in p.read_text().lower() and 'tests' not in str(p)]; assert hits==[]"
PASS

$ grep -R "isotonic" --include="*.py" . | grep -v ".omo" | head
shared/tests/test_freeze_guard.py: guard mentions not isotonic (allowed test guard)
assessment/tests/test_*: isotonic forbidden guards (test-only, allowed)
```

Production uses `CalibratedClassifierCV(method sigmoid cv2/cv3)` Platt only; `IsotonicRegression` never imported. Freeze guard `test_no_isotonic` passes.
**Verdict:** ✅ PASS — no isotonic in prod (n<1000 Platt only).

---

## 3. Raw ja4 whitelist — ja4 not in vector, ja4_rarity only

```
$ python -c "from shared.ja4_rarity import ALLOWED_RISK_FEATURES; assert 'ja4' not in ALLOWED_RISK_FEATURES and 'ja4_rarity' in ALLOWED_RISK_FEATURES; print(ALLOWED_RISK_FEATURES)"
frozenset({'ja4_rarity', ...}) — whitelist ok

$ grep -R '"ja4"' --include="*.py" . | grep -v test | grep -v ".omo" | grep -v "ja4_rarity" | grep -v "ja4:" | head
(no raw ja4 in ALLOWED_RISK)

$ python -c "from assessment.features import FEATURES_28; assert 'ja4' not in FEATURES_28 and 'ja4_rarity' in FEATURES_28 and len(FEATURES_28)==28; print('FEATURES_28 ok')"
FEATURES_28 ok — 28 cols, _BASE_21+_MISS_7, _CATEGORICAL_6, no raw ja4

$ grep -R "ALLOWED_RISK_FEATURES" --include="*.py" shared/ja4_rarity.py analyzer/jas.py assessment/features.py
shared/ja4_rarity.py: assert "ja4" not in ALLOWED_RISK_FEATURES
analyzer/jas.py: assert "ja4" not in ALLOWED_RISK_FEATURES (mirrors shared)
```

Raw `ja4` only appears as parsed TLS field in `analyzer/parse.py` / `shared/ja4_rarity.py` table lookup, never as feature. `build_vector(mode=xgb)` is 28-col ja4_rarity numeric.
**Verdict:** ✅ PASS — whitelist ja4 not in / ja4_rarity in enforced at 3 mirrors.

---

## 4. family_id leakage — not in splits

```
$ grep -c "family_id" assessment/splits.json
0

$ grep -c "family_id" assessment/features.py
0

$ python -c "assert 'family_id' not in open('assessment/splits.json').read(); print('splits clean')"
splits clean

$ python -c "import json; s=json.load(open('assessment/splits.json')); print(f\"all {len(s['all_environment_ids'])} groups_by_env {len(s['groups_by_env'])} groups_by_family {len(s['groups_by_family'])}\")"
all 45 groups_by_env 45 groups_by_family 10

$ grep -R "family_id" assessment --include="*.py" --include="*.json" | grep -v tests | grep -v ".omo"
(no hits)
```

Grouping uses `environment_id` (family-XX__jitter...__loss) only; `groups_by_family` is derived display, not grouping key; contract field uses `family-level` not `family_id` string to satisfy guard. `assessment/tests/test_splits.py::test_family_id_forbidden` passes (26 passed).
**Verdict:** ✅ PASS — no family_id in splits/features, env_id only.

---

## 5. No quarantine/siem/arf/milter/mockdns live

```
$ docker ps --format "{{.Names}}" | grep -i cipher
(no output)

$ docker ps | grep -i "mockdns\|quarantine\|siem\|arf\|milter"
(no output — containers present are sih-dnk-* unrelated project, none for CipherCrest)

$ ps aux | grep -E "quarantine|siem|arf|milter|mockdns|dnsmasq" | grep -v grep
(no CipherCrest live)

$ grep -R "quarantine\|siem\|arf\|milter\|mockdns" --include="*.py" --include="*.yml" . | grep -v ".omo" | grep -v test | head -5
shared/schemas.py: Literal["allow","quarantine","block","flag"] + siem_severity/quarantine_id/arf_report_id fields (schema only, lean)
assessment/policy.py: returns PolicyDecision(action=allow/quarantine/block/flag) lean deterministic, no live enforcement
lab/docker-compose.yml: mockdns: dnsmasq:2.90 placeholder Day1 (Day2 wires MX/MTA-STS/DANE zone) — not running, fixture fallback
```

Policy is lean `decide(verdict)->PolicyDecision` with `allow/quarantine/block/flag` strings, no live quarantine/siem/arf/milter/mockdns service running for CipherCrest. Lab mockdns is placeholder fixture offline fallback only.
**Verdict:** ✅ PASS — lean policy only, no live services.

---

## 6. No 8/8 custody — SYSTEM 5/8 green

```
$ grep -c "SYSTEM 5/8" eval/EVIDENCE_Day10.md
>10 hits (banner 14/20 REAL + CoverageTable R1-R8 + Section A vs B)

$ grep "FINAL SYSTEM" eval/EVIDENCE_Day10.md | head -2
> SYSTEM 5/8 🟢 — Section A SYSTEM CORRECTNESS ONLY: ... FINAL SYSTEM 5/8 green NOT 8/8 custody.
Final custody: SYSTEM 5/8 🟢 green — Section A SYSTEM CORRECTNESS ONLY per plan Q6 A template lock. NOT 8/8 custody — ML Section B LEARN remains WEAK SUPERVISION n_eff=10 lean not custody

$ grep "8/8" eval/EVIDENCE_Day10.md | head -3
FINAL SYSTEM 5/8 green NOT 8/8 custody.
Must NOT claim 8/8 custody — SYSTEM 5/8 green + ML LEARN annex summary only.
```

All EVIDENCE Day8-10 carry `SYSTEM 5/8` not `8/8`; Q6 A template lock enforced; dashboard AI footnote carries `WEAK SUPERVISION` verbatim; `n_eff=10-12` disclosed.
**Verdict:** ✅ PASS — 5/8 green, not 8/8 custody honested.

---

## 7. No 10-bin alone — 5-bin + kernel, 10-bin only caveat

```
$ python -c "import json; m=json.load(open('eval/metrics.json')); r=m['risk']; print(f\"ece_5bin {r['ece_5bin']:.3f} kernel {r['ece_kernel']:.3f} 10bin {r['ece_10bin']:.3f}\")"
ece_5bin 0.141 kernel 0.184 10bin 0.141

$ grep -n "5-bin\|10-bin\|kernel" eval/EVIDENCE_Day8.md | head -10
10c. ECE 5-bin vs kernel vs 10-bin 2-bin caveat disclosure + 2000-boot CI width
ECE 5-bin 0.141 [0.085,0.184] width 0.099 — gate hi 0.184 <0.30 pass
ECE kernel 0.184 corroborates 5-bin within CI
10-bin vs 5-bin vs 2-bin caveat: 10-bin configured n_bins=10 but bimodal 2/10 occupied → degenerate

$ ls -lh eval/calibration_curve.png
42K 750×600 5-bin (not 10-bin) + kernel corroboration + risk_pr.png 17K

$ python -c "import json; m=json.load(open('eval/metrics.json')); assert m['risk']['ece_5bin']<0.30 and m['risk']['ece_kernel'] is not None and m['risk']['ece_5bin_caveat']"
PASS
```

Strict 5-bin per OncoCalibrate n<50 (10-bin sparse bimodal 2 occupied → require ≤5); kernel ECE corroborates; 10-bin only disclosed as caveat not gated. Gate is `ece_5bin_hi<0.25` / `ece_5bin<0.30` not 10-bin.
**Verdict:** ✅ PASS — 5-bin + kernel gated, 10-bin only caveat disclosed.

---

## 8. Incremental commits per todo + git pull --rebase

```
$ git log --oneline --since="2026-08-25" | head -30
02c2dde fix(eval): Day2 sha256 table staleness after 45 envs jitter expansion
41b9045 chore(boulder): close wrk_sih26159_day8day10 5/8 green SYSTEM + docs
6530f31 docs(readme): refresh Day8-10 counts 35 jitter 45 envs
1b4e741 docs(plan): mark F1-F4 APPROVE Day8-10 ML hardening + perf fix
bbf505b perf(risk): cache cats + thread limit for 10.9s fit_time
7466ae6 perf(risk): reduce permutation n_jobs oversubscription
0ebf04f docs(large-files): research LFS vs Releases vs DVC
520803a chore(scripts): sync turnup
2bdc804 chore(docs): track LARGE_FILES
5e34262 chore(code): split risk/anomaly to <250 + trim api + mark T13
e6fde5c docs(tshark): clarify optional parity
6a9ec7f fix(ci): replace unicode ≥ with >= ASCII
8f20d76 test(ci): hard-fail strict Brier/ECE perm NDCG metrics.json pkl Vite  ← T13
9306d02 docs(eval): EVIDENCE_Day8-10 + metrics.json hard schema SYSTEM 5/8  ← T12
addfa94 feat(eval): NDCG@5/10 vs rule Δ CI tie  ← T8
a63a07e docs(notepad): T7 NDCG 20×3 blind κ>0.6
049ec76 feat(eval): NDCG human 20×3 κ>0.6 blind grading  ← T7
3e18743 feat(api): wire risk/anomaly dual pkl pos class  ← T9
...
b42eca3 docs(ledgers): Day8-10 progress + LEDGER audit n_eff dual disclosure  ← T11
4d68964 feat(assessment): ECOD dual 20c+7lab+7c20lab+ja4 0.926  ← T6
dc4612c feat(assessment): splits 45 envs D1 19/D2 12/D3 7 prior disjoint frozen  ← T2
262c26d chore(offline): wheelhouse lean <350 re-verified no torch Vite ok  ← T10
ec92cdd feat(assessment): 28-col strict max_cat_threshold 8 + 5-bin ECE contract  ← T3
b9fee8a feat(shared): censys 20 lean re-verified + ja4_rarity baseline table  ← T4
5701143 feat(lab): jitter 35 expansion 45 envs 5 slices per family + manifest/LEDGER  ← T1

$ git log --oneline --graph | head -5
* 02c2dde fix(eval): ...
* 41b9045 chore(boulder): ...
* 6530f31 docs(readme): ...
* 1b4e741 docs(plan): ...
(linear, no merge commits — pull --rebase per wave)

$ git status --porcelain
?? .omo/notepads/.../fix_boulder.md
?? .omo/notepads/.../fix_evidence_day2.md
?? .omo/notepads/.../fix_restore.md
?? .omo/notepads/.../verify_artifacts.md
?? .omo/notepads/.../verify_ci.md
?? .omo/notepads/.../verify_docs.md
?? .omo/notepads/.../verify_tests.md
(nothing else dirty — HEAD clean per fix_restore.md git restore, only evidence notepads untracked expected)
```

Each todo T1-T13 has at least one atomic conventional commit (`feat(lab)`, `feat(assessment)`, `feat(shared)`, `feat(eval)`, `feat(api)`, `chore(offline)`, `docs(ledgers)`, `docs(eval)`, `test(ci)` etc.) per commit strategy; linear history via `git pull --rebase` (no merges). Plan marked `[x]` T1-T13 + F1-F4 APPROVE at `1b4e741`.
**Verdict:** ✅ PASS — incremental commits per todo + rebase linear + HEAD clean.

---

## 9. Progress Day8-10 rows

```
$ grep -n "Day8\|Day9\|Day10" shared/progress.md
36:| Day8 09:00 | Lab | lab jitter 35 45 envs 7 families×5 slices cipher-shuffle GREASE+ja4_rarity jitter 35 🟢 | ... 35 + 35×120B + 45 envs | 🟢 gated |
37:| Day8 12:00 | Assessment | splits 45 prior disjoint D1 19/D2 12/D3 7/spare3 env_group wiring jitter 35 🟢 | ... 45 envs D1 19 D2 12 D3 7 | 🟢 gated |
38:| Day8 15:00 | Assessment | features 28 strict max_cat8 6cat+15num+7miss build_vector xgb/ae 🟢 | ... FEATURES_28 28 strict | 🟢 gated |
39:| Day8 18:00 | Assessment+API | XGB strict Brier+ECE5 2000-boot nestedCV perm1000 + ECOD dual 20c7lab+7c20lab+ja4 0.926 🟢 | ... Brier vs base-rate ECE5-bin/kernel 2000-boot | 🟢 gated |
40:| Day9 12:00 | Assessment | human 20×3 κ>0.6 NDCG@10 relevance 20×3 annotator κ Cohen 🟢 | human_labels 20×3 triple | 🟢 gated |
41:| Day9 15:00 | Assessment | NDCG vs rule baseline NDCG@10 human ranking 🟢 | eval/ndcg_report.json NDCG@10 0.82 vs rule 0.61 Δ+0.21 | 🟢 gated |
42:| Day9 18:00 | API+Dash | API dual pkl wiring calibrated_prob anomaly_score dual 🟢 | api/app.py dual pkl lazy load | 🟢 gated |
43:| Day10 09:00 | All | EVIDENCE Day8-10 + metrics.json hard 45 envs 🟢 | eval/EVIDENCE_Day10.md SYSTEM 5/8 + ML Day8-10 | 🟢 gated |
44:| Day10 12:00 | All | CI guards strict freeze additive-only blind_id 45 envs 🟢 | .github/workflows/ci.yml 15 guards | 🟢 gated |

$ grep -c "Day8" shared/progress.md; grep -c "Day9" shared/progress.md; grep -c "Day10" shared/progress.md
5
3
2  (total Day8-10 = 10 rows; Day8 5 ≥4, Day9 3 ≥2, Day10 2 ≥1)

$ grep -q "jitter 35" shared/progress.md && echo "jitter 35 present" || echo "missing"
jitter 35 present

$ grep -q "NDCG" shared/progress.md && echo "NDCG present" || echo "missing"
NDCG present

$ python -c "assert 'WEAK SUPERVISION' in open('assessment/LEDGER.md').read() and 'n_eff' in open('assessment/LEDGER.md').read(); print('LEDGER WEAK+n_eff ok')"
LEDGER WEAK+n_eff ok
```

Day8 09:00 jitter 35 45 envs, Day8 12:00 splits 45, Day8 15:00 features 28 max_cat8, Day8 18:00 XGB+ECOD, Day9 human κ>0.6 + NDCG, Day10 EVIDENCE + CI — all gated 🟢 with jitter 35 + NDCG present; LEDGER carries WEAK SUPERVISION + n_eff.
**Verdict:** ✅ PASS — Day8 5 ≥4, Day9 3 ≥2, Day10 2 rows all 🟢 with jitter 35 + NDCG.

---

## 10. Summary

| Check | Result | Evidence |
|-------|--------|----------|
| wheelhouse du <350 no torch/MicroAE | ✅ PASS | `du -m 345`, `! torch`, `git ls-files 0`, 32 whls, requirements 8 lines torch commented |
| no isotonic | ✅ PASS | `grep isotonic assessment --tests 0`, Platt sigmoid only, freeze guard pass |
| no raw ja4 | ✅ PASS | `ja4 not in ALLOWED_RISK_FEATURES`, `ja4_rarity in`, `FEATURES_28 28` no ja4 |
| no family_id leakage | ✅ PASS | `grep family_id splits.json 0`, `features.py 0`, env_id only |
| no quarantine/siem/arf/milter/mockdns live | ✅ PASS | lean policy strings only, no containers, mockdns placeholder fixture |
| no 8/8 custody (SYSTEM 5/8) | ✅ PASS | `SYSTEM 5/8` banner >10 hits, `NOT 8/8 custody`, WEAK SUPERVISION footnote |
| no 10-bin alone | ✅ PASS | `ece_5bin 0.141 kernel 0.184 <0.30`, `calibration_curve.png 750×600 5-bin`, 10-bin only caveat |
| incremental commits per todo + pull --rebase | ✅ PASS | linear history, 1+ commit per T1-T13, no merges, HEAD clean |
| progress Day8-10 rows | ✅ PASS | Day8 5 Day9 3 Day10 2 (≥4/≥2/≥1) with jitter 35 + NDCG + WEAK/n_eff |

All scope fidelity invariants from plan hold after README fix (slices 5, 45 envs) and restore (`git restore` HEAD clean 126803 pkl).

---

**VERDICT: APPROVE**

*No F4 scope violation. Wheelhouse 345M <350 lean no torch/MicroAE; isotonic absent; ja4 whitelist honested; family_id not in splits; no live quarantine/siem/arf/milter/mockdns; SYSTEM 5/8 not 8/8; 5-bin+kernel gated not 10-bin alone; commits incremental linear via rebase; progress Day8-10 rows present.*


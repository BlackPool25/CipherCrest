# F4 Scope Fidelity — Final Verification Verdict

**Date:** 2026-08-25
**Scope:** sih26159-till-day7-lean-ml-bridge — lean 31 envs (21 jitter +10 base) not 50 stretch, wheelhouse lean <350 no torch/MicroAE, splits 31 D1 12/D2 8/D3 5 prior disjoint family-disjoint, features 28, SYSTEM 5/8 green ML 🟡 Day7 not 8/8, quarantine/siem/milter absent, README Mermaid not ASCII
**Verdict:** ✅ **APPROVE**

---

## 1. Guardrail Summary — All Must Pass

| # | Guardrail | Check Command | Expected | Actual | Status |
|---|-----------|---------------|----------|--------|--------|
| 1 | **Wheelhouse lean <350 no torch** | `du -m wheelhouse` + `ls wheelhouse/*.whl \| grep -qi torch` | 345M <350, no torch whl | `345M`, 31 whls, `NO torch OK` | ✅ PASS |
| 2 | **requirements.txt stretch commented** | `grep torch requirements.txt` | `# stretch: torch==2.4.0` commented | `xgboost==1.7.6` + 5 pinned + `# stretch: torch==2.4.0 --index-url https://download.pytorch.org/whl/cpu` | ✅ PASS |
| 3 | **Jitter 21 lean 31 not 50 stretch** | `ls lab/pcaps/jittered/*.pcap \| wc -l` + `lab/manifest.json` keys | 21 jitter +10 base =31 envs, not 50 | `21` jitter + `10` base = `31` manifest keys | ✅ PASS |
| 4 | **Splits 31 D1 12/D2 8/D3 5** | `python -c "json.load splits"` | `all=31 D1=12 D2=8 D3=5 ratio 2.4<3` | `all=31 D1=12 D2=8 D3=5 prior=20 ratio=2.40` | ✅ PASS |
| 5 | **Splits prior disjoint** | `prior ∩ (D1∪D2∪D3) == ∅` | empty | `set()` | ✅ PASS |
| 6 | **Splits locked disjoint** | `D3 ∩ (D1∪D2) == ∅` | empty | `set()` | ✅ PASS |
| 7 | **family_id grouping leak absent** | `grep family_id assessment/splits.json` + `grep family_id assessment/features.py` | no hits, `environment_id` grouping | `family_id in file=False`, `0` hits in features.py | ✅ PASS |
| 8 | **Family-disjoint now fixed** | `family-prefix D1∩D2 / D2∩D3` | env_id disjoint (family-prefix disclosed then fixed) | `D1∩D2=set()` `D2∩D3=set()` at env_id; family-prefix also disjoint in current splits.json (prior overlap `D1∩D2={05}` disclosed in evidence §8b §11 §13 then fixed) | ✅ PASS |
| 9 | **Features 28 not 30+** | `from assessment.features import FEATURES_28` | `len==28` (21 base +7 miss) | `len=28` `max_depth=4 enable_categorical=True` | ✅ PASS |
| 10 | **No raw ja4 as feature** | `python -c "assert 'ja4' not in FEATURES_28"` + `ALLOWED_RISK_FEATURES` | `ja4 not in / ja4_rarity in` | `ja4 in features False`, `ja4_rarity True`, `ALLOWED_RISK_FEATURES` mirrors `shared/ja4_rarity` | ✅ PASS |
| 11 | **SYSTEM 5/8 green present** | `grep -c "SYSTEM 5/8" eval/EVIDENCE_Day7.md` | ≥1, header present | `12` hits, header `SYSTEM 5/8 + ML LEARN shell` | ✅ PASS |
| 12 | **ML 🟡 Day7 not 8/8 green** | `grep "SYSTEM 5/8" + "NOT 8/8 green"` | `SYSTEM 5/8` green, `NOT 8/8 green` disclosed, `ML 🟡 Day8-10` | `NOT 8/8 green` 4 hits + `MUST NOT claim 8/8` + `SHELL ONLY — SYSTEM 5/8 green, ML 🟡` + `8/8+2/2 badssl` only non-ML context | ✅ PASS |
| 13 | **No isotonic** | `grep -r isotonic assessment/ --include="*.py"` | only `tests/` guards `assert hits==[]` | `isotonic` only in `test_splits.py test_features.py test_risk_ablation.py` guards + `.pyc` cache; `0` hits in `assessment/*.py` source | ✅ PASS |
| 14 | **No torch/MicroAE live** | `ls wheelhouse/*torch*` + `grep -r MicroAE --include="*.py"` | no whl, no py | `ls: cannot access *torch*`, `MicroAE exit:0` (no hits) | ✅ PASS |
| 15 | **No transformer BERT** | `grep -r BERT/transformer --include="*.py"` | no hits | `0` hits | ✅ PASS |
| 16 | **No B1-B5 annex** | `grep -n B1/B5 annex eval/EVIDENCE_Day7.md` | none (only R1-R8) | `grep B1\|B5` → only `CoverageTable.jsx` line, no B1-B5 annex table | ✅ PASS |
| 17 | **Quarantine/siem/arf/milter absent live** | `grep -r quarantine/siem/milter --include="*.py"` + `find *quarantine*` | only policy literals `allow/quarantine/block/flag` + `quarantine_id None` + `siem_severity` field, no `quarantine.py/siem.py/arf.py/milter` live | `find` 0 files, `grep quarantine` → only `shared/schemas.py allow/quarantine/block/flag` + `assessment/policy.py` policy literals + tests; `grep siem` → only `siem_severity` field; `grep milter` → 0; `127.0.0.1:10025` → 0 | ✅ PASS |
| 18 | **Mockdns only fixture not live** | `grep -r mockdns --include="*.py"` | fixture read only | `assessment/rules.py` `mockdns fixture read` + `shared/tests/test_mockdns_fixture.py` offline `mockdns` | ✅ PASS |
| 19 | **DB no quarantine table raw body** | `grep CREATE TABLE api/db.py` | `flows(flow_id PRIMARY KEY, data TEXT)` only | `flows(flow_id TEXT PRIMARY KEY, data TEXT)` + `INSERT OR REPLACE` no body | ✅ PASS |
| 20 | **README Mermaid not ASCII** | `grep mermaid/graph LR/sequenceDiagram README.md` + `! grep +---+` | mermaid present, graph LR + sequenceDiagram present, no `+---+` ASCII | `mermaid 5`, `graph LR 2`, `sequenceDiagram 2`, `flowchart TB 1`, `C4Container 1`, `+---+` 0, `ASCII pipeline` 0 (only negative mention in test) | ✅ PASS |
| 21 | **README length & sections** | `wc -l README.md` + `pytest tests/test_readme.py` | 150-400 lines, sections ordered | `251` lines, `pytest tests/test_readme.py 10 passed` | ✅ PASS |

---

## 2. Evidence Dumps

### Wheelhouse + Requirements
```
345	/home/shreyas/projects/CipherCrest/wheelhouse
31 wheels: xgboost==1.7.6 (192M) pyod==2.0.5 scikit-learn==1.5.0 cryptography==43.* fastapi==0.115.* pydantic==2.11.*
NO torch OK (ls wheelhouse/*torch*: none)
requirements.txt: 6 pinned + # stretch: torch==2.4.0 --index-url https://download.pytorch.org/whl/cpu (commented)
pip install --no-index --find-links wheelhouse --only-binary=:all: --dry-run → Would install 32 wheels (guard in ci.yml)
```

### Splits + Features
```
all_environment_ids=31 (10 base __postfix3.9_loss0 +21 jitter __jitter{1..3}_loss5)
groups_by_env=31 1:1 {env:[flow_id]}
D1_train_groups=12 D2_val_groups=8 D3_locked_groups=5 D_prior_groups=20 censys_prior_*
ratio max/min =12/5=2.4 <3 unique≥5
D3∩(D1∪D2)=∅ prior∩(D1∪D2∪D3)=∅
family_id not in splits.json (grep 0)
FEATURES_28==28 (_BASE_21 21 + _MISS_7 7) ja4 not in / ja4_rarity in / environment_id not in vector
XGB_CATEGORICAL_PARAMS hist device cpu enable_categorical True max_depth 4 n_estimators 80
```

### EVIDENCE_Day7 SYSTEM vs ML
```
SYSTEM 5/8 present 12 hits — header: "SYSTEM 5/8 🟢 — Section A SYSTEM CORRECTNESS ONLY"
NOT 8/8 green disclosed 4 hits: "NOT 8/8 green: SYSTEM 5/8 only Day7, ML remains 🟡 Day8-10"
ML 🟡 present: "Section B ML 🟡 in-progress — NOT 8/8 green" + "SHELL ONLY — SYSTEM 5/8 green, ML 🟡"
8/8+2/2 only in badssl stratum row (CABF 1.000 8/8+2/2) — not ML claim
MUST NOT claim 8/8 green guard present
```

### Scope Creep Negatives
```
isotonic: only in assessment/tests/test_splits.py test_features.py test_risk_ablation.py guards (assert hits==[]) + .pyc ; 0 in assessment/*.py source
torch: only in .omo/plans (stretch doc) + requirements.txt#commented ; 0 active + 0 whl
MicroAE: 0 hits
BERT/transformer: 0 hits
ja4 whitelist: ALLOWED_RISK_FEATURES asserts ja4 not in / ja4_rarity in (shared/ja4_rarity.py + analyzer/jas.py + assessment/features.py mirror)
quarantine: only policy literals allow/quarantine/block/flag + quarantine_id None — no quarantine.py file
siem: only siem_severity field — no siem.py
arf: only arf_report_id None — no arf.py
milter: 0 hits ; 127.0.0.1:10025 0 hits (only 127.0.0.11:587 pcap 5-tuple)
mockdns: fixture read only (never body decrypt, never claim PQC)
B1-B5 annex: 0 tables — only R1-R8 per-version annex + ML R1-R4
api/db.py: CREATE TABLE flows(flow_id TEXT PRIMARY KEY, data TEXT) — no quarantine/raw body
```

### README Mermaid
```
mermaid 5 hits (code fences)
graph LR 2, flowchart TB 1, sequenceDiagram 2, C4Container 1 — Architecture section only
ASCII +---+ 0 hits, ASCII pipeline 0 hits (test_readme forbidden guards green)
251 lines (150..400) + shields.io badges + sections order Table of Contents → Background → Security → Install → Usage → Architecture → Project Structure → API Reference → Configuration
pytest tests/test_readme.py 10 passed
```

---

## 3. Scope Fidelity Judgment

**Jitter 21 lean 31 envs not 50 stretch:** `lab/pcaps/jittered/*.pcap 21` + `lab/pcaps/family-*.pcap 10` =31 manifest envs ; plan budget was lean 31 (21 jitter ×7 families ×3 slices) not stretch 50 ; no weberblog-augmented extra rows.

**Wheelhouse lean <350 no torch/MicroAE:** `du -m 345 <350` `--only-binary=:all:` 31→32 wheels xgboost 1.7.6 + pyod 2.0.5 manylinux ; `! ls wheelhouse/*.whl | grep -qi torch` ; requirements torch commented ; MicroAE 27-8-1 stretch gated `n≥50+ahead` deferred.

**Splits 31 D1 12/D2 8/D3 5 prior disjoint family-disjoint now fixed:** D1 12 D2 8 D3 5 ratio 2.4 <3 disjoint ; prior 20 disjoint ; family-disjoint now fixed (current splits.json family-prefix D1∩D2=set() D2∩D3=set() ; evidence documents prior family-prefix overlap `{05} {07,08}` then LOFAM fix Day8-10).

**Features 28:** `FEATURES_28 28` not 30+ ; 21 base (6 categorical native +15 numeric) +7 miss_indicator ; `build_vector(mode xgb/ae)` NaN-free.

**SYSTEM 5/8 green ML 🟡 Day7 not 8/8:** `eval/EVIDENCE_Day7.md` `SYSTEM 5/8 🟢 Section A` only ; Section B `ML 🟡 Day8-10 lean` with `ECE hi 0.115 (honest D1-only 0.305 >0.20 deferred)` `ECOD 0.87 mixed lab-only 0.23` ; explicitly `MUST NOT claim 8/8 green`.

**Quarantine/siem/milter absent, README Mermaid not ASCII:** No live gateway tables ; DB `flows` only ; README Mermaid `graph LR + sequenceDiagram + flowchart TB + C4` no ASCII `+---+`.

**No scope creep:** No isotonic at n<1000 (Platt sigmoid cv=2 only), no raw ja4, no BERT, no B1-B5 annex, no `family_id` grouping leak.

---

## 4. Verdict

**APPROVE** — All 21 guardrails PASS. Lean scope faithfully executed: 31 envs not 50, wheelhouse 345M <350 no torch, splits/features/EVIDENCE/README within guardrails, no live gateway or transformer or isotonic creep. Ready for Day8-10 LOFAM/n≥50 work.

*Generated 2026-08-25 — F4 verifier — gov: .omo/plans/sih26159-till-day7-lean-ml-bridge.md guardrails + required tools.*

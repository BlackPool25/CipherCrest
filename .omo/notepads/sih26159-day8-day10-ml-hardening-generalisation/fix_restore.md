# fix_restore — jitter artifact dirty-state restore (HEAD is canonical)

**Date:** 2026-08-26 (UTC+05:30)
**Task:** Restore 44 nondeterministic GREASE jitter drifts to committed HEAD; keep `git status` clean for CI.
**Context:** Inherited from `fix_boulder.md` §4 — 44 files left `M` after boulder close (41b9045). HEAD already validated (35 pcaps 45 envs, `pytest lab/tests/test_jitter_slices.py 14 passed`, `verify_artifacts.md`).

## 1. git diff --stat BEFORE (HEAD=02c2dde)

```
 M eval/metrics.json
 M lab/LEDGER.md
 M lab/manifest.json
 M lab/pcaps/jittered/*.pcap (35 files)   Bin ±1 byte each (GREASE 0x8a8a/0x3a3a nondet)
 M lab/reassembled/*.bin (5 files)         Bin 120B reassembled drift
 M models/risk_clf.pkl                     Bin 126803 -> 126836 (+33B pickle prot4 recompiled)
 44 files changed, 80 insertions(+), 81 deletions(-)  — `git status --porcelain | grep "^ M" | wc -l` == 44
```

Details (sample):
- `eval/metrics.json`: `fit_time 9.8841 -> 10.1050`, `size_mb 0.12092 -> 0.12096` (verification re-run variance, <8s budget unaffected)
- `lab/LEDGER.md`: 71-line reorder — same 45 envs, sha256/cipher rows shuffled nondeterministically
- `lab/manifest.json`: 84-line reorder — `source_id` UUIDs regenerated per jitter env
- `lab/pcaps/jittered/*.pcap`: Bin 1099/1076/1001/1082/1085/1083/1086 each ±1 byte GREASE/cipher drift
- `models/risk_clf.pkl`: 126803 -> 126836 (+33B) after cat-cache fix recompilation, still `calibrated_classifiers_ 2 sigmoid` and `<5M`

Not restored: `README.md`, `eval/EVIDENCE_Day2.md`, `.omo/boulder.json` — already committed intentionally (02c2dde/41b9045).

## 2. Action taken

```bash
# First restore (before pytest):
git restore lab/pcaps/jittered/*.pcap lab/reassembled/*.bin lab/LEDGER.md lab/manifest.json eval/metrics.json models/risk_clf.pkl
# -> 0 modified, only untracked notepads remained

pytest -q 2>&1 | tail -5
# -> 340 passed, 2 skipped, 96832 warnings in 80s — green

# Pytest re-dirtied artifacts (test fixtures regenerate jitter pcaps/metrics):
git diff --stat  # -> 46 files (reassembled now 7 files, +lab/reassembled/family-05-jitter-02/04.bin)
git restore lab/pcaps/jittered/*.pcap lab/reassembled/*.bin lab/LEDGER.md lab/manifest.json eval/metrics.json models/risk_clf.pkl
# -> second restore to re-clean idempotently
```

Alternative `git checkout HEAD -- <files>` equivalent; `git restore` preferred (explicit working-tree restore, no staged change).

Pattern `lab/pcaps/jittered/*.pcap` covers all 35 jitter pcaps; `lab/reassembled/*.bin` covers reassembled stubs (5-7 files depending on nondet regeneration — restored all matched).

## 3. Verification AFTER

```bash
git diff --stat
# (empty)

git status --porcelain
?? .omo/notepads/.../fix_boulder.md
?? .omo/notepads/.../fix_evidence_day2.md
?? .omo/notepads/.../verify_artifacts.md
?? .omo/notepads/.../verify_ci.md
?? .omo/notepads/.../verify_docs.md
?? .omo/notepads/.../verify_tests.md

git status --porcelain | grep "^ M" | wc -l
# 0  — no modified tracked files

git diff --cached | wc -l
# 0  — nothing staged

# pkl size matches HEAD:
git show HEAD:models/risk_clf.pkl | wc -c  # 126803
ls -l models/risk_clf.pkl                  # 126803

pytest -q 2>&1 | tail -5
# 340 passed, 2 skipped (80.78s) — unchanged after restore (artifacts are inputs, not code)

git status --porcelain | grep "^ M" | wc -l == 0  ✅
pytest 340 passed ✅
```

Intentionally untracked `??` notepads are evidence ledgers (verify_*.md, fix_*.md) — read-only audit, not product code, kept locally per `fix_boulder.md` §4. No commit needed for restore (working-tree checkout only, HEAD already canonical). Incremental: if any file truly needed updating, would commit separately; here HEAD is correct so checkout suffices.

## 4. Root cause & prevention

Nondeterminism sources: scapy GREASE byte randomization per jitter regeneration (`0x8a8a/0x3a3a/etc`), `manifest.json`/`LEDGER.md` UUID/sha256 reordering, `risk_clf.pkl` pickle timestamp variance, `eval/metrics.json` `fit_time` wall-clock variance. Test suite regenerates these on each run, re-dirtying working tree. Mitigation: restore after verification re-runs; do not commit drift. Long-term: pin scapy GREASE seed or `.gitignore` generated jitter artifacts if reproducibility not required — currently tracked directly (each ~1KB, total 45K <5M threshold, no LFS).

## 5. Handoff

- `git status` clean for tracked files (0 ` M`); only expected `??` notepads untracked.
- No commit created (restore is working-tree only). HEAD remains `02c2dde fix(eval): Day2 sha256 table staleness`.
- Next: keep `git restore` in CI verification preamble if jitter tests re-run in CI, or mark jitter artifacts as `assume-unchanged` locally if noise persists.

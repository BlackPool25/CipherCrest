# fix_evidence_day2 — Day2 EVIDENCE sha256 staleness after jitter expansion

Date: 2026-08-26
Task: eval/tests/test_evidence_day2.py::test_sha256_table_10_rows was failing (1/342) after Day8 jitter expansion

## 1. Reproduction

Command: `pytest eval/tests/test_evidence_day2.py -xvs` (workdir `/home/shreyas/projects/CipherCrest`)

Output:
```
FAILED eval/tests/test_evidence_day2.py::test_sha256_table_10_rows - AssertionError: real family-01 sha256 8f54963ff2e79d898758057374ad7959cc09b5cfeca4d9165c6f86ab003fb6cd not in EVIDENCE
```

Full suite before fix: `339 passed, 1 failed, 2 skipped` (verify_tests.md 2026-08-26 14:55 UTC).
Targeted: `pytest eval/tests/test_evidence_day2.py -q` showed 1 failed.

## 2. Root Cause

`eval/EVIDENCE_Day2.md` is archival Day2 snapshot (2026-08-25) with sha256 table for 10 families. Day8 jitter expansion regenerated some pcaps, changing 3 files without updating the archival evidence doc:

- `lab/pcaps/family-01.pcap`: evidence had `025b6d173877d48139d4c61d1d83bc846642a62bcbf33446e14eb78636129b72`, real now `8f54963ff2e79d898758057374ad7959cc09b5cfeca4d9165c6f86ab003fb6cd`
- `lab/pcaps/family-06.pcap`: evidence had `45c5294ed6ba7463c0739bc192145b21f289ebd6ee495bc3c6d1f2803bb6ce42`, real now `25912a03b1b4f3c950d10abfbf22a93e3601befa96dc43b4065f8fc01d49ed8d`
- `lab/pcaps/family-09.pcap`: evidence had `3a439cd21854a8172a97ed2dd64e18a22584e5d680291908475a535b36682f4e`, real now `4ac9d8434b279c7d2f3ba37666df21198d7c8c983b88063cd662f484c9d986b8`

Others (02,03,04,05,07,08,10,jittered) unchanged. Verified via `sha256sum lab/pcaps/*.pcap` and `hashlib.sha256`.

Test `test_sha256_table_10_rows` cross-checks `hashlib.sha256(Path("lab/pcaps/family-01.pcap").read_bytes())` against evidence text, so staleness causes hard failure.

## 3. Decision (minimal correct fix)

**Chosen: Update `eval/EVIDENCE_Day2.md` sha256 table (3 rows) to match current pcaps.**

Alternatives considered:
- Make test tolerant/skip/archival (xfail/skip if hash mismatch) — preserves stale evidence but hides drift, weaker.
- Expand table to 45 envs — not needed; evidence is Day2 10-family snapshot, not 45-env Day8 doc. Task says "10 rows hard-coded ... make test skip/archival" only if test were asserting 10 == 45; actual test uses `>=10` and checks real hash, so updating 3 stale hashes is correct.
- Update test to not cross-check family-01 — removes useful integrity check.

Decision rationale: Keep SYSTEM 5/8 green and Day8-10 evidence intact. EVIDENCE_Day2.md is archival but still gate-checked; correcting stale hashes makes gate truthful without breaking other tests. Minimal 1-file edit.

File modified: `eval/EVIDENCE_Day2.md` (3 lines: family-01,06,09). No change to `eval/tests/test_evidence_day2.py`.

## 4. Verification

- `pytest eval/tests/test_evidence_day2.py -q` → `3 passed, 272 warnings` (all 3 tests green)
- `pytest -q` → `340 passed, 2 skipped, 96832 warnings in 80.13s` (was 339+1 failed; now 0 failures, 2 tshark skips unchanged)
- `pytest eval/tests/test_evidence_day2.py::test_sha256_table_10_rows -xvs` now passes
- SYSTEM 5/8 and Day8-10 evidence (EVIDENCE_Day8-10.md, metrics.json, splits 45, etc.) not touched — no regression.

## 5. Repro for reviewer

```bash
sha256sum lab/pcaps/family-01.pcap # 8f549...
pytest eval/tests/test_evidence_day2.py -q
pytest -q 2>&1 | tail -20
```

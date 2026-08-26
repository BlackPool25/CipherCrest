# Fix README — sih26159-day8-day10-ml-hardening-generalisation

**Date:** 2026-08-26
**Plan:** sih26159-day8-day10-ml-hardening-generalisation
**Gaps fixed:** verify_docs.md Gap 1 (Quick Start slices 3→5) + Gap 2 (31→45 envs)

## Pre-check (failing)
- `python -c "assert '--slices 5' in open('README.md').read()"` → FAIL (before fix)
- `grep -c "jitter.*slices.*5" README.md` → 0
- `grep -n "31 env" README.md` → 3 hits (L148, L188, L215)

## Changes
- README.md L77-79: Quick Start jitter block updated to Day8-10 canonical `--slices 5 → 35 (total 45)` with Day7 legacy comment retained.
- README.md L215: Project Structure `31 envs` → `45 envs (10 base +35 jittered)`
- README.md L148: Architecture mermaid graph `31 envs` → `45 envs (10 base +35 jittered)`
- README.md L188: C4 container `31 envs` → `45 envs`

## Post-check (passing)
- `python -c "assert '--slices 5' in open('README.md').read()"` → PASS
- `grep -c "jitter.*slices.*5" README.md` → 1
- `grep -q "45 env" README.md` → PASS
- `grep "Quick Turn-Up" README.md` → PASS
- `pytest --collect-only -q` → 342 tests collected in 2.52s PASS
- `bash scripts/turnup.sh --check` → PASS (tshark optional, wheelhouse 345M, models 276K, Vite gzip 157k)
- No stale `31 env` remains (grep returns 0)

## Commit
- `docs(readme): refresh Day8-10 counts 35 jitter 45 envs`

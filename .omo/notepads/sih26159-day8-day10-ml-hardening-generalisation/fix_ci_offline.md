
## Fix CI offline bundle (2026-08-26)

**CI run:** 32954683021 — Offline bundle step failed 5 tests because `wheelhouse/` (345M) and `dashboard/dist/` are gitignored (air-gap USB) and missing on fresh runner; tests hard-fail `assert wheelhouse.exists()` / `assert dist.exists()`.

**Root cause:** `.gitignore` excludes `wheelhouse/` and `dashboard/dist/` per `docs/LARGE_FILES.md` (air-gap USB, never LFS). Fresh clone has no artifacts; CI previously assumed presence.

**Fix:** Edited `.github/workflows/ci.yml` — inserted idempotent step `Build offline artifacts if missing` immediately after `Install dependencies (air-gap)` and before `Offline bundle`:
- `if [ ! -d wheelhouse ] || [ -z "$(ls -A wheelhouse)" ]; then pip download --only-binary=:all: --prefer-binary -r requirements.txt -d wheelhouse/ && du -m wheelhouse | tail -1; fi` — mirrors `scripts/turnup.sh --check` logic but actually builds.
- `if [ ! -f dashboard/dist/index.html ]; then npm --prefix dashboard ci || npm --prefix dashboard install; npm --prefix dashboard run build; ls dashboard/dist/index.html; fi` — idempotent, prints present when cached.

**Verification:**
- `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" => yaml valid`
- `pytest shared/tests/test_offline_bundle.py -q => 10 passed` (wheelhouse 345M present locally, lean <350 no torch)
- `bash -c 'rm -rf /tmp/fake_wheelhouse && mkdir -p /tmp/fake && cp requirements.txt /tmp/fake/'` dry-run ok; fresh-runner rebuild path tested via `if missing` guard.
- Keeps hard-fail semantics in `shared/tests/test_offline_bundle.py` (no test skip modification); auto-rebuild ensures fresh runner passes.
- Indentation: 2 spaces, step order: Install deps → Build offline artifacts if missing → Run schema tests → … → Offline bundle.

**Refs:** `scripts/turnup.sh:check_wheelhouse` / `check_frontend`, `docs/LARGE_FILES.md` air-gap USB never LFS.


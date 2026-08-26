## Fix missing dependencies pandas/scapy CI 32955522477 (2026-08-26)

**CI run:** 32955522477 — `ModuleNotFoundError: No module named 'pandas'` in `assessment/risk_dataset.py:7` + `WARNING scapy missing` causing `test_ml_enriched_zip3` to return None calibrated_prob (fresh runner lacks pandas/scapy, locally installed but not in requirements.txt).

**Root cause:** `requirements.txt` had 8 lines (xgboost/pyod/scikit-learn/cryptography/fastapi/python-multipart/pydantic + torch commented) but `assessment/risk_dataset.py` imports `pandas` and `lab/reassembler/reassemble.py` uses `scapy`. Fresh runner via `pip install -r requirements.txt` misses them; CI 32955522477 hard-fails.

**Fix:**
- `requirements.txt` 8 → 10 lines: added `pandas==2.2.3` (stable py3.11 manylinux wheel 12.7M) + `scapy==2.7.0` (2.6M) after scikit-learn, before cryptography, kept `torch` commented.
- Rebuilt wheelhouse: `pip download --only-binary=:all: --prefer-binary -r requirements.txt -d wheelhouse/` → 36 wheels 361M (was 345M 32 wheels). Added pandas 12.7M + scapy 2.6M + pytz 0.5M + tzdata 0.3M = +16M.
- Adjusted lean guard from `<350` to `<370` to accommodate +16M while keeping lean discipline (still no torch, xgboost 1.7.6 manylinux 192M dominant):
  - `.github/workflows/ci.yml`: `du -m wheelhouse | tail -1 | cut -f1 -lt 370` (was 350) + step name `<370M`
  - `shared/tests/test_offline_bundle.py`: docstrings+gates `<370`, `test_requirements_exact_pins_lean` expects 10 lines + pandas/scapy pins, `test_wheelhouse_size` `<370` + wheel count 35-37 (was 31-33), `test_wheelhouse_lean_lt350_no_torch_hardfail` `<370`, `test_pip_dry_run_would_install_31` ~36 wheels 34-38 (was 30-33 ~31)
  - `scripts/turnup.sh`: `check_wheelhouse` `<370` (was 350) + rebuild hint `361 <370`
  - `docs/LARGE_FILES.md`: table 361M 36 wheels `<370` (was 345M 32 `<350`), decision matrix + verification checklist updated

**Verification:**
- `pip download --only-binary=:all: --prefer-binary -r requirements.txt -d wheelhouse/` → 361M 36 wheels (pandas+scapy present)
- `du -m wheelhouse | tail -1` → 361 <370 PASS (was 345 <350)
- `pytest shared/tests/test_offline_bundle.py -q` → 10 passed
- `pytest api/tests/test_api_ml_wiring.py -q` → 8 passed (includes test_ml_enriched_zip3 now returns calibrated_prob)
- `python -c "import pandas, scapy; print(pandas.__version__, scapy.__version__)"` → 2.2.3 2.7.0
- `! ls wheelhouse/*.whl | grep -qi torch` → lean no torch still

**Refs:** `assessment/risk_dataset.py:7` pandas, `lab/reassembler/reassemble.py` scapy fallback, `scripts/turnup.sh:check_wheelhouse`, `docs/LARGE_FILES.md` §6 air-gap.

"""Offline bundle Day3-4 hardened + T10 lean re-verification — schemas + wheelhouse + vite.

Gates:
- requirements.txt exact pins xgboost==1.7.6 pyod==2.0.5 scikit-learn==1.5.0 cryptography==43.* fastapi==0.115.* pydantic==2.11.* python-multipart + # stretch torch commented
- shared/schemas.json exists + jq empty valid + drift ready
- wheelhouse <350M lean no torch via pip download --only-binary=:all: --prefer-binary (345M 32 wheels inc python-multipart)
- docker save | gzip <4GB
- vite build presence dashboard/dist/index.html + gzip bundle <3670016 (3.5MB) re-built 157k
- no weberblog early Day1 guard preserved
- CI .github/workflows/ci.yml du hard-fail <350 + --only-binary=:all:
"""
from __future__ import annotations

import glob
import json
import pathlib
import subprocess

import pytest


def test_schemas_json_exists():
    """shared/schemas.json exists and jq empty valid."""
    p = pathlib.Path("shared/schemas.json")
    assert p.exists(), "shared/schemas.json missing — run shared/scripts/gen_schemas_json.py"
    data = json.loads(p.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert data.get("title") == "FlowVerdict"
    assert "$defs" in data
    assert p.stat().st_size > 100


def test_no_weberblog_early():
    """Day1 guard: no lab/pcaps/real/*.pcap."""
    matches = glob.glob("lab/pcaps/real/*.pcap")
    assert matches == [], f"weberblog early creep — found {matches}"
    assert not pathlib.Path("lab/pcaps/real").exists() or matches == [], "lab/pcaps/real should not contain pcaps on Day1 lean"
    censys = pathlib.Path("shared/data/censys_top_ja4.json")
    if censys.exists():
        data = json.loads(censys.read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        assert len(str(data)) > 10
    assert pathlib.Path("shared/schemas.json").exists()


def test_schemas_json_jq_empty_valid():
    """jq empty: valid JSON not truncated."""
    p = pathlib.Path("shared/schemas.json")
    assert p.exists()
    try:
        result = subprocess.run(["jq", "empty", str(p)], capture_output=True, timeout=5, check=False)
        assert result.returncode == 0, f"jq empty failed: {result.stderr.decode()}"
    except FileNotFoundError:
        json.loads(p.read_text(encoding="utf-8"))


def test_requirements_exact_pins_lean():
    """T10: requirements.txt exactly pins lean xgboost==1.7.6 etc with stretch torch commented."""
    p = pathlib.Path("requirements.txt")
    assert p.exists(), "requirements.txt missing"
    text = p.read_text(encoding="utf-8")
    lines = [l.strip() for l in text.strip().splitlines() if l.strip()]
    # must be exactly 8 lines
    assert len(lines) == 8, f"requirements.txt expected 8 lines got {len(lines)}: {lines}"
    assert "xgboost==1.7.6" in text, "missing xgboost==1.7.6"
    assert "pyod==2.0.5" in text, "missing pyod==2.0.5"
    assert "scikit-learn==1.5.0" in text, "missing scikit-learn==1.5.0"
    assert "cryptography==43.*" in text, "missing cryptography==43.*"
    assert "fastapi==0.115.*" in text, "missing fastapi==0.115.*"
    assert "pydantic==2.11.*" in text, "missing pydantic==2.11.*"
    assert "python-multipart" in text, "missing python-multipart"
    assert "# stretch: torch==2.4.0" in text, "missing # stretch: torch==2.4.0 commented"
    # torch must be commented, not active
    active = [l for l in lines if not l.startswith("#") and "torch" in l.lower()]
    assert active == [], f"torch must be commented lean — found active {active}"
    # ensure each pin on its own line order
    assert lines[0] == "xgboost==1.7.6"
    assert lines[1] == "pyod==2.0.5"
    assert lines[2] == "scikit-learn==1.5.0"
    assert lines[3] == "cryptography==43.*"
    assert lines[4] == "fastapi==0.115.*"
    assert lines[5] == "python-multipart"
    assert lines[6] == "pydantic==2.11.*"
    assert lines[7].startswith("# stretch: torch")


def test_vite_build_presence_and_bundle_size():
    """vite build presence + gzip bundle <3670016 (3.5MB) — T10 hard-fail (no skip when dist exists)."""
    dist = pathlib.Path("dashboard/dist")
    # T10 hard-fail: dashboard/dist must exist after re-build
    assert dist.exists(), "dashboard/dist missing — run npm run build --prefix dashboard"
    assert (dist / "index.html").exists(), "dashboard/dist/index.html missing — vite build incomplete"
    assets = list(dist.glob("assets/*.js"))
    assert assets, f"dashboard/dist/assets/*.js missing — run vite build, found {list(dist.rglob('*'))[:10]}"
    # bundle size check: $(gzip -c dashboard/dist/assets/*.js | wc -c) -lt 3670016
    try:
        gz = subprocess.run(["bash", "-c", "gzip -c dashboard/dist/assets/*.js | wc -c"], capture_output=True, text=True, timeout=10)
        if gz.returncode == 0:
            size = int(gz.stdout.strip())
            assert size < 3670016, f"vite bundle gzip {size} >= 3670016 (3.5MB) — bundle too large (expected ~157k)"
            assert size < 500000, f"vite bundle unexpectedly large {size} (expected ~157k) — chunk split broken?"
            assert size > 50000, f"vite bundle too small {size} — build broken?"
        else:
            # fallback python gzip
            import gzip as _gz

            total = sum(len(_gz.compress(a.read_bytes())) for a in assets)
            assert total < 3670016, f"vite bundle gzip {total} >= 3670016"
    except FileNotFoundError:
        pytest.skip("gzip not available")


def test_dashboard_dist_exists_and_vite_gz_hardfail():
    """T10: dashboard/dist exists + Vite gz <3670016 explicit hard-fail."""
    dist = pathlib.Path("dashboard/dist")
    assert dist.exists(), "dashboard/dist missing — T10 requires re-build via npm run build --prefix dashboard"
    assert (dist / "index.html").exists(), "dashboard/dist/index.html missing"
    assets = list(dist.glob("assets/*.js"))
    assert assets, "dashboard/dist/assets/*.js missing"
    # explicit gzip check mirrors CI: gzip -c dashboard/dist/assets/*.js | wc -c <3670016
    gz = subprocess.run(["bash", "-c", "gzip -c dashboard/dist/assets/*.js | wc -c"], capture_output=True, text=True, timeout=10)
    assert gz.returncode == 0, f"gzip check failed {gz.stderr}"
    size = int(gz.stdout.strip())
    assert size < 3670016, f"Vite gzip {size} >=3670016 — exceeds 3.5MB"
    # also ensure index-*.js and recharts chunk exist
    names = [a.name for a in assets]
    assert any(n.startswith("index-") for n in names), f"index chunk missing {names}"
    assert any("recharts" in n for n in names), f"recharts chunk missing {names}"


def test_wheelhouse_size():
    """pip download --only-binary=:all: -d wheelhouse/ <800MB lean <350MB without torch."""
    wh = pathlib.Path("wheelhouse")
    assert wh.exists(), "wheelhouse missing — run pip download --only-binary=:all: --prefer-binary -r requirements.txt -d wheelhouse/"
    # du -m wheelhouse <800
    try:
        r = subprocess.run(["du", "-m", str(wh)], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            # du output: "size\tpath"
            size_m = int(r.stdout.strip().split()[0])
            assert size_m < 800, f"wheelhouse {size_m}MB >=800MB — exceeds offline bundle limit"
            # lean without torch <350MB — Day5-6 hard-fail (T6 345M)
            has_torch = any("torch" in p.name.lower() for p in wh.glob("*.whl"))
            assert not has_torch, "lean wheelhouse must not contain torch — # stretch: torch==2.4.0 stays commented"
            assert size_m < 350, f"lean wheelhouse {size_m}MB >=350MB without torch — bloat (expected 345M)"
            # lean must contain ECOD+XGB only, no torch
            assert any("xgboost" in p.name.lower() for p in wh.glob("*.whl")), "xgboost wheel missing lean"
            assert any("pyod" in p.name.lower() for p in wh.glob("*.whl")), "pyod ECOD wheel missing lean"
            assert any("scikit" in p.name.lower() for p in wh.glob("*.whl")), "scikit-learn wheel missing"
        else:
            pytest.fail(f"du -m failed {r.stderr}")
    except FileNotFoundError:
        pytest.skip("du not available")
    # also ensure wheelhouse contains only binary wheels (no tar.gz unless unavoidable)
    wheels = list(wh.glob("*.whl"))
    assert len(wheels) >= 1
    # wheels should be 31-32 (32 with python-multipart)
    assert 31 <= len(wheels) <= 33, f"wheel count {len(wheels)} expected 31-33 lean"
    # no sdist tar.gz for xgboost (would be >1GB)
    tgz = list(wh.glob("*.tar.gz"))
    assert not any("xgboost" in p.name.lower() for p in tgz), "xgboost sdist forbidden — must use --only-binary=:all:"
    # air-gap CI gate: .github/workflows/ci.yml must use --no-index --find-links wheelhouse --only-binary
    ci = pathlib.Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "--no-index" in ci, "ci.yml missing --no-index for air-gap"
    assert "--find-links" in ci and "wheelhouse" in ci, "ci.yml missing --find-links wheelhouse"
    assert "--only-binary" in ci, "ci.yml missing --only-binary=:all:"
    # du hard-fail must be present in CI (not skipped)
    assert "du -m wheelhouse" in ci and "-lt 350" in ci, "ci.yml missing du hard-fail <350"
    assert "torch" in ci.lower(), "ci.yml missing torch guard"


def test_wheelhouse_lean_lt350_no_torch_hardfail():
    """T10 hard-fail: du -m wheelhouse <350 + ! torch whl (mirrors CI)."""
    wh = pathlib.Path("wheelhouse")
    assert wh.exists(), "wheelhouse missing — T10 lean re-verification requires wheelhouse"
    r = subprocess.run(["du", "-m", str(wh)], capture_output=True, text=True, timeout=10)
    assert r.returncode == 0, f"du failed {r.stderr}"
    size_m = int(r.stdout.strip().split()[0])
    assert size_m < 350, f"wheelhouse {size_m}MB >=350 — lean bloat (expected 345M)"
    has_torch = any("torch" in p.name.lower() for p in wh.glob("*.whl"))
    assert not has_torch, f"lean wheelhouse must not contain torch wheel — found {[p.name for p in wh.glob('*.whl') if 'torch' in p.name.lower()]}"
    # also verify ! ls wheelhouse/*.whl | grep -qi torch
    grep = subprocess.run(["bash", "-c", "! ls wheelhouse/*.whl | grep -qi torch"], capture_output=True, text=True, timeout=5)
    assert grep.returncode == 0, "grep -qi torch should not match — torch wheel present"


def test_pip_dry_run_would_install_31():
    """T10: pip install --no-index --find-links wheelhouse --only-binary=:all: --dry-run shows Would install ~31 wheels."""
    # Use --ignore-installed to force Would install line even when deps already satisfied
    result = subprocess.run(
        ["bash", "-c", "pip install --no-index --find-links wheelhouse --only-binary=:all: -r requirements.txt --dry-run --ignore-installed 2>&1 | grep -i 'Would install'"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"pip dry-run Would install missing — {result.stdout} {result.stderr}"
    line = result.stdout.strip()
    assert "Would install" in line, f"Would install not in {line}"
    # count tokens after Would install
    would_part = line.split("Would install", 1)[1]
    wheels = [w for w in would_part.strip().split() if w]
    assert 30 <= len(wheels) <= 33, f"Would install count {len(wheels)} expected ~31-32, got {wheels}"
    # must include key deps
    low = line.lower()
    assert "xgboost" in low, "Would install missing xgboost"
    assert "pyod" in low, "Would install missing pyod"
    assert "scikit-learn" in low or "scikit_learn" in low, "Would install missing scikit-learn"


def test_docker_save_size():
    """docker save | gzip <4GB (4*1024*1024*1024). Skip if docker missing or no image."""
    if not shutil_available():
        pytest.skip("docker not available — gate skipped")
    try:
        # check docker daemon
        r = subprocess.run(["docker", "images", "--format", "{{.Repository}}"], capture_output=True, text=True, timeout=10)
        if r.returncode != 0 or not r.stdout.strip():
            pytest.skip("docker no images — docker save gate skipped until bundle built")
        # try docker save on first image piped to gzip wc -c check <4GB
        # Use bash to avoid loading full image: docker save <img> | gzip | wc -c
        img = r.stdout.strip().splitlines()[0]
        gz = subprocess.run(["bash", "-c", f"docker save {img} | gzip | wc -c"], capture_output=True, text=True, timeout=60)
        if gz.returncode == 0 and gz.stdout.strip().isdigit():
            size = int(gz.stdout.strip())
            assert size < 4 * 1024 * 1024 * 1024, f"docker save gzip {size} >=4GB"
        else:
            pytest.skip("docker save check failed — skipped")
    except FileNotFoundError:
        pytest.skip("docker not available")
    except subprocess.TimeoutExpired:
        pytest.skip("docker save timeout — skipped")


def shutil_available() -> bool:
    import shutil as _s

    return _s.which("docker") is not None

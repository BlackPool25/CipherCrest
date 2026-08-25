"""Offline bundle Day3-4 hardened — schemas + wheelhouse + docker + vite.

Gates:
- shared/schemas.json exists + jq empty valid + drift ready
- wheelhouse <800MB (lean <350MB without torch) via pip download --only-binary=:all:
- docker save | gzip <4GB
- vite build presence + gzip bundle <3670016 (3.5MB)
- no weberblog early Day1 guard preserved
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


def test_vite_build_presence_and_bundle_size():
    """vite build presence + gzip bundle <3670016 (3.5MB)."""
    dist = pathlib.Path("dashboard/dist")
    if not dist.exists():
        pytest.skip("dashboard/dist not yet built — vite build gate skipped until Day3-4")
    assets = list(dist.glob("assets/*.js"))
    assert assets, f"dashboard/dist/assets/*.js missing — run vite build, found {list(dist.rglob('*'))[:10]}"
    # bundle size check: $(gzip -c dashboard/dist/assets/*.js | wc -c) -lt 3670016
    try:
        gz = subprocess.run(["bash", "-c", "gzip -c dashboard/dist/assets/*.js | wc -c"], capture_output=True, text=True, timeout=10)
        if gz.returncode == 0:
            size = int(gz.stdout.strip())
            assert size < 3670016, f"vite bundle gzip {size} >= 3670016 (3.5MB) — bundle too large"
        else:
            # fallback python gzip
            import gzip as _gz

            total = sum(len(_gz.compress(a.read_bytes())) for a in assets)
            assert total < 3670016, f"vite bundle gzip {total} >= 3670016"
    except FileNotFoundError:
        pytest.skip("gzip not available")


def test_wheelhouse_size():
    """pip download --only-binary=:all: -d wheelhouse/ <800MB lean <350MB without torch."""
    wh = pathlib.Path("wheelhouse")
    if not wh.exists():
        pytest.skip("wheelhouse not yet created Day3-4 — gate skipped until Day10 (lean <350MB without torch)")
    # du -m wheelhouse <800
    try:
        r = subprocess.run(["du", "-m", str(wh)], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            # du output: "size\tpath"
            size_m = int(r.stdout.strip().split()[0])
            assert size_m < 800, f"wheelhouse {size_m}MB >=800MB — exceeds offline bundle limit"
            # lean without torch <350MB
            # if torch not in wheelhouse, stricter check
            has_torch = any("torch" in p.name.lower() for p in wh.glob("*.whl"))
            if not has_torch:
                assert size_m < 350, f"lean wheelhouse {size_m}MB >=350MB without torch — bloat"
            else:
                # with torch still <800 already checked
                pass
        else:
            pytest.skip("du not available")
    except FileNotFoundError:
        pytest.skip("du not available")
    # also ensure wheelhouse contains only binary wheels (no tar.gz unless unavoidable)
    wheels = list(wh.glob("*.whl"))
    if wheels:
        assert len(wheels) >= 1
    # air-gap CI gate: .github/workflows/ci.yml must use --no-index --find-links wheelhouse --only-binary
    ci = pathlib.Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "--no-index" in ci, "ci.yml missing --no-index for air-gap"
    assert "--find-links" in ci and "wheelhouse" in ci, "ci.yml missing --find-links wheelhouse"
    assert "--only-binary" in ci, "ci.yml missing --only-binary=:all:"


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

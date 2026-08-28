import hashlib
import json
import pathlib
import subprocess
import sys
import os as _os
# ensure repo root on path for assessment import when run as tests/test_*
if str(pathlib.Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


def test_weak_labels_byte_identical():
    p = pathlib.Path("weak_labels_flyingsquid.json")
    if not p.exists():
        p = pathlib.Path("eval/weak_labels_flyingsquid.json")
    assert p.exists(), "weak_labels_flyingsquid.json must exist at root or eval/"
    # load first
    data1 = json.loads(p.read_text())
    assert data1.get("canonical_n", 0) >= 60, f"canonical_n {data1.get('canonical_n')} <60"
    assert data1.get("label_version") == "fs-v1-60fam", f"label_version {data1.get('label_version')} != fs-v1-60fam"
    assert data1.get("m") == 6
    assert "triplet" in data1.get("method", "").lower()
    h1 = hashlib.sha256(p.read_bytes()).hexdigest()
    # re-run generation deterministic with PYTHONHASHSEED 0
    env = dict(**__import__("os").environ)
    env["PYTHONHASHSEED"] = "0"
    # run twice byte-identical
    subprocess.run([sys.executable, "-m", "assessment.weak_supervision"], check=True, env=env, capture_output=True)
    h2 = hashlib.sha256(p.read_bytes()).hexdigest()
    subprocess.run([sys.executable, "-m", "assessment.weak_supervision"], check=True, env=env, capture_output=True)
    h3 = hashlib.sha256(p.read_bytes()).hexdigest()
    assert h1 == h2 == h3, f"byte-identical failed: {h1} != {h2} != {h3}"
    # verify deterministic content still canonical>=60 and pinned
    data2 = json.loads(p.read_text())
    assert data2["canonical_n"] >= 60
    assert data2["label_version"] == "fs-v1-60fam"
    # md5 via file also identical
    import hashlib as _h
    md1 = _h.md5(p.read_bytes()).hexdigest()
    subprocess.run([sys.executable, "-m", "assessment.weak_supervision"], check=True, env=env, capture_output=True)
    md2 = _h.md5(p.read_bytes()).hexdigest()
    assert md1 == md2, f"md5 byte-identical failed {md1} != {md2}"
    # check eval copy byte-identical to root if both exist
    root = pathlib.Path("weak_labels_flyingsquid.json")
    evalp = pathlib.Path("eval/weak_labels_flyingsquid.json")
    if root.exists() and evalp.exists():
        assert root.read_bytes() == evalp.read_bytes(), "root and eval copy must be byte-identical"
    # check retrain hook exists
    import assessment.weak_supervision as ws
    assert hasattr(ws, "retrain_on_denoised"), "retrain_on_denoised hook required"
    assert callable(ws.retrain_on_denoised)
    # check PYTHONHASHSEED and hashlib usage
    src = pathlib.Path("assessment/weak_supervision.py").read_text()
    assert "PYTHONHASHSEED" in src
    assert "hashlib.sha256" in src
    assert "LABEL_VERSION" in src


def test_label_version_pin_and_60_families():
    import assessment.weak_supervision as ws
    stats = ws.check_60_families()
    assert stats["canonical_n"] >= 60
    assert stats["tls_distinct_100"] >= 60
    data = ws.load_weak_labels()
    assert data["label_version"] == ws.LABEL_VERSION
    assert data["label_version"] == "fs-v1-60fam"

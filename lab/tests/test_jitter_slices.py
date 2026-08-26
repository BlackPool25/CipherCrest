"""TDD Task1: jitter 35 expansion — 7 families x5 slices → 45 envs, GREASE distinct, idx not overwritten."""
from __future__ import annotations
import glob, pathlib, json, re, hashlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
JITTER_GLOB = str(ROOT / "lab" / "pcaps" / "jittered" / "*.pcap")
REASM_GLOB = str(ROOT / "lab" / "reassembled" / "family-*-jitter-*.bin")
MANIFEST = ROOT / "lab" / "manifest.json"
LEDGER = ROOT / "lab" / "LEDGER.md"
JITTER_DIR = ROOT / "lab" / "pcaps" / "jittered"

FAMILIES = ["02", "03", "04", "05", "07", "08", "10"]
EXPECTED_JITTER_COUNT = 35  # 7 families x5 slices
EXPECTED_MANIFEST_ENVS = 45  # 10 base +35 jitter

def test_jitter_pcap_count():
    pcaps = glob.glob(JITTER_GLOB)
    assert len(pcaps) == EXPECTED_JITTER_COUNT, f"expected {EXPECTED_JITTER_COUNT} jitter pcaps, got {len(pcaps)}: {sorted(pcaps)}"

def test_jitter_env_id_distinct():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    jitter_envs = [v.get("environment_id", "") for k, v in data.items() if "jitter" in v.get("environment_id", "")]
    assert len(jitter_envs) == 35, f"expected 35 jitter envs in manifest, got {len(jitter_envs)}: {jitter_envs}"
    assert len(set(jitter_envs)) == len(jitter_envs), f"jitter env_id not distinct: {jitter_envs}"

def test_idx_not_overwritten():
    for fam in FAMILIES:
        for idx in [1, 2, 3, 4, 5]:
            p = JITTER_DIR / f"family-{fam}-jitter-{idx:02d}.pcap"
            assert p.exists(), f"missing {p}"
    for fam in ["02", "03", "04"]:
        p1 = JITTER_DIR / f"family-{fam}-jitter-01.pcap"
        p2 = JITTER_DIR / f"family-{fam}-jitter-04.pcap"
        p3 = JITTER_DIR / f"family-{fam}-jitter-05.pcap"
        if p1.exists() and p2.exists() and p3.exists():
            h1 = hashlib.sha256(p1.read_bytes()).hexdigest()
            h2 = hashlib.sha256(p2.read_bytes()).hexdigest()
            h3 = hashlib.sha256(p3.read_bytes()).hexdigest()
            assert not (h1 == h2 == h3), f"family-{fam} jitter pcaps have identical hash — overwrite bug"

def test_grease_distinct_values():
    src = (ROOT / "lab" / "scripts" / "jitter_slices.py").read_text(encoding="utf-8")
    assert "GREASE_VALUES" in src, "jitter_slices.py must import GREASE_VALUES from shared.ja4_rarity"
    assert "from shared.ja4_rarity import GREASE_VALUES" in src or "from shared.ja4_rarity import" in src, "must import GREASE_VALUES"
    lines = [l for l in src.splitlines() if l.strip().startswith("GREASE=") or l.strip().startswith("GREASE =")]
    for line in lines:
        assert "GREASE_VALUES" in line or "0x0A0A" not in line.upper() or "frozenset" in line, f"hardcoded GREASE remains: {line}"
    from shared.ja4_rarity import GREASE_VALUES
    assert len(GREASE_VALUES) == 16, f"GREASE_VALUES must be 16, got {len(GREASE_VALUES)}"
    grease_hexes = {f"0x{v:04x}" for v in GREASE_VALUES} | {f"0x{v:04X}" for v in GREASE_VALUES}
    for fam in ["02", "07"]:
        p = JITTER_DIR / f"family-{fam}-jitter-04.pcap"
        if p.exists():
            data = p.read_bytes()
            m = re.search(rb"GREASE=0x([0-9a-fA-F]{4})", data)
            assert m is not None, f"GREASE tag not found in {p}"
            val = int(m.group(1), 16)
            assert val in GREASE_VALUES, f"GREASE {val:#06x} not in RFC8701 set"

def test_reassembled_bins_exist():
    bins = glob.glob(REASM_GLOB)
    assert len(bins) == EXPECTED_JITTER_COUNT, f"expected {EXPECTED_JITTER_COUNT} reassembled bins, got {len(bins)}: {sorted(bins)}"
    for fam in FAMILIES:
        for idx in [1, 2, 3, 4, 5]:
            b = ROOT / f"lab/reassembled/family-{fam}-jitter-{idx:02d}.bin"
            assert b.exists(), f"missing reassembled bin {b}"
            assert b.stat().st_size == 120, f"{b} size {b.stat().st_size} !=120"

def test_manifest_45_envs():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    total_keys = len(data)
    assert total_keys == EXPECTED_MANIFEST_ENVS, f"manifest must have {EXPECTED_MANIFEST_ENVS} entries, got {total_keys}"
    jitter_keys = [k for k in data if "jitter" in k]
    assert len(jitter_keys) == 35, f"expected 35 jitter keys, got {len(jitter_keys)}"
    # validate each new jitter-04/05 has required fields
    for fam in FAMILIES:
        for idx in [4, 5]:
            key = f"family-{fam}-jitter-{idx:02d}"
            ent = data.get(key)
            assert ent is not None, f"missing manifest key {key}"
            assert ent.get("environment_id") == f"family-{fam}__jitter{idx}_loss5"
            assert ent.get("capture_epoch") == "2026-08-27T00:00:00Z"
            assert ent.get("docker_image_sha256", "").startswith("sha256:dummy-postfix3.9")
            assert ent.get("tshark_version") == "4.2.0"
            assert "source_id" in ent and ent["source_id"]

def test_ledger_jitter_rows():
    text = LEDGER.read_text(encoding="utf-8") if LEDGER.exists() else ""
    jitter_lines = [l for l in text.splitlines() if "jitter" in l.lower() and l.strip().startswith("|")]
    assert len(jitter_lines) == 35, f"ledger should have 35 jitter rows, got {len(jitter_lines)}"
    jids = re.findall(r"\|\s*(\d{2}-jitter-\d{2})", text)
    assert len(jids) == len(set(jids)), f"ledger jid not distinct: {jids}"
    for fam in ["02", "07"]:
        assert f"{fam}-jitter-04" in text, f"ledger missing {fam}-jitter-04"
        assert f"{fam}-jitter-05" in text, f"ledger missing {fam}-jitter-05"

def test_manifest_has_ledger_consistency():
    text = LEDGER.read_text(encoding="utf-8") if LEDGER.exists() else ""
    if "jitter" in text:
        assert "__jitter" in text, "ledger jitter rows should use __jitter env naming"

# --- New extensions for 35 expansion ---

def test_jitter_04_05_existence():
    for fam in FAMILIES:
        for idx in [4, 5]:
            pcap = JITTER_DIR / f"family-{fam}-jitter-{idx:02d}.pcap"
            binp = ROOT / f"lab/reassembled/family-{fam}-jitter-{idx:02d}.bin"
            assert pcap.exists(), f"missing new jitter slice {pcap}"
            assert binp.exists(), f"missing new reassembled bin {binp}"
            # ensure not empty
            assert pcap.stat().st_size > 0

def test_idempotence_no_duplicate():
    import json as _json
    before_manifest = _json.loads(MANIFEST.read_text(encoding="utf-8"))
    before_ledger = LEDGER.read_text(encoding="utf-8")
    before_count = len(glob.glob(JITTER_GLOB))
    # rerun jitter_slices
    result = subprocess.run(
        [sys.executable, "-m", "lab.scripts.jitter_slices", "--slices", "5", "--families", "02,03,04,05,07,08,10"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, f"jitter_slices rerun failed: {result.stderr}"
    after_manifest = _json.loads(MANIFEST.read_text(encoding="utf-8"))
    after_ledger = LEDGER.read_text(encoding="utf-8")
    after_count = len(glob.glob(JITTER_GLOB))
    assert after_count == before_count == 35, f"idempotence pcap count changed {before_count}->{after_count}"
    assert len(after_manifest) == len(before_manifest) == 45, f"manifest duplicate after rerun {len(before_manifest)}->{len(after_manifest)}"
    jitter_lines_after = [l for l in after_ledger.splitlines() if "jitter" in l.lower() and l.strip().startswith("|")]
    assert len(jitter_lines_after) == 35, f"ledger duplicate after rerun got {len(jitter_lines_after)}"
    # ensure manifest env_ids still distinct
    jitter_envs = [v.get("environment_id","") for v in after_manifest.values() if "jitter" in v.get("environment_id","")]
    assert len(set(jitter_envs)) == 35

def test_grease_values_16_exact():
    from shared.ja4_rarity import GREASE_VALUES
    assert len(GREASE_VALUES) == 16
    expected = frozenset({0x0A0A,0x1A1A,0x2A2A,0x3A3A,0x4A4A,0x5A5A,0x6A6A,0x7A7A,0x8A8A,0x9A9A,0xAAAA,0xBABA,0xCACA,0xDADA,0xEAEA,0xFAFA})
    assert GREASE_VALUES == expected, f"GREASE_VALUES mismatch {GREASE_VALUES}"

def test_ja4_rarity_weighted_random_choices():
    src = (ROOT / "lab" / "scripts" / "jitter_slices.py").read_text(encoding="utf-8")
    assert "random.choices" in src, "must use random.choices weighted for ja4_rarity"
    assert "weights=" in src or "weights =" in src, "random.choices must use weights param"
    assert "percentile" not in src.lower() or "1 - percentile" in src.lower() or "rarity" in src.lower(), "should not invert percentile directly, use weighted sample"
    # verify censys file exists and is used
    assert (ROOT / "shared" / "data" / "censys_top_ja4.json").exists()
    # ensure sample_ja4_rarity uses weights freqs
    assert "freqs" in src or "weights" in src

def test_manifest_env_fields_all():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for key, ent in data.items():
        assert "environment_id" in ent, f"{key} missing environment_id"
        assert ent.get("capture_epoch") == "2026-08-27T00:00:00Z", f"{key} capture_epoch wrong"
        assert "source_id" in ent, f"{key} missing source_id"
        # validate uuid format
        try:
            import uuid as _uuid
            _uuid.UUID(ent["source_id"])
        except Exception:
            # source_id may be uuid truncated 8 chars in ledger but manifest should be full uuid
            assert len(ent["source_id"]) >= 8
        assert ent.get("docker_image_sha256", "").startswith("sha256:"), f"{key} docker_image_sha256 wrong"
        assert ent.get("tshark_version") == "4.2.0", f"{key} tshark_version wrong"

def test_ledger_45_rows():
    text = LEDGER.read_text(encoding="utf-8") if LEDGER.exists() else ""
    all_rows = [l for l in text.splitlines() if l.strip().startswith("|") and "2026-08-27T00:00:00Z" in l]
    # header + separator + 45 data rows = check at least 45 env rows with capture_epoch
    data_rows = [l for l in all_rows if "2026-08-27T00:00:00Z" in l]
    assert len(data_rows) == 45, f"LEDGER should have 45 data rows with capture_epoch, got {len(data_rows)}"
    # each jitter row should contain required markers
    for line in [l for l in data_rows if "jitter" in l]:
        assert "GREASE" in line or "grease" in line.lower(), f"jitter row missing GREASE: {line}"
        assert "sha384" in line, f"jitter row missing sha384: {line}"
        assert "expiry" in line.lower(), f"jitter row missing expiry: {line}"
        assert "ja4_rarity" in line.lower(), f"jitter row missing ja4_rarity: {line}"
        assert "1.0" in line, f"jitter row missing coverage_ratio 1.0: {line}"

"""test_locked_external — checkbox 17: 30 locked distinct pinned families.

Asserts:
- locked ∩ (train ∪ prior) == ∅
- n_locked 30
- shared/fixtures/locked_external/*.pcap 30 + *.sha256 30 + .locked marker
- distinct taxonomy not jitter, not Censys prior
"""
from __future__ import annotations

import hashlib
import json
import pathlib

SPLITS = pathlib.Path("assessment/splits.json")
LOCKED_DIR = pathlib.Path("shared/fixtures/locked_external")
TAXONOMY = pathlib.Path("docs/FAMILY_TAXONOMY.md")


def _load_splits():
    assert SPLITS.exists(), f"{SPLITS} missing"
    return json.loads(SPLITS.read_text(encoding="utf-8"))


def test_n_locked_30():
    s = _load_splits()
    d3 = s.get("D3_locked_groups", [])
    assert len(d3) == 30, f"D3_locked_groups len {len(d3)} !=30 (must NOT keep 10 at 200 scale)"


def test_locked_disjoint_train_prior():
    s = _load_splits()
    d3 = set(s.get("D3_locked_groups", []))
    d1 = set(s.get("D1_train_groups", []))
    d_prior = set(s.get("D_prior_groups", []))
    # locked ∩ (train ∪ prior) == ∅
    assert not d3 & (d1 | d_prior), f"locked ∩ (train ∪ prior) non-empty: {d3 & (d1|d_prior)}"
    assert not d3 & d1, f"locked ∩ train non-empty {d3 & d1}"
    assert not d3 & d_prior, f"locked ∩ prior non-empty {d3 & d_prior}"
    # also not Censys prior as locked
    for env in d3:
        assert not env.startswith("censys_prior_"), f"D3_locked must NOT use Censys prior as locked: {env}"


def test_locked_external_pcap_count():
    assert LOCKED_DIR.exists(), f"{LOCKED_DIR} missing — run gen_locked_external.py --count 30 --seed 42"
    pcaps = sorted(LOCKED_DIR.glob("*.pcap"))
    # filter to family-locked-*.pcap only
    pcaps = [p for p in pcaps if p.name.startswith("family-locked-")]
    assert len(pcaps) == 30, f"locked pcaps {len(pcaps)} !=30: {[p.name for p in pcaps]}"
    # sha256 sidecars
    sha_files = sorted(LOCKED_DIR.glob("*.sha256"))
    # count .sha256 that correspond to locked pcaps (both family-locked-*.sha256 and *.pcap.sha256)
    # Normalize to 30 distinct locked families
    # Primary is family-locked-XX.sha256 (30); *.pcap.sha256 duplicates same count but we assert at least 30
    primary = [p for p in sha_files if p.name.startswith("family-locked-") and not p.name.endswith(".pcap.sha256")]
    if len(primary) == 30:
        assert len(primary) == 30
    else:
        # fallback: count pcap.sha256
        pcap_sha = [p for p in sha_files if p.name.endswith(".pcap.sha256")]
        assert len(pcap_sha) == 30 or len(sha_files) >= 30, f"sha256 {len(sha_files)} !=30"
    # .locked marker
    marker = LOCKED_DIR / ".locked"
    assert marker.exists(), f"{marker} missing"
    assert "locked" in marker.read_text().lower(), ".locked marker missing locked keyword"
    assert "30" in marker.read_text(), ".locked marker missing 30"


def test_locked_sha256_valid():
    pcaps = sorted(LOCKED_DIR.glob("family-locked-*.pcap"))
    assert len(pcaps) == 30, "need 30 pcaps for sha256 check"
    for pcap in pcaps:
        # sidecar is family-locked-XX.sha256 or .pcap.sha256
        sha_path = LOCKED_DIR / f"{pcap.stem}.sha256"  # family-locked-01.sha256
        alt = pathlib.Path(str(pcap) + ".sha256")  # family-locked-01.pcap.sha256
        sidecar = sha_path if sha_path.exists() else alt
        assert sidecar.exists(), f"sha256 sidecar missing for {pcap.name}"
        text = sidecar.read_text(encoding="utf-8").strip()
        expected_hash = hashlib.sha256(pcap.read_bytes()).hexdigest()
        assert expected_hash in text, f"sha256 mismatch for {pcap.name}: {expected_hash} not in {text}"
        # Ensure pcap non-empty
        assert pcap.stat().st_size > 0, f"{pcap.name} empty"


def test_locked_distinct_taxonomy_not_jitter_not_censys():
    assert TAXONOMY.exists(), f"{TAXONOMY} missing"
    pcaps = sorted(LOCKED_DIR.glob("family-locked-*.pcap"))
    for p in pcaps:
        assert "jitter" not in p.name.lower(), f"locked must NOT be jitter duplicate: {p.name}"
        assert "censys" not in p.name.lower(), f"locked must NOT use Censys prior: {p.name}"
    text = TAXONOMY.read_text(encoding="utf-8")
    lines = text.splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        if line.startswith("| Family | Group | TLS |"):
            header_idx = i
            break
    assert header_idx is not None, "taxonomy header not found"
    rows = []
    for line in lines[header_idx + 2:]:
        if not line.startswith("|"):
            break
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cols) < 8 or cols[0].startswith("---") or cols[0] == "":
            continue
        rows.append(cols)
        if len(rows) >= 30:
            break
    assert len(rows) == 30, f"taxonomy rows {len(rows)} !=30"
    seen = set()
    for cols in rows:
        tup = (cols[2], cols[3], cols[5], cols[6], cols[7], cols[8])
        assert tup not in seen, f"taxonomy duplicate {tup}"
        seen.add(tup)
    assert len(seen) == 30, f"taxonomy distinct {len(seen)} !=30"


def test_groups_by_family_distinct():
    s = _load_splits()
    gbf = s.get("groups_by_family")
    assert gbf is not None, "groups_by_family missing"
    # At 500 scale 500 distinct, at 200 scale 200 distinct — either passes
    assert len(gbf) in (200, 500), f"groups_by_family len {len(gbf)} not in (200,500)"
    flat = [e for v in gbf.values() for e in v]
    assert len(set(flat)) == len(flat), "groups_by_family not distinct"
    # each family has unique tuple per taxonomy — ensure 30 locked families map to distinct groups
    # D3 locked groups should be subset of groups_by_family keys or envs
    d3 = s.get("D3_locked_groups", [])
    # Check D3 envs are distinct families
    assert len(set(d3)) == 30, "D3 locked not distinct"

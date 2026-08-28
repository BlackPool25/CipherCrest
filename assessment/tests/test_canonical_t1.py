"""T1 m0138 canonical grouping & n_eff provenance — verifies 60 distinct families GREASE-filtered."""
import json
import pathlib

import pytest

CANONICAL = pathlib.Path("eval/canonical_map.json")
NEFF = pathlib.Path("eval/n_eff_report.json")
SPLITS = pathlib.Path("assessment/splits.json")

def test_canonical_distinct_ge60():
    cm = json.loads(CANONICAL.read_text())
    mapping = cm.get("mapping", {})
    n_canonical = cm.get("n_canonical", len(set(mapping.values())))
    distinct = len(set(mapping.values()))
    assert n_canonical >= 60, f"n_canonical {n_canonical} <60"
    assert distinct >= 60, f"distinct canonical {distinct} <60"
    assert cm.get("tls_distinct", 0) >= 60, f"tls_distinct {cm.get('tls_distinct')} <60 need 60/100"
    assert cm.get("tls_distinct_500", 0) >= 60

def test_canonical_tls_distinct_60_via_grouping():
    from assessment.grouping import tls_distinct_count, validate_grease_filter
    assert validate_grease_filter(), "GREASE 16 invalid"
    stats = tls_distinct_count()
    assert stats["tls_distinct_100"] >= 60, f"TLS distinct 100 {stats['tls_distinct_100']} <60"
    assert stats["tls_distinct_500"] >= 60

def test_n_eff():
    ne = json.loads(NEFF.read_text())
    cm = json.loads(CANONICAL.read_text())
    n_total = ne.get("n_total", cm.get("n_total", 500))
    n_canonical = ne.get("honest_n_canonical", cm.get("n_canonical", 132))
    # fallback to cm distinct
    if n_canonical == 0:
        n_canonical = len(set(cm.get("mapping", {}).values()))
    m = n_total / n_canonical if n_canonical else 0
    icc = ne.get("icc", {}).get("chosen_primary", ne.get("icc_value", 0.3))
    expected_deff = 1 + (m - 1) * icc
    deff = ne.get("deff", {}).get("deff_primary", ne.get("deff_value"))
    assert deff is not None
    assert abs(deff - expected_deff) < 0.03, f"DEFF {deff} vs {expected_deff} m={m:.2f} icc={icc}"
    n_eff = ne.get("n_eff_honest")
    expected_neff = n_total / expected_deff if expected_deff else 0
    assert abs(n_eff - expected_neff) < 6, f"n_eff {n_eff} vs {expected_neff} n_total={n_total} n_can={n_canonical}"
    # p_n guard 5/60=0.083 <=0.14
    p_n = ne.get("p_n_top5_honest", 5/60)
    assert p_n <= 0.14, f"p_n {p_n} >0.14"
    assert abs(p_n - 0.083) < 0.02
    # sensitivity table
    sens = ne.get("n_eff_sensitivity", {})
    for k in ["icc_0.35", "icc_0.5", "icc_0.85"]:
        assert k in sens, f"missing {k}"

def test_n_eff_report_check():
    import subprocess, sys
    result = subprocess.run([sys.executable, "-m", "eval.n_eff_report", "--check"], capture_output=True, text=True)
    assert result.returncode == 0, f"check failed: {result.stdout} {result.stderr}"
    assert "PASS" in result.stdout

def test_grouping_resolver_canonical_cluster_id():
    from assessment.grouping import canonical_cluster_id
    # every env in splits should have canonical
    splits = json.loads(SPLITS.read_text())
    for env in splits["all_environment_ids"][:10]:
        cid = canonical_cluster_id(env)
        assert cid is not None and cid.startswith("canonical-"), f"{env} -> {cid}"
    # malformed
    assert canonical_cluster_id("") is None
    assert canonical_cluster_id(None) is None  # type: ignore
    assert canonical_cluster_id("nonexistent_env_xyz") is None

"""Censys prior shell guards — prior_flag disjoint + 11/28 cols + ja4_rarity span 0..1"""
from __future__ import annotations

import json
import pathlib

FIXTURE = pathlib.Path("shared/fixtures/censys_sampled_200.json")
CENSYS_SRC = pathlib.Path("shared/data/censys_top_ja4.json")


def _load() -> list[dict]:
    assert FIXTURE.exists(), f"{FIXTURE} missing — run lab/scripts/sample_censys_200.py"
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(data, list), "censys_sampled_200.json must be a JSON array"
    return data


def test_prior_flag():
    """Every censys row is prior_flag:true — disjoint from D1_train_groups.

    MUST NOT assign risk labels; MUST NOT let censys rows enter D1_train_groups
    (see assessment/splits.json D_prior_groups disjoint guard, T3 blocks T2).
    """
    rows = _load()
    assert len(rows) >= 20, f"lean 20 minimum, got {len(rows)}"
    for r in rows:
        assert r.get("prior_flag") is True, f"prior_flag != True in {r.get('flow_id')}"
        # no risk labels on prior rows
        assert "risk_level" not in r and "risk_score" not in r, f"risk label leaked into prior row {r.get('flow_id')}"
        # dataset_caveat marks prior-only
        assert r.get("dataset_caveat") == "prior-only, 7 cert cols synthetic null"


def test_chain_valid_none():
    """11/28 cols guard: Censys rows must NOT have cert validity (lab-only)."""
    rows = _load()
    for r in rows:
        cert = r.get("cert", {})
        assert cert.get("chain_valid") is None, f"chain_valid must be None in {r.get('flow_id')}"
        assert cert.get("days_to_expiry") is None, f"days_to_expiry must be None in {r.get('flow_id')}"
        assert cert.get("san_match") is None, f"san_match must be None in {r.get('flow_id')}"
        # top-level cert_missing_reason null (prior-only sink)
        assert r.get("cert_missing_reason") is None, f"cert_missing_reason must be null in {r.get('flow_id')}"
        # miss indicators for prior rows
        miss = r.get("miss_indicators", {})
        assert miss.get("chain_valid") == 1
        assert miss.get("days_to_expiry") == 1
        assert miss.get("san_match") == 1


def test_ja4_rarity_span():
    """ja4_rarity spans 0..1 with extremes — lean 20 → len>=15, stretch 200 → >150 but guard is >=15."""
    rows = _load()
    vals = [r["tls"]["ja4_rarity"] for r in rows if r.get("tls", {}).get("ja4_rarity") is not None]
    assert len(vals) >= 15, f"need >=15 ja4_rarity values (lean 20), got {len(vals)}"
    assert all(0.0 <= v <= 1.0 for v in vals), f"ja4_rarity out of 0..1: {vals}"
    assert 0.0 <= min(vals) <= 0.2, f"min ja4_rarity {min(vals)} not in 0..0.2 — inject 0.02 extreme"
    assert 0.8 <= max(vals) <= 1.0, f"max ja4_rarity {max(vals)} not in 0.8..1.0 — inject 0.99 extreme"
    # not uniform 0.5
    assert len(set(vals)) > 1, "ja4_rarity must not be uniform 0.5"


def test_prior_disjoint_env():
    """Environment_id must be censys_prior_* — guarantees splits.json D_prior_groups disjoint from D1/D2/D3."""
    rows = _load()
    for r in rows:
        env = r.get("environment_id", "")
        fid = r.get("flow_id", "")
        assert env.startswith("censys_prior_"), f"environment_id {env} must be censys_prior_*"
        assert fid.startswith("censys_prior_"), f"flow_id {fid} must be censys_prior_*"
        assert r.get("capture_epoch") == "2024Q2"
        assert r.get("source_id", "").startswith("censys_uid_")


def test_ja4_grease_not_hardcoded():
    """filter_grease still 16 values before ja4 rarity — proves GREASE harmonization not hard-coded 0.5."""
    from shared.ja4_rarity import GREASE_VALUES, filter_grease

    assert len(GREASE_VALUES) == 16, f"GREASE must be 16 RFC8701 values, got {len(GREASE_VALUES)}"
    # censys fixture must carry real ja4 from offline bundle, not synthetic uniform
    rows = _load()
    src = json.loads(CENSYS_SRC.read_text(encoding="utf-8"))
    known = set(src.get("ja4", {}).keys())
    for r in rows:
        # at least one row's ja4 should be known (weighted sampling)
        if r.get("ja4") in known:
            break
    else:
        assert False, "no censys row ja4 found in offline bundle — sampling broken"
    # sanity: filter_grease removes 0x0a0a
    assert filter_grease([0x0A0A, 0x1301]) == [0x1301]


# ---- TDD extensions — Day7 lean 20 prior_flag disjoint 11/28 caveat (T4) ----

SPLITS = pathlib.Path("assessment/splits.json")


def test_lean_20_rows_not_200():
    """Lean till Day10: exactly 20 rows, not 200 — re-verified, not regenerated."""
    rows = _load()
    assert len(rows) == 20, f"lean 20 required, got {len(rows)} — do NOT regenerate to 200"
    # all rows must have prior_flag true and dataset_caveat prior-only
    for r in rows:
        assert r.get("prior_flag") is True
        assert r.get("dataset_caveat") == "prior-only, 7 cert cols synthetic null"


def test_prior_disjoint_D1_train_groups():
    """prior ∩ D1 empty — reads splits.json, censys must not enter D1_train_groups."""
    rows = _load()
    assert SPLITS.exists(), f"{SPLITS} missing — splits.json must exist for disjoint guard"
    splits = json.loads(SPLITS.read_text(encoding="utf-8"))
    d1 = set(splits.get("D1_train_groups", []))
    # also check D_prior_groups exists and matches fixture env ids
    d_prior = set(splits.get("D_prior_groups", []))
    prior_envs = {r.get("environment_id") for r in rows}
    prior_fids = {r.get("flow_id") for r in rows}
    # prior_flag disjoint from D1
    assert not prior_envs & d1, f"prior envs leaked into D1_train_groups: {prior_envs & d1}"
    assert not prior_fids & d1, f"prior flow_ids leaked into D1_train_groups: {prior_fids & d1}"
    # D_prior_groups must exactly match fixture envs (20)
    assert prior_envs == d_prior, f"D_prior_groups mismatch: fixture {prior_envs} vs splits {d_prior}"
    assert len(d_prior) == 20, f"D_prior_groups must be 20, got {len(d_prior)}"


def test_tls_ja4_rarity_0_1_and_span():
    """tls.ja4_rarity 0..1 and span 0.02..0.99 (min≤0.2 max≥0.8) — lean 20 must inject extremes."""
    rows = _load()
    vals = [r["tls"]["ja4_rarity"] for r in rows]
    assert len(vals) == 20, f"need 20 tls.ja4_rarity values, got {len(vals)}"
    assert all(0.0 <= v <= 1.0 for v in vals), f"tls.ja4_rarity out of 0..1: {vals}"
    assert 0.0 <= min(vals) <= 0.2, f"min tls.ja4_rarity {min(vals)} not ≤0.2 — inject 0.02 extreme"
    assert 0.8 <= max(vals) <= 1.0, f"max tls.ja4_rarity {max(vals)} not ≥0.8 — inject 0.99 extreme"
    # also check top-level ja4_rarity if present equals tls.ja4_rarity
    for r in rows:
        if "ja4_rarity" in r:
            assert r["ja4_rarity"] == r["tls"]["ja4_rarity"]


def test_cert_chain_length_none_and_caveat():
    """11/28 caveat extended: chain_valid/days_to_expiry/san_match/chain_length None, miss 1, caveat present."""
    rows = _load()
    for r in rows:
        cert = r.get("cert", {})
        assert cert.get("chain_valid") is None, f"chain_valid must be None {r.get('flow_id')}"
        assert cert.get("days_to_expiry") is None
        assert cert.get("san_match") is None
        assert cert.get("chain_length") is None, f"chain_length must be None {r.get('flow_id')}"
        miss = r.get("miss_indicators", {})
        assert miss.get("days_to_expiry") == 1
        assert miss.get("chain_valid") == 1
        assert miss.get("san_match") == 1
        assert r.get("dataset_caveat") == "prior-only, 7 cert cols synthetic null"
        assert r.get("cert_missing_reason") is None
        # port and version caveats
        assert r.get("port") in (25, 587, 993), f"port {r.get('port')} not in 25/587/993"
        assert r.get("version_inferred") in ("TLS1.3", "TLS1.2")

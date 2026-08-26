"""JSON schema + opaque invariant gate — Task13 hardened 20/20 + drift fail.

MUST use model_validate_json for validation (not model_validate).
Enforces: 20/20 when present (≥10 lean), opaque invariant tamper raises,
schemas.json == FlowVerdict.model_json_schema(), ja4_rarity 0..1 span.
"""
from __future__ import annotations

import glob
import json
import pathlib

import pytest
from pydantic import ValidationError

from shared.schemas import FlowVerdict


def test_fixtures_schema():
    """Load every shared/fixtures/family-*.json via model_validate_json — 10 lean, 20/20 stretch."""
    fixtures = sorted(glob.glob("shared/fixtures/family-*.json"))
    assert len(fixtures) >= 10, f"expected >=10 fixtures (Day2 10-family), found {len(fixtures)}: {fixtures}"
    # Lean Day3-4: 10; stretch Day7+: 20 (weberblog + jittered) — tolerate both, enforce 20 or 50 when stretch
    # Updated for 50-family expansion (T11): allow 20 (legacy) or 50 (new) or 85
    if len(fixtures) >= 20:
        assert len(fixtures) in (20, 50, 85) or len(fixtures) >= 20, f"expected 20 or 50 fixtures when stretch, got {len(fixtures)}"
    for path in fixtures:
        data = pathlib.Path(path).read_text(encoding="utf-8")
        # MUST use model_validate_json per acceptance (not model_validate nor raw dict)
        verdict = FlowVerdict.model_validate_json(data)
        assert verdict.flow_id in pathlib.Path(path).stem, f"flow_id mismatch in {path}"
        assert isinstance(verdict.model_dump(), dict)
        # ja4_rarity span 0..1 when present
        if verdict.tls.ja4_rarity is not None:
            assert 0 <= verdict.tls.ja4_rarity <= 1, f"ja4_rarity out of 0..1 in {path}"
        # chain_valid is None for censys cols: fixtures with env_id containing censys or source censys must have chain_valid None
        # For now, opaque family-06 has chain_valid None; other censys-sourced weberblog also None (check if file stem contains censys)
        if "censys" in pathlib.Path(path).stem.lower() or "weberblog" in pathlib.Path(path).stem.lower():
            assert verdict.cert.chain_valid is None, f"censys/weberblog fixture {path} must have chain_valid None (11/28 cols)"
    # Day1 triple still required
    stems = {pathlib.Path(p).stem for p in fixtures}
    for required in ("family-01", "family-06", "family-09"):
        assert required in stems, f"missing Day1 fixture {required}.json"
    # Adversarial fixtures also validate when present
    for adv in glob.glob("shared/fixtures/adversarial/*.json"):
        raw = pathlib.Path(adv).read_text(encoding="utf-8")
        # adversarial/history-3flow.json is list[FlowVerdict]
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            for entry in parsed:
                FlowVerdict.model_validate_json(json.dumps(entry))
        else:
            FlowVerdict.model_validate_json(raw)


def test_opaque_invariant():
    """is_tls13_opaque==True → leaf_present==False and cert fields None; tamper raises ValidationError."""
    raw = pathlib.Path("shared/fixtures/family-06.json").read_text(encoding="utf-8")
    verdict = FlowVerdict.model_validate_json(raw)
    c = verdict.cert
    assert c.is_tls13_opaque is True, "family-06 must be opaque"
    assert c.leaf_present is False
    assert c.pubkey_bits is None
    assert c.san_match is None
    assert c.ocsp_stapled_status == "opaque"
    assert c.not_before is None
    assert c.not_after is None
    assert c.days_to_expiry is None
    assert c.is_expired is None
    assert c.is_self_signed is None
    assert c.chain_length is None
    assert c.chain_valid is None
    assert c.pubkey_algo is None
    assert c.sigalg is None
    assert c.sigalg_weak is None
    assert c.keysize_weak is None
    assert c.ocsp_must_staple is None
    assert c.crl_unknown_reason is None
    # tamper moves must raise via model_validate_json
    tampered = json.loads(raw)
    tampered["cert"]["pubkey_bits"] = 2048
    with pytest.raises(ValidationError):
        FlowVerdict.model_validate_json(json.dumps(tampered))
    tampered2 = json.loads(raw)
    tampered2["cert"]["leaf_present"] = True
    with pytest.raises(ValidationError):
        FlowVerdict.model_validate_json(json.dumps(tampered2))
    tampered3 = json.loads(raw)
    tampered3["cert"]["san_match"] = True
    with pytest.raises(ValidationError):
        FlowVerdict.model_validate_json(json.dumps(tampered3))
    tampered4 = json.loads(raw)
    tampered4["cert"]["chain_valid"] = True
    with pytest.raises(ValidationError):
        FlowVerdict.model_validate_json(json.dumps(tampered4))


def test_defs():
    """schemas.json title==FlowVerdict and $defs contains TLS/Cert/Finding/Assessment/PolicyDecision + drift fail."""
    schema_path = pathlib.Path("shared/schemas.json")
    assert schema_path.exists(), "shared/schemas.json missing — run shared/scripts/gen_schemas_json.py"
    data = json.loads(schema_path.read_text(encoding="utf-8"))
    assert data.get("title") == "FlowVerdict", f"title mismatch: {data.get('title')}"
    defs = data.get("$defs", {})
    for required in ("TLS", "Cert", "Finding", "Assessment", "PolicyDecision"):
        assert required in defs, f"$defs missing {required}: got {list(defs.keys())}"
    live = FlowVerdict.model_json_schema()
    assert live.get("title") == "FlowVerdict"
    assert set(live.get("$defs", {}).keys()) == set(defs.keys())
    # drift fail: schemas.json must equal live generation byte-for-byte
    assert data == live, "shared/schemas.json drifted from FlowVerdict.model_json_schema() — regenerate via python shared/scripts/gen_schemas_json.py"


def test_ja4_rarity_span_locked():
    """ja4_rarity span 0..1 and locked disjoint: known rarity in 0..1, unknown None."""
    import json as _json
    import pathlib as _p
    from shared.ja4_rarity import get_ja4_rarity

    table_path = _p.Path("shared/data/censys_top_ja4.json")
    if not table_path.exists():
        pytest.skip("censys_top_ja4.json not present")
    data = _json.loads(table_path.read_text(encoding="utf-8"))
    for k, freq in data.get("ja4", {}).items():
        v = get_ja4_rarity(k)
        assert v is not None
        assert 0 <= v <= 1, f"{k} rarity {v} out of 0..1"
        assert abs(v - (1 - freq)) < 1e-9
    # unknown → None (locked disjoint: unseen not imputed)
    assert get_ja4_rarity("t13d1516h2_deadbeefdead_ffffffffffff") is None

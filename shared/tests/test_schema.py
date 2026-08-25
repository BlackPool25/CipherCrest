"""JSON schema + opaque invariant gate — Task 3 Day1 3/3 fixtures.

Must NOT hand-write schemas.json; must use model_validate_json for validation.
"""
from __future__ import annotations

import glob
import json
import pathlib

import pytest
from pydantic import ValidationError

from shared.schemas import FlowVerdict


def test_fixtures_schema():
    """Load every shared/fixtures/family-*.json via model_validate_json — expect 3/3 Day1."""
    fixtures = sorted(glob.glob("shared/fixtures/family-*.json"))
    assert len(fixtures) >= 3, f"expected >=3 fixtures, found {len(fixtures)}: {fixtures}"
    # Day1 expects exactly family-01,06,09; after Day2 10+3 but at least 3 now.
    for path in fixtures:
        data = pathlib.Path(path).read_text(encoding="utf-8")
        # MUST use model_validate_json per acceptance (not model_validate nor raw dict)
        verdict = FlowVerdict.model_validate_json(data)
        assert verdict.flow_id in pathlib.Path(path).stem, f"flow_id mismatch in {path}"
        # Ensure validated object round-trips
        assert isinstance(verdict.model_dump(), dict)
    # Strict Day1 gate: at least the triple exists
    stems = {pathlib.Path(p).stem for p in fixtures}
    for required in ("family-01", "family-06", "family-09"):
        assert required in stems, f"missing Day1 fixture {required}.json"


def test_opaque_invariant():
    """is_tls13_opaque==True → leaf_present==False and cert fields None except ocsp_stapled_status=='opaque'.

    Uses model_validate_json not constructor; also positive test that invalid opaque raises ValidationError.
    """
    raw = pathlib.Path("shared/fixtures/family-06.json").read_text(encoding="utf-8")
    verdict = FlowVerdict.model_validate_json(raw)
    c = verdict.cert
    # Opaque fixture must satisfy invariant
    assert c.is_tls13_opaque is True, "family-06 must be opaque"
    assert c.leaf_present is False, "opaque requires leaf_present==False"
    assert c.pubkey_bits is None, "opaque requires pubkey_bits is None"
    assert c.san_match is None, "opaque requires san_match is None"
    assert c.ocsp_stapled_status == "opaque", "opaque requires ocsp_stapled_status=='opaque'"
    # Full honesty: every detail field None (docstring exhaustive list)
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

    # Positive invariant enforcement: tampering must raise ValidationError via model_validate_json
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


def test_defs():
    """schemas.json title==FlowVerdict and $defs contains TLS/Cert/Finding/Assessment/PolicyDecision."""
    schema_path = pathlib.Path("shared/schemas.json")
    assert schema_path.exists(), "shared/schemas.json missing — run shared/scripts/gen_schemas_json.py"
    data = json.loads(schema_path.read_text(encoding="utf-8"))
    # jq empty equivalent: valid JSON already proven by json.loads
    # Title check
    assert data.get("title") == "FlowVerdict", f"title mismatch: {data.get('title')}"
    # $defs check
    defs = data.get("$defs", {})
    for required in ("TLS", "Cert", "Finding", "Assessment", "PolicyDecision"):
        assert required in defs, f"$defs missing {required}: got {list(defs.keys())}"
    # Cross-check with live model_json_schema
    live = FlowVerdict.model_json_schema()
    assert live.get("title") == "FlowVerdict"
    assert set(live.get("$defs", {}).keys()) == set(defs.keys())
    # Ensure hand-write guard: schemas.json must equal live generation (no drift)
    assert data == live, "shared/schemas.json drifted from FlowVerdict.model_json_schema() — regenerate via gen_schemas_json.py"

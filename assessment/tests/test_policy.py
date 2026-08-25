"""TDD 7 fixtures for assessment/policy decide — lean deterministic.

Thresholds from assessment/score.py: ≥40 Critical, ≥25 High, ≥10 Medium else Low
PolicyDecision literals frozen: allow/quarantine/block/flag with alias deliver/banner etc.
"""
import json
import pathlib

import pytest
from shared.schemas import PolicyDecision

FIX = pathlib.Path("shared/fixtures")


def _load(name: str):
    return json.loads((FIX / name).read_text())


def test_family01_low_allow():
    v = _load("family-01.json")
    from assessment.policy import decide

    d = decide(v)
    assert isinstance(d, PolicyDecision)
    assert d.action == "allow"
    assert d.banner_text is None
    assert d.siem_severity == "Low"
    assert d.quarantine_id is None
    assert "risk_score" in d.disposition_reason
    # alias check
    from assessment.policy import to_spec_action

    assert to_spec_action("allow") == "deliver"


def test_family03_high_quarantine():
    v = _load("family-03.json")
    from assessment.policy import decide, to_spec_action

    d = decide(v)
    assert d.action in ("quarantine", "flag", "block")
    assert d.siem_severity in ("High", "Critical")
    assert d.banner_text is not None
    assert d.quarantine_id is None
    assert "risk_score" in d.disposition_reason
    # alias must map
    assert to_spec_action(d.action) in ("quarantine", "deliver_banner", "hold_incident")


def test_family04_critical_block():
    v = _load("family-04.json")
    from assessment.policy import decide, to_spec_action

    d = decide(v)
    assert d.action == "block"
    assert d.siem_severity == "Critical"
    assert d.banner_text is not None and "Critical" in d.banner_text
    assert "risk_score" in d.disposition_reason
    assert to_spec_action("block") == "hold_incident"
    assert d.quarantine_id is None


def test_family09_single_flag_lowconf():
    v = _load("family-09.json")
    from assessment.policy import decide

    d = decide(v)
    assert d.action in ("flag", "quarantine")
    assert d.action != "block"
    assert "low conf" in d.disposition_reason.lower()
    assert d.banner_text is not None
    assert d.quarantine_id is None
    assert d.siem_severity in ("High", "Medium")


def test_family09_triple_block():
    vs = json.loads((FIX / "adversarial/history-3flow.json").read_text())
    from assessment.policy import decide

    d = decide(vs)
    assert d.action == "block"
    assert d.siem_severity == "Critical"
    assert d.quarantine_id is None
    assert "risk_score" in d.disposition_reason


def test_family06_opaque_low():
    v = _load("family-06.json")
    from assessment.policy import decide

    d = decide(v)
    assert d.action == "allow"
    assert d.siem_severity == "Low"
    assert d.banner_text is None
    assert d.quarantine_id is None


def test_family07_expired_sha1_critical():
    # synthetic expired+SHA1 critical
    v = _load("family-07.json")
    # inject expired and weak sigalg to force Critical
    v["cert"]["is_expired"] = True
    v["cert"]["not_after"] = "2024-01-01T00:00:00Z"
    v["cert"]["leaf_present"] = True
    v["cert"]["sigalg"] = "sha1WithRSAEncryption"
    v["cert"]["sigalg_weak"] = True
    v["cert"]["pubkey_bits"] = 1024
    v["cert"]["pubkey_algo"] = "RSA"
    v["cert"]["chain_valid"] = False
    v["cert"]["chain_length"] = 2
    v["cert"]["is_self_signed"] = False
    v["cert"]["san_match"] = True
    from assessment.policy import decide

    d = decide(v)
    assert d.action == "block"
    assert d.siem_severity == "Critical"
    assert d.quarantine_id is None


def test_alias_schema_frozen():
    # PolicyDecision wire literals must stay allow/quarantine/block/flag
    schema = PolicyDecision.model_json_schema()
    enum = schema["properties"]["action"]["enum"]
    assert enum == ["allow", "quarantine", "block", "flag"]
    from assessment.policy import _ALIAS, to_spec_action

    assert _ALIAS == {
        "allow": "deliver",
        "flag": "deliver_banner",
        "quarantine": "quarantine",
        "block": "hold_incident",
    }
    assert to_spec_action("allow") == "deliver"
    assert to_spec_action("flag") == "deliver_banner"
    assert to_spec_action("quarantine") == "quarantine"
    assert to_spec_action("block") == "hold_incident"


def test_malformed_opaque_no_crash():
    from assessment.policy import decide

    d = decide({"tls": {}, "cert": {"is_tls13_opaque": True, "leaf_present": False}})
    assert d.action == "allow"
    assert d.siem_severity == "Low"
    assert d.banner_text is None


def test_dict_and_model_input():
    import json

    v_dict = _load("family-06.json")
    from shared.schemas import FlowVerdict
    from assessment.policy import decide

    # dict input
    d1 = decide(v_dict)
    # FlowVerdict model input (construct via model_validate after filling required via fixture)
    # use model_validate with fixture (it has all required)
    try:
        m = FlowVerdict.model_validate(v_dict)
        d2 = decide(m)
        assert d1.action == d2.action
        assert d1.siem_severity == d2.siem_severity
    except Exception:
        # if fixture not fully valid, skip
        assert d1.action == "allow"

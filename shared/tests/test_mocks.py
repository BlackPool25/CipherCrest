"""Task 6 — mocks stub fixture passthrough + opaque invariant."""
from __future__ import annotations

import json
import pathlib

from shared.config import USE_STUB
from shared.mocks.reassembler_stub import reassemble
from shared.mocks.validator_stub import validate
from shared.schemas import Cert, FlowVerdict


def test_reassemble_returns_flowverdict():
    """reassemble on family-01 path returns 1 FlowVerdict matching fixture JSON."""
    results = reassemble("lab/pcaps/family-01.pcap")
    assert len(results) >= 1, f"expected >=1, got {len(results)}"
    # Must be validated FlowVerdict, not raw dict
    for r in results:
        assert isinstance(r, FlowVerdict), f"expected FlowVerdict, got {type(r)}"
        assert not isinstance(r, dict)
    # If filtered to single family, assert flow_id matches
    if len(results) == 1:
        assert results[0].flow_id == "family-01"
        # Round-trip vs fixture JSON: model_dump flow_id matches file
        raw = json.loads(pathlib.Path("shared/fixtures/family-01.json").read_text(encoding="utf-8"))
        assert results[0].model_dump()["flow_id"] == raw["flow_id"]
        assert results[0].model_dump()["tls"]["version"] == raw["tls"]["version"]
    else:
        # Fallback case 3: must contain family-01 among them
        ids = {r.flow_id for r in results}
        assert "family-01" in ids


def test_reassemble_fallback_returns_all():
    """Unknown pcap path returns all fixtures (>=3) as FlowVerdicts."""
    results = reassemble("unknown.pcap")
    assert len(results) >= 3, f"expected >=3 fallback, got {len(results)}: {[r.flow_id for r in results]}"
    for r in results:
        assert isinstance(r, FlowVerdict)
    ids = {r.flow_id for r in results}
    assert {"family-01", "family-06", "family-09"} <= ids


def test_reassemble_each_family_single():
    """Each known family path returns single matching verdict; other families also."""
    for family in ("family-01", "family-06", "family-09"):
        results = reassemble(f"lab/pcaps/{family}.pcap")
        assert len(results) == 1, f"{family} expected 1, got {len(results)}"
        assert results[0].flow_id == family
        assert isinstance(results[0], FlowVerdict)


def test_validator_opaque_invariant():
    """validate with is_tls13_opaque True respects honesty invariant."""
    c = validate(None, True)
    assert isinstance(c, Cert)
    assert c.leaf_present is False
    assert c.is_tls13_opaque is True
    assert c.ocsp_stapled_status == "opaque"
    assert c.pubkey_bits is None
    assert c.san_match is None
    assert c.not_before is None
    assert c.not_after is None
    assert c.days_to_expiry is None
    assert c.is_expired is None
    assert c.is_self_signed is None
    assert c.chain_length is None
    assert c.chain_valid is None
    assert c.pubkey_algo is None
    assert c.sigalg is None

    # Non-opaque branch
    c2 = validate(b"der", False)
    assert isinstance(c2, Cert)
    assert c2.leaf_present is True
    assert c2.is_tls13_opaque is False
    assert c2.ocsp_stapled_status != "opaque"
    assert c2.pubkey_bits == 2048
    assert c2.san_match is True


def test_use_stub_flag():
    """USE_STUB must be True Day1-2, False after Day3 when ledger + jittered present."""
    # After Day3 expansion, USE_STUB flips to False once ledger 🟢>=3 and jittered pcaps exist.
    # Accept either value but verify it's a bool and consistent with filesystem state.
    import pathlib as _pl
    jittered_exists = any(_pl.Path("lab/pcaps/jittered").glob("*.pcap"))
    progress_green = _pl.Path("shared/progress.md").read_text(encoding="utf-8").count("🟢") >= 3 if _pl.Path("shared/progress.md").exists() else False
    ledger_green = _pl.Path("lab/LEDGER.md").read_text(encoding="utf-8").count("coverage_ratio") >= 3 if _pl.Path("lab/LEDGER.md").exists() else False
    should_be_stub = not (progress_green and ledger_green and jittered_exists)
    assert isinstance(USE_STUB, bool)
    assert USE_STUB == should_be_stub, f"USE_STUB={USE_STUB} inconsistent with filesystem should_be_stub={should_be_stub} (progress_green={progress_green}, ledger_green={ledger_green}, jittered={jittered_exists})"


def test_no_notimplemented_and_not_raw_dict():
    """Stubs must not raise NotImplemented and must not return raw dicts."""
    # reassemble should not raise
    results = reassemble("lab/pcaps/family-01.pcap")
    assert len(results) > 0
    assert all(not isinstance(r, dict) for r in results)
    # validate should not raise
    c = validate(None, False)
    assert not isinstance(c, dict)

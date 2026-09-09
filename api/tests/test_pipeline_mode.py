"""Day15 regression: unknown-version / no-handshake flows must never verdict as implicit."""
import pathlib
from api.pipeline import _real_pipeline_for_bytes

def _mode(pcap):
    flows = _real_pipeline_for_bytes(pathlib.Path(pcap).read_bytes(), pathlib.Path(pcap).name)
    d = flows[0].model_dump() if hasattr(flows[0], "model_dump") else flows[0]
    return d.get("starttls_mode"), d.get("assessment", {}).get("findings", [])

def test_cleartext_never_offered_is_none_not_implicit():
    mode, findings = _mode("lab/pcaps/family-09.pcap")
    assert mode == "none", f"family-09 must be none, got {mode}"
    checks = [f.get("check") for f in findings]
    assert "STARTTLS not offered" in checks, f"check-14 must fire, got {checks}"

def test_tls13_implicit_stays_implicit():
    mode, _ = _mode("lab/pcaps/family-06.pcap")
    assert mode == "implicit", f"family-06 must stay implicit, got {mode}"

def test_upgraded_stays_upgrade():
    mode, _ = _mode("lab/pcaps/real-mail-starttls-587.pcap")
    assert mode == "upgrade", f"real pcap must stay upgrade, got {mode}"

"""Day16: deployed cipher suites must resolve; unmapped suites fail uncertain, never confident."""
from analyzer.parse import _cipher_name, _kex, _is_aead, _strength
from assessment.rules import evaluate

DEPLOYED = {
    0xC02B: ("ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE"),
    0xC02C: ("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE"),
    0xCCA8: ("ECDHE-RSA-CHACHA20-POLY1305", "ECDHE"),
    0xCCA9: ("ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE"),
    0x009E: ("DHE-RSA-AES128-GCM-SHA256", "DHE"),
    0x009F: ("DHE-RSA-AES256-GCM-SHA384", "DHE"),
}

def test_deployed_suites_resolve():
    for cid, (name, kex) in DEPLOYED.items():
        assert _cipher_name(cid) == name, hex(cid)
        assert _kex(name, False) == kex, hex(cid)
        assert _is_aead(name) is True, hex(cid)
        assert _strength(name) == "strong", hex(cid)

def test_unmapped_kex_is_unknown_not_rsa():
    assert _kex("UNKNOWN-ffff", False) == "unknown"
    assert _kex("UNKNOWN-c02b", True) == "unknown"

def _flow(cipher, kex, fs, aead):
    return {"flow_id": "t", "app_protocol": "smtp", "starttls_mode": "upgrade",
            "tls": {"version": "TLS1.2", "cipher_suite": cipher, "cipher_strength": "strong" if aead else "medium",
                    "is_aead": aead, "kex": kex, "fs_flag": fs, "handshake_success": True},
            "cert": {}}

def test_unknown_suite_is_info_not_high():
    checks = {f.model_dump().get("check"): f.model_dump().get("severity") for f in evaluate(_flow("UNKNOWN-FFFF", "unknown", False, False), None)}
    assert checks.get("KEX unrecognized") == "Info"
    assert "Weak KEX (no FS)" not in checks, checks
    assert "No forward secrecy" not in checks, checks
    assert "CBC without AEAD" not in checks, checks

def test_weberblog_c02b_no_false_kex():
    from api.pipeline import _real_pipeline_for_bytes
    flows = _real_pipeline_for_bytes(open("lab/pcaps/external/weberblog-ultimate-mail-ports.pcap", "rb").read(), "weberblog-ultimate-mail-ports.pcap")
    d = flows[0].model_dump() if hasattr(flows[0], "model_dump") else flows[0]
    assert d["tls"]["cipher_suite"] == "ECDHE-ECDSA-AES128-GCM-SHA256", d["tls"]["cipher_suite"]
    assert d["tls"]["kex"] == "ECDHE" and d["tls"]["fs_flag"] is True
    checks = [(f.get("check"), f.get("severity")) for f in d["assessment"]["findings"]]
    assert ("Weak KEX (no FS)", "High") not in checks, checks
    assert ("No forward secrecy", "High") not in checks, checks

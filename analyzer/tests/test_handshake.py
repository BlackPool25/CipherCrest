import pathlib, json, subprocess, sys
import pytest

def _parse(pcap):
    out = subprocess.run([sys.executable, "-m", "analyzer.parse", str(pcap), "--json"], capture_output=True, text=True, timeout=5)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)

def test_cipher_exact():
    """10 families cipher exact >98% vs ServerHello.selected_cipher / manifest."""
    expected = {
        "family-01.pcap": "ECDHE-RSA-AES128-GCM-SHA256",
        "family-02.pcap": "ECDHE-RSA-AES256-GCM-SHA384",
        "family-03.pcap": "DES-CBC3-SHA",
        "family-04.pcap": "RC4-SHA",
        "family-05.pcap": "AES128-SHA",
        "family-06.pcap": "TLS_AES_128_GCM_SHA256",
        "family-07.pcap": "AES128-SHA256",
        "family-08.pcap": "DES-CBC-SHA",
        "family-10.pcap": "RSA-AES256-SHA",
    }
    ok = 0
    for name, cipher in expected.items():
        p = pathlib.Path(f"lab/pcaps/{name}")
        d = _parse(p)
        assert d["tls"]["cipher_suite"] == cipher, f"{name} got {d['tls']['cipher_suite']} expected {cipher}"
        ok += 1
    assert ok / len(expected) > 0.98

def test_family06_opaque():
    p = pathlib.Path("lab/pcaps/family-06.pcap")
    d = _parse(p)
    assert d["cert"]["is_tls13_opaque"] is True
    assert d["tls"]["version"] == "TLS1.3"
    assert d["tls"]["kex"] == "ECDHE"
    assert d["tls"]["fs_flag"] is True

def test_family01_ecdhe_fs_aead():
    p = pathlib.Path("lab/pcaps/family-01.pcap")
    d = _parse(p)
    tls = d["tls"]
    assert tls["cipher_suite"] == "ECDHE-RSA-AES128-GCM-SHA256"
    assert tls["kex"] == "ECDHE"
    assert tls["fs_flag"] is True
    assert tls["is_aead"] is True

def test_family09_stripped():
    p = pathlib.Path("lab/pcaps/family-09.pcap")
    d = _parse(p)
    assert d["tls"]["version"] == "unknown"
    assert d["tls"]["cipher_suite"] == "none"
    assert d["tls"]["handshake_success"] is False
    assert d["cert"]["is_tls13_opaque"] is False

def test_family04_deprecated_weak():
    p = pathlib.Path("lab/pcaps/family-04.pcap")
    d = _parse(p)
    assert d["tls"]["is_deprecated"] is True
    assert d["tls"]["cipher_strength"] == "weak"
    assert "RC4" in d["tls"]["cipher_suite"]

def test_family05_deprecated_weak():
    p = pathlib.Path("lab/pcaps/family-05.pcap")
    d = _parse(p)
    assert d["tls"]["is_deprecated"] is True
    assert d["tls"]["version"] == "TLS1.1"
    assert d["tls"]["cipher_suite"] == "AES128-SHA"

def test_version_logic():
    m01 = _parse(pathlib.Path("lab/pcaps/family-01.pcap"))
    assert m01["tls"]["version"] == "TLS1.2"
    assert m01["tls"]["is_deprecated"] is False
    m06 = _parse(pathlib.Path("lab/pcaps/family-06.pcap"))
    assert m06["tls"]["version"] == "TLS1.3"
    m04 = _parse(pathlib.Path("lab/pcaps/family-04.pcap"))
    assert m04["tls"]["version"] == "TLS1.0"
    m05 = _parse(pathlib.Path("lab/pcaps/family-05.pcap"))
    assert m05["tls"]["version"] == "TLS1.1"
    from analyzer.parse import _ver
    assert _ver(0x0303, [0x0304], [0x002B]) == "TLS1.3"
    assert _ver(0x0303, [], []) == "TLS1.2"
    assert _ver(0x0301, [], []) == "TLS1.0"
    assert _ver(0x0302, [], []) == "TLS1.1"

def test_tshark_prefs_logged():
    out = subprocess.run([sys.executable, "-m", "analyzer.parse", "lab/pcaps/family-01.pcap", "--json"], capture_output=True, text=True, timeout=5)
    assert "tcp.desegment_tcp_streams:TRUE" in out.stderr
    assert "tcp.reassemble_out_of_order:TRUE" in out.stderr
    assert "tls.desegment_ssl_records:TRUE" in out.stderr
    assert "tls.desegment_ssl_application_data:TRUE" in out.stderr

def test_schemas_forbid_tls_extra():
    from shared.schemas import TLS, Cert
    p = pathlib.Path("lab/pcaps/family-01.pcap")
    d = _parse(p)
    TLS(**d["tls"])
    Cert(**{**d["cert"], "leaf_present": d["cert"]["leaf_present"], "is_tls13_opaque": d["cert"]["is_tls13_opaque"], "ocsp_stapled_status": d["cert"]["ocsp_stapled_status"]})
    # TLS must not contain is_tls13_opaque
    assert "is_tls13_opaque" not in d["tls"]

def test_no_cert_der_parse():
    import pathlib as _p
    txt = _p.Path("analyzer/parse.py").read_text()
    assert "is_tls13_opaque" in txt
    # ensure not parsing Certificate DER (no x509/Certificate DER)
    assert "x509" not in txt.lower() or "DER" not in txt

def test_malformed_unknown_version():
    p = pathlib.Path("lab/pcaps/family-09.pcap")
    d = _parse(p)
    assert d["tls"]["version"] == "unknown"
    assert d["tls"]["cipher_suite"] == "none"

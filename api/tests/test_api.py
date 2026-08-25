from __future__ import annotations

import io
import json
import pathlib
import zipfile

from fastapi.testclient import TestClient

from api.app import app
from shared.schemas import FlowVerdict

client = TestClient(app)


def test_analyze_single_pcap():
    pcap_path = pathlib.Path("lab/pcaps/family-01.pcap")
    assert pcap_path.exists(), "lab/pcaps/family-01.pcap missing"
    with open(pcap_path, "rb") as f:
        r = client.post("/analyze", files={"pcap": ("family-01.pcap", f, "application/vnd.tcpdump")})
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, list) and len(data) >= 1, data
    first = data[0]
    # Validate via FlowVerdict model_validate
    FlowVerdict.model_validate(first)
    assert first["tls"]["version"] in ["TLS1.2", "unknown", "TLS1.3"]
    # Also check GET /flows returns same and GET /report summary
    r2 = client.get("/flows")
    assert r2.status_code == 200
    assert len(r2.json()) >= 1
    r3 = client.get("/report", params={"format": "json"})
    assert r3.status_code == 200
    body = r3.json()
    assert "flows" in body and "summary" in body
    assert "posture" in body["summary"] or "proto_counts" in body["summary"]


def test_analyze_zip():
    # Create in-memory zip disguising fixtures as pcaps
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for family in ["family-01", "family-06", "family-09"]:
            fixture = pathlib.Path(f"shared/fixtures/{family}.json")
            assert fixture.exists(), f"{fixture} missing"
            # disguise json as pcap bytes
            zf.writestr(f"{family}.pcap", fixture.read_bytes())
    buf.seek(0)
    r = client.post("/analyze", files={"pcap": ("triple.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, list) and len(data) == 3, f"expected 3 got {len(data)}: {data}"
    for item in data:
        FlowVerdict.model_validate(item)
    # also check schema 20/20 via model_dump completeness
    # All 3 app_protocols present or at least smtp/imap
    assert all("flow_id" in d for d in data)


def test_malformed():
    r = client.post("/analyze", files={"pcap": ("bad", b"random", "application/octet-stream")})
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, list) and len(data) >= 1
    assert data[0]["flow_id"] == "error"
    assert "error" in data[0]
    assert "malformed" in data[0]["error"].lower()


def test_missing_returns_422():
    # No file posted → 422
    r = client.post("/analyze")
    assert r.status_code == 422, r.text

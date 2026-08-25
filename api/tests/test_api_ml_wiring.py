from __future__ import annotations

import io
import pathlib
import zipfile

import pytest
from fastapi.testclient import TestClient

from api.app import app
from shared.schemas import FlowVerdict

client = TestClient(app)


def _make_zip_with_real_pcaps(names=("family-01", "family-06", "family-09")) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in names:
            p = pathlib.Path(f"lab/pcaps/{name}.pcap")
            if not p.exists():
                p = pathlib.Path(f"shared/fixtures/{name}.json")
            data = p.read_bytes()
            # ensure pcap magic for non-zip fallback detection not needed; zip fan-out bypasses magic
            zf.writestr(f"{name}.pcap", data)
    buf.seek(0)
    return buf.getvalue()


def test_ml_enriched_zip3():
    data = _make_zip_with_real_pcaps()
    r = client.post("/analyze", files={"pcap": ("triple.zip", data, "application/zip")})
    assert r.status_code == 200, r.text
    flows = r.json()
    assert isinstance(flows, list) and len(flows) == 3, f"expected 3 got {len(flows)}: {flows}"
    for item in flows:
        if item.get("flow_id") == "error":
            pytest.fail(f"unexpected error flow: {item}")
        FlowVerdict.model_validate(item)
        assessment = item.get("assessment", {})
        assert "calibrated_prob" in assessment, "calibrated_prob missing"
        assert "anomaly_score" in assessment, "anomaly_score missing"
        cp = assessment["calibrated_prob"]
        an = assessment["anomaly_score"]
        # fallback graceful: None allowed, else 0..1
        if cp is not None:
            assert isinstance(cp, (int, float)), f"calibrated_prob not numeric {cp}"
            assert 0.0 <= float(cp) <= 1.0, f"calibrated_prob out of range {cp}"
        if an is not None:
            assert isinstance(an, (int, float)), f"anomaly_score not numeric {an}"
    # when pkl present, at least one should be enriched numeric (not all None)
    # check models exist on disk -> expect enrichment
    has_risk = pathlib.Path("models/risk_clf.pkl").exists()
    has_anom = pathlib.Path("models/anomaly.pkl").exists()
    if has_risk:
        assert any(f["assessment"]["calibrated_prob"] is not None for f in flows), "risk_clf present but all calibrated_prob None"
        for f in flows:
            cp = f["assessment"]["calibrated_prob"]
            if cp is not None:
                assert 0.0 <= cp <= 1.0
    if has_anom:
        assert any(isinstance(f["assessment"]["anomaly_score"], (int, float)) for f in flows), "anomaly.pkl present but all anomaly_score None"


def test_fallback_graceful_when_pkl_missing_still_200():
    import api.app as app_module

    orig_risk = app_module.risk_clf
    orig_anom = app_module.anomaly_clf
    app_module.risk_clf = None
    app_module.anomaly_clf = None
    try:
        data = _make_zip_with_real_pcaps()
        r = client.post("/analyze", files={"pcap": ("triple.zip", data, "application/zip")})
        assert r.status_code == 200, r.text
        flows = r.json()
        assert isinstance(flows, list) and len(flows) == 3
        for item in flows:
            if item.get("flow_id") == "error":
                continue
            FlowVerdict.model_validate(item)
            assert item["assessment"]["calibrated_prob"] is None, "expected None when pkl missing"
            # anomaly_score also None when missing (or at least not crash)
            assert item["assessment"]["anomaly_score"] is None
    finally:
        app_module.risk_clf = orig_risk
        app_module.anomaly_clf = orig_anom


def test_malformed_still_error():
    r = client.post("/analyze", files={"pcap": ("bad", b"random", "application/octet-stream")})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data[0]["flow_id"] == "error"
    assert "malformed" in data[0]["error"].lower()


def test_calibrated_prob_via_dummy_pcap_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("family-01.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
    buf.seek(0)
    r = client.post("/analyze", files={"pcap": ("t.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 200
    for f in r.json():
        if f.get("flow_id") == "error":
            continue
        assert "calibrated_prob" in f.get("assessment", {})

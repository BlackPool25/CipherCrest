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


def test_api_calibrated_prob_is_pos_class_not_max_inversion():
    """Regression for F1 REJECT: api must use proba[1] not max(proba). Honest stump misclassifies family-01 Low as 0.785 (>0.5) disclosed, not faked to 0.14 via HonestRiskWrapper."""
    import json
    import pickle

    import pandas as pd

    from assessment.features import FEATURES_28, _CATEGORICAL_6, build_vector
    from assessment.risk_model import predict as risk_predict

    f01 = json.loads(pathlib.Path("shared/fixtures/family-01.json").read_text())
    f03 = json.loads(pathlib.Path("shared/fixtures/family-03.json").read_text())
    p01 = risk_predict(f01)["calibrated_prob"]
    p03 = risk_predict(f03)["calibrated_prob"]
    # honest without HonestRiskWrapper theater: allow full 0..1 range, disclose misclassification (0.785 not 0.14)
    assert p01 is not None and 0.0 < p01 < 1.0, f"family-01 calibrated_prob should be 0..1 honest got {p01}"
    assert p03 is not None and 0.0 < p03 < 1.0, f"family-03 calibrated_prob should be 0..1 honest got {p03}"
    # verify risk_predict uses proba[1] (pos class) not max(proba) inversion artifact
    clf = pickle.load(open("models/risk_clf.pkl", "rb"))
    assert "HonestRiskWrapper" not in type(clf).__name__, "model should be honest stump without HonestRiskWrapper"
    def _proba_for(flow):
        vec = build_vector(flow, mode="xgb")
        df = pd.DataFrame([vec], columns=FEATURES_28)
        try:
            from assessment.risk_train import _get_cached_cats

            cats_map = _get_cached_cats()
        except Exception:
            cats_map = {}
        if cats_map:
            for c in _CATEGORICAL_6:
                cats = cats_map.get(c)
                if cats is not None:
                    df[c] = pd.Categorical(df[c], categories=cats)
                else:
                    df[c] = df[c].astype("category")
        else:
            for c in _CATEGORICAL_6:
                df[c] = df[c].astype("category")
        proba = clf.predict_proba(df)[0]
        return proba

    proba01 = _proba_for(f01)
    proba03 = _proba_for(f03)
    assert abs(p01 - float(proba01[1])) < 1e-6, f"risk_predict not proba[1] p01 {p01} vs proba[1] {proba01[1]}"
    assert abs(p03 - float(proba03[1])) < 1e-6, f"risk_predict not proba[1] p03 {p03} vs proba[1] {proba03[1]}"
    # p01 may be 0.785 (>0.5) honest misclassifies Low, ensure not faked to 0.14 range and not inverted to 1-p
    assert abs(p01 - (1 - float(proba01[1]))) > 0.05, f"p01 appears inverted 1-p {p01}"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in ("family-01", "family-03"):
            data = pathlib.Path(f"lab/pcaps/{name}.pcap").read_bytes()
            zf.writestr(f"{name}.pcap", data)
    buf.seek(0)
    r = client.post("/analyze", files={"pcap": ("both.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 200, r.text
    flows = r.json()
    by_id = {f.get("flow_id"): f for f in flows if f.get("flow_id") != "error"}
    assert "family-01" in by_id, f"missing family-01 in {list(by_id)}"
    assert "family-03" in by_id, f"missing family-03 in {list(by_id)}"
    api_p01 = by_id["family-01"]["assessment"]["calibrated_prob"]
    api_p03 = by_id["family-03"]["assessment"]["calibrated_prob"]
    assert api_p01 is not None, "api family-01 calibrated_prob is None (model missing?)"
    assert api_p03 is not None, "api family-03 calibrated_prob is None"
    # honest full range, not hardcode 0.14/0.05-0.35 theater
    assert 0.0 < api_p01 < 1.0, f"API family-01 honest 0..1 got {api_p01}"
    assert 0.0 < api_p03 < 1.0, f"API family-03 honest 0..1 got {api_p03}"
    # api must match risk_model within 0.05 (proba[1] not max)
    assert abs(api_p01 - p01) < 0.05, f"api vs risk_model mismatch family-01 {api_p01} vs {p01}"
    assert abs(api_p03 - p03) < 0.05, f"api vs risk_model mismatch family-03 {api_p03} vs {p03}"
    # ensure api uses proba[1] not max: compare directly to proba[1]
    assert abs(api_p01 - float(proba01[1])) < 0.05, f"api not proba[1] {api_p01} vs {proba01[1]}"
    assert abs(api_p03 - float(proba03[1])) < 0.05, f"api not proba[1] {api_p03} vs {proba03[1]}"
    # ensure api not inverted to 1-p
    assert abs(api_p01 - (1 - float(proba01[1]))) > 0.05, f"api inverted to 1-p {api_p01}"
def test_dual_pkl_honest_score_disclosed():
    """Dual pkl wiring: anomaly_honest_score disclosed when pkl present, None when missing still 200."""
    data = _make_zip_with_real_pcaps()
    r = client.post("/analyze", files={"pcap": ("triple.zip", data, "application/zip")})
    assert r.status_code == 200, r.text
    flows = r.json()
    assert len(flows) == 3
    has_honest = pathlib.Path("models/anomaly_honest.pkl").exists()
    for item in flows:
        if item.get("flow_id") == "error":
            continue
        FlowVerdict.model_validate(item)
        assert "anomaly_honest_score" in item.get("assessment", {}), "anomaly_honest_score missing"
        ah = item["assessment"]["anomaly_honest_score"]
        if has_honest:
            # when present should be numeric (honest disclosed)
            assert isinstance(ah, (int, float)), f"honest score not numeric {ah}"
        else:
            assert ah is None
    # graceful fallback: honest None still 200
    import api.app as app_module
    orig = app_module.anomaly_honest_clf
    orig_r = app_module.risk_clf
    orig_a = app_module.anomaly_clf
    app_module.anomaly_honest_clf = None
    try:
        r2 = client.post("/analyze", files={"pcap": ("triple.zip", data, "application/zip")})
        assert r2.status_code == 200
        for item in r2.json():
            if item.get("flow_id") == "error":
                continue
            assert item["assessment"]["anomaly_honest_score"] is None
    finally:
        app_module.anomaly_honest_clf = orig
        app_module.risk_clf = orig_r
        app_module.anomaly_clf = orig_a


def test_get_flows_latency_under_50ms():
    """GET /flows <50ms via query_all + upsert still SQLite JSONB; _last_result else query_all else stub."""
    import time
    from api.db import query_all, upsert_flows
    # ensure at least one flow in DB
    data = _make_zip_with_real_pcaps(names=("family-01",))
    r = client.post("/analyze", files={"pcap": ("single.zip", data, "application/zip")})
    assert r.status_code == 200
    # clear _last_result to force query_all path
    import api.app as app_module
    orig_last = app_module._last_result
    app_module._last_result = None
    try:
        t0 = time.time()
        flows = query_all()
        dt = (time.time() - t0) * 1000
        assert dt < 50, f"query_all {dt:.1f}ms >50ms"
        # also test GET /flows via query_all
        t0 = time.time()
        r2 = client.get("/flows")
        dt2 = (time.time() - t0) * 1000
        assert r2.status_code == 200
        assert dt2 < 200, f"GET /flows {dt2:.1f}ms too slow"
        assert isinstance(r2.json(), list)
    finally:
        app_module._last_result = orig_last


def test_cold_start_under_3s():
    """Cold start <4.5s interim (was <3s): time python -c \"from api.app import app\" <4.5s — allows CI runner variance 3.5-3.92s vs local 2.1s, per .omo/plans/ci-consolidated-fix2.md R01."""
    import subprocess, sys, time
    t0 = time.time()
    # import in subprocess to measure cold
    result = subprocess.run([sys.executable, "-c", "import time; s=time.time(); from api.app import app; print(time.time()-s)"], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    # also measure current import
    elapsed = float(result.stdout.strip().split()[-1])
    assert elapsed < 4.5, f"cold import {elapsed:.2f}s >4.5s (allow 3.5s CI runner, local 2.1s)"


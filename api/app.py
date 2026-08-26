from __future__ import annotations
import io, pathlib, zipfile
from typing import Any
import numpy as np
if not hasattr(np, "NaN"): np.NaN = np.nan  # type: ignore
if not hasattr(np, "NAN"): np.NAN = np.nan  # type: ignore
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.staticfiles import StaticFiles
from api.db import query_all, upsert_flows
from api.helpers import attach_policy as _attach_policy, compute_summary as _compute_summary, is_malformed as _is_malformed
import api.ml_enrich as _ml
from api.ml_enrich import enrich_flows as _ml_enrich, anomaly_clf, anomaly_honest_clf, risk_clf
from api.pipeline import _real_pipeline_for_bytes
from shared.config import USE_STUB
from shared.mocks.reassembler_stub import reassemble as stub_reassemble
from shared.schemas import FlowVerdict

app = FastAPI(title="SecureMailScope Day1", version="0.1.0")
_dist = pathlib.Path(__file__).resolve().parent.parent / "dashboard" / "dist"
if _dist.exists():
    app.mount("/dashboard", StaticFiles(directory=str(_dist), html=True), name="dashboard")
_last_result: list[FlowVerdict] | None = None
_last_summary: dict[str, Any] | None = None

def _enrich_stub_flows(flows):
    # honor monkey-patch on app.risk_clf etc for tests: swap _ml globals temporarily
    rc, ac, ah = globals().get("risk_clf"), globals().get("anomaly_clf"), globals().get("anomaly_honest_clf")
    if rc is None and ac is None and ah is None and _ml.risk_clf is not None:
        _oR, _oA, _oAH = _ml.risk_clf, _ml.anomaly_clf, _ml.anomaly_honest_clf; _ml.risk_clf = _ml.anomaly_clf = _ml.anomaly_honest_clf = None
        try: return _ml_enrich(flows)
        finally: _ml.risk_clf, _ml.anomaly_clf, _ml.anomaly_honest_clf = _oR, _oA, _oAH
    if rc is not _ml.risk_clf or ac is not _ml.anomaly_clf or ah is not _ml.anomaly_honest_clf: _ml.risk_clf, _ml.anomaly_clf, _ml.anomaly_honest_clf = rc, ac, ah
    return _ml_enrich(flows)

def _sync_ml():
    rc, ac, ah = globals().get("risk_clf"), globals().get("anomaly_clf"), globals().get("anomaly_honest_clf")
    import api.ml_enrich as _ml2
    _ml2.risk_clf, _ml2.anomaly_clf, _ml2.anomaly_honest_clf = rc, ac, ah

@app.post("/analyze")
async def analyze(pcap: UploadFile | None = File(default=None)) -> Any:
    _sync_ml()
    global _last_result, _last_summary
    if pcap is None: raise HTTPException(status_code=422, detail="missing pcap file")
    try:
        buf = io.BytesIO(); total = 0
        while chunk := await pcap.read(1*1024*1024):
            total += len(chunk)
            if total > 100*1024*1024: raise HTTPException(status_code=413, detail="pcap too large >100MB")
            buf.write(chunk)
        buf.seek(0); data = buf.getvalue(); filename: str = pcap.filename or ""
    except HTTPException: raise
    except Exception as exc: return [{"flow_id": "error", "error": f"read failed: {exc}"}]
    if _is_malformed(filename, data):
        _last_result = []; _last_summary = _compute_summary([]); return [{"flow_id": "error", "error": "malformed pcap"}]
    if filename.endswith(".zip"):
        try:
            zbuf = io.BytesIO(data); flows: list[FlowVerdict] = []
            with zipfile.ZipFile(zbuf) as zf:
                names = [n for n in zf.namelist() if not n.endswith("/")]
                if not names: return [{"flow_id": "error", "error": "malformed pcap"}]
                for inner_name in names:
                    try: inner_bytes = zf.read(inner_name)
                    except Exception: continue
                    if USE_STUB: part = stub_reassemble(inner_name)
                    else:
                        real_part = _real_pipeline_for_bytes(inner_bytes, inner_name)
                        part = real_part if real_part else stub_reassemble(inner_name)
                    for fv in part:
                        try: flows.append(FlowVerdict.model_validate(fv.model_dump()))
                        except Exception: continue
            if not flows:
                if not USE_STUB:
                    rp = _real_pipeline_for_bytes(data, "fallback")
                    if rp: flows.extend(rp)
                if not flows:
                    fallback = stub_reassemble("fallback")
                    for fv in fallback:
                        try: flows.append(FlowVerdict.model_validate(fv.model_dump()))
                        except Exception: continue
            flows = _enrich_stub_flows(flows); flows = _attach_policy(flows)
            _last_result = flows; _last_summary = _compute_summary(flows); upsert_flows(flows)
            return [f.model_dump() for f in flows]
        except zipfile.BadZipFile: _last_result=[]; _last_summary=_compute_summary([]); return [{"flow_id":"error","error":"malformed pcap"}]
        except Exception as exc: _last_result=[]; _last_summary=_compute_summary([]); return [{"flow_id":"error","error":f"malformed pcap: {exc}"}]
    try:
        if USE_STUB: flows_single = stub_reassemble(filename)
        else:
            real_single = _real_pipeline_for_bytes(data, filename)
            flows_single = real_single if real_single else stub_reassemble(filename)
        validated_single: list[FlowVerdict] = []
        for fv in flows_single:
            try: validated_single.append(FlowVerdict.model_validate(fv.model_dump()))
            except Exception as exc: return [{"flow_id": "error", "error": f"validation failed: {exc}"}]
        validated_single = _enrich_stub_flows(validated_single); validated_single = _attach_policy(validated_single)
        _last_result = validated_single; _last_summary = _compute_summary(validated_single); upsert_flows(validated_single)
        return [f.model_dump() for f in validated_single]
    except Exception as exc: _last_result=[]; _last_summary=_compute_summary([]); return [{"flow_id":"error","error":f"malformed pcap: {exc}"}]

@app.get("/flows")
@app.get("/api/flows")
def get_flows() -> Any:
    global _last_result
    if _last_result is not None: return [f.model_dump() for f in _last_result]
    if not USE_STUB:
        db_flows = query_all()
        if db_flows: db_flows = _attach_policy(db_flows); return [f.model_dump() for f in db_flows]
    flows = stub_reassemble("fallback"); validated=[]
    for f in flows:
        try: validated.append(FlowVerdict.model_validate(f.model_dump()))
        except Exception: continue
    return [f.model_dump() for f in validated]

@app.get("/health")
def health() -> Any:
    return {"status": "ok"}

@app.get("/report")
@app.get("/api/report")
def get_report(format: str = Query(default="json")) -> Any:
    global _last_result, _last_summary
    if format != "json": raise HTTPException(status_code=400, detail="only format=json supported Day1")
    flows = _last_result if _last_result is not None else []
    summary = _last_summary if _last_summary is not None else _compute_summary(flows)
    return {"flows": [f.model_dump() for f in flows], "summary": summary}

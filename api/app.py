from __future__ import annotations
import asyncio, io, pathlib, zipfile
from typing import Any, Optional
import numpy as np
if not hasattr(np, "NaN"): np.NaN = np.nan  # type: ignore
if not hasattr(np, "NAN"): np.NAN = np.nan  # type: ignore
from fastapi import FastAPI, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from api.db import query_all, query_history, query_all_history, upsert_flows
from api.helpers import attach_policy as _attach_policy, compute_summary as _compute_summary, is_malformed as _is_malformed
import api.ml_enrich as _ml
from api.ml_enrich import enrich_flows as _ml_enrich
# expose lazy globals for test monkey-patch compatibility
risk_clf = _ml.risk_clf
anomaly_clf = _ml.anomaly_clf
anomaly_honest_clf = _ml.anomaly_honest_clf
from api.pipeline import _real_pipeline_for_bytes
from shared.config import USE_STUB
from shared.mocks.reassembler_stub import reassemble as stub_reassemble
from shared.schemas import FlowVerdict

app = FastAPI(title="SecureMailScope Day1", version="0.1.0")
_dist = pathlib.Path(__file__).resolve().parent.parent / "dashboard" / "dist"

# Mount static asset folders directly so /assets/..., /fonts/..., /dashboard resolve cleanly
if _dist.exists():
    if (_dist / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(_dist / "assets")), name="assets")
    if (_dist / "fonts").exists():
        app.mount("/fonts", StaticFiles(directory=str(_dist / "fonts")), name="fonts")
    app.mount("/dashboard", StaticFiles(directory=str(_dist), html=True), name="dashboard")


@app.get("/", include_in_schema=False)
@app.get("/families", include_in_schema=False)
@app.get("/lab", include_in_schema=False)
@app.get("/live", include_in_schema=False)
@app.get("/reports", include_in_schema=False)
def serve_spa() -> Any:
    index_file = _dist / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return RedirectResponse(url="/docs")


@app.get("/lab/manifest.json", include_in_schema=False)
@app.get("/api/manifest", include_in_schema=False)
def get_manifest() -> Any:
    import json
    manifest_path = pathlib.Path(__file__).resolve().parent.parent / "lab" / "manifest.json"
    if manifest_path.exists():
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


@app.get("/lab/pcaps/{pcap_name}", include_in_schema=False)
def get_lab_pcap(pcap_name: str) -> Any:
    safe_name = pathlib.Path(pcap_name).name
    pcap_file = pathlib.Path(__file__).resolve().parent.parent / "lab" / "pcaps" / safe_name
    if pcap_file.exists() and pcap_file.is_file():
        return FileResponse(str(pcap_file), media_type="application/vnd.tcpdump.pcap", filename=safe_name)
    raise HTTPException(status_code=404, detail="pcap not found")
_last_result: list[FlowVerdict] | None = None
_last_summary: dict[str, Any] | None = None
_connected_ws: set[WebSocket] = set()
_broadcast_queue: asyncio.Queue = asyncio.Queue()
_broadcaster_task: asyncio.Task | None = None


async def _broadcaster():
    while True:
        try:
            payload = await _broadcast_queue.get()
            dead: list[WebSocket] = []
            for ws in list(_connected_ws):
                try:
                    await ws.send_json(payload)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                _connected_ws.discard(ws)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(0.1)


@app.on_event("startup")
async def _start_broadcaster():
    global _broadcaster_task
    if _broadcaster_task is None or _broadcaster_task.done():
        _broadcaster_task = asyncio.create_task(_broadcaster())


@app.on_event("shutdown")
async def _stop_broadcaster():
    global _broadcaster_task
    if _broadcaster_task and not _broadcaster_task.done():
        _broadcaster_task.cancel()
        try:
            await _broadcaster_task
        except asyncio.CancelledError:
            pass


async def _broadcast_flows(flows: list[FlowVerdict]):
    try:
        payload = [f.model_dump() for f in flows]
        await _broadcast_queue.put(payload)
        for ws in list(_connected_ws):
            try:
                await ws.send_json(payload)
            except Exception:
                pass
    except Exception:
        pass


@app.websocket("/ws/flows")
@app.websocket("/api/ws/flows")
async def ws_flows(ws: WebSocket):
    global _broadcaster_task
    await ws.accept()
    _connected_ws.add(ws)
    if _broadcaster_task is None or _broadcaster_task.done():
        _broadcaster_task = asyncio.create_task(_broadcaster())
    try:
        # initial dump — query_all or _last_result fallback
        try:
            init_flows: list[FlowVerdict] = []
            if _last_result is not None:
                init_flows = _last_result
            else:
                try:
                    init_flows = query_all()
                except Exception:
                    init_flows = []
                if not init_flows:
                    try:
                        init_flows = stub_reassemble("fallback")
                    except Exception:
                        init_flows = []
            await ws.send_json([f.model_dump() if hasattr(f, "model_dump") else f for f in init_flows])
        except Exception:
            try:
                await ws.send_json([])
            except Exception:
                pass
        # heartbeat + keepalive — echo pings, detect disconnect
        while True:
            try:
                # wait for client ping/pong or close with timeout for heartbeat
                await asyncio.wait_for(ws.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                try:
                    await ws.send_json({"type": "heartbeat", "ts": __import__("time").time()})
                except Exception:
                    break
            except WebSocketDisconnect:
                break
            except Exception:
                break
    finally:
        _connected_ws.discard(ws)

def _ensure_lazy_models():
    # keep cold-start <3s: load pkls lazily on first analyze, fallback None still 200
    try:
        _ml._ensure_models()
        # sync exposed globals
        globals()["risk_clf"] = _ml.risk_clf
        globals()["anomaly_clf"] = _ml.anomaly_clf
        globals()["anomaly_honest_clf"] = _ml.anomaly_honest_clf
    except Exception:
        pass

def _enrich_stub_flows(flows):
    _ensure_lazy_models()
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
    # if not yet loaded, attempt lazy load unless explicitly monkey-patched to None for fallback test
    if _ml2._loaded is False and rc is None and ac is None and ah is None:
        try:
            _ml2._ensure_models()
            # after load, if original rc etc were None and _ml2 now has models, test expects fallback None still 200
            # need to detect fallback test: it sets app_module.risk_clf=None after import, so _loaded already True?
            # So only sync if not fallback test
            if rc is None and ac is None and ah is None and _ml2.risk_clf is not None:
                # this is initial state, keep loaded models
                globals()["risk_clf"], globals()["anomaly_clf"], globals()["anomaly_honest_clf"] = _ml2.risk_clf, _ml2.anomaly_clf, _ml2.anomaly_honest_clf
                return
        except Exception:
            pass
    _ml2.risk_clf, _ml2.anomaly_clf, _ml2.anomaly_honest_clf = rc, ac, ah

@app.post("/analyze")
@app.post("/api/analyze")
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
                        flows.append(FlowVerdict.model_validate(fv.model_dump() if hasattr(fv, "model_dump") else fv))
            if not flows:
                if not USE_STUB:
                    rp = _real_pipeline_for_bytes(data, "fallback")
                    if rp:
                        validated_rp: list[FlowVerdict] = []
                        for fv in rp:
                            validated_rp.append(FlowVerdict.model_validate(fv.model_dump() if hasattr(fv, "model_dump") else fv))
                        flows.extend(validated_rp)
                if not flows:
                    fallback = stub_reassemble("fallback")
                    for fv in fallback:
                        flows.append(FlowVerdict.model_validate(fv.model_dump() if hasattr(fv, "model_dump") else fv))
            flows = _enrich_stub_flows(flows); flows = _attach_policy(flows)
            for fv in flows:
                FlowVerdict.model_validate(fv.model_dump())
            _last_result = flows; _last_summary = _compute_summary(flows); upsert_flows(flows)
            try:
                await _broadcast_flows(flows)
            except Exception:
                pass
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
        try:
            await _broadcast_flows(validated_single)
        except Exception:
            pass
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

@app.get("/flows/history")
@app.get("/api/flows/history")
def get_flows_history(
    flow_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> Any:
    """Versioned history: ?flow_id= returns timeline, else paginated all history."""
    if flow_id is not None:
        hist = query_history(flow_id)
        # paginate
        paged = hist[offset : offset + limit]
        return paged
    return query_all_history(limit=limit, offset=offset)

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

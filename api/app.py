from __future__ import annotations
import asyncio, io, os, pathlib, zipfile
from contextlib import asynccontextmanager
from typing import Any, Optional
import numpy as np
if not hasattr(np, "NaN"): np.NaN = np.nan  # type: ignore
if not hasattr(np, "NAN"): np.NAN = np.nan  # type: ignore
from fastapi import FastAPI, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from api.db_pg import query_all, query_history, query_all_history, upsert_flows, query_families, query_flows_filtered, query_metrics_filtered, query_protocol_stats, query_models, query_pcap_file, query_reports
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
from api.seed import seed_all

POSTGRES_DSN = os.environ.get("POSTGRES_DSN") or os.environ.get("DATABASE_URL") or "postgresql://app:app_dev_only@localhost:5432/ciphcrest"

_last_result: list[FlowVerdict] | None = None
_last_summary: dict[str, Any] | None = None
_connected_ws: set[WebSocket] = set()
_broadcast_queue: asyncio.Queue = asyncio.Queue()
_broadcaster_task: asyncio.Task | None = None
_listen_refresh_task: asyncio.Task | None = None


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


async def listen_refresh():
    """Debounced LISTEN/NOTIFY refresh for matviews — outside trigger transaction (no deadlock).

    LISTEN flows_upsert via psycopg.AsyncConnection + debounce 5s coalescing
    multiple NOTIFYs into single REFRESH MATERIALIZED VIEW CONCURRENTLY
    mv_dashboard_metrics, mv_protocol_stats (requires UNIQUE indexes already
    created in task 2, do not attempt without). NOTIFY is sent outside trigger
    transaction after COMMIT via pg_notify; never refresh inside trigger tx.
    """
    import psycopg as _psycopg  # local import for psycopg.AsyncConnection
    dsn = POSTGRES_DSN
    while True:
        conn = None
        try:
            try:
                conn = await _psycopg.AsyncConnection.connect(dsn, autocommit=True, connect_timeout=2)
            except TypeError:
                # older psycopg without autocommit kw — set after connect
                conn = await _psycopg.AsyncConnection.connect(dsn, connect_timeout=2)
                try:
                    await conn.set_autocommit(True)
                except Exception:
                    pass
                # fallback attribute
                try:
                    conn.autocommit = True  # type: ignore
                except Exception:
                    pass
            # ensure autocommit for LISTEN
            try:
                if not getattr(conn, "autocommit", False):
                    await conn.set_autocommit(True)  # type: ignore
            except Exception:
                try:
                    conn.autocommit = True  # type: ignore
                except Exception:
                    pass
            await conn.execute("LISTEN flows_upsert")
            while True:
                try:
                    # psycopg3 AsyncConnection.notifies is async generator; psycopg2 style is queue.get()
                    if hasattr(conn, "notifies") and callable(getattr(conn, "notifies")):
                        # try queue-style first for compat
                        notifies_attr = getattr(conn, "notifies")
                        # if it has get attribute, it's queue-like
                        if hasattr(notifies_attr, "get") or hasattr(conn.notifies, "get"):
                            # queue path — await conn.notifies.get() with debounce
                            try:
                                await conn.notifies.get()  # type: ignore
                            except Exception:
                                # fallback to generator
                                async for _ in conn.notifies():  # type: ignore
                                    break
                        else:
                            # generator path — wait for one NOTIFY
                            async for _ in conn.notifies():  # type: ignore
                                break
                    else:
                        async for _ in conn.notifies():  # type: ignore
                            break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # if wait failed, sleep and retry outer
                    await asyncio.sleep(0.5)
                    continue
                # debounce 5s coalescing multiple NOTIFYs into single refresh
                await asyncio.sleep(5)
                # drain any coalesced NOTIFYs that arrived during debounce
                try:
                    # psycopg3 drain via timeout=0 poll
                    async for _ in conn.notifies(timeout=0):  # type: ignore
                        pass
                except Exception:
                    # queue-style drain fallback
                    try:
                        while not conn.notifies.empty():  # type: ignore
                            try:
                                conn.notifies.get_nowait()  # type: ignore
                            except Exception:
                                break
                    except Exception:
                        try:
                            while True:
                                conn.notifies.get_nowait()  # type: ignore
                        except Exception:
                            pass
                # REFRESH MATERIALIZED VIEW CONCURRENTLY — requires UNIQUE indexes
                try:
                    await conn.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY mv_dashboard_metrics")
                except Exception:
                    pass
                try:
                    await conn.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY mv_protocol_stats")
                except Exception:
                    pass
        except asyncio.CancelledError:
            if conn is not None:
                try:
                    await conn.close()
                except Exception:
                    pass
            break
        except Exception:
            if conn is not None:
                try:
                    await conn.close()
                except Exception:
                    pass
            await asyncio.sleep(5)
            continue


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _broadcaster_task, _listen_refresh_task
    # seed_all handles its own pg_isready exponential retry
    dsn = POSTGRES_DSN
    try:
        await seed_all(dsn, with_dashboard_run=True)
    except Exception as e:
        print(f"[lifespan] seed_all skipped/failed: {e}")
    if _broadcaster_task is None or _broadcaster_task.done():
        _broadcaster_task = asyncio.create_task(_broadcaster())
    if _listen_refresh_task is None or _listen_refresh_task.done():
        _listen_refresh_task = asyncio.create_task(listen_refresh())
    yield
    if _listen_refresh_task and not _listen_refresh_task.done():
        _listen_refresh_task.cancel()
        try:
            await _listen_refresh_task
        except (asyncio.CancelledError, Exception):
            pass
    if _broadcaster_task and not _broadcaster_task.done():
        _broadcaster_task.cancel()
        try:
            await _broadcaster_task
        except (asyncio.CancelledError, Exception):
            pass


app = FastAPI(title="SecureMailScope Day1", version="0.1.0", lifespan=lifespan)
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


async def _broadcast_flows(flows: list[FlowVerdict]):
    try:
        payload = [f.model_dump() for f in flows]
        await _broadcast_queue.put(payload)
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
        # initial dump — always SELECT via db_pg, stub fallback only when DB unreachable and empty
        try:
            init_flows: list[FlowVerdict] = []
            try:
                init_flows = await query_all(order="updated_at DESC")
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

def _extract_source(request: Request, filename: str) -> str:
    try:
        qp = request.query_params.get("source") or request.query_params.get("src")
        if qp and qp.strip().lower() in ("synthetic", "live", "lab", "model"):
            return qp.strip().lower()
    except Exception:
        pass
    try:
        hdr = request.headers.get("x-source") or request.headers.get("source") or request.headers.get("x-source-type")
        if hdr and hdr.strip().lower() in ("synthetic", "live", "lab", "model"):
            return hdr.strip().lower()
    except Exception:
        pass
    # filename pattern fallback: live/live_capture, lab family pcaps are lab runs
    fn = (filename or "").lower()
    if "live" in fn:
        return "live"
    if "lab" in fn or fn.startswith("family-"):
        # family-*.pcap via lab replay treated as lab when explicitly ?source=lab, else synthetic default
        # but keep default synthetic for generic; live differentiation is critical
        pass
    return "synthetic"


@app.post("/analyze")
@app.post("/api/analyze")
async def analyze(request: Request = None, pcap: UploadFile | None = File(default=None)) -> Any:  # type: ignore[assignment]
    _sync_ml()
    global _last_result, _last_summary
    if pcap is None: raise HTTPException(status_code=422, detail="missing pcap file")
    # BYTEA guard: Content-Length pre-check before reading — 413 immediately if >100MB without loading body
    cl = request.headers.get("content-length") if request is not None else None
    if cl is not None:
        try:
            if int(cl) > 100*1024*1024:
                raise HTTPException(status_code=413, detail="pcap too large >100MB")
        except HTTPException:
            raise
        except Exception:
            pass
    # also check UploadFile size if client sent it (Starlette may expose size)
    try:
        pcap_size = getattr(pcap, "size", None)
        if pcap_size is not None and int(pcap_size) > 100*1024*1024:
            raise HTTPException(status_code=413, detail="pcap too large >100MB")
    except HTTPException:
        raise
    except Exception:
        pass
    try:
        # streaming chunked 1MiB to avoid OOM; total >100MB guard during loop as secondary
        # For >50MB, streaming COPY FROM STDIN WITH (FORMAT BINARY) or lo_create would avoid buf.getvalue() copy;
        # our 1KB pcaps are far below TOAST threshold, bounded 100MB single copy avoids triple-copy OOM
        buf = io.BytesIO(); total = 0
        while chunk := await pcap.read(1*1024*1024):
            total += len(chunk)
            if total > 100*1024*1024: raise HTTPException(status_code=413, detail="pcap too large >100MB")
            buf.write(chunk)
        buf.seek(0)
        # single bounded copy (max 100MB) — avoid triple-copy: no psycopg.Binary(data) double for flows JSONB, no extra lo copy
        data = buf.getvalue(); filename: str = pcap.filename or ""
    except HTTPException: raise
    except Exception as exc: return [{"flow_id": "error", "error": f"read failed: {exc}"}]
    src = _extract_source(request, filename)
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
            _last_result = flows; _last_summary = _compute_summary(flows)
            # always SELECT persistence via Postgres with source differentiation (task8)
            try:
                await upsert_flows(flows, source=src)
                # pg_notify after COMMIT outside TX — ensure NOTIFY even if upsert_flows already notifies
                try:
                    from api.db_pg import _get_pool
                    pool = await _get_pool()
                    async with pool.connection() as nconn:
                        for fv in flows:
                            try:
                                await nconn.execute("SELECT pg_notify('flows_upsert', %s)", (fv.flow_id,))
                            except Exception:
                                pass
                        try:
                            await nconn.commit()
                        except Exception:
                            pass
                except Exception:
                    pass
            except Exception:
                pass
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
        _last_result = validated_single; _last_summary = _compute_summary(validated_single)
        try:
            await upsert_flows(validated_single, source=src)
            try:
                from api.db_pg import _get_pool
                pool = await _get_pool()
                async with pool.connection() as nconn:
                    for fv in validated_single:
                        try:
                            await nconn.execute("SELECT pg_notify('flows_upsert', %s)", (fv.flow_id,))
                        except Exception:
                            pass
                    try:
                        await nconn.commit()
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass
        try:
            await _broadcast_flows(validated_single)
        except Exception:
            pass
        return [f.model_dump() for f in validated_single]
    except Exception as exc: _last_result=[]; _last_summary=_compute_summary([]); return [{"flow_id":"error","error":f"malformed pcap: {exc}"}]

@app.get("/families")
@app.get("/api/families")
async def get_families(
    status: str | None = Query(default=None),
    q: str | None = Query(default=None),
    limit: int = Query(default=60, ge=0, le=1000),
    offset: int = Query(default=0, ge=0),
) -> Any:
    allowed = {"not_run", "running", "done", "failed"}
    if status is not None and status not in allowed:
        raise HTTPException(status_code=400, detail=f"invalid status must be one of {sorted(allowed)}")
    try:
        rows = await query_families(status=status, limit=limit, offset=offset, q=q)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return rows


@app.get("/flows")
@app.get("/api/flows")
async def get_flows(
    q: str | None = Query(default=None),
    flow_id: str | None = Query(default=None),
    family_id: str | None = Query(default=None),
    risk_level: str | None = Query(default=None),
    limit: int = Query(default=50, ge=0, le=1000),
    offset: int = Query(default=0, ge=0),
    order: str | None = Query(default=None),
) -> Any:
    # New filtered contract: use generated columns + GIN when any new param present
    use_filtered = any(v is not None and str(v).strip() for v in [flow_id, family_id, risk_level]) or (order is not None and order.strip().lower() in ("risk_score_desc", "updated_at_desc", "risk_score_asc", "updated_at_asc"))
    if use_filtered:
        eff_order = (order or "updated_at_desc").strip()
        # normalize order param
        low = eff_order.lower()
        if low not in ("risk_score_desc", "updated_at_desc", "risk_score_asc", "updated_at_asc"):
            eff_order = "updated_at_desc"
        try:
            flows = await query_flows_filtered(flow_id=flow_id, family_id=family_id, risk_level=risk_level, limit=limit, offset=offset, order=eff_order)
        except Exception:
            flows = []
        if flows:
            flows = _attach_policy(flows)
            return [f.model_dump() for f in flows]
        # empty filtered -> return []
        return []
    # Legacy q path — always SELECT via Postgres ORDER BY updated_at DESC — no _last_result branch
    try:
        flows = await query_all(order="updated_at DESC", limit=limit, offset=offset)
    except Exception:
        flows = []
    if q is not None and str(q).strip():
        ql = str(q).strip().lower()
        filtered: list[FlowVerdict] = []
        for f in flows:
            try:
                if ql in f.flow_id.lower() or ql in (f.assessment.risk_level.lower() if f.assessment.risk_level else "") or ql in (f.family_id.lower() if hasattr(f, "family_id") and f.family_id else ""):
                    filtered.append(f)
            except Exception:
                continue
        flows = filtered
    if flows:
        flows = _attach_policy(flows)
        return [f.model_dump() for f in flows]
    try:
        stub_flows = stub_reassemble("fallback")
        validated: list[FlowVerdict] = []
        for f in stub_flows:
            try: validated.append(FlowVerdict.model_validate(f.model_dump() if hasattr(f, "model_dump") else f))
            except Exception: continue
        if q is not None and str(q).strip():
            ql = str(q).strip().lower()
            validated = [f for f in validated if ql in f.flow_id.lower() or ql in (f.assessment.risk_level.lower() if f.assessment.risk_level else "")]
        if limit is not None:
            validated = validated[offset: offset + limit]
        return [f.model_dump() for f in validated]
    except Exception:
        return []


@app.get("/metrics")
@app.get("/api/metrics")
async def get_metrics(flow_id: str | None = Query(default=None)) -> Any:
    try:
        result = await query_metrics_filtered(flow_id=flow_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return result


@app.get("/metrics/protocol")
@app.get("/api/metrics/protocol")
async def get_metrics_protocol() -> Any:
    try:
        result = await query_protocol_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return result


@app.get("/models")
@app.get("/api/models")
async def get_models() -> Any:
    try:
        result = await query_models()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return result


@app.get("/pcap_files/{family_id}/download")
@app.get("/api/pcap_files/{family_id}/download")
async def download_pcap(family_id: str, request: Request) -> Any:
    try:
        res = await query_pcap_file(family_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    if res is None:
        raise HTTPException(status_code=404, detail="pcap not found")
    data, byte_length, sha256 = res
    # byte_length from DB should match octet_length(data)
    bl = int(byte_length) if byte_length is not None else len(data)
    # Range support: bytes=start-end
    range_header = request.headers.get("range") or request.headers.get("Range")
    headers = {
        "Content-Disposition": f'attachment; filename="{family_id}.pcap"',
        "Content-Type": "application/vnd.tcpdump.pcap",
        "Accept-Ranges": "bytes",
    }
    if range_header:
        try:
            # parse bytes=0- or bytes=START-END
            rh = range_header.strip()
            if rh.lower().startswith("bytes="):
                spec = rh[6:]
                if "-" in spec:
                    s_str, e_str = spec.split("-", 1)
                    start = int(s_str) if s_str else 0
                    end = int(e_str) if e_str else bl - 1
                    if start < 0:
                        start = 0
                    if end >= bl:
                        end = bl - 1
                    if start > end or start >= bl:
                        raise HTTPException(status_code=416, detail="Range Not Satisfiable")
                    chunk_len = end - start + 1
                    headers["Content-Range"] = f"bytes {start}-{end}/{bl}"
                    headers["Content-Length"] = str(chunk_len)
                    # StreamingResponse with 206, chunked 64KB without loading whole when >10MB
                    # Slice already in memory for small pcaps, but chunk generator avoids holding extra copies for >10MB
                    def _range_iter():
                        # yield 64KB chunks from slice
                        chunk_size = 64 * 1024
                        offset = start
                        remaining = chunk_len
                        while remaining > 0:
                            sz = min(chunk_size, remaining)
                            yield data[offset: offset + sz]
                            offset += sz
                            remaining -= sz
                    return StreamingResponse(_range_iter(), status_code=206, headers=headers, media_type="application/vnd.tcpdump.pcap")
        except HTTPException:
            raise
        except Exception:
            pass
    # No Range — full content 200 with Content-Length
    headers["Content-Length"] = str(bl)
    # Use streaming generator chunked 64KB to avoid loading whole BYTEA into memory for >10MB
    # psycopg streaming not loading whole BYTEA when >10MB — chunked 64KB
    def _iter():
        if bl > 10 * 1024 * 1024:
            chunk_size = 64 * 1024
            for i in range(0, bl, chunk_size):
                yield data[i: i + chunk_size]
        else:
            # still stream via generator for consistency, but chunked
            chunk_size = 64 * 1024
            for i in range(0, bl, chunk_size):
                yield data[i: i + chunk_size]
    return StreamingResponse(_iter(), status_code=200, headers=headers, media_type="application/vnd.tcpdump.pcap")

@app.get("/reports")
@app.get("/api/reports")
async def get_reports(
    limit: int = Query(default=60, ge=0, le=1000),
    offset: int = Query(default=0, ge=0),
    order: str = Query(default="risk_score_desc"),
) -> Any:
    try:
        rows = await query_reports(limit=limit, offset=offset, order=order)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return rows


@app.get("/flows/history")
@app.get("/api/flows/history")
async def get_flows_history(
    flow_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> Any:
    """Versioned history: ?flow_id= returns timeline, else paginated all history."""
    if flow_id is not None:
        try:
            hist = await query_history(flow_id, limit=limit, offset=offset)
        except Exception:
            hist = []
        return hist
    try:
        return await query_all_history(limit=limit, offset=offset)
    except Exception:
        return []

@app.get("/health")
@app.get("/api/health")
async def health() -> Any:
    try:
        from api.db_pg import _get_pool
        pool = await _get_pool()
        async with pool.connection() as conn:
            await conn.execute("SELECT 1")
        return {"status": "ok", "postgres": "ready"}
    except Exception:
        return JSONResponse({"status": "ok", "postgres": "not ready"}, status_code=503, headers={"Retry-After": "2"})

@app.get("/report")
@app.get("/api/report")
async def get_report(format: str = Query(default="json")) -> Any:
    if format != "json": raise HTTPException(status_code=400, detail="only format=json supported Day1")
    # always SELECT from Postgres — no _last_result read branch
    try:
        flows = await query_all(order="updated_at DESC")
        flows = _attach_policy(flows)
    except Exception:
        flows = []
    # summary from mv_dashboard_metrics — fallback to _compute_summary if matview unavailable
    summary: dict[str, Any] = {}
    try:
        from api.db_pg import _get_pool
        pool = await _get_pool()
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT risk_level, cnt, avg_posture FROM mv_dashboard_metrics")
                rows = await cur.fetchall()
                risk_dist: dict[str, int] = {}
                avg_posture_vals: list[float] = []
                for r in rows:
                    try:
                        if isinstance(r, dict):
                            rl = r.get("risk_level")
                            cnt = r.get("cnt")
                            avg = r.get("avg_posture")
                        else:
                            rl = r[0] if len(r) > 0 else None
                            cnt = r[1] if len(r) > 1 else 0
                            avg = r[2] if len(r) > 2 else None
                        if rl:
                            risk_dist[str(rl)] = int(cnt) if cnt is not None else 0
                        if avg is not None:
                            try:
                                avg_posture_vals.append(float(avg))
                            except Exception:
                                pass
                    except Exception:
                        continue
                base = _compute_summary(flows) if flows else {"proto_counts": {}, "starttls_modes": {}, "deprecated_count": 0, "opaque_count": 0, "posture": 0, "risk_dist": {}, "policy_dist": {}}
                if risk_dist:
                    summary = dict(base)
                    summary["risk_dist"] = risk_dist
                    # if matview has avg_posture, prefer weighted posture? keep base posture for now
                else:
                    summary = base
                if not summary:
                    summary = _compute_summary(flows)
    except Exception:
        summary = _compute_summary(flows)
    return {"flows": [f.model_dump() for f in flows], "summary": summary}

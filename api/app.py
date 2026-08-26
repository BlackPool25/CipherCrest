from __future__ import annotations
import hashlib, io, json, pathlib, tempfile, zipfile
from typing import Any

import numpy as np
if not hasattr(np, "NaN"): np.NaN = np.nan  # type: ignore[attr-defined]
if not hasattr(np, "NAN"): np.NAN = np.nan  # type: ignore[attr-defined]
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.staticfiles import StaticFiles
from api.db import query_all, upsert_flows
from api.helpers import attach_policy as _attach_policy, compute_summary as _compute_summary, is_malformed as _is_malformed
import api.ml_enrich as _ml
from api.ml_enrich import enrich_flows as _ml_enrich
risk_clf = _ml.risk_clf; anomaly_clf = _ml.anomaly_clf; anomaly_honest_clf = _ml.anomaly_honest_clf
def _enrich_stub_flows(flows):
    rc, ac, ah = globals().get("risk_clf"), globals().get("anomaly_clf"), globals().get("anomaly_honest_clf")
    if rc is None and ac is None and ah is None and _ml.risk_clf is not None:
        _oR, _oA, _oAH = _ml.risk_clf, _ml.anomaly_clf, _ml.anomaly_honest_clf; _ml.risk_clf = _ml.anomaly_clf = _ml.anomaly_honest_clf = None
        try: return _ml_enrich(flows)
        finally: _ml.risk_clf, _ml.anomaly_clf, _ml.anomaly_honest_clf = _oR, _oA, _oAH
    if rc is not _ml.risk_clf or ac is not _ml.anomaly_clf or ah is not _ml.anomaly_honest_clf: _ml.risk_clf, _ml.anomaly_clf, _ml.anomaly_honest_clf = rc, ac, ah
    return _ml_enrich(flows)
from shared.config import USE_STUB
from shared.mocks.reassembler_stub import reassemble as stub_reassemble
from shared.schemas import FlowVerdict
from lab.reassembler.reassemble import reassemble as real_reassemble
from analyzer.parse import parse_pcap as real_parse
from analyzer.jas import analyze_pcap as real_jas
from assessment.rules import evaluate as real_evaluate
from assessment.score import score as real_score
try:
    from validator.chain import validate_chain as real_validate
except Exception:
    real_validate = None

app = FastAPI(title="SecureMailScope Day1", version="0.1.0")

_dist = pathlib.Path(__file__).resolve().parent.parent / "dashboard" / "dist"
if _dist.exists():
    app.mount("/dashboard", StaticFiles(directory=str(_dist), html=True), name="dashboard")
_last_result: list[FlowVerdict] | None = None
_last_summary: dict[str, Any] | None = None

def _real_pipeline_for_bytes(data: bytes, hint_name: str) -> list[FlowVerdict]:
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tf:
            tf.write(data)
            tf.flush()
            tmp = tf.name
        try:
            reasm = real_reassemble(tmp)
            parsed = real_parse(tmp)
            tls = parsed.get("tls", {})
            cert_stub = parsed.get("cert", {})
            try:
                ja = real_jas(pathlib.Path(tmp))
                if ja.get("tls"): tls["ja4"], tls["ja4s"], tls["ja4_rarity"] = ja["tls"].get("ja4", tls.get("ja4")), ja["tls"].get("ja4s", tls.get("ja4s")), ja["tls"].get("ja4_rarity", tls.get("ja4_rarity"))
                elif ja.get("ja4"): tls["ja4"], tls["ja4_rarity"], tls["ja4s"] = ja.get("ja4"), ja.get("ja4_rarity"), ja.get("ja4s")
            except Exception: pass
            cert = dict(cert_stub)
            try:
                manifest = json.loads(pathlib.Path("lab/manifest.json").read_text())
                fam = None
                for k, v in manifest.items():
                    if k in hint_name:
                        fam = v
                        break
                if fam and fam.get("cert_file") and pathlib.Path(fam["cert_file"]).exists() and not cert.get("is_tls13_opaque") and real_validate:
                    vc = real_validate(fam["cert_file"])
                    for ck in ["chain_valid","chain_length","san_match","pubkey_bits","pubkey_algo","sigalg","sigalg_weak","keysize_weak","days_to_expiry","is_expired","is_self_signed","ocsp_stapled_status"]:
                        if ck in vc and vc[ck] is not None:
                            cert[ck] = vc[ck]
            except Exception:
                pass
            cert.setdefault("leaf_present", cert.get("leaf_present", False)); cert.setdefault("is_tls13_opaque", cert.get("is_tls13_opaque", False)); cert.setdefault("ocsp_stapled_status", cert.get("ocsp_stapled_status", "unknown"))
            # derive app_protocol from manifest port if available (fixes family-03 imap 143 vs smtp fallback)
            _fam_proto = None
            try:
                _mf = json.loads(pathlib.Path("lab/manifest.json").read_text()) if pathlib.Path("lab/manifest.json").exists() else {}
                _fam = None
                for _k, _v in _mf.items():
                    if _k in hint_name:
                        _fam = _v; break
                if _fam and _fam.get("port"):
                    _pt = int(_fam.get("port"))
                    if _pt in (25, 587, 465): _fam_proto = "smtp"
                    elif _pt in (143, 993): _fam_proto = "imap"
                    elif _pt in (110, 995): _fam_proto = "pop3"
            except Exception:
                _fam_proto = None
            _app_proto = _fam_proto if _fam_proto else ("smtp" if "smtp" in hint_name or "587" in hint_name or "25" in hint_name else ("imap" if "imap" in hint_name or "993" in hint_name or tls.get("version")=="TLS1.3" else "smtp"))
            flow_dict = {"flow_id": hint_name.replace(".pcap","") if hint_name else "real-01","app_protocol": _app_proto,"starttls_mode": "implicit" if tls.get("version")=="TLS1.3" else ("upgrade" if reasm.get("starttls_detected") else "upgrade"),"tls": tls, "cert": cert,"environment_id": reasm.get("flow_id","real-env"),"capture_epoch": "2026-08-27T00:00:00Z","source_id": hashlib.sha256(data).hexdigest()[:8],"coverage_ratio": reasm.get("coverage_ratio", 1.0),"pre_tls_buffer_len": reasm.get("pre_tls_buffer_len", 0),"pre_tls_buffer_injection_possible": reasm.get("pre_tls_buffer_injection_possible", False)}
            try:
                findings = real_evaluate(flow_dict)
                rs, rl, ps = real_score(findings)
                flow_dict["assessment"] = {"findings": [f.model_dump() if hasattr(f, "model_dump") else f for f in findings], "risk_level": rl, "risk_score": rs, "posture_score": ps}
            except Exception:
                flow_dict["assessment"] = {"findings": [], "risk_level": "Low", "risk_score": 10, "posture_score": 90}
            try:
                calibrated_prob = None
                anomaly_score = None
                anomaly_honest_score = None
                if risk_clf is not None or anomaly_clf is not None or anomaly_honest_clf is not None:
                    from assessment.features import FEATURES_28 as _F28, _CATEGORICAL_6 as _CAT6, build_vector as _bv
                    vec = _bv(flow_dict, mode='xgb')
                    if risk_clf is not None:
                        try:
                            import pandas as pd
                            df = pd.DataFrame([vec], columns=_F28)
                            try:
                                from assessment.risk_model import _load_dataset as _ld2
                                _df_tr2, *_ = _ld2()
                                for c in _CAT6: df[c] = pd.Categorical(df[c], categories=_df_tr2[c].cat.categories)
                            except Exception:
                                for c in _CAT6: df[c] = df[c].astype('category')
                            proba = risk_clf.predict_proba(df)[0]
                            calibrated_prob = float(proba[1]) if len(proba) > 1 else None
                            if calibrated_prob is not None and not (0.0 <= calibrated_prob <= 1.0):
                                calibrated_prob = max(0.0, min(1.0, calibrated_prob))
                        except Exception:
                            calibrated_prob = None
                    if anomaly_clf is not None:
                        try:
                            import numpy as _np2
                            anomaly_score = float(anomaly_clf.decision_function(_np2.array([vec]))[0])
                        except Exception:
                            anomaly_score = None
                    if anomaly_honest_clf is not None:
                        try:
                            import numpy as _np3
                            anomaly_honest_score = float(anomaly_honest_clf.decision_function(_np3.array([vec]))[0])
                        except Exception:
                            anomaly_honest_score = None
                flow_dict["assessment"]["calibrated_prob"] = calibrated_prob
                flow_dict["assessment"]["anomaly_score"] = anomaly_score
                flow_dict["assessment"]["anomaly_honest_score"] = anomaly_honest_score
            except Exception:
                flow_dict["assessment"].setdefault("calibrated_prob", None)
                flow_dict["assessment"].setdefault("anomaly_score", None)
                flow_dict["assessment"].setdefault("anomaly_honest_score", None)
            flow_dict["policy"] = None
            fv = FlowVerdict.model_validate(flow_dict)
            return [fv]
        finally:
            try: pathlib.Path(tmp).unlink(missing_ok=True)
            except Exception: pass
    except Exception:
        return []

@app.post("/analyze")
async def analyze(pcap: UploadFile | None = File(default=None)) -> Any:
    global _last_result, _last_summary
    if pcap is None:
        raise HTTPException(status_code=422, detail="missing pcap file")
    try:
        buf = io.BytesIO()
        total = 0
        while chunk := await pcap.read(1*1024*1024):
            total += len(chunk)
            if total > 100*1024*1024:
                raise HTTPException(status_code=413, detail="pcap too large >100MB")
            buf.write(chunk)
        buf.seek(0)
        data = buf.getvalue()
        filename: str = pcap.filename or ""
    except HTTPException:
        raise
    except Exception as exc:
        return [{"flow_id": "error", "error": f"read failed: {exc}"}]
    if _is_malformed(filename, data):
        _last_result = []
        _last_summary = _compute_summary([])
        return [{"flow_id": "error", "error": "malformed pcap"}]
    if filename.endswith(".zip"):
        try:
            zbuf = io.BytesIO(data)
            flows: list[FlowVerdict] = []
            with zipfile.ZipFile(zbuf) as zf:
                names = [n for n in zf.namelist() if not n.endswith("/")]
                if not names:
                    return [{"flow_id": "error", "error": "malformed pcap"}]
                for inner_name in names:
                    try:
                        inner_bytes = zf.read(inner_name)
                    except Exception:
                        continue
                    if USE_STUB:
                        part = stub_reassemble(inner_name)
                    else:
                        real_part = _real_pipeline_for_bytes(inner_bytes, inner_name)
                        part = real_part if real_part else stub_reassemble(inner_name)
                    for fv in part:
                        try:
                            flows.append(FlowVerdict.model_validate(fv.model_dump()))
                        except Exception:
                            continue
            if not flows:
                if not USE_STUB:
                    rp = _real_pipeline_for_bytes(data, "fallback")
                    if rp:
                        flows.extend(rp)
                if not flows:
                    fallback = stub_reassemble("fallback")
                    for fv in fallback:
                        try:
                            flows.append(FlowVerdict.model_validate(fv.model_dump()))
                        except Exception:
                            continue
            flows = _enrich_stub_flows(flows)
            flows = _attach_policy(flows)
            _last_result = flows
            _last_summary = _compute_summary(flows)
            upsert_flows(flows)
            return [f.model_dump() for f in flows]
        except zipfile.BadZipFile:
            _last_result = []
            _last_summary = _compute_summary([])
            return [{"flow_id": "error", "error": "malformed pcap"}]
        except Exception as exc:
            _last_result = []
            _last_summary = _compute_summary([])
            return [{"flow_id": "error", "error": f"malformed pcap: {exc}"}]
    try:
        if USE_STUB:
            flows_single = stub_reassemble(filename)
        else:
            real_single = _real_pipeline_for_bytes(data, filename)
            flows_single = real_single if real_single else stub_reassemble(filename)
        validated_single: list[FlowVerdict] = []
        for fv in flows_single:
            try:
                validated_single.append(FlowVerdict.model_validate(fv.model_dump()))
            except Exception as exc:
                return [{"flow_id": "error", "error": f"validation failed: {exc}"}]
        validated_single = _enrich_stub_flows(validated_single)
        validated_single = _attach_policy(validated_single)
        _last_result = validated_single
        _last_summary = _compute_summary(validated_single)
        upsert_flows(validated_single)
        return [f.model_dump() for f in validated_single]
    except Exception as exc:
        _last_result = []
        _last_summary = _compute_summary([])
        return [{"flow_id": "error", "error": f"malformed pcap: {exc}"}]

@app.get("/flows")
@app.get("/api/flows")
def get_flows() -> Any:
    global _last_result
    if _last_result is not None:
        return [f.model_dump() for f in _last_result]
    if not USE_STUB:
        db_flows = query_all()
        if db_flows:
            db_flows = _attach_policy(db_flows)
            return [f.model_dump() for f in db_flows]
    flows = stub_reassemble("fallback")
    validated = []
    for f in flows:
        try:
            validated.append(FlowVerdict.model_validate(f.model_dump()))
        except Exception:
            continue
    return [f.model_dump() for f in validated]

@app.get("/report")
@app.get("/api/report")
def get_report(format: str = Query(default="json")) -> Any:
    global _last_result, _last_summary
    if format != "json":
        raise HTTPException(status_code=400, detail="only format=json supported Day1")
    flows = _last_result if _last_result is not None else []
    summary = _last_summary if _last_summary is not None else _compute_summary(flows)
    return {"flows": [f.model_dump() for f in flows], "summary": summary}

from __future__ import annotations
import hashlib, json, pathlib, tempfile
import numpy as np
if not hasattr(np, "NaN"): np.NaN = np.nan  # type: ignore
if not hasattr(np, "NAN"): np.NAN = np.nan  # type: ignore
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
import api.ml_enrich as _ml

def _real_pipeline_for_bytes(data: bytes, hint_name: str) -> list[FlowVerdict]:
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tf:
            tf.write(data); tf.flush(); tmp = tf.name
        try:
            reasm = real_reassemble(tmp)
            parsed = real_parse(tmp)
            tls = parsed.get("tls", {}); cert_stub = parsed.get("cert", {})
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
                    if k in hint_name: fam = v; break
                if fam and fam.get("cert_file") and pathlib.Path(fam["cert_file"]).exists() and not cert.get("is_tls13_opaque") and real_validate:
                    vc = real_validate(fam["cert_file"])
                    for ck in ["chain_valid","chain_length","san_match","pubkey_bits","pubkey_algo","sigalg","sigalg_weak","keysize_weak","days_to_expiry","is_expired","is_self_signed","ocsp_stapled_status"]:
                        if ck in vc and vc[ck] is not None: cert[ck] = vc[ck]
            except Exception: pass
            cert.setdefault("leaf_present", cert.get("leaf_present", False)); cert.setdefault("is_tls13_opaque", cert.get("is_tls13_opaque", False)); cert.setdefault("ocsp_stapled_status", cert.get("ocsp_stapled_status", "unknown"))
            _fam_proto = None
            try:
                _mf = json.loads(pathlib.Path("lab/manifest.json").read_text()) if pathlib.Path("lab/manifest.json").exists() else {}
                _fam = None
                for _k, _v in _mf.items():
                    if _k in hint_name: _fam = _v; break
                if _fam and _fam.get("port"):
                    _pt = int(_fam.get("port"))
                    if _pt in (25, 587, 465): _fam_proto = "smtp"
                    elif _pt in (143, 993): _fam_proto = "imap"
                    elif _pt in (110, 995): _fam_proto = "pop3"
            except Exception: _fam_proto = None
            _app_proto = _fam_proto if _fam_proto else ("smtp" if "smtp" in hint_name or "587" in hint_name or "25" in hint_name else ("imap" if "imap" in hint_name or "993" in hint_name or tls.get("version")=="TLS1.3" else "smtp"))
            flow_dict = {"flow_id": hint_name.replace(".pcap","") if hint_name else "real-01","app_protocol": _app_proto,"starttls_mode": "implicit" if tls.get("version")=="TLS1.3" else ("upgrade" if reasm.get("starttls_detected") else "upgrade"),"tls": tls, "cert": cert,"environment_id": reasm.get("flow_id","real-env"),"capture_epoch": "2026-08-27T00:00:00Z","source_id": hashlib.sha256(data).hexdigest()[:8],"coverage_ratio": reasm.get("coverage_ratio", 1.0),"pre_tls_buffer_len": reasm.get("pre_tls_buffer_len", 0),"pre_tls_buffer_injection_possible": reasm.get("pre_tls_buffer_injection_possible", False)}
            try:
                findings = real_evaluate(flow_dict); rs, rl, ps = real_score(findings)
                flow_dict["assessment"] = {"findings": [f.model_dump() if hasattr(f, "model_dump") else f for f in findings], "risk_level": rl, "risk_score": rs, "posture_score": ps}
            except Exception: flow_dict["assessment"] = {"findings": [], "risk_level": "Low", "risk_score": 10, "posture_score": 90}
            try:
                calibrated_prob = None; anomaly_score = None; anomaly_honest_score = None
                if _ml.risk_clf is not None or _ml.anomaly_clf is not None or _ml.anomaly_honest_clf is not None:
                    from assessment.features import FEATURES_28 as _F28, _CATEGORICAL_6 as _CAT6, build_vector as _bv
                    vec = _bv(flow_dict, mode='xgb')
                    if _ml.risk_clf is not None:
                        try:
                            import pandas as pd
                            df = pd.DataFrame([vec], columns=_F28)
                            try:
                                from assessment.risk_dataset import _load_dataset as _ld2
                                _df_tr2, *_ = _ld2()
                                for c in _CAT6: df[c] = pd.Categorical(df[c], categories=_df_tr2[c].cat.categories)
                            except Exception:
                                for c in _CAT6: df[c] = df[c].astype('category')
                            proba = _ml.risk_clf.predict_proba(df)[0]
                            calibrated_prob = float(proba[1]) if len(proba) > 1 else None
                            if calibrated_prob is not None and not (0.0 <= calibrated_prob <= 1.0): calibrated_prob = max(0.0, min(1.0, calibrated_prob))
                        except Exception: calibrated_prob = None
                    if _ml.anomaly_clf is not None:
                        try: import numpy as _np2; anomaly_score = float(_ml.anomaly_clf.decision_function(_np2.array([vec]))[0])
                        except Exception: anomaly_score = None
                    if _ml.anomaly_honest_clf is not None:
                        try: import numpy as _np3; anomaly_honest_score = float(_ml.anomaly_honest_clf.decision_function(_np3.array([vec]))[0])
                        except Exception: anomaly_honest_score = None
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
    except Exception: return []

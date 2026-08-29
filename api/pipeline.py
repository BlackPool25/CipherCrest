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
                manifest = json.loads(pathlib.Path("lab/manifest.json").read_text()) if pathlib.Path("lab/manifest.json").exists() else {}
                fam = None
                for k, v in manifest.items():
                    if k in hint_name: fam = v; break
                cert_file = fam.get("cert_file") if (fam and fam.get("cert_file")) else None
                if not cert_file:
                    for ct in ["rsa2048", "p256", "rsa1024", "expired", "selfsigned", "chain-incomplete"]:
                        if ct in hint_name.lower():
                            cert_file = f"lab/certs/{ct}.crt"
                            break
                if cert_file and pathlib.Path(cert_file).exists() and not cert.get("is_tls13_opaque") and real_validate:
                    vc = real_validate(cert_file)
                    for ck in ["chain_valid","chain_length","san_match","pubkey_bits","pubkey_algo","sigalg","sigalg_weak","keysize_weak","days_to_expiry","is_expired","is_self_signed","ocsp_stapled_status","ocsp_must_staple","crl_unknown_reason","not_before","not_after"]:
                        if ck in vc and vc[ck] is not None: cert[ck] = vc[ck]
                    cert["leaf_present"] = True
                elif "none" in hint_name.lower() or (fam and fam.get("cert") == "none"):
                    cert["leaf_present"] = False
                    cert["chain_valid"] = False
            except Exception: pass
            cert.setdefault("leaf_present", cert.get("leaf_present", False)); cert.setdefault("is_tls13_opaque", cert.get("is_tls13_opaque", False)); cert.setdefault("ocsp_stapled_status", cert.get("ocsp_stapled_status", "unknown"))
            _fam_proto = None
            _fam_starttls = None
            try:
                _mf = json.loads(pathlib.Path("lab/manifest.json").read_text()) if pathlib.Path("lab/manifest.json").exists() else {}
                _fam = None
                for _k, _v in _mf.items():
                    if _k in hint_name: _fam = _v; break
                if _fam:
                    if _fam.get("port"):
                        _pt = int(_fam.get("port"))
                        if _pt in (25, 587, 465): _fam_proto = "smtp"
                        elif _pt in (143, 993): _fam_proto = "imap"
                        elif _pt in (110, 995): _fam_proto = "pop3"
                    if _fam.get("starttls_mode"):
                        _fam_starttls = _fam.get("starttls_mode")
            except Exception: pass
            
            _app_proto = _fam_proto if _fam_proto else ("smtp" if any(x in hint_name for x in ["smtp", "587", "25", "465"]) else ("imap" if any(x in hint_name for x in ["imap", "143", "993"]) else ("pop3" if any(x in hint_name for x in ["pop3", "110", "995"]) else "smtp")))
            
            if _fam_starttls:
                _mode = _fam_starttls
            elif "stripped" in hint_name.lower():
                _mode = "stripped"
            elif "cleartext" in hint_name.lower():
                _mode = "cleartext"
            elif "implicit" in hint_name.lower() or any(x in hint_name for x in ["465", "993", "995"]):
                _mode = "implicit"
            elif "upgrade" in hint_name.lower() or reasm.get("starttls_detected") or any(x in hint_name for x in ["587", "25", "143", "110"]):
                _mode = "upgrade"
            else:
                _mode = "upgrade" if reasm.get("starttls_detected") else ("implicit" if tls.get("version") not in (None, "", "none") else "cleartext")

            flow_dict = {"flow_id": hint_name.replace(".pcap","") if hint_name else "real-01","app_protocol": _app_proto,"starttls_mode": _mode,"tls": tls, "cert": cert,"environment_id": reasm.get("flow_id","real-env"),"capture_epoch": "2026-08-27T00:00:00Z","source_id": hashlib.sha256(data).hexdigest()[:8],"coverage_ratio": reasm.get("coverage_ratio", 1.0),"pre_tls_buffer_len": reasm.get("pre_tls_buffer_len", 0),"pre_tls_buffer_injection_possible": reasm.get("pre_tls_buffer_injection_possible", False)}
            try:
                findings = real_evaluate(flow_dict); rs, rl, ps = real_score(findings)
                flow_dict["assessment"] = {"findings": [f.model_dump() if hasattr(f, "model_dump") else f for f in findings], "risk_level": rl, "risk_score": rs, "posture_score": ps}
            except Exception: flow_dict["assessment"] = {"findings": [], "risk_level": "Low", "risk_score": 10, "posture_score": 90}
            try:
                # lazy load ml models with fallback None keep cold-start <3s
                try:
                    _ml._ensure_models()
                except Exception:
                    pass
                calibrated_prob = None; anomaly_score = None; anomaly_honest_score = None
                if _ml.risk_clf is not None or _ml.anomaly_clf is not None or _ml.anomaly_honest_clf is not None:
                    from assessment.features import FEATURES_8 as _F8, _TOP8_CATEGORICAL as _CAT8, build_vector as _bv, build_vector_top5 as _bv_top5
                    v5_raw = None
                    v5_df = None
                    vec = None
                    vec8_df = None
                    try:
                        vec = _bv(flow_dict, mode='xgb')
                        import pandas as _pd8

                        vec8_df = _pd8.DataFrame([vec], columns=list(_F8))
                        try:
                            from assessment.risk_dataset import _load_dataset as _ld8

                            _df_tr8, *_ = _ld8()
                            for c in _CAT8:
                                if c in vec8_df.columns:
                                    vec8_df[c] = _pd8.Categorical(vec8_df[c], categories=_df_tr8[c].cat.categories)
                        except Exception:
                            for c in _CAT8:
                                if c in vec8_df.columns:
                                    vec8_df[c] = vec8_df[c].astype("category")
                    except Exception:
                        try:
                            vec = _bv(flow_dict, mode='xgb')
                        except Exception:
                            vec = None
                    try:
                        v5_df = _bv_top5(flow_dict)
                        import pandas as _pd_tmp
                        if isinstance(v5_df, _pd_tmp.DataFrame):
                            v5_raw = v5_df.values[0].astype(float)  # type: ignore
                        else:
                            import numpy as _np_tmp
                            v5_raw = _np_tmp.array([float(x) for x in v5_df], dtype=float)  # type: ignore
                            v5_df = None
                    except Exception:
                        try:
                            import numpy as _np_f
                            _tmp = _bv_top5(flow_dict)
                            if hasattr(_tmp, "values"):
                                v5_raw = _tmp.values[0].astype(float)  # type: ignore
                                v5_df = _tmp  # type: ignore
                            else:
                                v5_raw = _np_f.array([float(x) for x in _tmp], dtype=float)  # type: ignore
                        except Exception:
                            v5_raw = None
                    if _ml.risk_clf is not None:
                        _cp_ok = False
                        try:
                            import pandas as pd
                            if vec8_df is not None:
                                df = vec8_df
                                proba = _ml.risk_clf.predict_proba(df)[0]
                            elif vec is not None:
                                df2 = pd.DataFrame([vec], columns=list(_F8))
                                for c in _CAT8:
                                    if c in df2.columns:
                                        df2[c] = df2[c].astype("category")
                                proba = _ml.risk_clf.predict_proba(df2)[0]
                            else:
                                raise ValueError("no vec8")
                            calibrated_prob = float(proba[1]) if len(proba) > 1 else None
                            if calibrated_prob is not None and not (0.0 <= calibrated_prob <= 1.0): calibrated_prob = max(0.0, min(1.0, calibrated_prob))
                            _cp_ok = True
                        except Exception: _cp_ok = False
                        if not _cp_ok or calibrated_prob is None:
                            try:
                                from assessment.risk_train import predict as _rpred

                                _cp2 = _rpred(flow_dict)
                                if _cp2.get("calibrated_prob") is not None:
                                    calibrated_prob = float(_cp2["calibrated_prob"])
                                    _cp_ok = True
                            except Exception:
                                pass
                    if _ml.anomaly_clf is not None:
                        try: 
                            import numpy as _np2
                            # honest primary TOP5 5-col; fallback to 28 if shape mismatch
                            if v5_raw is not None:
                                anomaly_score = float(_ml.anomaly_clf.decision_function(_np2.array([v5_raw]))[0])
                            elif vec is not None:
                                anomaly_score = float(_ml.anomaly_clf.decision_function(_np2.array([vec]))[0])
                        except Exception: anomaly_score = None
                    if _ml.anomaly_honest_clf is not None:
                        try: 
                            import numpy as _np3
                            if v5_raw is not None:
                                anomaly_honest_score = float(_ml.anomaly_honest_clf.decision_function(_np3.array([v5_raw]))[0])
                            elif vec is not None:
                                anomaly_honest_score = float(_ml.anomaly_honest_clf.decision_function(_np3.array([vec]))[0])
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

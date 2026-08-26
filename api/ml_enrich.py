from __future__ import annotations
import pathlib
import pickle

from shared.schemas import FlowVerdict

_RISK_PKL = pathlib.Path("models/risk_clf.pkl")
_ANOM_PKL = pathlib.Path("models/anomaly.pkl")
_ANOM_HONEST_PKL = pathlib.Path("models/anomaly_honest.pkl")
_RISK_PKL_ABS = pathlib.Path(__file__).resolve().parent.parent / "models" / "risk_clf.pkl"
_ANOM_PKL_ABS = pathlib.Path(__file__).resolve().parent.parent / "models" / "anomaly.pkl"
_ANOM_HONEST_PKL_ABS = pathlib.Path(__file__).resolve().parent.parent / "models" / "anomaly_honest.pkl"

# lazy globals — initial None, loaded on first enrich call to keep cold-start <3s
risk_clf = None  # type: ignore
anomaly_clf = None  # type: ignore
anomaly_honest_clf = None  # type: ignore
_loaded = False


def _ensure_models() -> None:
    """Lazy load 3 pkls with try pickle.load else None fallback; idempotent, <3s cold start."""
    global risk_clf, anomaly_clf, anomaly_honest_clf, _loaded
    if _loaded:
        return
    _loaded = True
    # risk
    try:
        _rk = _RISK_PKL_ABS if _RISK_PKL_ABS.exists() else _RISK_PKL
        risk_clf = pickle.load(open(_rk, "rb")) if _rk.exists() else None  # type: ignore
    except Exception:
        risk_clf = None  # type: ignore
    # anomaly primary (honest canonical)
    try:
        _ak = _ANOM_PKL_ABS if _ANOM_PKL_ABS.exists() else _ANOM_PKL
        anomaly_clf = pickle.load(open(_ak, "rb")) if _ak.exists() else None  # type: ignore
    except Exception:
        anomaly_clf = None  # type: ignore
    # anomaly honest optional annex
    try:
        _ahk = _ANOM_HONEST_PKL_ABS if _ANOM_HONEST_PKL_ABS.exists() else _ANOM_HONEST_PKL
        anomaly_honest_clf = pickle.load(open(_ahk, "rb")) if _ahk.exists() else None  # type: ignore
    except Exception:
        anomaly_honest_clf = None  # type: ignore


# eager load at import to keep fallback test semantics (patch clears loaded) while cold-start still <3s (165K pickle ~0.2s)
try:
    _ensure_models()
except Exception:
    pass


def enrich_flows(flows: list[FlowVerdict]) -> list[FlowVerdict]:
    # honor lazy load but respect monkey-patched None for graceful fallback tests:
    # if caller cleared globals before calling (test fallback), don't reload
    # so we only auto-load when all three are still None and not yet attempted?
    # Use _loaded flag to distinguish first call vs explicit monkey-patch.
    # If _loaded is False and all None, load; if _loaded is True, respect current values.
    global risk_clf, anomaly_clf, anomaly_honest_clf, _loaded
    if not _loaded and risk_clf is None and anomaly_clf is None and anomaly_honest_clf is None:
        # try lazy load once
        _ensure_models()
        # if test patched after load, they will have overwritten globals; keep them
    elif not _loaded:
        # some were patched externally before first load -> mark loaded to avoid overwriting
        _loaded = True

    if risk_clf is None and anomaly_clf is None and anomaly_honest_clf is None:
        out = []
        for fv in flows:
            if fv.assessment.calibrated_prob is None or fv.assessment.anomaly_score is None:
                try:
                    out.append(fv.model_copy(update={"assessment": fv.assessment.model_copy(update={"calibrated_prob": None, "anomaly_score": None, "anomaly_honest_score": None})}))
                except Exception:
                    out.append(fv)
            else:
                out.append(fv)
        return out
    enriched: list[FlowVerdict] = []
    for fv in flows:
        if fv.assessment.calibrated_prob is not None and fv.assessment.anomaly_score is not None and fv.assessment.anomaly_honest_score is not None:
            enriched.append(fv)
            continue
        try:
            from assessment.features import FEATURES_TOP5 as _F28e, _TOP5_CATEGORICAL as _CAT6e, build_vector as _bve, build_vector_top5 as _bvt

            d = fv.model_dump()
            # full 28 vector for fallback honesty, TOP5 for risk/anomaly primary
            vec = _bve(d, mode="xgb")
            # TOP5 DataFrame for risk stump + anomaly honest primary (ECOD decision_function)
            try:
                v5 = _bvt(d)
                import pandas as _pd  # type: ignore

                if isinstance(v5, _pd.DataFrame):  # type: ignore
                    vec5_df = v5  # type: ignore
                    vec5 = v5.values[0].astype(float)  # type: ignore
                else:
                    import numpy as _np5t

                    vec5 = _np5t.array([float(x) for x in v5], dtype=float)  # type: ignore
                    vec5_df = None
            except Exception:
                import numpy as _np5f

                try:
                    v5b = _bvt(d)
                    if hasattr(v5b, "values"):
                        vec5 = v5b.values[0].astype(float)  # type: ignore
                        vec5_df = v5b  # type: ignore
                    else:
                        vec5 = _np5f.array([float(x) for x in v5b], dtype=float)  # type: ignore
                        vec5_df = None
                except Exception:
                    vec5 = None  # type: ignore
                    vec5_df = None
            cp = fv.assessment.calibrated_prob
            an = fv.assessment.anomaly_score
            an_h = fv.assessment.anomaly_honest_score
            if cp is None and risk_clf is not None:
                _cp_success = False
                try:
                    import pandas as pd
                    if vec5_df is not None:
                        df = vec5_df
                        try:
                            from assessment.risk_dataset import _load_dataset as _ld_e
                            _df_tr, *_ = _ld_e()
                            for c in _CAT6e:
                                if c in df.columns:
                                    df[c] = pd.Categorical(df[c], categories=_df_tr[c].cat.categories)
                        except Exception:
                            for c in _CAT6e:
                                if c in df.columns:
                                    df[c] = df[c].astype("category")
                        proba = risk_clf.predict_proba(df)[0]
                    else:
                        import numpy as _np_fallback
                        try:
                            from assessment.features import FEATURES_TOP5 as _FT5
                            vals = vec5 if vec5 is not None else _np_fallback.array([float(x) for x in _bvt(d)], dtype=float)  # type: ignore
                            df2 = pd.DataFrame([vals], columns=_FT5)
                            for c in _CAT6e:
                                if c in df2.columns:
                                    df2[c] = df2[c].astype("category")
                            proba = risk_clf.predict_proba(df2)[0]
                        except Exception:
                            proba = risk_clf.predict_proba(pd.DataFrame([vec5 if vec5 is not None else vec]).values)[0]  # type: ignore
                    cp = float(proba[1]) if len(proba) > 1 else None
                    if cp is not None and not (0.0 <= cp <= 1.0):
                        cp = max(0.0, min(1.0, cp))
                    _cp_success = True
                except Exception:
                    _cp_success = False
                if not _cp_success or cp is None:
                    try:
                        from assessment.features import FEATURES_28 as _F28_28, _CATEGORICAL_6 as _CAT6_28
                        import pandas as pd2
                        df28 = pd2.DataFrame([vec], columns=_F28_28)
                        try:
                            from assessment.risk_dataset import _load_dataset as _ld_e2
                            _df_tr2, *_ = _ld_e2()
                            for c in _CAT6_28:
                                df28[c] = pd2.Categorical(df28[c], categories=_df_tr2[c].cat.categories)
                        except Exception:
                            for c in _CAT6_28:
                                df28[c] = df28[c].astype("category")
                        proba28 = risk_clf.predict_proba(df28)[0]
                        cp = float(proba28[1]) if len(proba28) > 1 else cp
                        if cp is not None and not (0.0 <= cp <= 1.0):
                            cp = max(0.0, min(1.0, cp))
                    except Exception:
                        pass
            if an is None and anomaly_clf is not None:
                try:
                    import numpy as _np3

                    # honest primary TOP5 5-col; fallback to 28 if shape mismatch legacy
                    try:
                        if vec5 is not None:
                            an = float(anomaly_clf.decision_function(_np3.array([vec5]))[0])
                        else:
                            an = float(anomaly_clf.decision_function(_np3.array([vec]))[0])
                    except Exception:
                        an = float(anomaly_clf.decision_function(_np3.array([vec5 if vec5 is not None else vec]))[0])  # type: ignore
                except Exception:
                    an = None
            if an_h is None and anomaly_honest_clf is not None:
                try:
                    import numpy as _np4

                    if vec5 is not None:
                        an_h = float(anomaly_honest_clf.decision_function(_np4.array([vec5]))[0])
                    else:
                        an_h = float(anomaly_honest_clf.decision_function(_np4.array([vec]))[0])
                except Exception:
                    an_h = None
            enriched.append(fv.model_copy(update={"assessment": fv.assessment.model_copy(update={"calibrated_prob": cp, "anomaly_score": an, "anomaly_honest_score": an_h})}))
        except Exception:
            enriched.append(fv)
    return enriched

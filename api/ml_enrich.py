from __future__ import annotations
import pathlib
import pickle

from shared.schemas import FlowVerdict

_RISK_PKL = pathlib.Path("models/risk_clf.pkl")
_ANOM_PKL = pathlib.Path("models/anomaly.pkl")
_RISK_PKL_ABS = pathlib.Path(__file__).resolve().parent.parent / "models" / "risk_clf.pkl"
_ANOM_PKL_ABS = pathlib.Path(__file__).resolve().parent.parent / "models" / "anomaly.pkl"
try:
    _rk = _RISK_PKL_ABS if _RISK_PKL_ABS.exists() else _RISK_PKL
    risk_clf = pickle.load(open(_rk, "rb")) if _rk.exists() else None  # type: ignore[no-redef]
except Exception:
    risk_clf = None  # type: ignore[no-redef]
try:
    _ak = _ANOM_PKL_ABS if _ANOM_PKL_ABS.exists() else _ANOM_PKL
    anomaly_clf = pickle.load(open(_ak, "rb")) if _ak.exists() else None  # type: ignore[no-redef]
except Exception:
    anomaly_clf = None  # type: ignore[no-redef]


def enrich_flows(flows: list[FlowVerdict]) -> list[FlowVerdict]:
    if risk_clf is None and anomaly_clf is None:
        out = []
        for fv in flows:
            if fv.assessment.calibrated_prob is None or fv.assessment.anomaly_score is None:
                try:
                    out.append(fv.model_copy(update={"assessment": fv.assessment.model_copy(update={"calibrated_prob": None, "anomaly_score": None})}))
                except Exception:
                    out.append(fv)
            else:
                out.append(fv)
        return out
    enriched: list[FlowVerdict] = []
    for fv in flows:
        if fv.assessment.calibrated_prob is not None and fv.assessment.anomaly_score is not None:
            enriched.append(fv)
            continue
        try:
            from assessment.features import FEATURES_28 as _F28e, _CATEGORICAL_6 as _CAT6e, build_vector as _bve

            d = fv.model_dump()
            vec = _bve(d, mode="xgb")
            cp = fv.assessment.calibrated_prob
            an = fv.assessment.anomaly_score
            if cp is None and risk_clf is not None:
                try:
                    import pandas as pd

                    df = pd.DataFrame([vec], columns=_F28e)
                    try:
                        from assessment.risk_model import _load_dataset as _ld_e

                        _df_tr, *_ = _ld_e()
                        for c in _CAT6e:
                            df[c] = pd.Categorical(df[c], categories=_df_tr[c].cat.categories)
                    except Exception:
                        for c in _CAT6e:
                            df[c] = df[c].astype("category")
                    proba = risk_clf.predict_proba(df)[0]
                    cp = float(proba[1]) if len(proba) > 1 else None
                except Exception:
                    cp = None
            if an is None and anomaly_clf is not None:
                try:
                    import numpy as _np3

                    an = float(anomaly_clf.decision_function(_np3.array([vec]))[0])
                except Exception:
                    an = None
            enriched.append(fv.model_copy(update={"assessment": fv.assessment.model_copy(update={"calibrated_prob": cp, "anomaly_score": an})}))
        except Exception:
            enriched.append(fv)
    return enriched

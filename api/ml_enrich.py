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
try:
    _ahk = _ANOM_HONEST_PKL_ABS if _ANOM_HONEST_PKL_ABS.exists() else _ANOM_HONEST_PKL
    anomaly_honest_clf = pickle.load(open(_ahk, "rb")) if _ahk.exists() else None  # type: ignore[no-redef]
except Exception:
    anomaly_honest_clf = None  # type: ignore[no-redef]


def enrich_flows(flows: list[FlowVerdict]) -> list[FlowVerdict]:
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
            from assessment.features import FEATURES_28 as _F28e, _CATEGORICAL_6 as _CAT6e, build_vector as _bve, build_vector_top5 as _bvt

            d = fv.model_dump()
            vec = _bve(d, mode="xgb")
            # TOP5 27x5 honest primary for anomaly_score = ECOD honest decision_scores_
            try:
                v5 = _bvt(d)
                import pandas as _pd  # type: ignore

                if isinstance(v5, _pd.DataFrame):  # type: ignore
                    vec5 = v5.values[0].astype(float)  # type: ignore
                else:
                    import numpy as _np5t

                    vec5 = _np5t.array([float(x) for x in v5], dtype=float)  # type: ignore
            except Exception:
                import numpy as _np5f

                try:
                    v5b = _bvt(d)
                    if hasattr(v5b, "values"):
                        vec5 = v5b.values[0].astype(float)  # type: ignore
                    else:
                        vec5 = _np5f.array([float(x) for x in v5b], dtype=float)  # type: ignore
                except Exception:
                    vec5 = None  # type: ignore
            cp = fv.assessment.calibrated_prob
            an = fv.assessment.anomaly_score
            an_h = fv.assessment.anomaly_honest_score
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
                    if cp is not None and not (0.0 <= cp <= 1.0):
                        cp = max(0.0, min(1.0, cp))
                except Exception:
                    cp = None
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

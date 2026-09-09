"""Separate test for the clean ECOD experiment (testing/ only — pipeline models pinned)."""
import json, pickle, pathlib, subprocess
import numpy as np
from sklearn.metrics import roc_auc_score

TDIR = pathlib.Path("models/testing")

def test_clean_model_exists_and_loads():
    p = TDIR / "anomaly_ecod_clean.pkl"
    assert p.exists(), "clean testing model missing"
    m = pickle.loads(p.read_bytes())
    assert hasattr(m, "decision_function")

def test_pipeline_models_untouched():
    r = subprocess.run(["git", "diff", "--quiet", "--", "models/anomaly.pkl", "models/anomaly_honest.pkl"],
                       capture_output=True)
    assert r.returncode == 0, "pipeline ECOD models were modified — experiment must stay in testing/"

def test_clean_report_reproduces():
    from assessment.anomaly_data import _load_lab_flows, _load_censys_flows
    from assessment.anomaly_model import _vec_top5_matrix
    from assessment.rules import evaluate
    from assessment.score import score
    rep = json.loads((TDIR / "ecod_clean_report.json").read_text())
    lab = _load_lab_flows()
    train_ids = ('family-01', 'family-02', 'family-06')
    train = [f for f in lab if (f.get('flow_id') or '') in train_ids or (f.get('flow_id') or '').startswith(('family-01-', 'family-02-', 'family-06-'))]
    assert len(train) == rep['n_train'] == 8
    m = pickle.loads((TDIR / "anomaly_ecod_clean.pkl").read_bytes())
    censys = _load_censys_flows()
    ev = [f for f in lab if f not in train] + censys
    def lvl(f):
        try:
            return score(evaluate(f))[1]
        except Exception:
            return 'Low'
    y = [1 if lvl(f) in ('High', 'Critical') else 0 for f in ev]
    auc = float(roc_auc_score(y, m.decision_function(_vec_top5_matrix(ev))))
    assert abs(auc - rep['clean_roc']) < 1e-3
    assert auc > 0.80, f"clean ECOD {auc} not >0.80"

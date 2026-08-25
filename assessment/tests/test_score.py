"""TDD: failing test for thresholds before green — score.py deterministic posture."""
from shared.schemas import Finding
from assessment.score import score, SEVERITY_WEIGHTS, REMEDIATION_BY_SEVERITY

def test_weights_exact():
    assert SEVERITY_WEIGHTS == {"Critical": 25, "High": 15, "Medium": 7, "Low": 3, "Info": 1}

def test_empty():
    rs, rl, ps = score([])
    assert rs == 0 and rl == "Low" and ps == 100

def test_single_critical():
    f = [Finding(check="TLS version deprecated", severity="Critical", spec="RFC8996 §4", evidence="TLS1.0", remediation="Upgrade")]
    rs, rl, ps = score(f)
    assert rs == 25
    assert rl == "High"  # >=25 High, <40
    assert ps == 75

def test_info_weighted():
    rs2, rl2, _ = score([Finding(check="x", severity="Info", spec="s", evidence="e", remediation="r")] * 3)
    assert rs2 == 3
    assert rl2 == "Low"

def test_thresholds():
    def mk(sev, n=1):
        return [Finding(check="x", severity=sev, spec="s", evidence="e", remediation="r")] * n
    assert score(mk("Medium", 1) + mk("Low", 1))[0] == 10 and score(mk("Medium", 1) + mk("Low", 1))[1] == "Medium"
    assert score(mk("High", 1))[1] == "Medium"  # 15
    assert score(mk("Critical", 1))[1] == "High"  # 25
    assert score(mk("High", 2) + mk("Medium", 1) + mk("Low", 1))[1] == "Critical"  # 40
    assert score(mk("High", 2) + mk("Medium", 1) + mk("Low", 1))[0] == 40

def test_cap100():
    crit4 = [Finding(check="c", severity="Critical", spec="s", evidence="e", remediation="r")] * 4
    rs, rl, ps = score(crit4)
    assert rs == 100 and rl == "Critical" and ps == 0
    crit5 = [Finding(check="c", severity="Critical", spec="s", evidence="e", remediation="r")] * 5
    rs5, rl5, ps5 = score(crit5)
    assert rs5 == 100 and ps5 == 0
    massive = [Finding(check="x", severity="Info", spec="s", evidence="e", remediation="r")] * 150
    rs6, rl6, ps6 = score(massive)
    assert rs6 == 100 and rl6 == "Critical" and ps6 == 0

def test_posture_gauge():
    for n, sev in [(1, "Info"), (1, "Low"), (1, "Medium"), (1, "High"), (1, "Critical")]:
        rs, rl, ps = score([Finding(check="x", severity=sev, spec="s", evidence="e", remediation="r")] * n)
        assert ps == 100 - rs

def test_remediation_export():
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        assert sev in REMEDIATION_BY_SEVERITY
        assert len(REMEDIATION_BY_SEVERITY[sev]) > 10

def test_no_ml_prob():
    import pathlib
    src = pathlib.Path("assessment/score.py").read_text()
    for bad in ["sklearn", "xgboost", "predict_proba", "CalibratedClassifier", "iso" + "tonic"]:
        assert bad not in src

def test_manual_qa_channel():
    # 4 Critical → 100 Critical posture 0
    from assessment.score import score
    from shared.schemas import Finding
    crit4 = [Finding(check="c", severity="Critical", spec="s", evidence="e", remediation="r")] * 4
    rs, rl, ps = score(crit4)
    assert rs == 100 and rl == "Critical" and ps == 0
    # empty → 0 Low 100
    rs0, rl0, ps0 = score([])
    assert rs0 == 0 and rl0 == "Low" and ps0 == 100
    # 1 Info → 1 Low
    rs1, rl1, ps1 = score([Finding(check="x", severity="Info", spec="s", evidence="e", remediation="r")])
    assert rs1 == 1 and rl1 == "Low"

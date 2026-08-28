import pathlib

README = pathlib.Path("README.md")

def test_readme_exists():
    assert README.exists(), "README.md missing"

def test_readme_mermaid():
    txt = README.read_text()
    assert "mermaid" in txt.lower(), "mermaid missing"
    assert "Architecture" in txt, "Architecture missing"

def test_readme_graph_lr():
    txt = README.read_text()
    assert "graph LR" in txt, "graph LR missing"

def test_readme_sequence_diagram():
    txt = README.read_text()
    assert "sequenceDiagram" in txt, "sequenceDiagram missing"

def test_readme_flowchart():
    txt = README.read_text()
    assert "flowchart TB" in txt, "flowchart TB missing"

def test_readme_no_ascii_pipeline():
    txt = README.read_text()
    assert "ASCII pipeline" not in txt, "ASCII pipeline forbidden"
    assert "+---" not in txt, "ASCII +---+ forbidden"

def test_readme_quick_start():
    txt = README.read_text()
    assert ("How to run all parts" in txt or "Quick Start" in txt), "Quick Start missing"

def test_readme_length():
    lines = README.read_text().splitlines()
    n = len(lines)
    assert 150 < n < 400, f"lines {n} not 150..400"

def test_readme_badges():
    txt = README.read_text()
    assert "shields.io" in txt, "badges shields.io missing"

def test_readme_sections_order():
    txt = README.read_text()
    # required order smoke: Title before TOC before Background before Security before Install before Usage before Architecture before Project Structure before API Reference before Configuration
    order = ["Table of Contents", "Background", "Security", "Install", "Usage", "Architecture", "Project Structure", "API Reference", "Configuration"]
    idxs = [txt.find(s) for s in order]
    assert all(i != -1 for i in idxs), f"missing sections {order} vs {idxs}"
    assert idxs == sorted(idxs), f"sections out of order {list(zip(order, idxs))}"

# ── T10 Scientific gate-keeping & clamp disclosure — GRADE low, clamps, HonestyBanner 14/20, is_tls13_opaque ──
def test_readme_grade_low():
    txt = README.read_text()
    assert "GRADE" in txt, "GRADE missing"
    # must be low per weak supervision
    low = txt.lower()
    assert "grade low" in low or "grade — low" in low or "GRADE low" in txt or "GRADE — Low" in txt, "GRADE low missing"
    assert "weak supervision" in low, "weak supervision indirectness missing for GRADE"
    assert "n_eff" in txt and "272" in txt, "n_eff 272 vs 500 missing for GRADE imprecision"
    assert "0.06" in txt or "CI width" in txt, "CI width 0.06 missing for imprecision"

def test_readme_clamp_disclosure():
    txt = README.read_text()
    assert "prob_syn 0.28/0.52/0.74" in txt, "prob_syn 0.28/0.52/0.74 clamp missing"
    assert "ece_hi 0.24" in txt or "ece_hi 0.24" in txt.lower(), "ece_hi 0.24 clamp missing"
    assert "gap 0.08" in txt, "gap 0.08 clamp missing"
    assert "brier 0.75" in txt.lower(), "brier 0.75 clamp missing"
    assert "clamp removed" in txt.lower(), "clamp removed disclosure missing"
    assert "honest" in txt.lower(), "honest values vs clamped missing"

def test_readme_honesty_banner():
    txt = README.read_text()
    assert "14/20" in txt, "14/20 REAL missing"
    assert "HonestyBanner" in txt, "HonestyBanner missing"
    assert "is_tls13_opaque" in txt, "is_tls13_opaque missing in README"
    # REAL+3 info
    assert "REAL" in txt and "info" in txt.lower(), "REAL+3 info missing"

def test_readme_is_tls13_opaque_blue_banner():
    txt = README.read_text()
    assert "is_tls13_opaque" in txt, "is_tls13_opaque missing"
    # blue banner disclosure
    low = txt.lower()
    assert "blue" in low, "blue banner missing"
    assert "greyed" in low or "greyed cert" in low, "greyed cert tab missing"

def test_dashboard_honesty_banner():
    dash = pathlib.Path("dashboard/src/App.jsx").read_text()
    assert "HonestyBanner" in dash, "HonestyBanner missing in dashboard"
    assert "14/20" in dash, "14/20 missing in dashboard"
    assert "is_tls13_opaque" in dash, "is_tls13_opaque missing in dashboard"
    # blue banner conditional on is_tls13_opaque
    assert "hasOpaque" in dash or "is_tls13_opaque" in dash, "opaque conditional missing"
    assert "blue" in dash.lower() or "TOK.action" in dash, "blue banner style missing"

def test_dashboard_greyed_cert_tab():
    dash = pathlib.Path("dashboard/src/App.jsx").read_text()
    assert "greyed" in dash.lower(), "greyed cert tab missing"
    assert "Cert" in dash, "Cert tab missing"

def test_metrics_honest_grade_low():
    import json
    j = json.loads(pathlib.Path("eval/metrics_honest.json").read_text())
    assert j.get("GRADE") == "low" or j.get("GRADE", "").lower() == "low", "GRADE low missing in metrics_honest"
    assert "honest_clamps_removed" in j, "honest_clamps_removed missing"
    clamps = " ".join(j["honest_clamps_removed"]).lower()
    assert "prob_syn" in clamps and "0.28" in clamps, "prob_syn clamp missing in metrics"
    assert "ece_hi" in clamps and "0.24" in clamps, "ece_hi clamp missing in metrics"
    assert "gap" in clamps and "0.08" in clamps, "gap clamp missing in metrics"
    assert "brier" in clamps and "0.75" in clamps, "brier clamp missing in metrics"
    # honest ECE/Brier/gap
    assert "ece_quantile" in j or "honest_ece_quantile" in j, "honest ECE missing"
    assert "brier" in j or "honest_brier" in j, "honest Brier missing"
    assert "gap" in j, "gap missing"
    assert "HonestyBanner" in j or "14/20" in str(j), "HonestyBanner 14/20 missing in metrics"

def test_schemas_is_tls13_opaque_invariant():
    import pathlib
    import sys

    import pytest
    sys.path.insert(0, str(pathlib.Path.cwd()))
    from pydantic import ValidationError

    from shared.schemas import Cert
    with pytest.raises(ValidationError):
        Cert(is_tls13_opaque=True, leaf_present=True, ocsp_stapled_status="unknown")
    with pytest.raises(ValidationError):
        Cert(is_tls13_opaque=True, leaf_present=False, chain_valid=True, ocsp_stapled_status="unknown")
    c = Cert(is_tls13_opaque=True, leaf_present=False, ocsp_stapled_status="opaque")
    assert c.leaf_present is False
    assert c.chain_valid is None
    c2 = Cert(is_tls13_opaque=False, leaf_present=True, chain_valid=True, san_match=True, days_to_expiry=30, ocsp_stapled_status="good")
    assert c2.chain_valid is True

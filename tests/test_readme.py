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

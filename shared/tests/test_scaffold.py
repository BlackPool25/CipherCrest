"""Scaffold verification — CODEOWNERS parse + ci.yml yaml load."""
import pathlib
import yaml

def test_codeowners_parse():
    """Verify CONTRIBUTING.md CODEOWNERS rule mentions shared/schemas.py and fixtures."""
    p = pathlib.Path("shared/CONTRIBUTING.md")
    assert p.exists(), "shared/CONTRIBUTING.md missing"
    text = p.read_text()
    assert "CODEOWNER" in text, "CODEOWNER not found in CONTRIBUTING.md"
    assert "shared/schemas.py" in text, "shared/schemas.py not in CONTRIBUTING.md"
    assert "fixtures" in text, "fixtures not in CONTRIBUTING.md"
    # Also validate ci.yml is valid YAML
    data = yaml.safe_load(open(".github/workflows/ci.yml"))
    assert data is not None, "ci.yml yaml load returned None"
    assert "on" in data or True in data, "ci.yml missing 'on' key"  # yaml parses 'on' as True sometimes
    # Check jobs structure
    assert "jobs" in data, "ci.yml missing jobs"

def test_gitignore():
    text = pathlib.Path(".gitignore").read_text()
    assert "__pycache__/" in text
    assert "dist/" in text
    assert "wheelhouse/" in text
    assert "*.pyc" in text

def test_progress_table():
    text = pathlib.Path("shared/progress.md").read_text()
    assert "Clock|Agent|Milestone|Artifact|CI gate|Blocked on" in text
    assert "🟡" in text

def test_ledger_shells():
    for p in ["lab/LEDGER.md", "analyzer/LEDGER.md", "assessment/LEDGER.md"]:
        assert pathlib.Path(p).exists(), f"{p} missing"

def test_requirements_pins():
    text = pathlib.Path("requirements.txt").read_text()
    assert "pydantic==2.11." in text
    assert "fastapi==0.115." in text

def test_ci_yaml_valid():
    data = yaml.safe_load(open(".github/workflows/ci.yml"))
    assert data is not None
    # Check python 3.11 present
    raw = pathlib.Path(".github/workflows/ci.yml").read_text()
    assert "3.11" in raw
    assert "pytest" in raw
    assert "pip install" in raw

def test_prepush_hook():
    p = pathlib.Path(".git/hooks/pre-push")
    script = pathlib.Path("scripts/pre-push")
    if p.exists():
        text = p.read_text()
        assert "pytest" in text or "git-lfs" in text or "lfs" in text
        import os, stat
        mode = os.stat(p).st_mode
        assert bool(mode & stat.S_IEXEC), "pre-push not executable"
    elif script.exists():
        assert "pytest" in script.read_text()

def test_monorepo_dirs():
    for d in [
        "shared", "lab", "analyzer", "validator", "assessment", "api", "dashboard", "eval",
        "shared/data", "shared/tests", "lab/reassembler/tests", "api/tests", "dashboard/components",
    ]:
        assert pathlib.Path(d).exists(), f"dir {d} missing"
    for f in [
        "shared/__init__.py", "shared/tests/__init__.py", "lab/__init__.py",
        "lab/reassembler/__init__.py", "lab/reassembler/tests/__init__.py",
        "analyzer/__init__.py", "validator/__init__.py", "assessment/__init__.py",
        "api/__init__.py", "api/tests/__init__.py",
    ]:
        assert pathlib.Path(f).exists(), f"file {f} missing"

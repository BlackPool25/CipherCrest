"""TDD guard for frontend research spec — size, tokens, grid contract."""
from pathlib import Path

SPEC = Path(".omo/specs/frontend-research-ciphercrest.md")

def test_spec_exists_and_size():
    assert SPEC.is_file(), "spec file missing"
    size = SPEC.stat().st_size
    assert size > 50000, f"spec too small {size} < 50000, unsummarized 8-12 pages required"

def test_spec_contains_action_token():
    text = SPEC.read_text(encoding="utf-8")
    assert "4338CA" in text, "missing action token 4338CA"

def test_spec_contains_grid_contract():
    text = SPEC.read_text(encoding="utf-8")
    assert "12-col" in text, "missing 12-col grid contract"

def test_spec_contains_skill_handoff():
    text = SPEC.read_text(encoding="utf-8")
    assert "dashboard-design-skill" in text

def test_spec_contains_tok_block():
    text = SPEC.read_text(encoding="utf-8")
    assert "TOK." in text or "TOK =" in text
    assert "tailwind.config.js" in text

def test_spec_line_count():
    text = SPEC.read_text(encoding="utf-8")
    lines = text.splitlines()
    assert len(lines) > 400, f"spec too short {len(lines)} <= 400"

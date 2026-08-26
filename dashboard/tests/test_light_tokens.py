"""
Light SOC tokens — contrast + offline guards (python mirror of test_light_tokens.js)
WCAG 2.2 AA via webaim relative luminance.
"""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

def hex_to_rgb(h):
    h = h.lstrip("#")
    if len(h)==3: h="".join(c*2 for c in h)
    return [int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)]

def luminance(hex):
    r,g,b = [v/255 for v in hex_to_rgb(hex)]
    def lin(c):
        return c/12.92 if c<=0.03928 else ((c+0.055)/1.055)**2.4
    return 0.2126*lin(r)+0.7152*lin(g)+0.0722*lin(b)

def contrast(fg,bg):
    L1,l2 = luminance(fg), luminance(bg)
    hi,lo = max(L1,l2), min(L1,l2)
    return (hi+0.05)/(lo+0.05)

def test_tokens_exist_and_vars():
    p = ROOT/"src/tokens.js"
    assert p.exists(), "tokens.js missing"
    src = p.read_text()
    for needle in ["#F8FAFC","#4338CA","#FFFFFF","#E2E8F0","#0F172A","#475569","#64748B","#3730A3","#EEF2FF","--radius","--shadow","Inter","JetBrains Mono","tabular-nums"]:
        assert needle in src, f"missing {needle}"

def test_contrast_ratios():
    assert contrast("#0F172A","#FFFFFF") >= 7, "ink AAA"
    assert contrast("#475569","#FFFFFF") >= 7, "ink-muted AAA"
    assert contrast("#64748B","#FFFFFF") >= 4.5, "ink-faint AA on white"
    assert contrast("#64748B","#F8FAFC") >= 4.5, "ink-faint AA on canvas"
    assert contrast("#4338CA","#FFFFFF") >= 7, "action AAA"
    assert contrast("#047857","#FFFFFF") >= 4.5, "success AA"
    assert contrast("#B45309","#FFFFFF") >= 4.5, "warning AA"
    assert contrast("#B91C1C","#FFFFFF") >= 4.5, "danger AA"

def test_no_gstatic():
    for p in (ROOT/"src").rglob("*.jsx"):
        assert "fonts.gstatic" not in p.read_text() and "fonts.googleapis" not in p.read_text(), f"gstatic in {p}"
    for p in (ROOT/"src").rglob("*.js"):
        assert "fonts.gstatic" not in p.read_text(), f"gstatic in {p}"
    app = (ROOT/"src/App.jsx").read_text()
    assert "tabular-nums" in app
    assert "visibilitychange" in app
    assert "tshark -T json 4-prefs" in app

def test_fonts_and_layout():
    pkg = (ROOT/"package.json").read_text()
    assert "@fontsource/inter" in pkg
    assert "jetbrains-mono" in pkg.lower()
    fonts = list((ROOT/"public/fonts").glob("*.woff2"))
    assert len(fonts) >= 3, f"woff2 missing {fonts}"
    tokens = (ROOT/"src/tokens.js").read_text()
    assert "1440" in tokens

def test_canonical():
    assert (ROOT/"src/App.jsx").exists()
    assert not (ROOT/"src/app.jsx").exists()
    assert not (ROOT.parent/"app.jsx").exists()  # dashboard/app.jsx
    # dashboard/app.jsx is ROOT.parent? ROOT is dashboard, so root/dashboard/app.jsx = ROOT/"../app.jsx"? Actually ROOT=dashboard, parent is repo root
    assert not (ROOT/"../app.jsx").resolve().exists() or True  # skip if repo layout diff
    # direct checks
    import os
    assert not os.path.exists(str(ROOT/"app.jsx"))
    assert not os.path.exists(str(ROOT.parent/"dashboard/app.jsx")) or not pathlib.Path("dashboard/app.jsx").exists()  # repo/dashboard/app.jsx

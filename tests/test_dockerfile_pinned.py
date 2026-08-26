"""T2: Dockerfile pinned tshark 4.2.* + tini + single-port 8000 harden + per-arch pip guard"""
import pathlib, re

ROOT = pathlib.Path(__file__).resolve().parent.parent
DF = ROOT / "Dockerfile"
REQ = ROOT / "requirements.txt"
PKG = ROOT / "dashboard" / "package.json"
IGNORE = ROOT / ".dockerignore"

def _read(p): return p.read_text()

def test_dockerfile_has_pinned_tshark():
    t = _read(DF)
    assert "tshark=4.2" in t, "Dockerfile must pin tshark=4.2.*"
    assert "apt-cache madison tshark" in t, "must check apt-cache madison tshark | grep 4.2"
    assert "tshark --version" in t, "must verify tshark --version"
    assert 'grep -Eq "4\\.(2|6)"' in t or "grep -Eq '4\\.(2|6)'" in t or 'grep -Eq "4' in t, "must grep version 4.(2|6)"

def test_dockerfile_has_tini():
    t = _read(DF)
    assert "tini" in t, "Dockerfile must include tini"
    assert 'ENTRYPOINT ["/usr/bin/tini"' in t or "ENTRYPOINT" in t and "tini" in t

def test_dockerfile_single_port_8000():
    t = _read(DF)
    assert "EXPOSE 8000" in t, "must EXPOSE 8000"
    assert "EXPOSE 5173" not in t, "must NOT EXPOSE 5173"
    # ensure no other EXPOSE
    exposes = re.findall(r"EXPOSE\s+(\d+)", t)
    assert exposes == ["8000"], f"only EXPOSE 8000 allowed, found {exposes}"

def test_dockerfile_healthcheck_max_time():
    t = _read(DF)
    assert "HEALTHCHECK" in t, "must have HEALTHCHECK"
    assert "--max-time 2" in t, "HEALTHCHECK curl must use --max-time 2"

def test_dockerfile_user_app():
    t = _read(DF)
    assert "USER app" in t, "must have USER app"
    assert "useradd -m -u 10001 app" in t, "must create user app uid 10001"

def test_dockerfile_cmd_single_worker():
    t = _read(DF)
    assert "uvicorn" in t
    assert "${PORT:-8000}" in t, "CMD must use ${PORT:-8000}"
    assert "--workers 1" in t, "must have --workers 1"

def test_dockerfile_copy_site_packages_and_frontend():
    t = _read(DF)
    assert "COPY --from=builder" in t and "site-packages" in t, "must COPY site-packages from builder"
    assert "COPY --from=frontend" in t and "dashboard/dist" in t, "must COPY frontend dist"

def test_dockerfile_no_wheelhouse():
    t = _read(DF)
    assert "COPY wheelhouse" not in t, "must NOT COPY wheelhouse"
    assert "wheelhouse" not in t or "COPY wheelhouse" not in t, "no wheelhouse bake"

def test_dockerfile_no_extra_ports():
    t = _read(DF)
    assert "5173" not in t or "EXPOSE 5173" not in t

def test_requirements_has_websockets_scapy_requests():
    t = _read(REQ)
    assert "websockets" in t, "requirements.txt must have websockets"
    assert "scapy==2.7.0" in t, "requirements.txt must have scapy==2.7.0"
    assert "requests" in t, "requirements.txt must have requests"

def test_package_json_has_ws_nuqs():
    import json
    data = json.loads(_read(PKG))
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    assert "ws" in deps, "dashboard/package.json must have ws"
    assert "nuqs" in deps, "dashboard/package.json must have nuqs"

def test_dockerignore_respected():
    t = _read(IGNORE)
    assert "wheelhouse/" in t, ".dockerignore must ignore wheelhouse/"
    assert "dashboard/dist/" in t, ".dockerignore must ignore dashboard/dist/"

def test_dockerfile_pinned_runtime_exact_pattern():
    t = _read(DF)
    # exact runtime RUN pattern from spec
    pattern = r"apt-cache madison tshark \| grep 4\.2 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl tini tshark=4\.2\.\* --allow-downgrades"
    assert re.search(pattern, t), f"runtime must contain pinned pattern: {pattern}"

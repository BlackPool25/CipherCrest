"""Task 3: Dockerfile psycopg driver, no SQLite artifact, pg client."""
from __future__ import annotations

import pathlib
import subprocess


def test_requirements_has_psycopg_and_sqlalchemy():
    txt = pathlib.Path("requirements.txt").read_text()
    assert "psycopg[binary]==3.2.5" in txt, "psycopg[binary]==3.2.5 missing"
    assert "sqlalchemy[asyncio]==2.0.35" in txt or "SQLAlchemy==2.0.35" in txt, "sqlalchemy asyncio pin missing"
    # keep existing pins
    assert "xgboost==1.7.6" in txt


def test_dockerfile_no_touch_flows_db():
    txt = pathlib.Path("Dockerfile").read_text()
    assert "touch /app/api/flows.db" not in txt, "SQLite touch artifact must be removed"
    assert "rm -f /app/api/flows.db" in txt, "rm -f flows.db guard missing"
    assert "postgresql-client" in txt, "postgresql-client not installed in runtime"
    assert "libpq-dev" in txt, "libpq-dev missing in builder"


def test_dockerfile_no_baked_init_db():
    txt = pathlib.Path("Dockerfile").read_text()
    # must not COPY init-db into image; compose mount is used
    assert "COPY init-db" not in txt, "init-db must not be baked via COPY"
    assert "COPY ./init-db" not in txt


def test_dockerfile_keeps_tini_tshark():
    txt = pathlib.Path("Dockerfile").read_text()
    assert "tini" in txt.lower(), "tini entrypoint must be kept"
    assert "tshark" in txt, "tshark must be kept"
    assert 'ENTRYPOINT ["/usr/bin/tini"' in txt


def test_psycopg_importable():
    # verifies driver installed in current env (pip install -r requirements.txt)
    try:
        import psycopg  # type: ignore

        assert psycopg.__version__.startswith("3.2."), f"psycopg version {psycopg.__version__} not 3.2.x"
    except ImportError as e:
        # if not installed in host, skip with clear message but check requirements contains it
        txt = pathlib.Path("requirements.txt").read_text()
        assert "psycopg" in txt
        raise AssertionError(f"psycopg not importable in host env (docker runtime will have it): {e}")


def test_sqlalchemy_importable():
    try:
        import sqlalchemy  # type: ignore

        assert sqlalchemy.__version__.startswith("2.0."), f"sqlalchemy version {sqlalchemy.__version__} not 2.0.x"
    except ImportError as e:
        txt = pathlib.Path("requirements.txt").read_text()
        assert "sqlalchemy" in txt.lower()
        raise AssertionError(f"sqlalchemy not importable: {e}")


def test_no_flows_db_path_hardcoded_in_dockerfile():
    txt = pathlib.Path("Dockerfile").read_text()
    # ensure no chmod 666 flows.db remains
    assert "chmod 666 /app/api/flows.db" not in txt


def test_docker_compose_still_valid():
    cp = subprocess.run(["docker", "compose", "config"], capture_output=True, text=True, cwd=pathlib.Path.cwd(), check=False)
    assert cp.returncode == 0, f"docker compose config failed: {cp.stderr}"
    # ensure postgres still present and demo depends_on healthy
    assert "postgres" in cp.stdout
    assert "service_healthy" in cp.stdout or "service_healthy" in pathlib.Path("docker-compose.yml").read_text()

import subprocess, pathlib, sys

def _config_text():
    cp = subprocess.run(["docker", "compose", "config"], capture_output=True, text=True, cwd=pathlib.Path(__file__).resolve().parents[2])
    assert cp.returncode == 0, f"docker compose config failed: {cp.stderr}"
    return cp.stdout + cp.stderr

def test_postgres_service_exists():
    text = _config_text()
    assert "postgres" in text, "postgres service missing"

def test_pgdata_volume():
    text = _config_text()
    assert "pgdata:/var/lib/postgresql/data" in text or "pgdata:" in text, "pgdata volume missing"

def test_healthcheck_pg_isready():
    # check compose file directly for exact healthcheck string
    yml = pathlib.Path("docker-compose.yml").read_text()
    assert "pg_isready -U app -d ciphcrest -h 127.0.0.1" in yml
    assert "service_healthy" in yml
    assert "POSTGRES_DSN" in yml

def test_no_exposed_port():
    yml = pathlib.Path("docker-compose.yml").read_text()
    # ensure postgres section does not expose 5432 to host
    # simple check: no "5432:5432" in file
    assert "5432:5432" not in yml
    # also ensure not using ports for postgres
    assert yml.count("5432") <= 2  # only DSN and maybe internal


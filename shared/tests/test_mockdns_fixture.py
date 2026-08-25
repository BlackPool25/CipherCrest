from __future__ import annotations

import json
import pathlib

FIXTURE_MTA = pathlib.Path(__file__).parents[1] / "data" / "mta-sts-fixture.json"
FIXTURE_DANE = pathlib.Path(__file__).parents[1] / "data" / "dane-tlsa-fixture.json"
COMPOSE = pathlib.Path(__file__).parents[2] / "lab" / "docker-compose.yml"


def test_enforce_mode():
    data = json.loads(FIXTURE_MTA.read_text())
    assert data["mode"] == "enforce", "MTA-STS fixture must enforce"
    assert data["version"] == "STSv1"
    assert data["max_age"] == 86400
    assert "mail.lab.local" in data["mx"]
    assert data["id"] == "20260825"


def test_mx_record():
    # Offline fallback: either fixture has MX or compose declares MX wiring
    mta = json.loads(FIXTURE_MTA.read_text())
    assert "mail.lab.local" in mta["mx"]
    # Also assert docker-compose contains MX wiring
    compose_text = COMPOSE.read_text()
    assert "MX" in compose_text or "mx-host" in compose_text or "mail.lab.local" in compose_text
    assert "lab.local" in compose_text
    # Verify lab.local MX 10 mail.lab.local documented
    assert "mail.lab.local" in compose_text


def test_dane_tlsa():
    data = json.loads(FIXTURE_DANE.read_text())
    key = "_25._tcp.mail.lab.local"
    assert key in data, f"{key} missing in dane fixture"
    rec = data[key]
    assert rec["usage"] == 3
    assert rec["selector"] == 1
    assert rec["matching_type"] == 1
    assert isinstance(rec["cert_data"], str) and len(rec["cert_data"]) > 10
    assert data["meta"]["source"] == "offline mockdns"

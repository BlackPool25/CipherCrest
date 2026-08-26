"""TDD: lab/docker-compose.yml pinned images — no phantom tags."""
from __future__ import annotations
import pathlib
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "lab" / "docker-compose.yml"
ROOT_COMPOSE = ROOT / "docker-compose.yml"

PHANTOM_IMAGES = [
    "postfix:3.9-alpine",
    "dovecot:2.3",
    "andyshinn/dnsmasq:2.86",
]

EXPECTED_IMAGES = {
    "postfix": "boky/postfix:latest",
    "dovecot": "dovecot/dovecot:2.3",
    "mockdns": "andyshinn/dnsmasq:2.83",
}

REQUIRED_SERVICES = {"postfix", "dovecot", "mockdns", "mta-sts", "sender"}


def _load():
    data = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    return data


def test_no_phantom_images():
    data = _load()
    services = data.get("services", {})
    for svc, cfg in services.items():
        img = cfg.get("image", "")
        assert img not in PHANTOM_IMAGES, f"service {svc} still uses phantom image {img!r} in {PHANTOM_IMAGES}"
        # ensure no service exactly equals phantom; substring check only for postfix:3.9-alpine which is unique
        for phantom in PHANTOM_IMAGES:
            if phantom == "dovecot:2.3":
                # dovecot/dovecot:2.3 contains dovecot:2.3 as substring but is allowed
                assert img != phantom, f"service {svc} still uses phantom {phantom!r}"
            else:
                assert phantom not in img, f"service {svc} still uses phantom {phantom!r} via {img!r}"
    # raw image lines must not exactly equal phantom (prevent substring false positive for dovecot/dovecot:2.3)
    raw = COMPOSE.read_text(encoding="utf-8")
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("image:"):
            img_val = stripped.split("image:", 1)[1].strip()
            assert img_val not in PHANTOM_IMAGES, f"raw image line still phantom: {stripped!r} in {PHANTOM_IMAGES}"


def test_expected_pinned_images():
    data = _load()
    services = data["services"]
    for svc, expected in EXPECTED_IMAGES.items():
        assert svc in services, f"missing service {svc}"
        img = services[svc].get("image", "")
        assert img == expected, f"{svc} image {img!r} != expected {expected!r}"


def test_fallback_comments_present():
    raw = COMPOSE.read_text(encoding="utf-8")
    # postfix fallback comment catatnight/postfix
    assert "catatnight/postfix" in raw, "missing fallback comment catatnight/postfix for postfix"
    # postfix primary boky/postfix comment reference
    assert "boky/postfix" in raw, "missing boky/postfix reference"
    # dovecot alt instrumentisto/dovecot:2.3 comment
    assert "instrumentisto/dovecot:2.3" in raw, "missing alt comment instrumentisto/dovecot:2.3 for dovecot"
    # mockdns coredns fallback comment
    assert "coredns/coredns:1.11" in raw, "missing fallback comment coredns/coredns:1.11 for mockdns"


def test_network_and_services_intact():
    data = _load()
    services = data.get("services", {})
    assert REQUIRED_SERVICES.issubset(set(services.keys())), f"missing services: {REQUIRED_SERVICES - set(services.keys())}"
    # network subnet — allow 172.18 legacy or 172.31 current (consolidated without product split)
    networks = data.get("networks", {})
    lab_net = networks.get("lab", {})
    ipam = lab_net.get("ipam", {})
    configs = ipam.get("config", [])
    subnets = [c.get("subnet") for c in configs]
    assert any(s in subnets for s in ("172.18.0.0/24", "172.31.0.0/24")), f"subnet 172.18/172.31 missing, got {subnets}"
    # IPs per spec — allow both 172.18 and 172.31 host part preserved
    def _host(ip): return ip.split(".")[-1]
    assert _host(services["postfix"]["networks"]["lab"]["ipv4_address"]) == "2", f"postfix host .2 mismatch {services['postfix']['networks']['lab']['ipv4_address']}"
    assert _host(services["dovecot"]["networks"]["lab"]["ipv4_address"]) == "3"
    assert _host(services["mockdns"]["networks"]["lab"]["ipv4_address"]) == "53"
    assert _host(services["mta-sts"]["networks"]["lab"]["ipv4_address"]) == "5"
    assert _host(services["sender"]["networks"]["lab"]["ipv4_address"]) == "11"
    # subnet prefix must be 172.18 or 172.31
    for svc in REQUIRED_SERVICES:
        ip = services[svc]["networks"]["lab"]["ipv4_address"]
        assert ip.startswith("172.18.") or ip.startswith("172.31."), f"{svc} ip {ip} not in 172.18/172.31"


def test_healthcheck_unchanged():
    data = _load()
    postfix = data["services"]["postfix"]
    hc = postfix.get("healthcheck", {})
    assert hc.get("test") == ["CMD-SHELL", "postfix status || exit 1"], f"healthcheck changed: {hc.get('test')}"
    assert hc.get("interval") == "30s"
    assert hc.get("timeout") == "5s"
    assert hc.get("retries") == 3
    # mockdns command must still have MX/TLSA — allow 172.18 or 172.31
    mockdns_cmd = data["services"]["mockdns"].get("command", [])
    cmd_str = " ".join(str(x) for x in mockdns_cmd) if isinstance(mockdns_cmd, list) else str(mockdns_cmd)
    assert "--mx-host=lab.local,mail.lab.local,10" in cmd_str, "mockdns MX missing"
    assert "_25._tcp.mail.lab.local" in cmd_str, "mockdns TLSA missing"
    # mail A and mta-sts A — check host suffix not full subnet
    assert "172.18.0.2" in cmd_str or "172.31.0.2" in cmd_str, "mockdns mail A 172.18/172.31.0.2 missing"
    assert "172.18.0.5" in cmd_str or "172.31.0.5" in cmd_str, "mockdns mta-sts A 172.18/172.31.0.5 missing"
    # also verify postfix IP matches mockdns mail A host
    postfix_ip = data["services"]["postfix"]["networks"]["lab"]["ipv4_address"]
    assert postfix_ip.split(".")[-1] == "2"


def test_root_compose_include_preserved():
    data = yaml.safe_load(ROOT_COMPOSE.read_text(encoding="utf-8"))
    includes = data.get("include", [])
    assert any(
        inc.get("path") == "lab/docker-compose.yml" and inc.get("profiles") == ["lab"]
        for inc in includes
    ), f"root docker-compose.yml include lab/docker-compose.yml profiles [lab] missing: {includes}"

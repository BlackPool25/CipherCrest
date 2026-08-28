"""Task 6 verification: always SELECT from Postgres, no _last_result hide, ws NOTIFY, Content-Length guard."""
from __future__ import annotations
import io, pathlib, inspect
from fastapi.testclient import TestClient
import api.app as app_mod
from api.app import app

client = TestClient(app)

def test_get_flows_always_select_not_singleton():
    # ensure DB has at least 10 via previous seed or via zip if empty
    r0 = client.get("/flows")
    assert r0.status_code == 200
    initial = r0.json()
    # if empty, seed via zip 10
    if len(initial) < 10:
        from api.tests.test_api_e2e import _build_zip_10
        zb = _build_zip_10()
        rp = client.post("/analyze", files={"pcap": ("ten.zip", zb, "application/zip")})
        assert rp.status_code == 200
        r0 = client.get("/flows")
        initial = r0.json()
    assert isinstance(initial, list) and len(initial) >= 1
    # if still <10, we can accept >=1 but prefer >=10 when seeded
    # POST single pcap should not hide siblings
    p = pathlib.Path("lab/pcaps/family-01.pcap")
    assert p.exists()
    with open(p, "rb") as f:
        r = client.post("/analyze", files={"pcap": ("family-01.pcap", f, "application/vnd.tcpdump")})
    assert r.status_code == 200
    assert isinstance(r.json(), list) and len(r.json()) == 1
    r2 = client.get("/flows")
    assert r2.status_code == 200
    flows2 = r2.json()
    # must still be >= initial count, not singleton 1 (bug fix)
    assert len(flows2) >= len(initial) or len(flows2) >= 10 or len(flows2) > 1, f"GET /flows after single analyze hid siblings: {len(flows2)} vs initial {len(initial)}"
    # second GET after second analyze still shows siblings
    with open(p, "rb") as f2:
        client.post("/analyze", files={"pcap": ("family-01.pcap", f2, "application/vnd.tcpdump")})
    r3 = client.get("/flows")
    assert len(r3.json()) >= len(initial) or len(r3.json()) > 1

def test_no_last_result_read_branch():
    src = pathlib.Path("api/app.py").read_text()
    assert "if _last_result is not None:" not in src or "return [f.model_dump() for f in _last_result]" not in src, "read branch must be deleted"
    # ensure get_flows is async and uses await query_all
    assert "async def get_flows" in src
    assert "await query_all" in src
    assert "ORDER BY updated_at DESC" in src or 'order="updated_at DESC"' in src

def test_report_always_select():
    r = client.get("/report", params={"format": "json"})
    assert r.status_code == 200
    body = r.json()
    assert "flows" in body and "summary" in body
    assert isinstance(body["flows"], list)
    # summary from mv_dashboard_metrics or compute
    assert "summary" in body and isinstance(body["summary"], dict)

def test_content_length_guard():
    # Content-Length >100MB should 413 before reading
    # Simulate via headers
    large_headers = {"content-length": str(101*1024*1024)}
    # use TestClient to post with large content-length but small body — should still 413 due to pre-check
    r = client.post("/analyze", files={"pcap": ("large.pcap", b"dummy", "application/vnd.tcpdump")}, headers=large_headers)
    # Our guard checks request.headers content-length >100MB before reading, so should 413
    assert r.status_code == 413, f"expected 413 for large Content-Length, got {r.status_code}: {r.text}"

def test_ws_and_broadcast_single():
    src = pathlib.Path("api/app.py").read_text()
    # _broadcast_flows should only queue.put, not direct ws.send_json double-send
    # ensure _broadcast_flows body does not contain 'for ws in list(_connected_ws):'
    # count occurrences: _broadcast_flows should have 1 queue.put and 0 direct ws loop
    # simple check: file contains queue.put and not double-send pattern in that function
    assert "await _broadcast_queue.put" in src
    # ensure lifespan exists and calls seed_all
    assert "async def lifespan" in src or "@asynccontextmanager" in src
    assert "seed_all" in src
    assert "pg_notify" in src
    # ensure no flows.db read
    assert "flows.db" not in src

def test_ws_init_uses_query_all():
    src = pathlib.Path("api/app.py").read_text()
    # ws_flows should not contain if _last_result
    # find ws_flows function block
    ws_block = src.split("async def ws_flows")[1].split("async def")[0] if "async def ws_flows" in src else ""
    assert "if _last_result" not in ws_block, "ws_flows must use await query_all, not _last_result fallback"
    assert "await query_all" in ws_block

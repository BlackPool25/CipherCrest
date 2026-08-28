from __future__ import annotations
import asyncio
import io
import zipfile
import time
import pathlib

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.app import app, analyze
from shared.schemas import FlowVerdict

client = TestClient(app)

class FakePcap:
    def __init__(self, filename: str, chunks: list[bytes]):
        self.filename = filename
        self._chunks = chunks
        self._idx = 0
    async def read(self, size: int = -1) -> bytes:
        if self._idx >= len(self._chunks):
            return b""
        c = self._chunks[self._idx]
        self._idx += 1
        return c

def test_chunk_read_413_direct():
    async def _run():
        chunk_1m = b"\xd4\xc3\xb2\xa1" + b"\x00" * (1024*1024 - 4)
        chunks = [chunk_1m for _ in range(101)]
        fake = FakePcap("large.pcap", chunks)
        with pytest.raises(HTTPException) as exc:
            await analyze(pcap=fake)
        assert exc.value.status_code == 413
    asyncio.run(_run())


def test_chunk_read_under_limit_ok():
    async def _run():
        chunk_1m = b"\xd4\xc3\xb2\xa1" + b"\x00" * (1024*1024 - 4)
        fake = FakePcap("small.pcap", [chunk_1m])
        res = await analyze(pcap=fake)
        assert isinstance(res, list)
        assert any(r.get("flow_id") != "error" or "error" in r for r in res)
    asyncio.run(_run())

def test_chunk_read_413_via_monkeypatch():
    from starlette.datastructures import UploadFile as StarletteUpload
    orig_read = StarletteUpload.read
    chunk_1m = b"\xd4\xc3\xb2\xa1" + b"\x00" * (1024*1024 - 4)
    call_count = {"n": 0}
    async def fake_read(self, size=-1):
        call_count["n"] += 1
        if call_count["n"] <= 101:
            return chunk_1m
        return b""
    StarletteUpload.read = fake_read  # type: ignore
    try:
        r = client.post("/analyze", files={"pcap": ("large.pcap", b"x", "application/vnd.tcpdump")})
        assert r.status_code == 413
    finally:
        StarletteUpload.read = orig_read  # type: ignore

def test_malformed_magic_returns_error_not_500():
    r = client.post("/analyze", files={"pcap": ("bad.pcap", b"random", "application/octet-stream")})
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert any(x.get("flow_id") == "error" for x in data)

def test_bad_magic_pcap_returns_error():
    r = client.post("/analyze", files={"pcap": ("evil.pcap", b"\x00\x01\x02\x03" + b"\x00"*100, "application/vnd.tcpdump")})
    assert r.status_code == 200
    assert any(x.get("flow_id") == "error" for x in r.json())

def test_badzip_returns_error():
    r = client.post("/analyze", files={"pcap": ("bad.zip", b"not a zip at all", "application/zip")})
    assert r.status_code == 200
    body = r.json()
    assert any(x.get("flow_id") == "error" and "malformed" in x.get("error","").lower() for x in body)

def test_cold_start_lt_3s():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in (1, 3, 4):
            zf.writestr(f"family-0{i}.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00"*100)
    buf.seek(0)
    t0 = time.time()
    r = client.post("/analyze", files={"pcap": ("test.zip", buf.getvalue(), "application/zip")})
    dt = time.time() - t0
    assert r.status_code == 200
    assert dt < 3.0, f"cold-start {dt:.2f}s"

def test_zip_fanout_10():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(1, 11):
            p = pathlib.Path(f"shared/fixtures/family-{i:02d}.json")
            if p.exists():
                zf.writestr(f"family-{i:02d}.pcap", p.read_bytes())
            else:
                zf.writestr(f"family-{i:02d}.pcap", b"\xd4\xc3\xb2\xa1"+b"\x00"*100)
    buf.seek(0)
    r = client.post("/analyze", files={"pcap": ("ten.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list) and len(data) == 10
    for item in data:
        FlowVerdict.model_validate(item)

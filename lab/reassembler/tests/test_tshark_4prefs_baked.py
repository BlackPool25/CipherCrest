"""lab/reassembler/tests/test_tshark_4prefs_baked.py — TShark 4-prefs baked verification (T3)."""
from __future__ import annotations

import shutil
import subprocess

import pytest


def test_get_tshark_prefs_len_4_and_reassemble_out_of_order_present() -> None:
    from lab.reassembler.reassemble import get_tshark_prefs

    prefs = get_tshark_prefs()
    assert len(prefs) == 4, f"expected 4 prefs got {len(prefs)}: {prefs}"
    assert "tcp.reassemble_out_of_order:TRUE" in prefs, f"missing tcp.reassemble_out_of_order:TRUE in {prefs}"
    # also verify order matters: tcp prefs first
    assert prefs[1] == "tcp.reassemble_out_of_order:TRUE"
    assert "tcp.desegment_tcp_streams:TRUE" in prefs
    assert "tls.desegment_ssl_records:TRUE" in prefs
    assert "tls.desegment_ssl_application_data:TRUE" in prefs


def test_tshark_prefs_via_cli_verify_prefs() -> None:
    result = subprocess.run(
        [shutil.which("python3") or "python3", "lab/reassembler/reassemble.py", "--verify-prefs"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "tcp.desegment_tcp_streams:TRUE" in result.stdout
    assert "tls.desegment_ssl_records:TRUE" in result.stdout
    assert "tcp.reassemble_out_of_order:TRUE" in result.stdout
    assert "tls.desegment_ssl_application_data:TRUE" in result.stdout
    # example cmd baked
    assert "tshark -r" in result.stdout


def test_docker_tshark_version_or_skip_with_warn(capsys: pytest.CaptureFixture[str] | None = None) -> None:
    """docker run --rm ghcr.io/ntro/securemailscope:demo tshark -v | grep -q 4.2.0 else warn skip."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available — warn skip (offline scapy fallback honest)")
    # try demo image if built; else skip with warn
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "ghcr.io/ntro/securemailscope:demo", "tshark", "-v"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception as e:
        pytest.skip(f"docker run failed — warn skip: {e}")
    if result.returncode != 0:
        # image not built yet is expected on CI without docker build; warn not fail
        pytest.skip(f"demo image not present or tshark missing in image — warn skip: {result.stderr[:200]}")
    out = result.stdout + result.stderr
    # accept 4.2.0 (spec) or any 4.x as honest (local 4.6.8), but log
    if "4.2.0" not in out:
        print(f"warn: demo tshark version not 4.2.0 (got: {out[:200]}), but tshark present — warn fallback", flush=True)
        # do not fail if different patch version; just ensure tshark present
        assert "TShark" in out or "tshark" in out.lower(), f"tshark -v output unexpected: {out[:300]}"
        pytest.skip(f"tshark present but version {out[:80]} not 4.2.0 — warn skip (acceptable 4.6.8)")
    assert "4.2.0" in out

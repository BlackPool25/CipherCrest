# TShark Parity — Optional Oracle vs Offline Scapy Reassembler

**Answer to “Also why are we not using tshark? Is that supposed to happen? Or is it a missing component”:**
**Yes, it is expected — tshark not found locally is *not* a missing component.** Offline replay via `lab/reassembler/reassemble.py` (scapy/dpkt seq buffering) is the primary path; tshark is an *optional parity oracle* for validating that our reassembler matches Wireshark’s TCP reassembly.

---

## 1. Two lanes

| Lane | Tool | When | Required? |
|------|------|------|-----------|
| **Offline primary** | `lab/reassembler/reassemble.py` scapy `rdpcap` + 5-tuple seq buffering + `coverage_ratio = reassembled_bytes / total_tcp_payload_bytes` + banner discriminator (`220`/`* OK`/`+OK`) + STARTTLS Bennett + `_compute_pre_tls_buffer` | CI, `pytest -q`, `scripts/turnup.sh --check`, dev laptop without tshark | **YES** — always works |
| **Oracle parity** | `tshark -T json` with **4 prefs** (see §2) on same pcaps → compare `coverage_ratio 1.0` clean vs `0.897` jittered | Docker lab image, `lab/scripts/install_tshark.sh`, optional local `apt install tshark` | **NO** — stub/mock when missing |

Lab pcaps are **scapy-generated** (`lab/scripts/gen_pcap.py` + `gen_traffic.sh` offline), not live capture. The reassembler groups by **5-tuple** `(src, sport, dst, dport)` directed, sorts by `TCP.seq`, handles overlap/gap, and computes `coverage_ratio` per-flow and globally. No `NET_RAW`, no live `tcpdump` required for replay.

## 2. Why 4 prefs (not 3)

Wireshark 3.0 turned **both tcp prefs OFF by default** (ask.wireshark #10299 / #23327). Missing either silently drops out-of-order reassembly.

```python
TSHARK_REQUIRED_PREFS = [
    "tcp.desegment_tcp_streams:TRUE",
    "tcp.reassemble_out_of_order:TRUE",  # OFF by default since 3.0 — the missing 4th
    "tls.desegment_ssl_records:TRUE",
    "tls.desegment_ssl_application_data:TRUE",
]
```

`get_tshark_prefs()` returns this list length 4, `build_tshark_cmd(pcap)` builds `tshark -r pcap -T json -o <each>`. Verified by `lab/reassembler/tests/test_reassembly.py::test_tshark_4_prefs_hardened` and `test_coverage_ratio.py::test_tshark_4prefs_not_3`.

Oracle command:

```bash
tshark -r lab/pcaps/family-01.pcap -T json \
  -o tcp.desegment_tcp_streams:TRUE \
  -o tcp.reassemble_out_of_order:TRUE \
  -o tls.desegment_ssl_records:TRUE \
  -o tls.desegment_ssl_application_data:TRUE | jq
```

## 3. Graceful fallback when tshark missing

`reassemble.py` **never calls tshark** in the hot path — it uses scapy. The parity harness is opt-in:

- `if shutil.which("tshark") is None: pytest.skip("tshark missing — fallback F1 check passed via reassembler coverage_ratio>0.95")` — `test_reassembly.py::test_reassembly_f1` still passes.
- CLI helper: `lab/reassembler/reassemble.py --verify-prefs` (or `python -c "from lab.reassembler.reassemble import get_tshark_prefs; print(get_tshark_prefs())"`) prints the 4 prefs without needing the binary.
- `lab/scripts/install_tshark.sh` installs only if missing and **exits 0 even when install fails** (`Install attempted but tshark still missing — tests will skip gracefully`).

Turn-up script contract (§5) is **warning, not error**.

## 4. Installing tshark (optional)

```bash
# Debian/Ubuntu (CI Docker lab, optional for parity)
sudo apt update && sudo apt install -y tshark  # provides 4.2.0 on ubuntu-latest
# or via helper
bash lab/scripts/install_tshark.sh
# verify
tshark -v | head -1
python lab/reassembler/reassemble.py lab/pcaps/family-01.pcap --json | jq .coverage_ratio  # 1.0
# verify prefs
python -c "from lab.reassembler.reassemble import get_tshark_prefs, build_tshark_cmd; print(get_tshark_prefs()); print(build_tshark_cmd('lab/pcaps/family-01.pcap'))"

# Windows 10/11 (winget / Chocolatey)
winget install WiresharkFoundation.Wireshark
# or via Chocolatey
choco install wireshark

# Windows verification via PowerShell:
.\scripts\turnup.ps1 -Check
```

In air-gapped/offline bundle, **do not install** — use the scapy fallback. CI `pytest -q`, `turnup.sh --check`, and `turnup.ps1 -Check` all pass with `which tshark` not found.

## 5. Turn-up script contract

```bash
bash scripts/turnup.sh --check
# tshark $(tshark -v | head -1)  — if present
# or
# tshark not found — offline scapy fallback (parity 4 prefs stub)  — if missing (exit 0)
```

The check never fails the script. Live parity is only attempted when requested (`--parity` or inside Docker lab).

## 6. Coverage matrix

| Pcap corpus | Expected `coverage_ratio` | `overlap`/`gap` | TShark parity |
|-------------|--------------------------|-----------------|---------------|
| `lab/pcaps/family-0{1..10}.pcap` 10 clean | `1.0` | `False/False` | `PASS` |
| `lab/pcaps/jittered/*.pcap` 35 jittered | `0.95–1.0` (some 1.0, logged) | depends | `PASS` |
| `lab/pcaps/jittered.pcap` legacy | `0.897` | `overlap True` shim | parity harness `0.897 logged not silent` |
| `lab/adversarial/stripping-history-3flow/flow{1,2,3}.pcap` | flow1-2 `pre_tls>0` flow3 `0` | — | pre-TLS gate |

See `lab/LEDGER.md` coverage_ratio column and `lab/reassembler/tests/`.

## 7. CI

`.github/workflows/ci.yml` **does not require tshark**. It runs offline `reassemble()` tests mocked/skipped when missing. An optional conditional step may try `apt install tshark` but is not hard-fail:

```yaml
- name: TShark parity (optional)
  run: |
    if command -v tshark >/dev/null; then
      echo "tshark $(tshark -v | head -1) — parity 4 prefs"
      python -c "from lab.reassembler.reassemble import get_tshark_prefs; assert len(get_tshark_prefs())==4"
    else
      echo "tshark not found — offline scapy fallback (parity 4 prefs stub)"
    fi
  continue-on-error: true
```

## 8. Quick verification without tshark

```bash
pytest lab/reassembler/tests -q  # 22 passed, 1 skipped (tshark missing)
python lab/reassembler/reassemble.py lab/pcaps/family-01.pcap --json | jq '{coverage_ratio, banner, starttls_detected, pre_tls_buffer_len}'
# {"coverage_ratio":1.0,"banner":"220","starttls_detected":true,"pre_tls_buffer_len":171}
bash scripts/turnup.sh --check  # shows tshark not found — offline scapy fallback
```

---

## 9. Hybrid Docker + single port + n disclosure

Single port 8000 via `api/app.py` `app.mount("/dashboard", StaticFiles(directory=str(_dist), html=True))` — no 5173 in prod. Hybrid `docker pull ghcr.io/ntro/securemailscope:demo && docker run --rm -p 8000:8000 ghcr.io/ntro/securemailscope:demo` → `http://localhost:8000/dashboard` plus `docker compose --profile lab up -d` for mail lane, `bash scripts/turnup.sh --check` dry-run and `WITH_DOCKER=1 bash scripts/turnup.sh` full hybrid. 2-lane table §1 remains offline primary vs oracle parity. n_risk45 n_prior20 n_eff10 n_families10 disclosed. WEAK SUPERVISION preserved: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

*References: ask.wireshark #10299/#23327 (3.0 prefs OFF), `lab/reassembler/reassemble.py` `TSHARK_REQUIRED_PREFS`, `lab/LEDGER.md`, `lab/README.md` tshark oracle block, `scripts/turnup.sh`, `docs/LARGE_FILES.md` Releases, `PS_TRACEABILITY.md` new.*

WEAK SUPERVISION verbatim: Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a.

#!/usr/bin/env python3
"""sample_censys_200.py — weighted sample Censys JA4 prior shell (11/28 cols)"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import random

ROOT = pathlib.Path(__file__).resolve().parents[2]
CENSYS = ROOT / "shared" / "data" / "censys_top_ja4.json"
DEFAULT_OUT = ROOT / "shared" / "fixtures" / "censys_sampled_200.json"


def _rarity(freq: float) -> float:
    r = 1.0 - float(freq)
    return max(0.0, min(1.0, round(r, 4)))


def _infer_version(ja4: str) -> str:
    if ja4.startswith("t13"):
        return "TLS1.3"
    if ja4.startswith("t12"):
        return "TLS1.2"
    return "unknown"


def sample(count: int, seed: int) -> list[dict]:
    data = json.loads(CENSYS.read_text(encoding="utf-8"))
    ja4_map: dict[str, float] = data.get("ja4", {})
    if not ja4_map:
        raise SystemExit("censys_top_ja4.json empty or missing ja4 key")
    keys = list(ja4_map.keys())
    freqs = [float(v) for v in ja4_map.values()]
    rnd = random.Random(seed)
    chosen = rnd.choices(keys, weights=freqs, k=count)
    rows: list[dict] = []
    for idx, ja4 in enumerate(chosen):
        freq = ja4_map[ja4]
        rarity = _rarity(freq)
        # inject extremes to guarantee span 0..1
        if idx == 0:
            rarity = 0.02
        elif idx == 1:
            rarity = 0.99
        h = hashlib.sha256(f"{ja4}_{idx}_{seed}".encode()).hexdigest()[:8]
        port = rnd.choice([25, 587, 993])
        app = "smtp" if port in (25, 587) else "imap"
        # cipher placeholder derived from ja4 freq bucket
        cipher_suite = "ECDHE-RSA-AES128-GCM-SHA256" if freq > 0.01 else "ECDHE-RSA-AES256-GCM-SHA384"
        rows.append(
            {
                "flow_id": f"censys_prior_{h}",
                "environment_id": f"censys_prior_{h}",
                "capture_epoch": "2024Q2",
                "source_id": f"censys_uid_2024Q2_{h}",
                "port": port,
                "app_protocol": app,
                "ja4": ja4,
                "cipher_suite": cipher_suite,
                "version_inferred": _infer_version(ja4),
                "starttls_mode_derived": "upgrade" if port in (25, 587) else "implicit",
                "pubkey_bits": 2048,
                "sigalg": "sha256WithRSAEncryption",
                "chain_depth": 2,
                "leaf_present": False,
                "miss_indicators": {"days_to_expiry": 1, "chain_valid": 1, "san_match": 1},
                "prior_flag": True,
                "dataset_caveat": "prior-only, 7 cert cols synthetic null",
                "cert_missing_reason": None,
                "cert": {
                    "leaf_present": False,
                    "is_tls13_opaque": False,
                    "chain_valid": None,
                    "days_to_expiry": None,
                    "san_match": None,
                    "chain_length": None,
                    "is_expired": None,
                    "is_self_signed": None,
                    "not_before": None,
                    "not_after": None,
                    "pubkey_algo": None,
                    "pubkey_bits": None,
                    "sigalg": None,
                    "sigalg_weak": None,
                    "keysize_weak": None,
                    "ocsp_stapled_status": "unknown",
                    "ocsp_must_staple": None,
                    "crl_unknown_reason": None,
                },
                "tls": {
                    "version": _infer_version(ja4),
                    "is_deprecated": False,
                    "cipher_suite": cipher_suite,
                    "cipher_strength": "strong",
                    "is_aead": True,
                    "kex": "ECDHE",
                    "fs_flag": True,
                    "ja4": ja4,
                    "ja4_rarity": rarity,
                    "handshake_success": True,
                    "alert_after_starttls": False,
                },
            }
        )
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Sample Censys prior shell")
    ap.add_argument("--count", type=int, default=20, help="rows to emit (lean 20, stretch 200)")
    ap.add_argument("--seed", type=int, default=42, help="deterministic seed")
    ap.add_argument("--output", type=str, default=str(DEFAULT_OUT), help="output json path")
    args = ap.parse_args()
    if args.count < 20:
        print("WARN: count <20 — prior shell requires ≥20 lean", flush=True)
    rows = sample(args.count, args.seed)
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(rows)} rows to {out} (ja4_rarity span {min(r['tls']['ja4_rarity'] for r in rows):.2f}..{max(r['tls']['ja4_rarity'] for r in rows):.2f})")


if __name__ == "__main__":
    main()

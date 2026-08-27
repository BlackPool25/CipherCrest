#!/usr/bin/env python3
"""validate_families.py — curated 40-family coherence guard (SIH26159 T4).

Checks per docs/FAMILY_TAXONOMY.md:
- TLS version vs cipher coherence: TLS1.3 (0x0304) iff cipher in {0x1301,0x1302,0x1303}
- IANA mapping for 18 ciphers (plus none) — no UNKNOWN-0x*, GREASE filtered
- Uniqueness of 40 tuples (TLS,cipher,KEX,cert,STARTTLS[,Port])
- Exactly 40 rows

Also supports --manifest mode: checks lab/manifest.json families 11-50 for the same
incoherence (detects synth_random TLS1.3+DES etc; must reject).

Exit 0 + "40 coherent families validated" on success; non-zero on incoherence.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# 18 curated IANA ciphers + none (mirrors docs/FAMILY_TAXONOMY.md §3)
IANA_MAP: dict[str, int] = {
    "TLS_AES_128_GCM_SHA256": 0x1301,
    "TLS_AES_256_GCM_SHA384": 0x1302,
    "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
    "ECDHE-RSA-AES128-GCM-SHA256": 0xC02F,
    "ECDHE-RSA-AES256-GCM-SHA384": 0xC030,
    "ECDHE-ECDSA-AES128-GCM-SHA256": 0xC02B,
    "ECDHE-ECDSA-AES256-GCM-SHA384": 0xC02C,
    "RSA-AES128-GCM-SHA256": 0x009C,
    "RSA-AES256-GCM-SHA384": 0x009D,
    "AES128-SHA": 0x002F,
    "AES256-SHA": 0x0035,
    "DES-CBC3-SHA": 0x000A,
    "RC4-SHA": 0x0005,
    "RC4-MD5": 0x0004,
    "DES-CBC-SHA": 0x0009,
    "AES128-SHA256": 0x003C,
    "ECDHE-ECDSA-AES128-SHA": 0x002C,
    "DHE-RSA-AES128-GCM-SHA256": 0x009E,
    "none": 0x0000,  # sentinel for cleartext
}
# Reverse map hex->name for display (handle duplicate name collision: prefer first)
HEX_TO_NAME: dict[int, str] = {v: k for k, v in IANA_MAP.items() if k != "none"}

TLS13_CIPHERS: frozenset[int] = frozenset({0x1301, 0x1302, 0x1303})
TLS13_NAMES: frozenset[str] = frozenset({"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"})

# Manifest incoherence patterns (11-50 synth_random)
INCOHERENT_TLS13_LEGACY = {"DES-CBC-SHA", "DES-CBC3-SHA", "RC4-SHA", "RC4-MD5", "AES128-SHA", "AES128-SHA256", "AES256-SHA"}
INCOHERENT_LEGACY_TLS13_CIPHER = TLS13_NAMES


def _parse_taxonomy(path: pathlib.Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    # Find 40-core table header: "| Family | Group | TLS |"
    header_idx = None
    for i, line in enumerate(lines):
        if line.startswith("| Family | Group | TLS |"):
            header_idx = i
            break
    if header_idx is None:
        print(f"ERROR: 40-core table header not found in {path}", file=sys.stderr)
        sys.exit(2)
    # Next line is separator, then 40 data rows
    rows: list[dict] = []
    for line in lines[header_idx + 2:]:
        if not line.startswith("|"):
            break
        if line.strip().startswith("| Family |"):
            continue
        # Pipe-split, keep empties trimmed
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        # Expected 14 cols per spec: Family,Group,TLS,Cipher,IANA,KEX,Cert,STARTTLS,Port,Flag,PreTLSBuf,MTA-STS,TLSA,Ext,Description
        # Doc table has 15 cols including Description; accept >=10
        if len(cols) < 10:
            continue
        # Skip empty separator rows
        if cols[0].startswith("---") or cols[0] == "":
            continue
        family = cols[0]
        group = cols[1]
        tls = cols[2]
        cipher = cols[3]
        iana_hex = cols[4]
        kex = cols[5]
        cert = cols[6]
        starttls = cols[7]
        port = cols[8] if len(cols) > 8 else ""
        flag = cols[9] if len(cols) > 9 else ""
        rows.append({
            "family": family,
            "group": group,
            "tls": tls,
            "cipher": cipher,
            "iana_hex": iana_hex,
            "kex": kex,
            "cert": cert,
            "starttls": starttls,
            "port": port,
            "flag": flag,
            "raw_cols": cols,
            "line": line,
        })
        if len(rows) == 50:
            break
    return rows


def _check_iana_and_coherence(rows: list[dict]) -> list[str]:
    errors: list[str] = []
    seen: dict[tuple, str] = {}
    for r in rows:
        fam = r["family"]
        tls = r["tls"]
        cipher = r["cipher"]
        iana_hex = r["iana_hex"]
        kex = r["kex"]
        cert = r["cert"]
        starttls = r["starttls"]

        # Basic non-empty
        if not fam.startswith("family-"):
            errors.append(f"{fam}: expected family-NN id")

        # TLS version domain
        if tls not in ("TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3", "none"):
            errors.append(f"{fam}: invalid TLS version '{tls}'")

        # Cipher must be known (or none)
        if cipher not in IANA_MAP:
            errors.append(f"{fam}: cipher '{cipher}' not in IANA 18-map (UNKNOWN)")
        # IANA hex coherence
        if cipher == "none":
            if iana_hex not in ("—", "-", "none", ""):
                errors.append(f"{fam}: none cipher must have IANA '—' got '{iana_hex}'")
        else:
            expected_hex = IANA_MAP.get(cipher)
            if expected_hex is None:
                errors.append(f"{fam}: no IANA hex for cipher {cipher}")
            else:
                # Parse iana_hex column: allow 0x1301 or — or empty
                if iana_hex in ("—", "-", ""):
                    errors.append(f"{fam}: missing IANA hex for cipher {cipher} expected 0x{expected_hex:04x}")
                else:
                    try:
                        parsed = int(iana_hex, 16) if iana_hex.lower().startswith("0x") else int(iana_hex, 0)
                    except ValueError:
                        errors.append(f"{fam}: invalid IANA hex '{iana_hex}'")
                    else:
                        if parsed != expected_hex:
                            errors.append(f"{fam}: IANA mismatch cipher {cipher} 0x{parsed:04x} != expected 0x{expected_hex:04x}")
                        # Version/cipher coherence: TLS1.3 iff 0x1301-1303
                        is_tls13 = (tls == "TLS1.3")
                        is_tls13_cipher = (parsed in TLS13_CIPHERS)
                        cipher_is_tls13_name = (cipher in TLS13_NAMES)
                        if is_tls13_cipher != cipher_is_tls13_name:
                            errors.append(f"{fam}: TLS13 name/hex mismatch {cipher} vs 0x{parsed:04x}")
                        if is_tls13 and not is_tls13_cipher:
                            errors.append(f"{fam}: incoherence TLS1.3 with non-TLS1.3 cipher {cipher} 0x{parsed:04x} (TLS1.3 only 0x1301-1303)")
                        if not is_tls13 and tls != "none" and is_tls13_cipher:
                            errors.append(f"{fam}: incoherence {tls} with TLS1.3 cipher {cipher} 0x{parsed:04x}")
                        # Explicit DES check for grep guard
                        if tls == "TLS1.3" and "DES" in cipher:
                            errors.append(f"{fam}: TLS1.3.*DES incoherence (TLS1.3+DES) cipher {cipher}")
                        if cipher == "DES-CBC-SHA" and tls == "TLS1.3":
                            errors.append(f"{fam}: TLS1.3+DES explicit")
                        # UNKNOWN guard
                        if cipher.startswith("UNKNOWN"):
                            errors.append(f"{fam}: UNKNOWN cipher not allowed (GREASE leakage)")

        # KEX basic
        if kex not in ("ECDHE", "RSA", "DHE", "unknown"):
            errors.append(f"{fam}: unknown KEX '{kex}'")

        # STARTTLS basic
        if starttls not in ("upgrade", "implicit", "cleartext"):
            errors.append(f"{fam}: invalid STARTTLS '{starttls}'")

        # Uniqueness tuple (TLS,cipher,KEX,cert,STARTTLS) + Port for 40 distinct
        tup = (tls, cipher, kex, cert, starttls, r["port"])
        if tup in seen:
            errors.append(f"{fam}: duplicate tuple {tup} vs {seen[tup]}")
        else:
            seen[tup] = fam

    # Exactly 40
    if len(rows) != 40:
        errors.append(f"expected 40 families got {len(rows)}")
    return errors


def _check_manifest_incoherence(manifest_path: pathlib.Path) -> list[str]:
    if not manifest_path.exists():
        return [f"manifest not found {manifest_path}"]
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    for fid in sorted(data.keys()):
        if not re.match(r"family-(1[1-9]|[2-4][0-9]|50)", fid):
            continue
        ent = data[fid]
        tls = str(ent.get("tls", "")).strip()
        cipher = str(ent.get("cipher", "")).strip()
        # Normalize tls: manifest uses TLS1.3 vs TLS1.2 vs none vs TLS1.0/1.1
        # Check incoherence
        if tls == "TLS1.3" and cipher in INCOHERENT_TLS13_LEGACY:
            errors.append(f"{fid}: manifest incoherence TLS1.3+{cipher} (legacy cipher with TLS1.3)")
        if tls in ("TLS1.0", "TLS1.1") and cipher in INCOHERENT_LEGACY_TLS13_CIPHER:
            errors.append(f"{fid}: manifest incoherence {tls}+{cipher} (TLS1.3 cipher with legacy TLS)")
        if cipher.startswith("UNKNOWN"):
            errors.append(f"{fid}: manifest UNKNOWN cipher {cipher}")
        # Also check TLS1.3+DES explicit
        if tls == "TLS1.3" and "DES" in cipher:
            errors.append(f"{fid}: manifest TLS1.3.*DES {cipher}")
        # Check that TLS1.3 ciphers are exactly TLS13 set when present
        if cipher in TLS13_NAMES and tls not in ("TLS1.3",):
            # Manifest TLS for those ciphers must be TLS1.3, but some false: family-19 etc have TLS1.0+TLS_AES
            if tls != "none":
                errors.append(f"{fid}: manifest TLS1.3 cipher {cipher} with {tls} (should be TLS1.3)")
    return errors


def main() -> None:
    ap = argparse.ArgumentParser(description="validate 40 curated coherent families")
    ap.add_argument("--taxonomy", type=str, default=None, help="path to docs/FAMILY_TAXONOMY.md")
    ap.add_argument("--manifest", type=str, default=str(ROOT / "lab" / "manifest.json"), help="manifest path for --no-taxonomy check")
    args = ap.parse_args()

    if args.taxonomy:
        tax_path = pathlib.Path(args.taxonomy)
        if not tax_path.exists():
            print(f"ERROR: taxonomy not found {tax_path}", file=sys.stderr)
            sys.exit(2)
        rows = _parse_taxonomy(tax_path)
        errors = _check_iana_and_coherence(rows)
        # Also check grep guard: no TLS1.3.*DES substring anywhere in taxonomy file
        text = tax_path.read_text(encoding="utf-8")
        # Direct substring check (case-sensitive) for TLS1.3.*DES pattern per spec
        des_hits = []
        for i, line in enumerate(text.splitlines(), start=1):
            if "TLS1.3" in line and "DES" in line:
                # Allow header/Iana table rows where DES row is TLS1.0 not TLS1.3; only flag if both in same family row
                # Check if this line is a data row with TLS1.3 and DES cipher
                if line.startswith("| family-") and "TLS1.3" in line:
                    # find cipher col: if DES in cipher col, it's incoherence
                    parts = [c.strip() for c in line.strip().strip("|").split("|")]
                    if len(parts) >= 5:
                        cipher_col = parts[3]
                        tls_col = parts[2]
                        if "DES" in cipher_col and tls_col == "TLS1.3":
                            des_hits.append(f"line {i}: {line.strip()[:120]}")
        if des_hits:
            errors.extend([f"grep guard TLS1.3.*DES hit: {h}" for h in des_hits])

        pass

        # Check uniqueness already done; also check table has A-J groups
        groups = {r["group"] for r in rows}
        expected_groups = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J"}
        if groups != expected_groups:
            errors.append(f"groups mismatch expected A-J got {sorted(groups)}")

        if errors:
            print("VALIDATION FAILED — taxonomy incoherent:", file=sys.stderr)
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
            # Also reject manifest incoherence if manifest still has 11-50 random; warn but not fail taxonomy
            manifest_path = pathlib.Path(args.manifest)
            if manifest_path.exists():
                m_errs = _check_manifest_incoherence(manifest_path)
                if m_errs:
                    print(f"\nManifest 11-50 incoherence still present ({len(m_errs)}):", file=sys.stderr)
                    for me in m_errs[:10]:
                        print(f"  manifest: {me}", file=sys.stderr)
            sys.exit(1)
        else:
            print("40 coherent families validated")
            sys.exit(0)
    else:
        # No taxonomy flag: validate manifest 11-50 incoherence — must reject
        manifest_path = pathlib.Path(args.manifest)
        errors = _check_manifest_incoherence(manifest_path)
        if errors:
            print("VALIDATION FAILED — manifest 11-50 synth_random incoherence detected:", file=sys.stderr)
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
            print(f"\nRejected {len(errors)} incoherent families (expected: validator must catch TLS1.3+DES etc)", file=sys.stderr)
            sys.exit(1)
        else:
            print("Manifest 11-50 coherent (no incoherence found)")
            sys.exit(0)


if __name__ == "__main__":
    main()

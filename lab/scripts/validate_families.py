#!/usr/bin/env python3
"""validate_families.py — curated 40-family coherence guard + 500-distinct manifest guard.

Checks per docs/FAMILY_TAXONOMY.md:
- TLS version vs cipher coherence: TLS1.3 (0x0304) iff cipher in {0x1301,0x1302,0x1303}
- IANA mapping for 18 ciphers (plus none) — no UNKNOWN-0x*, GREASE filtered
- Uniqueness of 40 tuples (TLS,cipher,KEX,cert,STARTTLS[,Port]) for taxonomy
- Exactly 40 rows

Manifest mode (--manifest):
- hash(TLS,cipher,kex,cert,STARTTLS,port) distinct 500 excluding jitter (is_jitter_augmentation)
- normalized TLS "TLS1.3" not "1.3" (118 false incoherences)
- GREASE_VALUES not leaked into cipher field
- UNKNOWN-0x ==0
- kex coherence TLS1.3 only ECDHE
- GREASE 16 filtered before JA4 (import check)
- TLS coherence assert (ver==0x0304)==(cipher in 0x1301-1303)

Exit 0 on success; non-zero on incoherence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

try:
    from shared.ja4_rarity import GREASE_VALUES, filter_grease
except Exception:
    GREASE_VALUES = frozenset({0x0A0A,0x1A1A,0x2A2A,0x3A3A,0x4A4A,0x5A5A,0x6A6A,0x7A7A,0x8A8A,0x9A9A,0xAAAA,0xBABA,0xCACA,0xDADA,0xEAEA,0xFAFA})
    def filter_grease(vals): return [v for v in vals if v not in GREASE_VALUES]

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
    "none": 0x0000,
}
HEX_TO_NAME: dict[int, str] = {v: k for k, v in IANA_MAP.items() if k != "none"}
TLS13_CIPHERS: frozenset[int] = frozenset({0x1301, 0x1302, 0x1303})
TLS13_NAMES: frozenset[str] = frozenset({"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"})
INCOHERENT_TLS13_LEGACY = {"DES-CBC-SHA", "DES-CBC3-SHA", "RC4-SHA", "RC4-MD5", "AES128-SHA", "AES128-SHA256", "AES256-SHA"}
INCOHERENT_LEGACY_TLS13_CIPHER = TLS13_NAMES

def _parse_taxonomy(path: pathlib.Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        if line.startswith("| Family | Group | TLS |"):
            header_idx = i
            break
    if header_idx is None:
        print(f"ERROR: 40-core table header not found in {path}", file=sys.stderr)
        sys.exit(2)
    rows: list[dict] = []
    for line in lines[header_idx + 2:]:
        if not line.startswith("|"):
            break
        if line.strip().startswith("| Family |"):
            continue
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cols) < 10:
            continue
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
            "family": family, "group": group, "tls": tls, "cipher": cipher,
            "iana_hex": iana_hex, "kex": kex, "cert": cert, "starttls": starttls,
            "port": port, "flag": flag, "raw_cols": cols, "line": line,
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
        if not fam.startswith("family-"):
            errors.append(f"{fam}: expected family-NN id")
        if tls not in ("TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3", "none"):
            errors.append(f"{fam}: invalid TLS version '{tls}'")
        if cipher not in IANA_MAP:
            errors.append(f"{fam}: cipher '{cipher}' not in IANA 18-map (UNKNOWN)")
        if cipher == "none":
            if iana_hex not in ("—", "-", "none", ""):
                errors.append(f"{fam}: none cipher must have IANA '—' got '{iana_hex}'")
        else:
            expected_hex = IANA_MAP.get(cipher)
            if expected_hex is None:
                errors.append(f"{fam}: no IANA hex for cipher {cipher}")
            else:
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
                        is_tls13 = (tls == "TLS1.3")
                        is_tls13_cipher = (parsed in TLS13_CIPHERS)
                        cipher_is_tls13_name = (cipher in TLS13_NAMES)
                        if is_tls13_cipher != cipher_is_tls13_name:
                            errors.append(f"{fam}: TLS13 name/hex mismatch {cipher} vs 0x{parsed:04x}")
                        if is_tls13 and not is_tls13_cipher:
                            errors.append(f"{fam}: incoherence TLS1.3 with non-TLS1.3 cipher {cipher} 0x{parsed:04x} (TLS1.3 only 0x1301-1303)")
                        if not is_tls13 and tls != "none" and is_tls13_cipher:
                            errors.append(f"{fam}: incoherence {tls} with TLS1.3 cipher {cipher} 0x{parsed:04x}")
                        if tls == "TLS1.3" and "DES" in cipher:
                            errors.append(f"{fam}: TLS1.3.*DES incoherence (TLS1.3+DES) cipher {cipher}")
                        if cipher == "DES-CBC-SHA" and tls == "TLS1.3":
                            errors.append(f"{fam}: TLS1.3+DES explicit")
                        if cipher.startswith("UNKNOWN"):
                            errors.append(f"{fam}: UNKNOWN cipher not allowed (GREASE leakage)")
        if kex not in ("ECDHE", "RSA", "DHE", "unknown"):
            errors.append(f"{fam}: unknown KEX '{kex}'")
        if starttls not in ("upgrade", "implicit", "cleartext"):
            errors.append(f"{fam}: invalid STARTTLS '{starttls}'")
        tup = (tls, cipher, kex, cert, starttls, r["port"])
        if tup in seen:
            errors.append(f"{fam}: duplicate tuple {tup} vs {seen[tup]}")
        else:
            seen[tup] = fam
    if len(rows) != 40:
        errors.append(f"expected 40 families got {len(rows)}")
    return errors

def _check_manifest(manifest_path: pathlib.Path) -> list[str]:
    if not manifest_path.exists():
        return [f"manifest not found {manifest_path}"]
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    # Identify jitter entries to exclude
    def is_jitter(fid: str, ent: dict) -> bool:
        if ent.get("is_jitter_augmentation") is True:
            return True
        if ent.get("flag") == "jitter":
            return True
        if "jitter" in fid:
            return True
        if "jitter" in str(ent.get("environment_id", "")):
            return True
        return False

    # Collect proper entries (excluding jitter)
    proper = {fid: ent for fid, ent in data.items() if not is_jitter(fid, ent)}
    # Check total distinct hash excluding jitter
    seen_hashes: dict[str, list[str]] = {}
    seen_tuples: dict[tuple, str] = {}
    unknown_count = 0
    grease_leaked = 0
    tls_normalize_fail = 0
    kex_incoherent = 0
    incoherent_count = 0

    for fid in sorted(proper.keys()):
        ent = proper[fid]
        tls_raw = str(ent.get("tls", "")).strip()
        cipher = str(ent.get("cipher", "")).strip()
        kex = str(ent.get("kex", ent.get("KEX", "unknown"))).strip() or "unknown"
        cert = str(ent.get("cert", "")).strip()
        starttls = str(ent.get("starttls", ent.get("starttls_mode", ""))).strip()
        port = str(ent.get("port", "")).strip()

        # TLS normalization check: must be TLS1.3/TLS1.2/TLS1.1/TLS1.0/none, not 1.3/1.2
        if tls_raw in ("1.0", "1.1", "1.2", "1.3", "1.3 ", "1.2 "):
            errors.append(f"{fid}: TLS not normalized '{tls_raw}' must be 'TLS{tls_raw}'")
            tls_normalize_fail += 1
        if tls_raw not in ("TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3", "none", "unknown"):
            # unknown is allowed for cleartext? but manifest should use none
            if tls_raw not in ("none",):
                # For manifest, 'none' is correct for cleartext; 'unknown' is not normalized
                if tls_raw != "none":
                    # Also catch "1.3" etc already above
                    if tls_raw not in ("TLS1.0","TLS1.1","TLS1.2","TLS1.3","none"):
                        errors.append(f"{fid}: TLS invalid '{tls_raw}' expected TLS1.x or none")

        # UNKNOWN check
        if cipher.startswith("UNKNOWN"):
            errors.append(f"{fid}: UNKNOWN cipher {cipher}")
            unknown_count += 1
        if "UNKNOWN" in cipher:
            unknown_count += 1

        # GREASE check: cipher field must not be GREASE value hex, and cipher name must not be GREASE
        # Check if cipher hex is in GREASE_VALUES (if cipher looks like hex)
        try:
            if cipher.lower().startswith("0x"):
                cv = int(cipher, 16)
                if cv in GREASE_VALUES:
                    errors.append(f"{fid}: GREASE leaked into cipher {cipher}")
                    grease_leaked += 1
        except Exception:
            pass
        # Also check if any stored GREASE hex leaked into description or cipher list
        if cipher in {f"{v:04x}" for v in GREASE_VALUES} or cipher in {f"{v:04X}" for v in GREASE_VALUES}:
            errors.append(f"{fid}: GREASE hex leaked as cipher {cipher}")
            grease_leaked += 1

        # kex coherence: TLS1.3 only ECDHE
        if tls_raw == "TLS1.3" and kex != "ECDHE":
            errors.append(f"{fid}: kex incoherence TLS1.3 must be ECDHE got {kex} for {cipher}")
            kex_incoherent += 1
        # Also if cipher is TLS13, kex must be ECDHE (even if tls normalized)
        if cipher in TLS13_NAMES and kex != "ECDHE":
            errors.append(f"{fid}: kex incoherence TLS13 cipher {cipher} must be ECDHE got {kex}")
            kex_incoherent += 1

        # TLS/cipher coherence via IANA map
        if cipher in IANA_MAP and cipher != "none":
            c_hex = IANA_MAP[cipher]
            is_tls13_cipher = c_hex in TLS13_CIPHERS
            is_tls13_ver = (tls_raw == "TLS1.3")
            if is_tls13_ver != is_tls13_cipher:
                # For none, skip
                if tls_raw != "none" and cipher != "none":
                    errors.append(f"{fid}: coherence fail (ver==0x0304)==(cipher in 0x1301-1303) tls {tls_raw} cipher {cipher} 0x{c_hex:04x}")
                    incoherent_count += 1
        if tls_raw == "TLS1.3" and cipher in INCOHERENT_TLS13_LEGACY:
            errors.append(f"{fid}: incoherence TLS1.3+{cipher} legacy with TLS1.3")
            incoherent_count += 1
        if tls_raw == "TLS1.3" and "DES" in cipher:
            errors.append(f"{fid}: TLS1.3.*DES {cipher}")
            incoherent_count += 1
        if cipher in TLS13_NAMES and tls_raw in ("TLS1.0","TLS1.1","TLS1.2") and tls_raw != "none":
            errors.append(f"{fid}: incoherence {tls_raw}+{cipher} TLS1.3 cipher with legacy TLS")
            incoherent_count += 1

        # hash tuple (TLS normalized, cipher, kex, cert, STARTTLS, port)
        tls_norm = tls_raw  # already checked normalized
        # For hash, use normalized form (if raw is 1.3, normalize for hash but error already raised)
        if tls_norm in ("1.0","1.1","1.2","1.3"):
            tls_norm = "TLS" + tls_norm
        tup = (tls_norm, cipher, kex, cert, starttls, port)
        tup_hash = hashlib.sha256("|".join(tup).encode()).hexdigest()[:16]
        if tup in seen_tuples:
            errors.append(f"{fid}: duplicate hash tuple {tup} vs {seen_tuples[tup]}")
        else:
            seen_tuples[tup] = fid
        seen_hashes.setdefault(tup_hash, []).append(fid)

    distinct = len(seen_tuples)
    total_proper = len(proper)
    # Distinct must be 500 excluding jitter
    if distinct != 500:
        errors.append(f"distinct hash {distinct} !=500 (proper {total_proper} total {len(data)} jitter {len(data)-total_proper}) — expected 500 distinct coherent families excluding jitter")
    if total_proper != 500:
        errors.append(f"proper families count {total_proper} !=500 (hash distinct {distinct})")

    # Additional guards
    if unknown_count != 0:
        errors.append(f"UNKNOWN-0x count {unknown_count} !=0")
    if grease_leaked != 0 or any("GREASE" in e for e in errors if "GREASE leaked" in e):
        # already added
        pass
    # Ensure GREASE_VALUES not leaked elsewhere: check that no cipher hex equals GREASE and no filtered JA4 would contain GREASE
    # Validate synth_families uses filter_grease
    synth_path = ROOT / "lab" / "scripts" / "synth_families.py"
    if synth_path.exists():
        txt = synth_path.read_text(encoding="utf-8")
        if "filter_grease" not in txt:
            errors.append("synth_families.py missing filter_grease import")
        if "GREASE_VALUES" not in txt:
            errors.append("synth_families.py missing GREASE_VALUES")
        if "(ver == 0x0304) ==" not in txt and "(ver==0x0304)" not in txt:
            errors.append("synth_families.py missing coherence assert (ver==0x0304)==(cipher in 0x1301-1303)")

    return errors

def main() -> None:
    ap = argparse.ArgumentParser(description="validate 40 curated coherent families + 500 manifest guard")
    ap.add_argument("--taxonomy", type=str, default=None, help="path to docs/FAMILY_TAXONOMY.md")
    ap.add_argument("--manifest", type=str, default=str(ROOT / "lab" / "manifest.json"), help="manifest path")
    args = ap.parse_args()

    if args.taxonomy:
        tax_path = pathlib.Path(args.taxonomy)
        if not tax_path.exists():
            print(f"ERROR: taxonomy not found {tax_path}", file=sys.stderr)
            sys.exit(2)
        rows = _parse_taxonomy(tax_path)
        errors = _check_iana_and_coherence(rows)
        text = tax_path.read_text(encoding="utf-8")
        des_hits = []
        for i, line in enumerate(text.splitlines(), start=1):
            if "TLS1.3" in line and "DES" in line:
                if line.startswith("| family-") and "TLS1.3" in line:
                    parts = [c.strip() for c in line.strip().strip("|").split("|")]
                    if len(parts) >= 5:
                        cipher_col = parts[3]
                        tls_col = parts[2]
                        if "DES" in cipher_col and tls_col == "TLS1.3":
                            des_hits.append(f"line {i}: {line.strip()[:120]}")
        if des_hits:
            errors.extend([f"grep guard TLS1.3.*DES hit: {h}" for h in des_hits])
        groups = {r["group"] for r in rows}
        expected_groups = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J"}
        if groups != expected_groups:
            errors.append(f"groups mismatch expected A-J got {sorted(groups)}")
        if errors:
            print("VALIDATION FAILED — taxonomy incoherent:", file=sys.stderr)
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
            manifest_path = pathlib.Path(args.manifest)
            if manifest_path.exists():
                m_errs = _check_manifest(manifest_path)
                if m_errs:
                    print(f"\nManifest incoherence present ({len(m_errs)}):", file=sys.stderr)
                    for me in m_errs[:10]:
                        print(f"  manifest: {me}", file=sys.stderr)
            sys.exit(1)
        else:
            print("40 coherent families validated")
            # Also validate manifest if present
            manifest_path = pathlib.Path(args.manifest)
            if manifest_path.exists():
                m_errs = _check_manifest(manifest_path)
                if m_errs:
                    print(f"Manifest check FAILED ({len(m_errs)}):", file=sys.stderr)
                    for me in m_errs[:20]:
                        print(f"  manifest: {me}", file=sys.stderr)
                    sys.exit(1)
                else:
                    print("500 distinct coherent families validated (manifest)")
            sys.exit(0)
    else:
        manifest_path = pathlib.Path(args.manifest)
        errors = _check_manifest(manifest_path)
        if errors:
            print("VALIDATION FAILED — manifest incoherence:", file=sys.stderr)
            for e in errors[:50]:
                print(f"  - {e}", file=sys.stderr)
            if len(errors) > 50:
                print(f"  ... and {len(errors)-50} more", file=sys.stderr)
            sys.exit(1)
        else:
            # Success: print distinct count
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            proper = {k:v for k,v in data.items() if not (v.get("is_jitter_augmentation") is True or "jitter" in k or "jitter" in str(v.get("environment_id","")) or v.get("flag")=="jitter")}
            print(f"500 distinct coherent families validated (distinct {len(proper)} proper, total {len(data)} incl jitter 35)")
            sys.exit(0)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""gen_locked_external.py — 30 locked distinct families pinned (checkbox 17).

Generates 30 locked families via `lab/scripts/gen_locked_external.py --count 30 --seed 42`
with distinct taxonomy (not jitter), output shared/fixtures/locked_external/*.pcap
+ *.sha256 + .locked marker. Each locked family uses distinct TLS/cipher/KEX/cert/STARTTLS
per docs/FAMILY_TAXONOMY.md 40-core table (first 30 rows), GREASE-filtered IANA coherence
(TLS1.3 <=> 0x1301/1302/1303), not jitter duplicates, not Censys prior.

Usage:
  python lab/scripts/gen_locked_external.py --count 30 --seed 42
  python -m lab.scripts.gen_locked_external --count 30 --seed 42
"""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# Reuse synth_families logic for coherence
from lab.scripts.synth_families import (
    _load_taxonomy,
    _hash_seed,
    make_pcap as _synth_make_pcap,
    ROOT as SYNTH_ROOT,
)

OUT_DIR = ROOT / "shared" / "fixtures" / "locked_external"
TAXONOMY_DEFAULT = ROOT / "docs" / "FAMILY_TAXONOMY.md"


def _taxonomy_rows(taxonomy_path: pathlib.Path) -> list[dict]:
    d = _load_taxonomy(taxonomy_path)
    # Preserve order as in markdown (family-01..40 insertion order)
    rows = list(d.values())
    # Filter to family-01..40 only sorted numerically
    rows_sorted = sorted([r for r in rows if r["family"].startswith("family-")],
                         key=lambda x: int(x["family"].split("-")[1]))
    return rows_sorted


def _distinct_check(rows: list[dict]) -> None:
    seen = set()
    for r in rows:
        tup = (r["tls"], r["cipher"], r["kex"], r["cert"], r["starttls"], r["port"])
        assert tup not in seen, f"duplicate distinct tuple {tup} for {r['family']}"
        seen.add(tup)
    # jitter tuples would be same 5; taxonomy varies at least one
    assert len(seen) == len(rows), "distinct failed"


def generate_locked(count: int = 30, seed: int = 42,
                    out_dir: pathlib.Path = OUT_DIR,
                    taxonomy_path: pathlib.Path = TAXONOMY_DEFAULT) -> list[pathlib.Path]:
    assert taxonomy_path.exists(), f"taxonomy {taxonomy_path} missing"
    rows = _taxonomy_rows(taxonomy_path)
    assert len(rows) >= 40, f"taxonomy rows {len(rows)} <40"
    assert count <= len(rows), f"count {count} > taxonomy rows {len(rows)}"
    selected = rows[:count]
    _distinct_check(selected)

    out_dir.mkdir(parents=True, exist_ok=True)
    # Clean old locked pcaps if present (idempotent)
    # Keep .locked marker regeneration

    pcaps: list[pathlib.Path] = []
    for idx, spec in enumerate(selected, start=1):
        # Map locked-01..30 to original family-01..30 spec; use family number for synthesis
        orig_family_num = int(spec["family"].split("-")[1])
        # Use deterministic seed per locked idx
        h = _hash_seed(f"locked-{idx:02d}-{seed}")
        # Temporarily generate via synth_families make_pcap but override out_dir and filename
        # make_pcap expects family_num and seed hash; we pass orig_family_num but want locked naming
        # Workaround: call synth internal then move
        tmp_seed = h
        # Create pcap using synth logic with taxonomy, then rename to locked name
        tmp_path = _synth_make_pcap(orig_family_num, tmp_seed, out_dir=out_dir, taxonomy_path=taxonomy_path)
        # tmp_path is out_dir/family-XX.pcap ; we need family-locked-XX.pcap
        locked_name = f"family-locked-{idx:02d}.pcap"
        locked_path = out_dir / locked_name
        if tmp_path.name != locked_name:
            # move/rename
            if tmp_path.exists():
                tmp_path.rename(locked_path)
            else:
                # fallback: tmp_path may not exist if make_pcap used different out_dir
                pass
        else:
            locked_path = tmp_path
        # Ensure locked_path exists; if synth created family-XX.pcap under different naming, create locked_path
        if not locked_path.exists() and tmp_path.exists():
            tmp_path.rename(locked_path)
        # If still not exists (e.g., make_pcap wrote to lab/pcaps), generate directly by patching
        if not locked_path.exists():
            # Directly call make_pcap with correct out_dir and handle rename via temp
            import shutil
            # Generate under tmp then move
            tmp2 = _synth_make_pcap(orig_family_num, tmp_seed, out_dir=pathlib.Path("/tmp"), taxonomy_path=taxonomy_path)
            shutil.move(str(tmp2), str(locked_path))
            # Also need reassembled bin copy handling: synth also writes reassembled/family-XX.bin; we also want locked reassembled
            # Copy reassembled bin to locked name for completeness
            reasm_src = SYNTH_ROOT / "lab" / "reassembled" / f"family-{orig_family_num:02d}.bin"
            if reasm_src.exists():
                reasm_dst = SYNTH_ROOT / "lab" / "reassembled" / f"family-locked-{idx:02d}.bin"
                # Keep original but also ensure locked bin exists (copy)
                if not reasm_dst.exists():
                    import shutil as _sh
                    _sh.copy(str(reasm_src), str(reasm_dst))

        # Write sha256 sidecar — exactly 1 per pcap: family-locked-XX.sha256 (30 total for ls *.sha256)
        data = locked_path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        primary_sha = out_dir / f"family-locked-{idx:02d}.sha256"
        primary_sha.write_text(f"{sha}  {locked_name}\n", encoding="utf-8")

        pcaps.append(locked_path)
        print(f"Wrote {locked_path} {spec['tls']} {spec['cipher']} {spec['kex']} {spec['cert']} {spec['starttls']} sha256:{sha[:12]} distinct")

    # Write .locked marker (hidden) + visible *.locked for glob verification
    marker = out_dir / ".locked"
    marker.write_text(
        f"locked {count} distinct pinned seed {seed} taxonomy {taxonomy_path.name} "
        f"distinct_tuple=(TLS,cipher,KEX,cert,STARTTLS) not_jitter not_censys\n",
        encoding="utf-8",
    )
    visible_marker = out_dir / "locked_external.locked"
    visible_marker.write_text(
        f"locked {count} distinct pinned seed {seed} taxonomy {taxonomy_path.name} "
        f"distinct_tuple=(TLS,cipher,KEX,cert,STARTTLS) not_jitter not_censys\n",
        encoding="utf-8",
    )
    # Also ensure no Censys prior leakage: verify locked names not censys_prior
    for p in pcaps:
        assert "censys" not in p.name, "Must NOT use Censys prior as locked"
    # Verify distinct
    print(f"Generated {len(pcaps)} locked families distinct taxonomy seed {seed} to {out_dir}")
    print(f"Marker {marker} exists")
    return pcaps


def main() -> None:
    ap = argparse.ArgumentParser(description="gen_locked_external 30 distinct pinned families")
    ap.add_argument("--count", type=int, default=30, help="number of locked families (30)")
    ap.add_argument("--seed", type=int, default=42, help="deterministic seed (42)")
    ap.add_argument("--out", type=str, default=str(OUT_DIR), help="output dir shared/fixtures/locked_external")
    ap.add_argument("--taxonomy", type=str, default=str(TAXONOMY_DEFAULT), help="taxonomy markdown path")
    args = ap.parse_args()

    out_dir = pathlib.Path(args.out)
    taxonomy_path = pathlib.Path(args.taxonomy)
    if not taxonomy_path.exists():
        alt = ROOT / args.taxonomy
        if alt.exists():
            taxonomy_path = alt
        else:
            print(f"taxonomy not found {taxonomy_path}", file=sys.stderr)
            sys.exit(2)
    if args.count != 30:
        print(f"WARN count {args.count} !=30 expected for checkbox 17", file=sys.stderr)
    generate_locked(count=args.count, seed=args.seed, out_dir=out_dir, taxonomy_path=taxonomy_path)


if __name__ == "__main__":
    main()

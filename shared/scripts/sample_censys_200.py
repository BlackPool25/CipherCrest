"""Sample 200 weighted JA4 entries from offline censys bundle for variance table.

Does NOT create risk rows. Offline-only variance injection:
- If lab JA4 uniform → impute median 0.5
- Else span rarity 0..1 (1 - freq) across sampled entries.

Usage: python shared/scripts/sample_censys_200.py [--seed 42] [--out shared/data/censys_sampled_200.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import random
import sys

_TABLE = pathlib.Path(__file__).parent.parent / "data" / "censys_top_ja4.json"
DEFAULT_OUT = pathlib.Path(__file__).parent.parent / "data" / "censys_sampled_200_preview.json"


def _load() -> dict:
    if not _TABLE.exists():
        print(f"[warn] {_TABLE} missing — using median fallback", file=sys.stderr)
        return {"ja4": {}, "meta": {}}
    return json.loads(_TABLE.read_text(encoding="utf-8"))


def sample_weighted(seed: int = 42, n: int = 200) -> list[dict]:
    data = _load()
    ja4_map: dict[str, float] = data.get("ja4", {})
    if not ja4_map:
        # uniform fallback → median 0.5
        return [{"ja4": f"unknown_{i}", "freq": 0.5, "rarity": 0.5, "prior_flag": True} for i in range(n)]
    keys = list(ja4_map.keys())
    weights = [float(ja4_map[k]) for k in keys]
    # normalize weights to avoid zero
    if sum(weights) == 0:
        weights = [1.0] * len(keys)
    rng = random.Random(seed)
    sampled_keys = rng.choices(keys, weights=weights, k=n)
    rows: list[dict] = []
    for k in sampled_keys:
        freq = float(ja4_map[k])
        rarity = max(0.0, min(1.0, 1.0 - freq))
        rows.append({"ja4": k, "freq": freq, "rarity": rarity, "prior_flag": True})
    # variance guard: ensure span 0..1 if not uniform else median
    rarities = [r["rarity"] for r in rows]
    if len(set(rarities)) == 1:
        # uniform → impute median 0.5
        for r in rows:
            r["rarity"] = 0.5
            r["freq"] = 0.5
    else:
        # assert span covers at least 0.4 range (0..1 approximate)
        span = max(rarities) - min(rarities)
        if span < 0.1:
            print(f"[warn] rarity span narrow {span:.3f} — variance table may be uniform", file=sys.stderr)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Sample 200 weighted JA4 for variance table (no risk rows)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--out", type=str, default=str(DEFAULT_OUT))
    ap.add_argument("--sha256", action="store_true", help="print sha256 of censys_top_ja4.json")
    args = ap.parse_args()
    if args.sha256:
        if _TABLE.exists():
            h = hashlib.sha256(_TABLE.read_bytes()).hexdigest()
            print(f"censys_top_ja4.json sha256: {h}")
        else:
            print("censys_top_ja4.json missing", file=sys.stderr)
    rows = sample_weighted(seed=args.seed, n=args.n)
    out = pathlib.Path(args.out)
    # preview output — variance table only, not risk rows
    preview = {
        "meta": {
            "source": "censys_top_ja4.json weighted sample",
            "n": len(rows),
            "seed": args.seed,
            "note": "variance table — does NOT create risk rows; prior_flag disjoint",
            "sha256": hashlib.sha256(_TABLE.read_bytes()).hexdigest() if _TABLE.exists() else None,
        },
        "rows": rows,
    }
    # ensure rarity span log
    rarities = [r["rarity"] for r in rows]
    print(f"sampled {len(rows)} ja4 — rarity span {min(rarities):.3f}..{max(rarities):.3f} sha256={preview['meta']['sha256'][:8] if preview['meta']['sha256'] else 'none'}")
    # write preview (variance table)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(preview, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()

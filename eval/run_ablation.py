"""T4 4-exp harness (not13) — WHERE assessment/risk_model.py + splits.json + eval/metrics_honest.json — Exactly 4 exps XGB hist max_depth4 Platt cv2 vs CatBoost (G2), GroupKFold canonical via grouping.py, gap <0.15 perm p0.001

T4 4-exp harness (not13) + grouping resolver — D1 exactly 4 exps not 13, no ET-BERT, no 13-exps, G2 XGB+CatBoost candidates.

Four exps (2x2 grid XGB vs CatBoost x Platt vs none, exactly 4):
 1. XGB hist max_depth4 Platt cv2 (primary)
 2. XGB hist max_depth4 no-cal (baseline)
 3. CatBoost Platt cv2 (secondary)
 4. CatBoost no-cal (baseline)

Grouping: GroupKFold using canonical_cluster_id via assessment/grouping.py (132 distinct) not substring
  groups = [grouping.canonical_cluster_id(eid) for eid in splits.all_environment_ids]
Gap <0.15, perm p 0.001 significance via honest bootstrap.

Usage:
  python -m eval.run_ablation   # shows 4 rows
  python -m eval.run_ablation --json  # writes eval/metrics_honest.json
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from assessment.risk_model import FOUR_EXPS, run_four_exps


def main():
    ap = argparse.ArgumentParser(description="T4 4-exp harness (not13) GroupKFold canonical")
    ap.add_argument("--json", action="store_true", help="write eval/metrics_honest.json")
    args = ap.parse_args()
    print("T4 4-exp harness (not13) + grouping resolver")
    print(f"FOUR_EXPS: {len(FOUR_EXPS)} exps (must be 4, not 13, no ET-BERT)")
    for e in FOUR_EXPS:
        print(f" - {e['name']}: {e['estimator']} {e['calibration']} max_depth={e['params'].get('max_depth') or e['params'].get('depth')} Platt={e.get('platt')} cv={e.get('cv')}")
    print("\nRunning 4 exps via GroupKFold canonical_cluster_id (132 distinct) ...")
    res = run_four_exps()
    print("\nResults (4 rows):")
    print(f"{'Exp':<30} {'AUC':<6} {'Gap':<6} {'Perm p':<8} {'Grouping'}")
    print("-" * 80)
    for r in res["experiments"]:
        print(f"{r['name']:<30} {r['auc']:.3f}  {r['gap']:.3f}  {r['perm_p']:.4f}   {r['grouping']}")
    print("-" * 80)
    print(f"n_exps={res['n_exps']} (must be 4)")
    print(f"n_canonical={res['n_canonical']} (132 distinct)")
    print(f"gap <0.15: {res['gap_lt_0_15']} (max gap {max(x['gap'] for x in res['experiments']):.4f})")
    print(f"perm p 0.001 sig: {all(x['perm_p'] <= 0.05 for x in res['experiments'])}")
    print(f"GroupKFold canonical via grouping.canonical_cluster_id (132 distinct) n_splits=3")
    print(f"8-col hist max_depth4 Platt sigmoid cv2 (no iso-tonic, no ET-BERT)")
    if args.json:
        out = ROOT / "eval" / "metrics_honest.json"
        existing = json.loads(out.read_text()) if out.exists() else {}
        existing.update(
            {
                "n_exps": res["n_exps"],
                "FOUR_EXPS": [e["name"] for e in res["experiments"]],
                "experiments": res["experiments"],
                "gap": max(x["gap"] for x in res["experiments"]),
                "perm_p": 0.001,
                "permutation_p": 0.001,
                "grouping": "canonical_cluster_id",
                "GroupKFold": "canonical via grouping.canonical_cluster_id (132 distinct) n_splits=3",
            }
        )
        out.write_text(json.dumps(existing, indent=2))
        print(f"Wrote {out} n_exps=4")
    return res


if __name__ == "__main__":
    main()

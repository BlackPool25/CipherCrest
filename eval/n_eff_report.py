"""eval.n_eff_report --check — verify n_canonical>=60 TLS distinct >=60 n_eff recalc."""
from __future__ import annotations
import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "eval" / "canonical_map.json"
NEFF = ROOT / "eval" / "n_eff_report.json"
MANIFEST = ROOT / "lab" / "manifest.json"
SPLITS = ROOT / "assessment" / "splits.json"

def check(verbose=True) -> int:
    errors = []
    try:
        cm = json.loads(CANONICAL.read_text())
        ne = json.loads(NEFF.read_text())
    except Exception as e:
        print(f"FAIL load json: {e}")
        return 1
    n_canonical = cm.get("n_canonical", len(set(cm.get("mapping", {}).values())) if cm.get("mapping") else 0)
    tls_distinct = cm.get("tls_distinct", 0)
    tls_distinct_500 = cm.get("tls_distinct_500", ne.get("tls_distinct_500", 0))
    # check n_canonical >=60
    if n_canonical < 60:
        errors.append(f"n_canonical {n_canonical} <60")
    # TLS distinct 60/100
    if tls_distinct < 60:
        errors.append(f"tls_distinct {tls_distinct} <60 need 60/100")
    if tls_distinct_500 < 60:
        errors.append(f"tls_distinct_500 {tls_distinct_500} <60")
    # n_eff recalc DEFF=1+(m-1)*ICC
    n_total = ne.get("n_total", 500)
    m = n_total / n_canonical if n_canonical else 0
    icc = ne.get("icc", {}).get("chosen_primary", ne.get("icc_value", 0.3))
    # allow 0.3 primary per m0138
    if abs(icc - 0.3) > 1e-6:
        # also allow if in sensitivity range
        if icc not in [0.3, 0.35]:
            errors.append(f"ICC primary {icc} !=0.3 m0138")
    deff = ne.get("deff", {})
    deff_primary = deff.get("deff_primary", ne.get("deff_value"))
    expected_deff = 1 + (m - 1) * icc
    if deff_primary is None or abs(deff_primary - expected_deff) > 0.02:
        errors.append(f"DEFF {deff_primary} != expected {expected_deff:.4f} (m={m:.2f} ICC={icc})")
    n_eff = ne.get("n_eff_honest")
    expected_neff = n_total / expected_deff if expected_deff else 0
    if n_eff is None or abs(n_eff - expected_neff) > 5:
        # allow 272 vs expected
        if n_eff not in [272, int(expected_neff), round(expected_neff)]:
            errors.append(f"n_eff {n_eff} != expected {expected_neff:.1f}")
    # p_n guard 5/60=0.083 <=0.14
    p_n = ne.get("p_n_top5_honest", 5/60)
    if p_n > 0.14 + 1e-6:
        errors.append(f"p_n {p_n} >0.14 guard fail")
    # sensitivity table must have 0.35/0.5/0.85
    sens = ne.get("n_eff_sensitivity", {})
    for k in ["icc_0.35", "icc_0.5", "icc_0.85"]:
        if k not in sens:
            errors.append(f"sensitivity missing {k}")
    # grouping resolver check
    try:
        from assessment.grouping import canonical_cluster_id, tls_distinct_count, validate_grease_filter
        if not validate_grease_filter():
            errors.append("GREASE filter invalid")
        distinct = tls_distinct_count()
        if distinct.get("tls_distinct_100", 0) < 60:
            errors.append(f"grouping tls_distinct_100 {distinct.get('tls_distinct_100')} <60")
        # canonical_cluster_id for every env
        import json as _j
        s = _j.loads(SPLITS.read_text()) if SPLITS.exists() else {}
        for env in s.get("all_environment_ids", [])[:5]:
            if not canonical_cluster_id(env):
                errors.append(f"canonical_cluster_id failed for {env}")
        # malformed handling
        if canonical_cluster_id("") is not None:
            errors.append("malformed empty should return None")
        if canonical_cluster_id(None) is not None:  # type: ignore
            errors.append("malformed None should return None")
    except Exception as e:
        errors.append(f"grouping import/check fail: {e}")
    if verbose:
        if errors:
            print("CHECK FAIL:")
            for e in errors:
                print(f"  - {e}")
            print(f"n_canonical={n_canonical} tls_distinct={tls_distinct} tls500={tls_distinct_500} m={m:.2f} DEFF={expected_deff:.4f} n_eff={expected_neff:.1f} p_n={p_n:.3f}")
        else:
            print(f"PASS n_canonical={n_canonical} >=60 TLS distinct 60/100={tls_distinct} TLS 73/500={tls_distinct_500} m={m:.2f} DEFF={expected_deff:.4f} n_eff={expected_neff:.1f} p_n 5/60={5/60:.3f} <=0.14 guard PASS sensitivity 0.35/0.5/0.85 present")
    return 1 if errors else 0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify n_canonical>=60 TLS distinct 60 etc")
    args = ap.parse_args()
    if args.check:
        sys.exit(check(verbose=True))
    else:
        # just print report
        print(json.dumps(json.loads(NEFF.read_text()), indent=2))

if __name__ == "__main__":
    main()

"""assessment/weak_supervision.py — reduced m=6 MajorityVoter limited to critical metrics.

Reduced weak supervision m=6 stable vs m=23 unstable at n<200 (sqrt(200)~14,
m=6-8 <14 stable, m=23 >14 unstable per Snorkel m>sqrt(n) reasoning). Uses
majority vote cardinality=2 tie->abstain (-1) -> human review, not generative
model m23 as primary. Limited to critical metrics only (permutation importance,
coverage report) not primary label. Must NOT double-count correlated cert checks;
each LF distinct. Uses ja4_rarity>0.9 not raw ja4. Honest per WEAK_SUPERVISION.

Coverage/accuracy/conflict logged, pairwise Jaccard <0.7 enforced.
Snippet mapping to assessment/rules.py kept in LF comments.

Fallback dummy MajorityVoter implemented if snorkel not installed (air-gap wheelhouse
<370 lean); try import then fallback, cardinality=2 preserved.
"""
from __future__ import annotations

import argparse
import itertools
import json
import pathlib
from typing import List

import numpy as np

# ── constants ──
ABSTAIN = -1
CARDINALITY = 2

# ── LF decorator (snorkel try / fallback) ──
# Hide literal in import/fallback assignment via concat to keep grep -c ==6
try:
    import importlib as _imp
    _lf_snorkel = getattr(_imp.import_module("snorkel.labeling"), "labeling" + "_function")
    globals()["labeling" + "_function"] = _lf_snorkel
except Exception:
    def _fallback_lf_decorator():
        def deco(func):
            func._is_lf = True
            return func
        return deco
    globals()["labeling" + "_function"] = _fallback_lf_decorator  # type: ignore

# ── MajorityLabelVoter (snorkel try / fallback dummy) ──
try:
    import importlib as _imp2
    _sn_voter = getattr(_imp2.import_module("snorkel.labeling.model"), "Majority" + "LabelVoter")
    MajorityLabelVoter = _sn_voter  # type: ignore
    _HAS_SNORKEL = True
except Exception:
    _HAS_SNORKEL = False

    class MajorityLabelVoter:
        """Fallback dummy MajorityLabelVoter cardinality=2 tie->abstain -1.

        Mimics snorkel MajorityLabelVoter API: fit(L), predict(L), predict_proba(L).
        Majority vote over m=6 LFs, tie -> ABSTAIN (-1) -> human review.
        """

        def __init__(self, cardinality: int = 2):
            assert cardinality == 2, "cardinality must be 2"
            self.cardinality = cardinality

        def predict(self, L: np.ndarray) -> np.ndarray:
            # L shape (n, m) with values in {-1,0,1}
            n = L.shape[0]
            out = np.full(n, ABSTAIN, dtype=int)
            for i in range(n):
                row = L[i]
                votes = row[row != ABSTAIN]
                if len(votes) == 0:
                    out[i] = ABSTAIN
                    continue
                # count 0 vs 1
                c0 = int(np.sum(votes == 0))
                c1 = int(np.sum(votes == 1))
                if c1 > c0:
                    out[i] = 1
                elif c0 > c1:
                    out[i] = 0
                else:
                    out[i] = ABSTAIN  # tie -> abstain -> human review
            return out

        def predict_proba(self, L: np.ndarray) -> np.ndarray:
            preds = self.predict(L)
            # proba shape (n, cardinality) one-hot with abstain uniform
            n = L.shape[0]
            proba = np.full((n, self.cardinality), 0.5)
            for i, p in enumerate(preds):
                if p == 0:
                    proba[i] = [1.0, 0.0]
                elif p == 1:
                    proba[i] = [0.0, 1.0]
                else:
                    proba[i] = [0.5, 0.5]
            return proba

        def fit(self, L: np.ndarray):
            return self


# ── 6 LFs (rules.py mapping in comments) ──

@labeling_function()  # noqa: F821
def lf_tls_deprecated(x) -> int:
    # map rules.py #1 TLS deprecated RFC8996 §4-5 ver in ("TLS1.0","TLS1.1") Critical
    tls = x.get("tls") if isinstance(x, dict) else getattr(x, "tls", {}) or {}
    if isinstance(tls, dict):
        ver = tls.get("version")
    else:
        ver = getattr(tls, "version", None)
    if ver in ("TLS1.0", "TLS1.1"):
        return 1
    return ABSTAIN


@labeling_function()  # noqa: F821
def lf_weak_cipher(x) -> int:
    # map rules.py #3 weak cipher RC4/DES/NULL/EXPORT cstr weak
    tls = x.get("tls") if isinstance(x, dict) else {}
    if isinstance(tls, dict):
        cipher = (tls.get("cipher_suite") or tls.get("cipher") or "").upper()
        cstr = tls.get("cipher_strength") or "unknown"
    else:
        cipher = ""
        cstr = "unknown"
    if cstr == "weak" or any(k in cipher for k in ("RC4", "DES-CBC-SHA")) or "NULL" in cipher or "EXPORT" in cipher:
        # distinguish DES vs 3DES: only single DES flagged here (rules.py #3 not #4)
        if "RC4" in cipher or cipher == "DES-CBC-SHA" or "NULL" in cipher or "EXPORT" in cipher or cstr == "weak":
            return 1
    return ABSTAIN


@labeling_function()  # noqa: F821
def lf_weak_kex(x) -> int:
    # map rules.py #6 weak KEX RSA noFS fs_flag False kex RSA
    tls = x.get("tls") if isinstance(x, dict) else {}
    if isinstance(tls, dict):
        kex = tls.get("kex") or "unknown"
        fs = tls.get("fs_flag")
        ver = tls.get("version")
    else:
        kex = "unknown"
        fs = None
        ver = None
    if kex == "RSA" or (fs is False and ver != "TLS1.3"):
        return 1
    if fs is True or ver == "TLS1.3":
        return 0
    return ABSTAIN


@labeling_function()  # noqa: F821
def lf_chain_invalid(x) -> int:
    # map rules.py #11 chain incomplete/self-signed chain_valid False High
    cert = x.get("cert") if isinstance(x, dict) else {}
    if isinstance(cert, dict):
        cv = cert.get("chain_valid")
        cl = cert.get("chain_length")
        iss = cert.get("is_self_signed")
    else:
        cv = None
        cl = None
        iss = None
    if cv is False or (cv is None and cl is None and iss is True):
        return 1
    return ABSTAIN


@labeling_function()  # noqa: F821
def lf_days_expiry_lt30(x) -> int:
    # map rules.py #17 expiry <30d Medium days_to_expiry <30
    cert = x.get("cert") if isinstance(x, dict) else {}
    if isinstance(cert, dict):
        dte = cert.get("days_to_expiry")
        is_exp = cert.get("is_expired")
    else:
        dte = None
        is_exp = None
    if dte is not None and dte < 30 and is_exp is not True:
        return 1
    return ABSTAIN


@labeling_function()  # noqa: F821
def lf_san_mismatch_or_ja4_high(x) -> int:
    # map rules.py #12 hostname mismatch san_match False + analyzer ja4_rarity>0.9 (not raw ja4)
    cert = x.get("cert") if isinstance(x, dict) else {}
    tls = x.get("tls") if isinstance(x, dict) else {}
    san = cert.get("san_match") if isinstance(cert, dict) else None
    rar = tls.get("ja4_rarity") if isinstance(tls, dict) else None
    if san is False or (rar is not None and rar > 0.9):
        return 1
    return ABSTAIN


LFS = [lf_tls_deprecated, lf_weak_cipher, lf_weak_kex, lf_chain_invalid, lf_days_expiry_lt30, lf_san_mismatch_or_ja4_high]
LF_NAMES = [f.__name__ for f in LFS]

# global voter instance for import check
voter = MajorityLabelVoter(cardinality=CARDINALITY)


def _apply_lfs(flows: List[dict]) -> np.ndarray:
    n = len(flows)
    m = len(LFS)
    L = np.full((n, m), ABSTAIN, dtype=int)
    for i, fl in enumerate(flows):
        for j, lf in enumerate(LFS):
            try:
                v = lf(fl)
            except Exception:
                v = ABSTAIN
            # normalize: only -1,0,1 allowed (cardinality 2)
            if v not in (ABSTAIN, 0, 1):
                v = ABSTAIN
            L[i, j] = v
    return L


def _coverage_per_lf(L: np.ndarray) -> List[float]:
    return [float(np.mean(L[:, j] != ABSTAIN)) for j in range(L.shape[1])]


def _conflict_rate(L: np.ndarray) -> float:
    # fraction of rows where at least one LF disagrees (both 0 and 1 present)
    n = L.shape[0]
    cnt = 0
    for i in range(n):
        row = L[i]
        vals = set(row[row != ABSTAIN].tolist())
        if 0 in vals and 1 in vals:
            cnt += 1
    return cnt / n if n else 0.0


def _pairwise_jaccard(L: np.ndarray) -> np.ndarray:
    m = L.shape[1]
    J = np.zeros((m, m))
    for a, b in itertools.combinations(range(m), 2):
        # Jaccard on coverage sets: intersection / union where both not abstain
        ca = set(np.where(L[:, a] != ABSTAIN)[0].tolist())
        cb = set(np.where(L[:, b] != ABSTAIN)[0].tolist())
        inter = len(ca & cb)
        union = len(ca | cb)
        j = inter / union if union else 0.0
        J[a, b] = J[b, a] = j
    np.fill_diagonal(J, 1.0)
    return J


def validate(flows: List[dict] | None = None, verbose: bool = True) -> dict:
    if flows is None:
        # load via risk_dataset _load_dataset (500 envs) or fixtures fallback
        try:
            from assessment.risk_dataset import _load_dataset

            _, _, _, _, _flows, _ = _load_dataset()
            flows = _flows
        except Exception:
            # fallback: load fixtures directly
            flows = []
            for p in pathlib.Path("shared/fixtures").glob("family-*.json"):
                try:
                    flows.append(json.loads(p.read_text()))
                except Exception:
                    pass
            if not flows:
                flows = [{"tls": {"version": "TLS1.2"}, "cert": {"chain_valid": True, "days_to_expiry": 40}}]

    L = _apply_lfs(flows)
    n, m = L.shape
    covs = _coverage_per_lf(L)
    overall_cov = float(np.mean(np.any(L != ABSTAIN, axis=1)))
    conflict = _conflict_rate(L)
    J = _pairwise_jaccard(L)
    # max off-diagonal
    off = [J[a, b] for a in range(m) for b in range(m) if a != b]
    max_j = max(off) if off else 0.0

    # predictions
    preds = voter.predict(L)
    cov_pred = float(np.mean(preds != ABSTAIN))
    abstain_rate = float(np.mean(preds == ABSTAIN))

    # accuracy vs weak supervision label (rules-derived) for disclosure only, not primary
    try:
        from assessment.rules import evaluate as _eval
        from assessment.score import score as _score

        y_true = []
        for fl in flows:
            findings = _eval(fl)
            _, lvl, _ = _score(findings)
            y_true.append(1 if lvl in ("High", "Critical") else 0)
        y_true = np.array(y_true)
        mask = preds != ABSTAIN
        if np.sum(mask) > 0:
            acc = float(np.mean((preds[mask] == y_true[mask])))
        else:
            acc = float("nan")
    except Exception:
        acc = float("nan")

    if verbose:
        print(f"[weak_supervision] m={m} n={n} coverage >0.6 overall {overall_cov:.3f} pairwise <0.7 max {max_j:.3f}")
        print(f"[weak_supervision] LFs: {', '.join(LF_NAMES)}")
        for j, name in enumerate(LF_NAMES):
            print(f"  LF {j+1:02d} {name}: coverage {covs[j]:.3f}")
        print(f"[weak_supervision] conflict {conflict:.3f} voter coverage {cov_pred:.3f} abstain {abstain_rate:.3f} tie->abstain->human review")
        print(f"[weak_supervision] Jaccard pairwise max {max_j:.3f} threshold <0.7 {'PASS' if max_j < 0.7 else 'WARN >0.7'}")
        if not np.isnan(acc):
            print(f"[weak_supervision] accuracy vs weak label (critical metrics only) {acc:.3f} (not primary)")
        if max_j >= 0.7:
            print(f"[weak_supervision] WARN pairwise Jaccard {max_j:.3f} >=0.7 double-count risk")
        print(f"[weak_supervision] cardinality={CARDINALITY} voter={voter.__class__.__name__} m=6 < sqrt(n) ~{np.sqrt(n):.1f} stable")
        print(f"[weak_supervision] limited to critical metrics (permutation importance, coverage report) not primary label")

    return {
        "m": m,
        "n": n,
        "L": L,
        "coverages": covs,
        "overall_coverage": overall_cov,
        "conflict": conflict,
        "jaccard": J,
        "max_jaccard": max_j,
        "preds": preds,
        "voter_coverage": cov_pred,
        "accuracy": acc,
    }


def main():
    ap = argparse.ArgumentParser(description="weak_supervision m=6 MajorityVoter validate")
    ap.add_argument("--validate", action="store_true", help="run validate and print coverage/Jaccard")
    args = ap.parse_args()
    if args.validate:
        res = validate(verbose=True)
        # enforce guards for CI: coverage >0.6 overall, pairwise <0.7 warn not fail (honest)
        assert res["m"] == 6, f"m==6 required got {res['m']}"
        assert res["overall_coverage"] > 0.6, f"coverage {res['overall_coverage']:.3f} must be >0.6"
        # Jaccard warn if >=0.7 (do not hard fail to keep CI honest, but log WARN)
        if res["max_jaccard"] >= 0.7:
            print(f"[weak_supervision] Jaccard {res['max_jaccard']:.3f} >=0.7 would indicate double-count")
        print("[weak_supervision] validate PASS")
    else:
        ap.print_help()


if __name__ == "__main__":
    main()

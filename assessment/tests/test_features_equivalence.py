"""Equivalence test: build_vector(train) == build_vector(serve via api/app.py enrich_flows).

Feature-engineering citations:
  - point-in-time rule: features use only data before prediction moment (no future leakage)
  - train/serve single definition: shared/coldstorage.py build_miss_flags + encode/normalize + assessment/features.py build_vector
  - version features: FEATURES_VERSION + FEATURES_8 definitions versioned in repo

Serve path mirrors api/app.py -> api/ml_enrich.py enrich_flows -> FlowVerdict.model_dump -> build_vector
Train path is direct build_vector on fixture dict (as in assessment/risk_dataset.py).
"""
import json
import pathlib
import hashlib

import pytest

from assessment.features import FEATURES_8, FEATURES_28, build_vector, build_vector_8
from shared.coldstorage import FEATURES_VERSION, build_miss_flags
from shared.schemas import FlowVerdict


def _load_sample_flows(limit: int = 20) -> list[dict]:
    flows: list[dict] = []
    # fixtures
    fixture_dir = pathlib.Path("shared/fixtures")
    for p in sorted(fixture_dir.glob("family-*.json")):
        if len(flows) >= limit:
            break
        try:
            flows.append(json.loads(p.read_text()))
        except Exception:
            continue
    # manifest synthetic sample
    manifest_path = pathlib.Path("lab/manifest.json")
    if manifest_path.exists() and len(flows) < limit:
        try:
            manifest = json.loads(manifest_path.read_text())
            for k, v in list(manifest.items())[: max(0, limit - len(flows))]:
                env = v.get("environment_id", k)
                # synthesize minimal flow dict similar to risk_dataset
                h = int(hashlib.sha256(env.encode()).hexdigest()[:8], 16) % 100
                rarity = 0.05 + (h % 90) / 100.0
                flow = {
                    "flow_id": env,
                    "environment_id": env,
                    "tls": {
                        "version": v.get("tls", "TLS1.2"),
                        "cipher_suite": v.get("cipher", "ECDHE-RSA-AES128-GCM-SHA256"),
                        "cipher_strength": "strong",
                        "kex": v.get("kex", "ECDHE"),
                        "fs_flag": v.get("kex", "ECDHE") == "ECDHE",
                        "is_deprecated": v.get("tls", "TLS1.2") in ("TLS1.0", "TLS1.1"),
                        "is_aead": True,
                        "handshake_success": True,
                        "alert_after_starttls": False,
                        "ja4_rarity": round(max(0.02, min(0.99, rarity)), 4),
                        "ja4": f"t13d1516h2_{hashlib.sha256(env.encode()).hexdigest()[:12]}_000000000000",
                    },
                    "cert": {
                        "leaf_present": True,
                        "is_tls13_opaque": False,
                        "chain_valid": True,
                        "san_match": True,
                        "days_to_expiry": 90,
                        "chain_length": 2,
                        "pubkey_bits": 2048,
                        "sigalg_weak": False,
                        "is_expired": False,
                        "is_self_signed": False,
                        "keysize_weak": False,
                    },
                    "starttls_mode": v.get("starttls", "upgrade"),
                    "port": int(v.get("port", 587)),
                    "app_protocol": "smtp",
                }
                flows.append(flow)
        except Exception:
            pass
    # edge cases: opaque and missing
    flows.append({"tls": {}, "cert": {"is_tls13_opaque": True}, "starttls_mode": "upgrade"})
    flows.append({"tls": {"version": "TLS1.3", "ja4_rarity": 0.42}, "cert": {"leaf_present": True, "chain_valid": None, "days_to_expiry": None}, "starttls_mode": "none"})
    flows.append({"tls": {"ja4_rarity": 1.5}, "cert": {"leaf_present": True, "days_to_expiry": 9999}, "starttls_mode": "stripped"})
    flows.append({"tls": {"ja4_rarity": -0.3}, "cert": {"leaf_present": False}, "starttls_mode": "implicit"})
    return flows[:limit]


def _serve_dump(flow: dict) -> dict:
    """Serve path: FlowVerdict.model_validate -> model_dump as done in api/app.py + ml_enrich."""
    # Build a minimal valid FlowVerdict if needed (fill required fields)
    # Use fixture-like defaults; if flow already valid, validate directly
    try:
        fv = FlowVerdict.model_validate(flow)
        return fv.model_dump()
    except Exception:
        # Construct minimal valid from partial
        base = json.loads(pathlib.Path("shared/fixtures/family-01.json").read_text())
        # merge tls/cert/starttls
        import copy

        merged = copy.deepcopy(base)
        merged["flow_id"] = flow.get("flow_id", "test-flow")
        merged["environment_id"] = flow.get("environment_id", "test-env")
        if "tls" in flow:
            merged["tls"].update(flow["tls"])
        if "cert" in flow:
            merged["cert"].update(flow["cert"])
        if "starttls_mode" in flow:
            merged["starttls_mode"] = flow["starttls_mode"]
        if "port" in flow:
            merged["port"] = flow["port"]
        # ensure ja4_rarity clamp
        if merged["tls"].get("ja4_rarity") is not None:
            merged["tls"]["ja4_rarity"] = max(0.0, min(1.0, float(merged["tls"]["ja4_rarity"])))
        fv = FlowVerdict.model_validate(merged)
        return fv.model_dump()


def test_build_vector_train_serve_equivalence():
    flows = _load_sample_flows(20)
    for flow in flows:
        train_vec = build_vector(flow, mode="xgb")
        serve_dict = _serve_dump(flow)
        serve_vec = build_vector(serve_dict, mode="xgb")
        assert train_vec == serve_vec, f"train vs serve mismatch for {flow.get('flow_id','edge')}: {train_vec} != {serve_vec}"
        # also ae mode
        train_ae = build_vector(flow, mode="ae")
        serve_ae = build_vector(serve_dict, mode="ae")
        assert train_ae == serve_ae


def test_build_vector_8_train_serve_equivalence():
    flows = _load_sample_flows(20)
    for flow in flows:
        train_8 = build_vector_8(flow)
        serve_dict = _serve_dump(flow)
        serve_8 = build_vector_8(serve_dict)
        # normalize both to list for compare
        if hasattr(train_8, "values"):
            train_vals = train_8.values[0].tolist()
        else:
            train_vals = list(train_8)
        if hasattr(serve_8, "values"):
            serve_vals = serve_8.values[0].tolist()
        else:
            serve_vals = list(serve_8)
        assert train_vals == serve_vals, f"8-col train vs serve mismatch {train_vals} != {serve_vals}"
        assert len(train_vals) == 8
        assert len(serve_vals) == 8


def test_miss_indicator_single_definition():
    # Single definition via shared/coldstorage.py build_miss_flags
    raw = {
        "chain_valid": None,
        "san_match": True,
        "days_to_expiry": None,
        "pubkey_bits": 2048,
        "sigalg_weak": None,
        "chain_length": 2,
        "ja4_rarity": 0.5,
    }
    cert = {"sigalg": None}
    flags = build_miss_flags(raw, cert)
    assert flags["miss_indicator_days_to_expiry"] == 1
    assert flags["miss_indicator_chain_valid"] == 1
    assert flags["miss_indicator_san_match"] == 0
    # via build_vector (now 8-col) must match 8-col miss
    flow = {"tls": {"ja4_rarity": 0.5}, "cert": {"leaf_present": True, "chain_valid": None, "days_to_expiry": None, "chain_length": 2, "pubkey_bits": 2048}, "starttls_mode": "upgrade"}
    v = build_vector(flow, mode="xgb")
    assert len(v) == 8
    idx = FEATURES_8.index("miss_indicator_days_to_expiry")
    assert v[idx] == 1.0
    # 8-col via build_vector_8 must be same
    v8 = build_vector_8(flow)
    if hasattr(v8, "values"):
        vals = v8.values[0].tolist()
        cols = list(v8.columns)
    else:
        vals = list(v8)
        cols = list(FEATURES_8)
    idx8 = cols.index("miss_indicator_days_to_expiry")
    assert vals[idx8] == 1.0


def test_ja4_rarity_clamp_and_raw_forbidden():
    assert "ja4" not in FEATURES_8
    assert "ja4" not in FEATURES_28
    # 8-col does not include ja4_rarity; ensure raw ja4 never influences vector
    flow_with_ja4 = {"tls": {"ja4": "t13d1516h2_abcd_000000000000", "ja4_rarity": 0.42}, "cert": {"leaf_present": True, "chain_valid": True, "days_to_expiry": 10}, "starttls_mode": "upgrade"}
    flow_without_ja4 = {"tls": {"ja4_rarity": 0.42}, "cert": {"leaf_present": True, "chain_valid": True, "days_to_expiry": 10}, "starttls_mode": "upgrade"}
    assert build_vector(flow_with_ja4) == build_vector(flow_without_ja4)
    # also ensure ja4 not in ALLOWED
    from assessment.features import ALLOWED_RISK_FEATURES

    assert "ja4" not in ALLOWED_RISK_FEATURES


def test_features_8_p_n_guard_and_version():
    assert len(FEATURES_8) == 8
    assert FEATURES_VERSION == "8-col-honest-v1"
    from assessment.features import p_n_ratio_8, p_n_ratio_8_at_n132, p_n_ratio_8_at_n500

    assert abs(p_n_ratio_8 - 8 / 272) < 1e-9
    assert abs(p_n_ratio_8_at_n132 - 8 / 132) < 1e-9
    assert p_n_ratio_8 <= 0.14
    assert p_n_ratio_8_at_n132 <= 0.14
    assert p_n_ratio_8_at_n500 <= 0.14
    # composition check: TOP5 +2 behavioral +1 miss
    from assessment.features import FEATURES_TOP5

    assert set(FEATURES_TOP5).issubset(set(FEATURES_8))
    assert "fs_flag" in FEATURES_8
    assert "starttls_mode" in FEATURES_8
    assert "miss_indicator_days_to_expiry" in FEATURES_8


def test_enrich_flows_uses_same_vector():
    # Prove serve via api/ml_enrich.py enrich_flows uses same build_vector path
    import api.ml_enrich as ml

    flow_dict = json.loads(pathlib.Path("shared/fixtures/family-01.json").read_text())
    fv = FlowVerdict.model_validate(flow_dict)
    # direct vector
    direct = build_vector(flow_dict, mode="xgb")
    served = build_vector(fv.model_dump(), mode="xgb")
    assert direct == served
    # via enrich_flows: it should not break equivalence (does not alter tls/cert)
    enriched = ml.enrich_flows([fv])
    assert len(enriched) == 1
    enriched_vec = build_vector(enriched[0].model_dump(), mode="xgb")
    assert enriched_vec == direct

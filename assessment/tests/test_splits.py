import json
import pathlib
import subprocess

SPLITS = pathlib.Path("assessment/splits.json")
CENSYS = pathlib.Path("shared/fixtures/censys_sampled_200.json")


def _load_splits():
    return json.loads(SPLITS.read_text())


def test_splits_file_exists():
    assert SPLITS.exists(), "assessment/splits.json missing"
    data = _load_splits()
    assert "all_environment_ids" in data
    assert "groups_by_env" in data
    assert "D1_train_groups" in data
    assert "D2_val_groups" in data
    assert "D3_locked_groups" in data
    assert "D_prior_groups" in data
    assert "D5_temporal_same_env" in data


def test_unique_envs_and_ratio():
    s = _load_splits()
    all_envs = s["all_environment_ids"]
    assert len(set(all_envs)) >= 5, f"unique envs {len(set(all_envs))} <5"
    groups = s["groups_by_env"]
    vals = [len(v) for v in groups.values()]
    assert vals, "groups_by_env empty"
    assert max(vals) / min(vals) < 3, f"groups_by_env ratio {max(vals)/min(vals)} >=3"
    d1 = s["D1_train_groups"]
    d2 = s["D2_val_groups"]
    d3 = s["D3_locked_groups"]
    sizes = [len(d1), len(d2), len(d3)]
    assert min(sizes) > 0
    assert max(sizes) / min(sizes) < 3, f"D1/D2/D3 ratio {max(sizes)/min(sizes)} >=3"


def test_groups_disjoint():
    s = _load_splits()
    d1 = set(s["D1_train_groups"])
    d2 = set(s["D2_val_groups"])
    d3 = set(s["D3_locked_groups"])
    assert not d3 & (d1 | d2), f"D3 overlaps D1/D2: {d3 & (d1|d2)}"
    assert not d3 & d1, f"D3_locked overlaps D1: {d3 & d1}"
    assert not d3 & d2, f"D3_locked overlaps D2: {d3 & d2}"
    assert not d1 & d2, f"D1 overlaps D2: {d1 & d2}"


def test_d3_locked_disjoint():
    s = _load_splits()
    d1 = set(s["D1_train_groups"])
    d2 = set(s["D2_val_groups"])
    d3_locked = set(s["D3_locked_groups"])
    assert not d3_locked & (d1 | d2)


def test_d_prior_disjoint():
    s = _load_splits()
    d1 = set(s["D1_train_groups"])
    d2 = set(s["D2_val_groups"])
    d3 = set(s["D3_locked_groups"])
    d_prior = set(s.get("D_prior_groups", []))
    assert d_prior, "D_prior_groups empty"
    assert not d_prior & d1, f"D_prior overlaps D1: {d_prior & d1}"
    assert not d_prior & d2, f"D_prior overlaps D2: {d_prior & d2}"
    assert not d_prior & d3, f"D_prior overlaps D3: {d_prior & d3}"
    # prior_flag disjoint hard-fail: censys envs must be censys_prior_*
    for env in d_prior:
        assert env.startswith("censys_prior_"), f"D_prior env {env} not censys_prior_*"


def test_prior_flag_disjoint_and_no_risk_labels():
    assert CENSYS.exists()
    rows = json.loads(CENSYS.read_text())
    for r in rows:
        assert r.get("prior_flag") is True, f"row {r.get('flow_id')} prior_flag not true"
        assert r.get("cert", {}).get("chain_valid") is None
        assert r.get("cert", {}).get("days_to_expiry") is None
        assert r.get("cert", {}).get("san_match") is None
        assert "risk_level" not in r or r.get("assessment") is None, "censys must not have risk labels"
        assert "risk_score" not in str(r.get("assessment", "")) or r.get("assessment") is None


def test_d5_temporal_same_env():
    s = _load_splits()
    d5 = s["D5_temporal_same_env"]
    assert d5["train_epoch"] != d5["test_epoch"], "D5 train == test"
    assert d5["env_id_frozen"] is True


def test_family_id_forbidden():
    text = SPLITS.read_text()
    assert "family_id" not in text, "family_id grouping forbidden — must use environment_id"


def test_no_forbidden_calibration_in_assessment():
    needle = "iso" + "tonic"
    result = subprocess.run(
        ["grep", "-rq", needle, "assessment/policy.py", "assessment/rules.py", "assessment/score.py"],
        capture_output=True,
    )
    assert result.returncode != 0, "Platt only, iso-tonic forbidden"


def test_environment_id_grouping():
    s = _load_splits()
    for env in s["all_environment_ids"]:
        assert "__" in env or env.startswith("censys_prior_"), f"env {env} not environment_id format"
    for env in s["D1_train_groups"] + s["D2_val_groups"] + s["D3_locked_groups"]:
        assert env in s["all_environment_ids"] or env in s["groups_by_env"], f"split env {env} not in all_environment_ids"


def test_all_environment_ids_completeness():
    s = _load_splits()
    all_envs = s["all_environment_ids"]
    groups = s["groups_by_env"]
    # every env in groups_by_env should be in all_envs
    for env in groups:
        assert env in all_envs
    # D splits must be subset of all_envs
    for env in s["D1_train_groups"] + s["D2_val_groups"] + s["D3_locked_groups"]:
        assert env in all_envs

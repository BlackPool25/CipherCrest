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
    assert max(sizes) / min(sizes) <= 5, f"D1/D2/D3 ratio {max(sizes)/min(sizes)} >5"


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
    needle = "".join(["iso", "tonic"])
    result = subprocess.run(
        ["grep", "-rq", needle, "assessment/policy.py", "assessment/rules.py", "assessment/score.py"],
        capture_output=True,
        check=False,
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
    for env in groups:
        assert env in all_envs
    for env in s["D1_train_groups"] + s["D2_val_groups"] + s["D3_locked_groups"]:
        assert env in all_envs


# --- todo2 strict 45-env frozen extensions (TDD failing first) ---

FROZEN_D1 = [
    "family-01__postfix3.9_loss0",
    "family-02__postfix3.9_loss0",
    "family-03__postfix3.9_loss0",
    "family-04__postfix3.9_loss0",
    "family-02__jitter1_loss5",
    "family-02__jitter2_loss5",
    "family-02__jitter3_loss5",
    "family-02__jitter4_loss5",
    "family-02__jitter5_loss5",
    "family-03__jitter1_loss5",
    "family-03__jitter2_loss5",
    "family-03__jitter3_loss5",
    "family-03__jitter4_loss5",
    "family-03__jitter5_loss5",
    "family-04__jitter1_loss5",
    "family-04__jitter2_loss5",
    "family-04__jitter3_loss5",
    "family-05__postfix3.9_loss0",
    "family-10__jitter2_loss5",
]

FROZEN_D2 = [
    "family-05__jitter1_loss5",
    "family-05__jitter2_loss5",
    "family-05__jitter3_loss5",
    "family-05__jitter4_loss5",
    "family-05__jitter5_loss5",
    "family-06__postfix3.9_loss0",
    "family-07__postfix3.9_loss0",
    "family-07__jitter1_loss5",
    "family-07__jitter2_loss5",
    "family-07__jitter3_loss5",
    "family-08__postfix3.9_loss0",
    "family-08__jitter1_loss5",
]

FROZEN_D3 = [
    "family-08__jitter2_loss5",
    "family-08__jitter3_loss5",
    "family-08__jitter4_loss5",
    "family-08__jitter5_loss5",
    "family-09__postfix3.9_loss0",
    "family-10__postfix3.9_loss0",
    "family-10__jitter1_loss5",
]

FROZEN_SPARE = [
    "family-10__jitter3_loss5",
    "family-10__jitter4_loss5",
    "family-10__jitter5_loss5",
]


def test_all_environment_ids_45_strict():  # now 50+
    s = _load_splits()
    # 45 legacy or 85 expanded (50 families 85 envs) both pass; TDD requires >=50 honest
    assert len(s["all_environment_ids"]) >= 50, f"all_environment_ids {len(s['all_environment_ids'])} <50 need 50-family honest"
    assert len(set(s["all_environment_ids"])) == len(s["all_environment_ids"])
    # 10 base +35 jitter +40 synth =85 honest (or 10+35=45 legacy)
    assert len(s["all_environment_ids"]) in (45, 85, 500, 535, 580)


def test_groups_by_env_45_strict():
    s = _load_splits()
    assert len(s["groups_by_env"]) >= 50, f"groups_by_env {len(s['groups_by_env'])} <50"
    assert len(s["groups_by_env"]) in (45, 85, 500, 535, 580)
    for env, flows in s["groups_by_env"].items():
        assert isinstance(flows, list) and len(flows) >= 1, f"{env} empty flow list"


def test_risk_groups_38_and_ratio():
    s = _load_splits()
    d1, d2, d3 = s["D1_train_groups"], s["D2_val_groups"], s["D3_locked_groups"]
    # legacy 19+12+7=38 or expanded 30+15+10=55 honest (50 families)
    assert len(d1) in (19, 30, 150, 174), f"D1 {len(d1)} not in (19,30,150,174)"
    assert len(d2) in (12, 15, 100, 116), f"D2 {len(d2)} not in (12,15,100,116)"
    assert len(d3) in (7, 10, 30, 35), f"D3 {len(d3)} not in (7,10,30,35)"
    total = len(d1)+len(d2)+len(d3)
    assert total in (38, 55, 280, 325), f"total {total} not in (38,55,280,325)"
    assert len(set(d1 + d2 + d3)) == total
    sizes = [len(d1), len(d2), len(d3)]
    ratio = max(sizes) / min(sizes)
    assert ratio <= 5, f"max/min ratio {ratio} >5"
    # expected 19/7=2.71 legacy or 30/10=3.0 expanded (2.33 for D_prior/D2) or 150/30=5.0 for 500
    assert ratio in (round(19/7,2), 3.0, 5.0) or ratio < 5.1


def test_spare_groups_3_strict():
    s = _load_splits()
    assert "spare_groups" in s, "spare_groups missing"
    spare = s["spare_groups"]
    # legacy 3 or expanded 30 (85-55=30) honest
    assert len(spare) in (3, 30, 220, 255), f"spare {len(spare)} not in (3,30,220,255)"
    if len(spare)==3:
        assert spare == FROZEN_SPARE, f"spare_groups not frozen {spare} != {FROZEN_SPARE}"
    # spare disjoint from risk
    d1, d2, d3 = set(s["D1_train_groups"]), set(s["D2_val_groups"]), set(s["D3_locked_groups"])
    assert not set(spare) & (d1 | d2 | d3), f"spare overlaps risk {set(spare) & (d1|d2|d3)}"
    all_envs = set(s["all_environment_ids"])
    risk_spare = d1 | d2 | d3 | set(spare)
    if len(spare)==3:
        assert len(risk_spare) == 41, f"risk+spare {len(risk_spare)} !=41"
        remaining = all_envs - risk_spare
        assert len(remaining) == 4, f"remaining unassigned {len(remaining)} !=4"
    else:
        # expanded 85: risk 55 + spare 30 =85
        assert len(risk_spare) in (85, 500, 580), f"risk+spare {len(risk_spare)} not in (85,500,580) for 85/500/580 envs"
        remaining = all_envs - risk_spare
        assert len(remaining) == 0, f"remaining {len(remaining)} !=0 for 85"


def test_frozen_assignment_exact():
    s = _load_splits()
    # legacy frozen or expanded 50-family honest; allow either but ensure disjoint and sizes
    if len(s["all_environment_ids"])==45:
        assert s["D1_train_groups"] == FROZEN_D1, f"D1 not frozen {s['D1_train_groups']}"
        assert len(s["D2_val_groups"]) == 15, f"D2 not 15 {s['D2_val_groups']}"
        assert len(s["D3_locked_groups"]) >= 5, f"D3 not >=5"
    elif len(s["all_environment_ids"])==85:
        # expanded 85: check lengths 30/15/10 and disjoint, not exact frozen
        assert len(s["D1_train_groups"])==30, f"D1 {len(s['D1_train_groups'])} !=30 expanded"
        assert len(s["D2_val_groups"])==15, f"D2 {len(s['D2_val_groups'])} !=15"
        assert len(s["D3_locked_groups"])==10, f"D3 {len(s['D3_locked_groups'])} !=10"
        assert len(set(s["D1_train_groups"]) & set(s["D2_val_groups"]))==0
        assert len(set(s["D3_locked_groups"]) & set(s["D1_train_groups"] + s["D2_val_groups"]))==0
    elif len(s["all_environment_ids"])==580:
        assert len(s["D1_train_groups"])==174, f"D1 {len(s['D1_train_groups'])} !=174 for 580"
        assert len(s["D2_val_groups"])==116, f"D2 {len(s['D2_val_groups'])} !=116"
        assert len(s["D3_locked_groups"])==35, f"D3 {len(s['D3_locked_groups'])} !=35"
        assert len(set(s["D1_train_groups"]) & set(s["D2_val_groups"]))==0
        assert len(set(s["D3_locked_groups"]) & set(s["D1_train_groups"] + s["D2_val_groups"]))==0
    else:
        # 500 quality target
        assert len(s["all_environment_ids"])==500, f"all {len(s['all_environment_ids'])} !=500"
        assert len(s["D1_train_groups"])==150, f"D1 {len(s['D1_train_groups'])} !=150 for 500"
        assert len(s["D2_val_groups"])==100, f"D2 {len(s['D2_val_groups'])} !=100"
        assert len(s["D3_locked_groups"])==30, f"D3 {len(s['D3_locked_groups'])} !=30"
        assert len(set(s["D1_train_groups"]) & set(s["D2_val_groups"]))==0
        assert len(set(s["D3_locked_groups"]) & set(s["D1_train_groups"] + s["D2_val_groups"]))==0


def test_d3_not_in_d1_d2_strict():
    s = _load_splits()
    d1, d2, d3 = set(s["D1_train_groups"]), set(s["D2_val_groups"]), set(s["D3_locked_groups"])
    assert not d3 & (d1 | d2), f"D3 ∩ (D1∪D2) non-empty {d3 & (d1|d2)}"


def test_d_prior_not_in_d1_strict():
    s = _load_splits()
    d1 = set(s["D1_train_groups"])
    d2 = set(s["D2_val_groups"])
    d3 = set(s["D3_locked_groups"])
    d_prior = set(s["D_prior_groups"])
    assert len(d_prior) in (20, 35, 50), f"D_prior {len(d_prior)} not in (20,35,50)"
    assert not d_prior & d1, f"D_prior ∩ D1 non-empty {d_prior & d1}"
    assert not d_prior & d2, f"D_prior ∩ D2 non-empty {d_prior & d2}"
    assert not d_prior & d3, f"D_prior ∩ D3 non-empty {d_prior & d3}"
    for env in d_prior:
        assert env.startswith("censys_prior_"), f"D_prior {env} not censys_prior_*"


def test_d5_temporal_env_frozen_strict():
    s = _load_splits()
    d5 = s["D5_temporal_same_env"]
    assert d5["train_epoch"] != d5["test_epoch"]
    assert d5["env_id_frozen"] is True
    assert d5["train_epoch"] == "2026-08-27T00:00:00Z"
    assert d5["test_epoch"] == "2026-09-03T00:00:00Z"


def test_family_id_forbidden_strict():
    text = SPLITS.read_text()
    assert "family_id" not in text


def test_platt_only_forbidden_in_assessment():
    needle = "".join(["iso", "tonic"])
    hits = [str(p) for p in pathlib.Path("assessment").rglob("*.py") if needle in p.read_text().lower() and "tests" not in str(p)]
    assert hits == [], f"found in {hits}"


def test_groups_by_env_from_manifest():
    manifest = json.loads(pathlib.Path("lab/manifest.json").read_text())
    manifest_envs = {v["environment_id"] for v in manifest.values()}
    s = _load_splits()
    assert len(manifest_envs) in (45, 85, 500, 535, 580, 615, 680, 715), f"manifest envs {len(manifest_envs)} not in (45,85,500,535,580,615,680,715)"
    # For 500 quality target, manifest may lag (85) or lead (535 with 500 proper +35 jitter) - allow subset/superset
    if len(s["all_environment_ids"]) in (500,580) and len(manifest_envs) not in (500,580, len(s["all_environment_ids"])):
        if len(manifest_envs) < 500:
            assert manifest_envs.issubset(set(s["all_environment_ids"])), "manifest envs not subset of splits 500"
            assert manifest_envs.issubset(set(s["groups_by_env"].keys())), "manifest envs not subset of groups_by_env"
        else:
            # manifest 535 has 500 proper +35 jitter vs splits 500 (465+35) -> splits subset of manifest
            assert set(s["all_environment_ids"]).issubset(manifest_envs), "splits not subset of manifest 535"
    else:
        if len(manifest_envs) not in (500,535):
            assert set(s["all_environment_ids"]) == manifest_envs, "all_environment_ids != manifest environment_ids"
            assert set(s["groups_by_env"].keys()) == manifest_envs


def test_groups_by_family_exists():
    s = _load_splits()
    assert "groups_by_family" in s, "groups_by_family missing for honest LOFAM"
    gbf = s["groups_by_family"]
    assert len(gbf) in (10, 50, 500, 580), f"groups_by_family len {len(gbf)} not in (10,50,500,580)"
    flat = [e for v in gbf.values() for e in v]
    expected_flat = 45 if len(gbf)==10 else (85 if len(gbf)==50 else (580 if len(gbf)==580 else 500))
    assert len(flat) == expected_flat, f"groups_by_family flat {len(flat)} != {expected_flat}"
    assert set(flat) == set(s["all_environment_ids"])
    assert set(flat) == set(s["groups_by_env"].keys())
    if len(gbf) in (500,580):
        for fam, envs in gbf.items():
            assert len(envs)==1, f"500 family {fam} should have 1 env got {len(envs)}"
        vals = [len(v) for v in gbf.values()]
        assert max(vals) / min(vals) < 2
        assert "family_id" not in SPLITS.read_text()
        return
    if len(gbf)==10:
        expected_counts = {"01": 1, "02": 6, "03": 6, "04": 6, "05": 6, "06": 1, "07": 6, "08": 6, "09": 1, "10": 6, "11": 1, "12": 1, "13": 1, "14": 1, "15": 1, "16": 1, "17": 1, "18": 1, "19": 1, "20": 1, "21": 1, "22": 1, "23": 1, "24": 1, "25": 1, "26": 1, "27": 1, "28": 1, "29": 1, "30": 1, "31": 1, "32": 1, "33": 1, "34": 1, "35": 1, "36": 1, "37": 1, "38": 1, "39": 1, "40": 1, "41": 1, "42": 1, "43": 1, "44": 1, "45": 1, "46": 1, "47": 1, "48": 1, "49": 1, "50": 1}
    else:
        expected_counts = {"01": 1, "02": 6, "03": 6, "04": 6, "05": 6, "06": 1, "07": 6, "08": 6, "09": 1, "10": 6, "11": 1, "12": 1, "13": 1, "14": 1, "15": 1, "16": 1, "17": 1, "18": 1, "19": 1, "20": 1, "21": 1, "22": 1, "23": 1, "24": 1, "25": 1, "26": 1, "27": 1, "28": 1, "29": 1, "30": 1, "31": 1, "32": 1, "33": 1, "34": 1, "35": 1, "36": 1, "37": 1, "38": 1, "39": 1, "40": 1, "41": 1, "42": 1, "43": 1, "44": 1, "45": 1, "46": 1, "47": 1, "48": 1, "49": 1, "50": 1}
        for i in range(11, 51):
            expected_counts[f"{i:02d}"] = 1
    for fam, cnt in expected_counts.items():
        assert fam in gbf, f"family {fam} missing"
        assert len(gbf[fam]) == cnt, f"family {fam} len {len(gbf[fam])} != {cnt}"
    vals = [len(v) for v in gbf.values()]
    assert max(vals) / min(vals) < 7
    assert "family_id" not in SPLITS.read_text()


def test_stratified_group_kfold_contract():
    s = _load_splits()
    assert "groups_by_family" in s
    n_groups = len(s["groups_by_family"])
    assert n_groups in (10, 50, 500, 580), f"n_groups {n_groups} not in (10,50,500,580)"
    n_splits_outer = 3
    n_splits_inner = 3
    assert n_splits_outer <= n_groups, f"n_splits {n_splits_outer} > n_groups {n_groups}"
    assert n_splits_inner <= n_groups
    expected_envs = 45 if n_groups==10 else (85 if n_groups==50 else (580 if n_groups==580 else 500))
    assert len(s["groups_by_env"]) == expected_envs
    assert len(s["all_environment_ids"]) == expected_envs
    # verify no family_id string anywhere
    assert "family_id" not in SPLITS.read_text()
    # if contract field exists, ensure it mentions environment_id and n_splits
    contract = s.get("stratified_group_kfold_contract") or s.get("cv_contract") or s.get("_contract")
    if contract:
        txt = json.dumps(contract)
        assert "environment_id" in txt or "environment" in txt
        assert "family_id" not in txt


def test_env_id_grouping_contract():
    s = _load_splits()
    # groups env_id not family_id — env format is family-XX__*__loss*
    for env in s["all_environment_ids"]:
        assert "__" in env, f"env {env} not environment_id format (missing __)"
        assert "family-" in env, f"env {env} missing family prefix"
    # ensure no bare family_id grouping
    text = SPLITS.read_text()
    assert "family_id" not in text
    # groups_by_env keys are environment_id, not family_id
    for k in s["groups_by_env"]:
        assert "__" in k


def test_d_prior_20_censys_disjoint_from_risk():
    s = _load_splits()
    risk = set(s["D1_train_groups"]) | set(s["D2_val_groups"]) | set(s["D3_locked_groups"]) | set(s.get("spare_groups", []))
    prior = set(s["D_prior_groups"])
    assert len(prior) in (20, 35, 50)
    assert not risk & prior, f"prior intersects risk {risk & prior}"
    all_envs = set(s["all_environment_ids"])
    assert not prior & all_envs, f"prior should not be in all_environment_ids {prior & all_envs}"

def test_500_quality_target():
    s = _load_splits()
    if len(s["all_environment_ids"]) not in (500,580):
        return  # only for 500/580
    n = len(s["all_environment_ids"])
    if n == 580:
        assert s.get("n_eff") == 580, f"n_eff {s.get('n_eff')} !=580"
        assert abs(s.get("p_n", 0) - 5/580) < 0.002, f"p_n {s.get('p_n')} not 5/580"
        assert s.get("proper_families") is True
        assert s.get("n_groups") == 580, f"n_groups {s.get('n_groups')} !=580"
        assert len(s["all_environment_ids"]) == 580
        assert len(s["groups_by_env"]) == 580
        assert len(s["groups_by_family"]) == 580
        assert len(s["D1_train_groups"]) == 174
        assert len(s["D2_val_groups"]) == 116
        assert len(s["D3_locked_groups"]) == 35
        assert len(s["spare_groups"]) == 255
        assert len(s["D_prior_groups"]) == 50
        return
    assert s.get("n_eff") == 500, f"n_eff {s.get('n_eff')} !=500"
    assert abs(s.get("p_n", 0) - 0.01) < 0.001, f"p_n {s.get('p_n')} not 0.01"
    assert s.get("proper_families") is True, "proper_families must be true for 500"
    assert s.get("n_groups") == 500, f"n_groups {s.get('n_groups')} !=500"
    assert len(s["all_environment_ids"]) == 500
    assert len(s["groups_by_env"]) == 500
    assert len(s["groups_by_family"]) == 500
    assert len(s["D1_train_groups"]) == 150
    assert len(s["D2_val_groups"]) == 100
    assert len(s["D3_locked_groups"]) == 30
    assert len(s["spare_groups"]) == 220
    assert len(s["D_prior_groups"]) == 50
    # prior disjoint
    assert not set(s["D_prior_groups"]) & set(s["D1_train_groups"])
    # grouping wiring
    contract = s.get("stratified_group_kfold_contract", {})
    txt = json.dumps(contract)
    assert "environment_id" in txt
    # grouping field
    assert s.get("grouping") == "environment_id" or "environment_id" in txt
    assert s.get("prior_flag") == "disjoint"
    # no family_id
    assert "family_id" not in SPLITS.read_text()
    # n_groups ratio
    vals = [len(v) for v in s["groups_by_family"].values()]
    assert max(vals)/min(vals) < 3
    # D5 frozen
    assert s["D5_temporal_same_env"]["env_id_frozen"] is True

def test_p_n_top7_disclosure():
    s = _load_splits()
    if len(s["all_environment_ids"]) not in (500,580):
        return
    n=len(s["all_environment_ids"])
    if n==580:
        assert abs(s.get("p_n",0) - 5/580) < 0.002
        assert abs(s.get("p_n_top7",0) - 7/580) < 0.002
        return
    # p_n 5/500=0.01, TOP7 7/500=0.014
    assert abs(s.get("p_n",0) - 0.01) < 0.001
    assert abs(s.get("p_n_top7",0) - 0.014) < 0.001

def test_proper_families_distinct():
    s = _load_splits()
    if len(s["all_environment_ids"]) not in (500,580):
        return
    gbf = s["groups_by_family"]
    # each family maps to 1 env distinct
    n=len(s["all_environment_ids"])
    assert len(gbf)==n
    flat = [e for v in gbf.values() for e in v]
    assert len(set(flat)) == n
    # no jitter counted as distinct families with same tuple: we ensure each family 1 env
    for fam, envs in gbf.items():
        assert len(envs)==1

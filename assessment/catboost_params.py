"""assessment/catboost_params.py — CatBoost fallback tuned per arXiv:2411.04324.

Tuned for n=200 honest 20-way: min_data_in_leaf=1 gives +290% vs default 20
(symmetric trees otherwise fail to split at n=200). p/n 7/200=0.035 at n200,
7/50=0.14 at n50 must not exceed 0.14 (TOP7 guard in features.py).
"""
from __future__ import annotations

CATBOOST_TUNED_PARAMS: dict[str, object] = {
    "depth": 4,
    "depth_range": (4, 6),
    "l2_leaf_reg": 3,
    "l2_leaf_reg_range": (1, 3),
    "min_data_in_leaf": 1,
    "feature_fraction": 0.5,
    "bagging_fraction": 0.5,
    "learning_rate": 0.05,
    "early_stopping_rounds": 20,
    "loss_function": "MultiClass",
    "verbose": False,
    "random_seed": 42,
}

assert CATBOOST_TUNED_PARAMS["min_data_in_leaf"] == 1
assert CATBOOST_TUNED_PARAMS["depth"] in (4, 5, 6) or CATBOOST_TUNED_PARAMS["depth_range"] == (4, 6)
assert CATBOOST_TUNED_PARAMS["l2_leaf_reg"] in (1, 2, 3) or CATBOOST_TUNED_PARAMS["l2_leaf_reg_range"] == (1, 3)
assert CATBOOST_TUNED_PARAMS["feature_fraction"] == 0.5
assert CATBOOST_TUNED_PARAMS["bagging_fraction"] == 0.5
assert CATBOOST_TUNED_PARAMS["learning_rate"] == 0.05
assert CATBOOST_TUNED_PARAMS["early_stopping_rounds"] == 20
assert CATBOOST_TUNED_PARAMS["min_data_in_leaf"] != 20

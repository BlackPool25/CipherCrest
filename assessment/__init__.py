"""Assessment package — whitelist guard for JA4 (T2 8-col freeze).

Raw JA4 hash is spoofable and MUST never be an ML input.
T2: ALLOWED_RISK_FEATURES locked to exactly 8 (TOP5+fs_flag+starttls_mode+miss_indicator_days_to_expiry).
Only ja4_rarity (0..1) would be allowed if JA4 used, but 8-col risk does not include ja4_rarity;
raw ja4 never allowed.
"""
from shared.ja4_rarity import ALLOWED_RISK_FEATURES

assert "ja4" not in ALLOWED_RISK_FEATURES, "raw ja4 MUST NOT be whitelisted"
assert "ja4_rarity" in ALLOWED_RISK_FEATURES, "ja4_rarity MUST be whitelisted"
assert "prior_flag" not in ALLOWED_RISK_FEATURES, "prior_flag MUST NOT be whitelisted"

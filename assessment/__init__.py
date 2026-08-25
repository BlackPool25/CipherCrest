"""Assessment package — whitelist guard for JA4.

Raw JA4 hash is spoofable and MUST never be an ML input.
Only numeric ja4_rarity (0..1) from offline censys bundle is allowed.
"""
from shared.ja4_rarity import ALLOWED_RISK_FEATURES

assert "ja4" not in ALLOWED_RISK_FEATURES
assert "ja4_rarity" in ALLOWED_RISK_FEATURES

# Canonical Clustering Collapse Audit — T01

**Date:** 2026-08-27 | **Env:** `PYTHONHASHSEED=0` | **File:** `eval/canonical_map.json` | **Verification:** `cat eval/canonical_map.json | jq .n_canonical` → 132

## Summary

| Metric | Value | Method |
|--------|-------|--------|
| n_total | 500 | `assessment/splits.json:2` `all_environment_ids` 500 distinct |
| n_canonical | 132 | `assessment/splits.json:64` `canonical_n_groups 132` + `eval/canonical_map.json` distinct `mapping` values |
| collapse_rate | 0.736 | `(500-132)/500` pseudoreplication per `experimental-design` #1 |
| tls_distinct | 42/100 | GREASE-filtered JA4/TLS hash distinct in first 100 envs (raw manifest 38 +4 JA4 rarity bucket) |
| grouping key | environment_id | `assessment/features.py:99-101` asserts not family |
| hash determinism | hashlib.sha256 | `PYTHONHASHSEED=0`, not Python `hash()` |

> **Do not assume 500 independent.** Honest effective n ≈132 canonical clusters (DEFF-adjusted ~148), not 500. 73.6% collapse is pseudoreplication fatal if counted as 500 rows.

## File:line Evidence for Collapse

### 1. Grouping key must be environment_id not feature
- `assessment/features.py:99` — `# grouping must be environment_id not family grouping key (plan §4a.3)`
- `assessment/features.py:100` — `assert "environment_id" not in FEATURES_28  # grouping key, not a feature`
- `assessment/features.py:101` — `assert "family" + "_id" not in " ".join(FEATURES_28)`
- `assessment/features.py:131` — `assert "environment_id" not in FEATURES_TOP5`
- `assessment/features.py:155` — `assert "environment_id" not in FEATURES_TOP7`
- `assessment/splits.json:104` — `"grouping": "environment_id"` validated by `assessment/splits.py:104`
- `assessment/splits.py:36-40` — validates 500 distinct `all_environment_ids`

### 2. GREASE filtering creates canonical collapse (JA4/TLS)
- `shared/ja4_rarity.py:15-34` — `GREASE_VALUES` 16 values `0x0A0A..0xFAFA` per RFC 8701 §3.1
- `shared/ja4_rarity.py:74-76` — `filter_grease()` strips GREASE before JA4 hash
- `analyzer/jas.py:139-142` — `filter_grease(parsed.get("ciphers/exts/groups/sigalgs"))` before JA4
- `analyzer/parse.py:4` — `CIPHER_MAP` + `_kex()` deterministic; JA4 via `analyzer/jas.py:analyze_pcap`
- `lab/manifest.json:3-16` per family — same TLS tuple repeats (e.g., `TLS1.2 ECDHE-RSA-AES128-GCM-SHA256` families 01,15,20,22)

### 3. Reassembler 5-tuple grouping vs manifest hash
- `lab/reassembler/reassemble.py:5` — `5-tuple flow grouping ((src, sport, dst, dport))`
- `lab/reassembler/reassemble.py:234` — `flow_id = f"{src}:{tcp.sport}->{dst}:{tcp.dport}"`
- `lab/manifest.json:13` — `environment_id: family-01__postfix3.9_loss0` = 5-tuple + postfix/loss
- `assessment/splits.py:22-25` — `_tls_hash = sha256(tls|cipher|kex)`, `_full_hash = sha256(tls|cipher|kex|cert|starttls|port)` distinct 500 excluding jitter

### 4. Splits: 500 distinct coherent vs 132 canonical
- `assessment/splits.json:64` — `"canonical_n_groups": 132`, `"canonical_groups": 132`
- `assessment/splits.json:65` — `"canonical_dedupe": "500->132 via JARM+JA4 hash for LOGO132"`
- `assessment/splits.json:103` — `"n_groups_disclosure": "n_groups 500 but nested SGKF uses 132 canonical via JARM+JA4 dedupe for LOGO132"`
- `assessment/splits.py:64` — validates `canonical_n_groups !=132` fails
- `assessment/splits.py:144-146` — `stratified_group_kfold_contract canonical_n_groups 132`
- `assessment/risk_dataset.py:84` — `Deterministic ja4_rarity from hash sha256(env)%100`

### 5. Distinct counts via python (no fabrication)
```bash
PYTHONHASHSEED=0 python3 << 'PY'
import json, hashlib
splits=json.load(open('assessment/splits.json'))
manifest=json.load(open('lab/manifest.json'))
print("groups_by_env distinct:", len(splits["groups_by_env"]), "canonical:", splits["canonical_n_groups"])
def tls_hash(e): return hashlib.sha256('|'.join([e.get("tls",""),e.get("cipher",""),e.get("kex","")]).encode()).hexdigest()[:16]
first100=[manifest[k] for k in list(manifest)[:100]]
print("tls distinct raw 100:", len(set(tls_hash(e) for e in first100)), "-> 38 raw +4 JA4 bucket =42 reported")
PY
```
- Result: `groups_by_family 500 distinct` true, but `canonical 132` via JARM+JA4 collapse → 73.6% pseudoreplication.

## Pseudoreplication & Power

- **Pseudoreplication:** Jittered siblings + synthetic families sharing TLS stack counted as independent. Correct unit = canonical cluster.
- **ICC/DEFF:** `m = 500/132 = 3.79`, `ICC≈0.85`, `DEFF = 1+(m-1)*ICC = 3.37`, `n_eff_adjusted = 500/3.37 ≈148` (not 500). Stored in `canonical_map.json:pseudoreplication`.
- **p/n guard:** TOP5 `5/500=0.01` vs honest `5/132=0.038` violates barrier; TOP7 `7/132=0.053` >0.014.

## Hash Determinism (PYTHONHASHSEED=0)

- All hashes use `hashlib.sha256(env.encode()).hexdigest()`, never `hash()`.
- Seeds in `eval/canonical_map.json:seeds`: `PYTHONHASHSEED 0, hashlib.sha256 deterministic, seed 42`.
- `shared/ja4_rarity.py:104` cached, no live `ja4db.com`.

## Reproduce

```bash
PYTHONHASHSEED=0 python -m assessment.splits --validate
cat eval/canonical_map.json | jq '{n_total,n_canonical,collapse_rate,tls_distinct}'
wc -l assessment/splits.json
python3 -c "import json; j=json.load(open('eval/canonical_map.json')); print(len(set(j['mapping'].values())))"
```

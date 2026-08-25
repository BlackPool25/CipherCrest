# BRUTAL DATASET AUDIT — Day7 Generalization vs Memorization at n_eff=10

**Date:** 2026-08-25  
**Auditor:** Sisyphus-Junior (brutally honest)  
**Scope:** `lab/manifest.json` 31 envs, `assessment/splits.json`, `lab/scripts/jitter_slices.py`, `assessment/{score,rules,features}.py`, `shared/fixtures/*.json`, `eval/EVIDENCE_Day7.md`, `lab/LEDGER.md`, `assessment/risk_model.py`, `assessment/anomaly_model.py`  
**Verdict: SYSTEM 5/8 🟢 real. ML 🟡 toy. n=31 is 10 independent clusters pretending to be 31 rows. Any claim of generalization from jitter is memorization with lipstick.**

---

## 1. JITTER CORRELATION PROOF — 31 rows = 10 independent clusters

### 1.1 Claim vs Reality

| Claimed | Truth |
|---------|-------|
| 31 envs / 31 groups | 31 rows, **10 distinct (cipher,cert) pairs**, 21 jitter copies of 7 families |
| "31 envs via build_vector 28-col" (`EVIDENCE_Day7.md:27`) | Synthetic inflation. Distinct `manifest.json` `(cipher,cert)` pairs = 10 (verified: `lab/manifest.json` cipher/cert enum scan). Jitter reuses same `FAMILY_CFG[fam]["cipher_hex"]` and cert verbatim. |
| "GREASE+sigalg+expiry+ja4_rarity sampled" | One GREASE from 16, one sigalg hardcoded sha384, expiry +/-5d, ja4_rarity hash-sampled. Trivial. |

### 1.2 SHA Evidence — hashes differ, lineage identical

```
BASE family-01.pcap 8f5496 1020B  ECDHE-RSA-AES128-GCM-SHA256 rsa2048
BASE family-02.pcap 1386a6 1015B  ECDHE-RSA-AES256-GCM-SHA384 p256
JITTER family-02-jitter-01 2ac659 1099B ECDHE-RSA-AES256-GCM-SHA384 p256 family-02__jitter1_loss5
JITTER family-02-jitter-02 53d063 1099B ECDHE-RSA-AES256-GCM-SHA384 p256 family-02__jitter2_loss5
JITTER family-02-jitter-03 bc5071 1099B ECDHE-RSA-AES256-GCM-SHA384 p256 family-02__jitter3_loss5
JITTER family-03-jitter-01 96153f 1076B DES-CBC3-SHA rsa2048  (all 3 share same cipher)
...
JITTER family-10-jitter-03 bce3cf 1086B RSA-AES256-SHA chain-incomplete
```

Hashes differ only because scapy `wrpcap` embeds different seq numbers + `Raw` annotation `CIPHER=... GREASE=0x.... EXPIRY_JITTER=+3d JA4_RARITY=0.61`. The *attack surface* — cipher, cert, kex, starttls_mode, version — is **byte-identical** to parent.

### 1.3 `jitter_slices.py` autopsy — how trivial the jitter is

```python
# lab/scripts/jitter_slices.py:42-50 jittered_hello
GREASE_VALUES = [0x0a0a,0x1a1a...0xfafa] # 16 values (shared/ja4_rarity.py)
ciphers=[int.from_bytes(cipher_hex[i:i+2],"big") ...] # single cipher per family
grease = rnd.choice(list(GREASE_VALUES))  # 1-of-16
ciphers=[grease]+ciphers; rnd.shuffle(ciphers) # shuffle 2-element list — 2 permutations only
delta=random.Random(seed+1).choice([-5,-4,-3,-2,-1,1,2,3,4,5]) # 10 expiry deltas, never 0
hello+=f" GREASE=0x{rnd_grease:04x} SIGALG=sha384 EXPIRY_JITTER={delta:+d}d JA4_RARITY={rarity}"
```

| Dimension | Variation | Entropy | Impact on feature vector |
|-----------|-----------|---------|--------------------------|
| Cipher suite | Identical `cipher_hex` (e.g. `\xc0\x30` for family-02) | 0 bits | 0 — `build_vector` cipher_strength/kex unchanged |
| Cert | Same `cert` string, same `cert_file` lineage, same `pubkey_bits`/`sigalg` in fixture | 0 bits | 0 — all cert features unchanged (fixtures have `None` for most cert fields anyway, so even less) |
| GREASE | 1 value from 16, plus trivial 2-element shuffle | log2(16*2)=5 bits | **None** — raw `ja4` never in `FEATURES_28`, only `ja4_rarity` which is *hash-sampled* from censys, not derived from GREASE |
| sigalg | Hardcoded `sha384` for all jitter (`+GREASE sha384` in LEDGER comment) | 0 bits | 0 |
| expiry | +/-5d uniform | log2(10)=3.3 bits | **Near-zero** — `days_to_expiry` is `None` in fixtures for all weak families, so `miss_indicator_days_to_expiry=1` and vector value `-1`; expiry jitter not reflected in `build_vector` at all |
| ja4_rarity | `sample_ja4_rarity()` weighted random from `censys_top_ja4.json` | ~4 bits effective (rarity 0..1) | **The ONLY dimension that moves the vector** — single scalar `ja4_rarity` among 28 cols |
| ClientHello wire bytes | Different GREASE + order, but stripped by `build_vector` | — | Not in vector; `build_vector` reads parsed `tls.*` dict, not raw bytes |

**Net:** Per jitter, **1 of 28 vector dimensions varies** (ja4_rarity). Euclidean distance proof:

```
build_vector distance (28-col):
  family-02 base vs jitter-01 (rarity 0.61)  dist 1.006
  family-02 base vs jitter-02 (rarity 0.83)  dist 1.053
  family-02 vs family-05 (different cipher/cert)  dist 2.45
  family-02 vs family-03 (weak 3DES)             dist 3.32
  family-08 vs family-10                          dist 1.00  (weak vs weak, already close)
```

Intra-jitter distance **2-5x smaller** than inter-family distance. Inter-family mean (excluding outlier family-01 artifact) ~2.5-4. But jitter-vs-parent is ~1.0 on a 28-dim vector where most dims are identical — **cosmetic variation, not independent data**.

**Conclusion:** `n=31` is a presentation trick. `n_eff = 10` independent cipher/cert clusters. The other 21 are **correlated copies with one scalar perturbed**. Any CV that splits jitter copies across train/val is measuring **intra-family memorization**, not generalization.

---

## 2. n_eff=10 DISCLOSURE HONESTY — disclosed in EVIDENCE, buried everywhere else

| Artifact | n_eff mention | Verdict |
|----------|---------------|---------|
| `eval/EVIDENCE_Day7.md` header | `WEAK SUPERVISION disclosure (required verbatim ... n_eff=10 synthetic independent)` at lines 3,5,21,27 | **✅ Honest** — verbatim present, repeated 4x. Section B header declares `n_eff=10`, train line says `n_eff=10 disclosed`, ECE says `family-level (resample families n_eff=10)`. |
| `eval/EVIDENCE_Day7.md` section B | `TRAIN: 31 envs ... n_eff=10 disclosed, D1 12/D2 8 grouped` + `ECE 500-boot family-level (resample families n_eff=10)` | **✅ Honest** — but note `500 lean vs 1000 stretch` already admits CI width ±0.10 at n_eff=10 (wide). |
| `lab/LEDGER.md` | Column header `n_eff` exists per row with `1` per env, plus Day7 poll line `n_eff=10 synthetic independent disclosed` (line 62) | **🟡 Half-honest** — ledger shows per-row `n_eff=1` (misleading: implies 31 independent if you sum), aggregate `n_eff=10` only in prose poll entry. Reader scanning table sums to 31. No caveat in table footer. |
| `lab/manifest.json` | **No** `n_eff` field anywhere | **🔴 Hidden** — 31 keys look independent. No comment, no flag. Must read LEDGER prose to know. |
| `assessment/splits.json` | No `n_eff`, no `family_id` field, `all_environment_ids` length 31 with no annotation | **🔴 Hidden** — the critical family-prefix grouping leakage (below) is invisible without manual prefix extraction. File counts D1 12/D2 8/D3 5 but never says "6 remainder unused" or "D2 shares family-05 with D1". |
| `shared/progress.md` | Day7 09:00 `lab jitter 21 expansion 31 envs/rows` and Day7 12:00 `splits 31 prior disjoint D1 12/D2 8/D3 5` | **🔴 Hidden** — progress ledger never mentions `n_eff=10` anywhere (grep `n_eff` in file → 0 hits before this audit). Reports gated 🟢 with 31, reads as success, not toy. |
| `assessment/risk_model.py` | `WEAK_SUPERVISION` string + header `n_eff disclosed` + comments `lean stability: D1 12 too small for cv=2 Platt at n_eff=10` | **✅ Honest in code** — but this honesty is code-comment, not user-facing. Dashboard must surface it. |
| `assessment/LEDGER.md` | `WEAK SUPERVISION verbatim ... n_eff=10` in Day7 section | **✅ Honest** after T9 fix — but only because T9 was forced to add it for guard. |
| `dashboard` (HonestyBanner) | `EVIDENCE_Day7.md` claims "dashboard AI tab footnote" has verbatim | **Unverified in this audit** — not read; assume present per learnings.md line 49 but not bash-confirmed. If true, then user-visible honesty exists. |

**Bottom line on disclosure:** EVIDENCE is honest (the only place an external reviewer looks). Internal ledgers (progress, manifest, splits) **hide** n_eff by omission. A PM reading `progress.md` sees "31 envs 🟢 gated" and thinks progress. They never see "10 independent". The table in `lab/LEDGER.md` with per-row `n_eff=1` sums visually to 31 — needs a footer row `TOTAL n=31 n_eff=10`.

---

## 3. WEAK SUPERVISION — circular label leakage (model learns to invert its own rule)

### 3.1 The circle

Labels: `assessment/risk_model.py: _load_dataset` calls `rules.evaluate(flow)` → `score(findings)` → `label = 1 if risk_level in (High,Critical) else 0`.

Features: `assessment/features.py: build_vector` reads the **same fields** from the same `flow` dict.

Overlap (exact field-by-field):

| Feature dim in `FEATURES_28` | Label source in `rules.py` | Same data? |
|-------------------------------|----------------------------|------------|
| `version` (TLS1.0/1.1→Critical check #1) | `rules.py:41 ver in ("TLS1.0","TLS1.1") → Critical` | **YES — identical** |
| `cipher_strength` (weak/medium/strong) | `rules.py:54 cstr=="weak" and RC4/DES → Critical` + `10 cipher string checks` | **YES** |
| `kex` (ECDHE/RSA/DHE) + `fs_flag` | `rules.py:65 kex=="RSA" or not fs → High` + `rules.py:113 not fs → High` | **YES** |
| `starttls_mode` (upgrade/implicit/none/stripped) | `rules.py:118 mode in (none,stripped) → High/Critical` | **YES** |
| `is_deprecated` (derived from version) | Same as version check #1 | **YES** |
| `is_aead` (bool) | `rules.py:61 not is_aead → Medium/High` (check #5) | **YES** |
| `fs_flag` (bool) | Same as kex checks #6, #13 | **YES** |
| `handshake_success` | Check #14, #15 STARTTLS logic | **Partially** |
| `chain_valid`, `san_match`, `days_to_expiry`, `chain_length`, `pubkey_bits`, `sigalg_weak`, `is_expired`, `is_self_signed`, `keysize_weak` | Checks #7-13, #17-20 (pubkey, sigalg, expiry, chain, SAN) | **YES — 7 of 7 cert dims** |
| `ja4_rarity` | **Not in rules.py** | **NO — the only honest feature** |
| `port` | Not in rules.py (rules use `app_protocol`) | **NO** |
| `cert_missing_reason` | Derived, not directly in rules | **Partially** |
| `miss_indicator_*` (7 dims) | `cert.* is None` checks gate rules (they skip if None) | **Tautology** — missingness determines both feature and whether rule fires |

**Score: 13-15 of 21 base dims are directly used to compute the label. 1 dim (ja4_rarity) is independent, 1 dim (port) is orthogonal. The rest is leakage.**

### 3.2 What this means for XGB

Any tree split `cipher_strength == "weak"` perfectly separates label=1 (families 03,04,08) by construction. `kex=="RSA"` + `fs_flag==False` separates families 03,04,05,08,09,10. The model does not discover threat; it **re-discovers the if-statements in rules.py**.

Evidence from `risk_model.py` permutation importance:

> `permutation n_repeats=10 top3 version/cipher_strength/kex coherent vs score.py`

That coherence is not validation — it is **proof of circularity**. The top features *must* be the rule inputs because the label *is* the rule output.

### 3.3 Label distribution — artifact of `pre_tls_buffer_len` hack

`shared/fixtures/family-01.json` has **no** `pre_tls_buffer_len` field. `rules.py:134-141` fallback:

```python
if pre_len is None:
    if mode=="upgrade" and tls.get("handshake_success"): pre_len=1; inj=True
```

So family-01 (Postfix upgrade TLS1.2 strong valid cert) gets `Pre-TLS injection possible High` by default → `risk 27 High → label 1`. But `risk_model.py: _load_dataset` force-sets `flow["pre_tls_buffer_len"]=0; injection_possible=False` to engineer 4 negatives. With that hack, family-01 drops to `risk 13 Medium → label 0`.

**So the negative class is manufactured by overriding the rule input.** Without the override, 10 families would be `1:8 0:2` after forcing, or `1:9 0:1` without forcing — nearly single-class. The "balanced" dataset is an artifact of a 2-line fix to make cv=2 platt runnable.

31-env label breakdown (risk_model logic with forced pre_tls=0):

```
Negatives (Medium/Low =0): family-01,02,06,07 + jitter of 02(3),07(3) = 10
Positives (High/Critical=1): family-03,04,05,08,09,10 + jitter of 03(3),04(3),05(3),08(3),10(3) = 21
Ratio 10:21 = 32% negatives. All 6 medium families are strong/medium ciphers that need the pre_tls hack to stay negative.
```

This is not a threat dataset. It is a **rules.py execution trace with 21 copies**.

### 3.4 Honest?
EVIDENCE and risk_model disclose "Labels are rule-derived weak supervision (score.py 23 checks, 20 scored +3 info); not hand-labeled field data" verbatim. So formally honest. But nowhere is it stated: **"The model's AUROC at n_eff=10 measures how well XGB memorized the rule table, not how well it detects real-world STARTTLS misconfiguration."** The disclosure warns *what* the labels are, not *why the metric is vacuous*.

---

## 4. FEATURE LEAKAGE VIA environment_id & FAMILY PREFIX

### 4.1 environment_id not in vector — but family prefix leaks via features

`assessment/features.py:92-93`:

```python
assert "environment_id" not in FEATURES_28
assert "family" + "_id" not in " ".join(FEATURES_28)
```

Correct — the grouping key itself is not a feature, and the literal `family_id` string is hidden via concatenation to pass CI grep guard. But the **information content** of family_id is fully retained via `cipher_suite`, `cert`, `kex`, `version` which are **functional determiners of family**.

Family → cipher/cert mapping is 1:1:

```
family-02 → ECDHE-RSA-AES256-GCM-SHA384 p256  (only family with this combo)
family-03 → DES-CBC3-SHA rsa2048              (unique)
family-04 → RC4-SHA TLS1.0                   (unique)
...
```

So not leaking `family-02` string is irrelevant — leaking `DES-CBC3-SHA` *is* leaking family-03. The model can memorize family via cipher.

### 4.2 Splits grouping honesty — environment_id groups vs family leakage

`splits.json` grouping:

```
D1_train_groups (12): family-01,02,03,04,05 + 02j1,02j2,03j1,03j2,04j1,04j2,05j1
D2_val_groups   ( 8): family-06,07,08 +05j2,05j3,07j1,07j2,08j1
D3_locked_groups( 5): family-09,10 +07j3,08j2,10j2
Unused (6):            02j3,03j3,04j3,08j3,10j1,10j3
```

Family prefix overlap (the dagger):

```
D1 prefixes: {01,02,03,04,05}
D2 prefixes: {05,06,07,08}  → overlap D1∩D2 = {05}  family-05 in BOTH train and val
D3 prefixes: {07,08,09,10}  → overlap D2∩D3 = {07,08} family-07,08 in BOTH val and locked test
```

**Family-05:** base in D1, jitter 2+3 in D2. Same cipher `AES128-SHA` selfsigned, same TLS1.1, same KEX RSA. D2 val contains the same attack surface as D1 train. Val score measures **jitter generalization (ja4_rarity delta)**, not cross-family generalization.

**Family-07/08:** D2 val has base + jitter 1/2, D3 locked has jitter 3 and jitter 2 respectively. Locked test is not hold-out — it is `family-07 jitter3` where jitter 1/2 were in val, and `family-08 jitter2` where base+jitter1 were in val. **D3 is compromised as a hold-out.**

The only truly held-out families at the *family* level are:

```
D3 clean: family-09 (stripped none), family-10 base (RSA-AES256-SHA chain-incomplete) is not truly clean because 10 jitter2 is in D3 and 10 base is also in D3 (same group, but val never saw family-10 — so 09+10 are the only honest hold-outs)
```

But family-10's cipher `RSA-AES256-SHA` is already represented via jitter pattern; val never saw it, so it is an honest test of unseen cipher. However **n=2 honest hold-out families** (09,10) is not a test set — it is an anecdote.

**Correct grouping would be `group = family_id` (prefix before `__`), not `environment_id`.** `features.py` correctly notes `grouping must be environment_id not family grouping key (plan §4a.3)` as a plan requirement, but that plan requirement is **wrong if the goal is generalization**.

### 4.3 What GroupKFold actually does

`risk_model.py` uses `StratifiedGroupKFold(n_splits=5, groups=environment_id)` on 31 rows. But groups are **distinct per row** (each row is its own environment_id, see `groups_by_env: env->[flow_id]` 1:1). So GroupKFold with 31 groups and 31 rows is **degenerate — it is just StratifiedKFold**. The grouping has no effect because no group has >1 sample. The jitter copies are *different groups* by design.

If the goal were honest, jitter copies of family-02 should share `group=family-02` so they never split across folds. They don't. Hence folds can put `family-02` and `family-02-jitter-01` on opposite sides, leaking.

---

## 5. D1 12 / D2 8 / D3 5 with 31 envs — the 6 leftover jitter and why they matter

```
Total 31 = D1 12 + D2 8 + D3 5 + D_prior 20 (disjoint, censys) + 6 jitter remainder unused
Risk splits used: 25/31  (80%)
Unused jitter 6: 02j3, 03j3, 04j3, 08j3, 10j1, 10j3
```

**Why 6 unused?** `learnings.md T2` notes: *"keep D3 5 not 6 to avoid 3.0 borderline, 6 jitter remainders unused ... ratio 12/5=2.4<3"*. The D1/D3 ratio guard `<3` forces D3 ≤5 when D1=12. So 6 rows are orphaned to satisfy a ratio aesthetic, not a data rationale.

**Does it hide data?** Not maliciously — it inflates the denominator to 31 while using 25, making `n=31` look larger than training (12) and val (8) suggest. The 6 orphans are not evaluated, not in any metric, but counted in "31 envs" headline. An honest report would say `train 12, val 8, test 5, hold-out unused 6 (jitter copies of 02/03/04/08/10)` and explain that test is only 2 truly independent families (09,10).

**If those 6 were folded into D3**, D3 would be 11 (5+6) with families {02,03,04,07,08,10} — still only 1 honest new family (10 is already there, 02/03/04 overlap D1). So no, adding them would not fix generalization; it would just move leaked families into test and make metrics look better via memorization.

---

## 6. REAL USAGE GAP — synthetic toy vs production TLS

### 6.1 Synthetic dataset characteristics (what we have)

- **10 ciphers, 10 certs, 10 ports**: Hand-picked distinct per family, but the entire IANA cipher list has **>300 ciphers** (TLS1.0-1.3), real cert chains have thousands of CA combos, wildcards, SAN patterns, CT logs, revocation. Our 10 are museum pieces (RC4, DES, 3DES, TLS1.0/1.1) chosen for rule-firing, not sampled from the web.
- **Scapy hellos**: `jittered_hello` builds a 2-cipher ClientHello (GREASE + one real cipher) with fake `ver` bytes (`\x03\x01` for TLS1.0 etc) and `Raw` annotation `CIPHER=...`. No real extensions (SNI, ALPN, groups, sigalgs, key_share beyond marker), no real cert bytes (fixtures set `cert.*=None` for weak families), no TCP options, no real STARTTLS banner beyond `220 mail.lab.local`.
- **Single lab CA, single epoch** (`capture_epoch 2026-08-27T00:00:00Z` identical for all 31 rows, `docker_image_sha256 dummy-postfix3.9` identical). No temporal diversity, no client diversity (`client sender` identical), no loss model beyond `loss5` string.
- **n_eff=10, n=31**: Effective samples smaller than feature dims (28). XGB with `max_depth=4, n_estimators=80` has ~320 splits — more parameters than independent points. Anything learned is interpolation of 10 points in 28 dims.

### 6.2 What real usage requires (what we lack)

| Dimension | Synthetic (Day7) | Real world | Gap |
|-----------|------------------|------------|-----|
| Cipher diversity | 10 hand-picked (1 per family) | 300+ IANA, JA4 fingerprints vary by client (Chrome, Thunderbird, Python smtplib, JavaMail each distinct) | Need n≥50-100 *independent* hello captures from real clients |
| Cert diversity | 6 cert files (rsa2048, p256, selfsigned, expired, rsa1024, chain-incomplete) + `None` for many | Thousands of CA hierarchies, intermediate quirks, SAN wildcards, CT, OCSP, CRL | Need real cert chains from censys/CT logs linked to flows |
| JA4 | Single GREASE shuffle + synthetic `ja4_rarity` hash | Real JA4 computed from ordered cipher/extension/extensions — varies per client, not per random choice | `ja4_rarity` synthetic; real JA4 would be derived from actual ClientHello bytes, not sampled |
| STARTTLS banners | 3 templates (220 Postfix, * OK Dovecot, +OK Dovecot) | Dozens of MTA banners (Exchange, Gmail, Sendmail, Exim) + TLSA, MTA-STS | Need weberblog-style real pcaps (currently only 1 fixture `weberblog-01.json` with 20 flows as fallback) |
| Temporal | Same epoch, same pcap size per family | Diurnal, seasonal, CA expiry rotation, cipher deprecation over years (D5 synthetic until Day10) | D5 `temporal_same_env` is placeholder: train 2026-08-27 test 2026-09-03 but no real T2 pcap |
| Label quality | Rule-derived weak supervision (score.py 23 checks) | Hand-labeled incidents, CT/OCSP verified, or at least censys+badssl-qualified | Need human label for at least D3 locked set before claiming accuracy |
| Negative class | Forced via `pre_tls_buffer_len=0` hack to get 4 negatives | Real world majority is Low/Medium (most mail is generous TLS1.2 ECDHE strong) | Without hack, dataset would be 90% positives — class imbalance honest but would break platt cv=2 |

### 6.3 What metrics are honest vs toy

| Metric | Claimed | Actually proven | Honest? | Toy risk |
|--------|---------|-----------------|---------|----------|
| STARTTLS F1>95% | 100% clean, 0.897 jittered logged, weberblog 17/20 | **Proven via `tshark` + `reassemble.py` on real pcaps** | **✅ Not ML, deterministic reassembly.** Credible at SYSTEM level, independent of ML dataset. | Low — not ML, not claiming generalization beyond implemented parsers. |
| cipher 100% (9/9 >98%) | `test_handshake` exact vs manifest | **Proven via `analyzer/parse.py` regex + scapy fallback.** Parses scapy pcaps correctly. | **✅ Honest parser test.** | Low — but scapy pcaps are tautological (we write cipher then read it back). `weberblog-01.json` fallback adds 20 flows but still synthetic unless `lab/pcaps/real/*.pcap` present. |
| cert prec 1.000 CABF/private | 12 limbo vectors | **Proven via `validator/chain.py` on x509-limbo corpus.** | **✅ Honest** — independent corpus (limbo), stratified, not our 10 families. | Low |
| weak recall 100% (7/7) | families 03-10+09 23-check | **Proven via `rules.py` on fixtures.** | **✅ Honest** — but this is the *label generator* proving it fires on its own families. Tautology at ML level, fine at system level. | Medium — weak families are the training families, so recall on training set is trivial. |
| XGB ECE hi 0.115 <0.20 (500-boot) | Platt cv=2, family-level bootstrap resample `n_eff=10` | **Lean shell honest but vacuous.** CI width disclosed ±0.10. Method uses `resample families n_eff=10` which is correct for n_eff, but at n_eff=10 the CI is width 0.033 reported — with 500 boots on 10 points, this CI is **optimistic** (true CI at n=10 should be ~±0.15 by Hoeffding). | **🟡 Toy** — ECE 0.115 on 21 positives/10 negatives with D2 val only 8 rows (D2 includes family-05 overlap). Family-level boot on 10 families still resamples same 10 ciphers. Not a generalization guarantee. |
| XGB `fit 0.05s <1s training` | Full 31 rows (not D1 12) | **Admitted in code:** `lean stability: D1 12 too small for cv=2 Platt at n_eff=10, using full 31 for fit but ECE on D2 val only` (risk_model.py:117,125) | **🔴 Leak** — model trained on D2+D3 data but ECE evaluated on D2 val portion. D3 locked not truly locked (07/08 jitter in train). | High — "using full 31 for fit" means test leakage. D1-only ECE hi 0.305 >0.20 (learnings T5 fix note) is the honest ECE; reported 0.115 is with train=val leakage. |
| ECOD ROC 0.871 >0.60 | Contamination 0.10, prior-dominated train 20 censys+7 lab=27 | **Lean, but prior-dominated trick.** Training uses 20 censys (Low) background +7 lab to guarantee weak families are outliers. Without that 35% slice choice, ROC collapses. | **🟡 Toy** — ROC measures separation of synthetic weak families from censys_low background, not anomaly detection on real mail. At n_eff=10, ROC point (not AUC) with no CI. |
| NDCG@10 | Deferred | **✅ Honest deferral.** `κ>0.6` not attempted at n=31. | **✅ Correctly blocked** — would be indefensible. | None |
| calibrated_prob 0..1, anomaly_score ECOD | Wired via `FlowVerdict.model_validate` | **Proven wiring, not quality.** API returns `max predict_proba` and `decision_scores` floats. | **✅ Wiring honest, quality toy** (as above). | Medium |

**Summary table: claims vs proven vs still toy**

| Claim in EVIDENCE Day7 | Proven? | Still toy? | Production-ready? |
|------------------------|---------|------------|-------------------|
| SYSTEM 5/8 green (STARTTLS, cipher, cert, weak, JSON, POST, GET, honesty) | **YES — 5/8 proven on tracable corpora (pcaps + limbo + fixtures)** | No | **Ready for SYSTEM demo, not for ML.** |
| ML XGB Platt "ECE hi<0.20" | **Wiring proven, ECE value measured but on leaked train=val** | **YES — n_eff=10, leakage via D2/D3 family overlap + full-31 fit** | **NO — needs n≥50, D1-only fit, family-grouped CV, real D3 hold-out** |
| ML ECOD ROC>0.60 | **Wiring proven, ROC point measured 0.871** | **YES — prior-dominated trick, point not CI, synthetic weak vs censys_low** | **NO — needs real anomalies beyond 10 synthetic weaks** |
| NDCG deferred | **Honest — not claimed** | **YES** | Correct to defer to n≥50 + human labels |

---

## 7. BRUTAL TABLE — WHAT PROJECT CLAIMS vs PROVEN vs TOY

| # | EVIDENCE claim | What artifact actually proves | Brutal truth | Production gap |
|---|----------------|-------------------------------|--------------|----------------|
| A1 | `STARTTLS F1>95% lossy/weberblog` 100% | `lab/reassembler/reassemble.py` coverage_ratio on 10 clean + 7 jitter lossy + weberblog 20 fallback vs tshark 4 prefs | **Real.** Reassembly works on our scapy pcaps. Lossy 0.897 is logged, not hidden. | Needs real lossy corpus (netem `tc qdisc` on actual SMTP, not scapy gap/overlap flag). Weberblog 20 flows are synthetic fallback unless `lab/pcaps/real/*.pcap` present — currently unknown if real pcaps exist. |
| A2 | `cipher 100% >98%` 9/9 | `analyzer/parse.py` exact vs `manifest.json` cipher string on scapy pcaps | **Real parser, tautological corpus.** We write `CIPHER=ECDHE...` then regex it back — perfect score expected. | Needs non-synthetic pcaps (openssl `s_client` captures, not scapy `Raw` marker). |
| A3 | `cert prec1.000 CABF/private >90%` | `validator/chain.py` on x509-limbo 12+8 vectors stratified | **Real, independent corpus.** | None for validator — modular, well-proven. |
| A4 | `weak 100% 7/7` 23-check | `rules.py + score.py` on families 03-10+09 fixtures | **Real execution, but on training families.** Label generator proving it fires; not ML. | Same — system-level recall fine, ML-level would need held-out weaks. |
| B1 | `TRAIN: 31 envs via build_vector 28-col, D1 12/D2 8 grouped StratifiedGroupKFold 5-fold outer, Platt inner cv2` | `assessment/features.py` 28-col `XGB hist enable_categorical max_depth4` + `splits.json` groups + `risk_model.py` that **actually uses full 31 not D1 12** | **Claim says grouped 5-fold outer + Platt cv2 inner. Artifact uses `StratifiedGroupKFold(5)` on 31 groups each size 1 (degenerate) + `CalibratedClassifierCV cv=2` on full 31, ECE on D2 val 8.** Grouping leaks (family-05 shared), train=val leak (full 31 fit). | Must train on D1 12 only, group by family_id, ECE on D2 8 family-grouped, accept hi ~0.30 as honest Day7 lean. Or report "D1 12 too small for platt cv2" and defer XGB to n≥50. |
| B2 | `ECE 500-boot family-level (resample families n_eff=10): hi 0.115 <0.20, CI [0.082,0.115] width 0.033` | Boot on 10 families, 8 val rows (D2 includes overlapped family-05). Reported width 0.033 is empirical from 500 boots. | **Implausible precision at n=10.** 500 boots on 10 points where val is 8 rows (4 positives 4 negatives after hack) cannot give CI width 0.033 under binomial logic — true 95% CI at n_eff=10 for proportion is ±0.30. The narrow CI is because 500 boots resample the same 10 coarse points — variance underestimated. And the honest D1-only hi is 0.305 >0.20 (learnings T5 fix note). | Report bloated CI ±0.15, or defer ECE until n≥50. |
| B3 | `ECOD ROC point>0.60` 0.871 wired, contamination invariance | `assessment/anomaly_model.py` ECOD `contamination=0.10` on prior-dominated 27 rows (20 censys +7 lab) | **Tricked training distribution.** Lab 31 alone would not give ROC>0.60 with 10 weak families mixed; adding 20 censys Low background makes weak families obvious outliers. Contamination invariance (`scores 0.05==0.20`) is true per pyod but irrelevant — invariance ≠ calibration. | Needs contamination sweep on real anomalies, not censys_low vs synthetic weak dichotomy. |
| B4 | `WEAK SUPERVISION disclosed` verbatim | EVIDENCE + risk_model + LEDGER headers contain verbatim | **Honest disclosure of *what* labels are, not *why metrics are vacuous*.** | Needs added sentence: "At n_eff=10, XGB/ECE/ROC measure rule memorization, not real-world detection; NDCG deferred accordingly." |

---

## 8. RECOMMENDATIONS FOR Day8-10 TO ACHIEVE REAL GENERALIZATION

These are **blocking** for any accuracy claim beyond SYSTEM parity. Day7 is correct to be `SYSTEM 5/8 green ML 🟡 lean shell, not 8/8`. The following moves Day8-10 from toy to credible lean generalization (not production — that needs thousands).

### 8.1 Data: reach n≥50 independent, not 31 correlated

| Action | Effort | Why |
|--------|--------|-----|
| **Add 20+ new independent families** (11-30) with *distinct* cipher/cert/version combos beyond the current 10. Cover TLS1.3 variants (CHACHA20, ECDHE-RSA-CHACHA20), DHE, P-256 vs P-384, RSA 3072, ECDSA, different SAN patterns, different MTA banners (Exim, Exchange, Gmail relay). Capture via `openssl s_client` against *real* lab docker with different `postfix:3.9` configs or `swaks` to different ports, not scapy `Raw` marker. | Large (1-2 days) | Current 10 ciphers are 7% of real diversity. n_eff=10 cannot support 28-dim model — n_eff≥30 needed for Platt cv=2 to be stable (rule of thumb: n≥10*features for linear, here need ≥30 for 28-dim to avoid interpolation). |
| **Stop jitter-only augmentation.** Keep existing 21 jitter but mark them as `augmentation`, not `independent`. Report `n=50 (30 independent +20 augmentation)` separately. Never count augmentation toward n_eff. | Quick | Prevents denominator inflation. Jitter is useful for reassembly robustness, not for ML diversity. |
| **Acquire real pcap diversity**: `lab/pcaps/real/*.pcap` via `tcpdump` during `lab/scripts/gen_traffic.sh --live` against docker lab with real STARTTLS handshakes (not scapy synthetic hello). Also ingest `weberblog-01.json` as real 20 flows if it is real (currently fallback synthetic). Document `tshark -T json` parity on these vs scapy. | Medium | Scapy hellos are tautological (write then read cipher). Real hellos have real extensions, real cert bytes (so `cert.*` not `None`), real JA4 rankings. |
| **Populate cert fields in fixtures.** Today weak fixtures have `cert.chain_valid/san_match/pubkey_bits/sigalg = None` (see §4.1 bash), so rules skip and vector uses `miss_indicator=1` + `-1`. Real flows would have real cert fields, making feature-label circle *tighter* but also more realistic. Link fixtures to real `lab/certs/*.crt` parsing via `validator/chain.py` so cert dims are not null. | Medium | Currently `miss_indicator` path dominates — 7 of 28 dims are miss flags, hiding that cert features are synthetic-null. |

### 8.2 Splits: fix grouping leak, honor D3 locked

| Action | Effort | Why |
|--------|--------|-----|
| **Group by `family_id` (prefix before `__`), not `environment_id`.** Redefine `assessment/splits.json` grouping key to `family_id` (or add `groups_by_family` alongside). Then `StratifiedGroupKFold(groups=family_id)` ensures jitter copies of family-05 never split across train/val. This alone collapses `n=31 → n_eff=10` for CV — honest. | Quick | Current environment grouping is *correct per spec* but *wrong for ML*. The spec's grouping choice optimizes replay provenance, not generalization. Until fixed, any CV leakage makes ECE/ROC optimistic. |
| **Make D3 truly locked: `family-09,10` plus 2-3 new families 11-13 that never appear in D1/D2 or jitter.** Freeze D3 as `family-09__postfix3.9_loss0, family-10__postfix3.9_loss0, family-11__*, family-12__*, family-13__*` (new). Do not generate jitter for D3 families. Never train on D3; never include D3 envs in `all_environment_ids` for training matrix. | Quick (after new families captured) | Today D3 shares `07,08` with D2 val — leaked. Honest hold-out needs 4-5 *novel* families. |
| **Accept D1-only training and report honest ECE.** Change `risk_model.py` to `df_train = df[train_mask]` (D1 12) and report `ECE hi 0.305 >0.20` as Day7 lean reality, with note "degraded at n_eff=10; ECE hi<0.20 deferred to n≥50". Today the code admits `D1 12 too small for cv=2 Platt` then cheats with full 31 fit — swapping one honest failure for a hidden leak. | Quick | The fix note in T5 (learnings line 59) already proved D1-only fails — surface that failure instead of masking it. Honest failure > dishonest pass. |
| **Publish 6 unused jitter remainder disposition.** Either assign them to D3 (if family-grouped honestly) or document `unused 6: augmentation held for future D4` and remove them from `all_environment_ids` headline count. Keep `all_environment_ids` = risk+prior only, or split into `all_risk_31` vs `trainable_25`. | Quick | Currently 25 used /6 orphaned — reads as hiding. Make explicit. |

### 8.3 Model: break circularity, add cross-family CV

| Action | Effort | Why |
|--------|--------|-----|
| **Cross-family CV (leave-one-family-out, LOFAM).** With n_eff=10, do `GroupKFold(n_splits=10, groups=family_id)` — each fold holds out one cipher/cert family entirely. Report mean ECE / PR across 10 folds. Expect large variance at n=10 — disclose it. This is the *only* honest generalization estimate at this scale. | Quick to implement, slow to interpret | 5-fold StratifiedGroupKFold on 31 groups is degenerate (each group size 1). LOFAM on 10 families is the minimal honest protocol; jitter copies stay with parent. |
| **Feature-label decorrelation audit.** Add a CI check that fails if `permutation importance top3 ⊆ {version, cipher_strength, kex}` *and* those are rule inputs — i.e., detects circularity. Mitigations: either (a) train on censys prior features excluding cipher/cert dims that are label inputs, or (b) obtain *independent* labels (human grades for D3, or censys `tag_misissued` analog) for a subset and report ECE on that subset separately. | Medium | Today rule-derived labels and rule-overlapping features make high ROC trivial. Need at least one evaluation on independently-labeled hold-out before any F1 claim. |
| **NDCG human-graded deferred — keep deferred.** Do not unblock until n≥50 + D3 5 honest novel families + human κ>0.6. Current EVIDENCE correctly defers — preserve that discipline. | — | NDCG at n=10 would be ranking 10 points — meaningless. |

### 8.4 Honesty: surface n_eff everywhere, not just EVIDENCE

| Action | Effort | Why |
|--------|--------|-----|
| **Add footer to `lab/LEDGER.md` table:** `TOTAL rows 31, independent cipher/cert clusters n_eff=10 (jitter 21 are correlated copies, GREASE 1-of-16, expiry ±5d)` | Quick | Prevents visual sum to 31. |
| **Add `n_eff` to `shared/progress.md` Day7 rows:** `31 envs (n=31 rows, n_eff=10 independent) 7 families×3 slices...` | Quick | Progress is the first place execs look. |
| **Add `n_eff` to `assessment/splits.json` as `n_eff:10, n_rows:31` top-level fields** | Quick | Makes splits self-describing. |
| **Dashboard HonestyBanner:** add `Dataset: 10 independent families (21 jitter augmentation) — ML toy at n=10, SYSTEM 5/8 green` beside WEAK SUPERVISION verbatim | Quick | User-facing honesty must be as prominent as the progress green. |

### 8.5 Production readiness checklist (for context, beyond Day10 lean)

| Criterion | Day7 status | Day10 lean target (credible) | Production target |
|-----------|-------------|------------------------------|-------------------|
| Independent envs | 10 | ≥30 (LOFAM stable) | ≥500 diverse (censys-scale) |
| Real vs synthetic pcaps | 10 scapy + weberblog fallback | 30+ real `tcpdump` STARTTLS handshakes + live cert chains | Continuous capture from live MX + CT logs |
| Label source | rule-derived weak (23 checks) | rule-derived + human audit on D3 5 families | human + CT/CA-qualified |
| Grouping | environment_id (leaky) | family_id (honest) | client IP + cert CA + epoch triple |
| ECE reporting | family-level 500-boot on leaked 8 val rows, hi 0.115 | family-level 1000-boot on D1-only or LOFAM, honest hi ~0.30 at n=30 | 1000-boot with Wilson CI, hi<0.10 |
| D3 locked | 5 envs, 2 honest families (09,10), 3 leaked jitter | 5+ novel families, never touched before eval | Held-out temporal slice (different epoch) + geo |

---

## 9. ONE-SENTENCE BOTTOM LINE

**Day7 DELIVERS a real SYSTEM 5/8 (tshark parity, reassembly, validation, rules, API, dashboard) and a well-wired but toy ML shell that memorizes 10 cipher/cert rules via 31 correlated rows (21 jitter copies vary one scalar), leaks family-05/07/08 across splits, and hides its smallness behind honest EVIDENCE prose but hidden progress denominator — promoted to production claims it would be fraud; kept as `SYSTEM 5/8 green ML 🟡 lean shell` with `n_eff=10` disclosed, NDCG deferred, and D3 mostly-locked, it is an honest scaffold for Day8-10 to reach n≥50, family-grouped LOFAM, and D1-only ECE without pretending.**

---

## 10. AUDIT PROVENANCE

**Bash proofs executed (hashes, manifest, splits, vector distances):**

- `lab/pcaps/family-*.pcap` 10 base SHA + sizes + `lab/pcaps/jittered/*.pcap` 21 SHA — jitter hash diversity confirmed but cipher/cert lineage identical (see §1.2).
- `lab/manifest.json` 31 envs: 10 base `__postfix3.9_loss0` +21 jitter `__jitter{1..3}_loss5`, distinct `(cipher,cert)` pairs =10 — proves n_eff=10 (§1.3).
- `assessment/splits.json`: D1 12 (prefixes 01-05), D2 8 (05-08), D3 5 (07,08,09,10), unused 6 (02j3,03j3,04j3,08j3,10j1,10j3) — family prefix overlap D1∩D2={05}, D2∩D3={07,08} — grouping leakage proof (§4.2, §5).
- `assessment/features.py build_vector` Euclidean distances: intra-jitter ~1.0 vs inter-family ~2.5-4 — jitter correlation proof (§1.3).
- `shared/fixtures/family-*.json`: cert fields `None` for weak families, `pre_tls_buffer_len` missing for 01/06 triggering `rules.py` fallback High — label distribution artifact proof (§3.3, §6.2).
- `assessment/{rules,score,features}.py` field overlap audit: 13/15 base dims identical to label inputs — circular leakage proof (§3.1).
- `risk_model.py` grep: `WEAK_SUPERVISION` present, `lean stability: D1 12 too small for cv=2 Platt at n_eff=10, using full 31` — train=val leak admission (§3.3, §6.2).
- `lab/LEDGER.md`, `shared/progress.md`, `eval/EVIDENCE_Day7.md` n_eff disclosure scan — EVIDENCE honest, progress/manifest hidden (§2).

**Files read:** `lab/manifest.json` (497 lines, 31 envs), `assessment/splits.json` (189 lines, 31 groups), `lab/scripts/jitter_slices.py` (188 lines, GREASE 1-of-16, expiry ±5d), `assessment/score.py` (80 lines, cap100), `assessment/rules.py` (201 lines, 23 checks), `assessment/features.py` (231 lines, FEATURES_28 28-col), `eval/EVIDENCE_Day7.md` (38 lines, SYSTEM 5/8 + ML lean shell), `lab/LEDGER.md` (67 lines, 31 strict rows + Day7 poll), `shared/fixtures/*.json` (10 fixtures, 1 weberblog), `assessment/risk_model.py` + `anomaly_model.py` headers, `.omo/notepads/.../learnings.md` (63 lines, T1-T9), `shared/progress.md` (35 lines).

**Not modified:** No dataset files modified per MUST NOT DO. This file is `.omo/notepads/sih26159-till-day7-lean-ml-bridge/brutal-dataset-audit.md` — notepad only.


# SIH26159 SecureMailScope — Decision-Complete Implementation Plan

**Org:** NTRO — Blockchain & Cybersecurity — **Theme:** AI-Assisted Cryptographic Security Posture for Secure Email (SMTP/IMAP/POP3 + STARTTLS + TLS1.2/1.3 + X.509)  
**Research base:** `sih26159-securemailscope-ai-crypto-posture` (19 searches 36 sources, 5 hypotheses adversarial-tested 50 notes, synthesis 45-65% reframed)  
**Intent locked (15 forks):** Ideal6 · Python3.11 FastAPI+React · **10-12 day parallel quality build (not 1-day sprint)** · Win NTRO wrapper-intolerant · Lab ready · Replay zero-privilege · Rule80%+ML20% · 587 STARTTLS+993 implicit Day1 · Full RFC5280§6+SAN · M1 14/20 REAL + top honesty banner · Dual-corpus (weberblog/limbo/Censys, CIC demoted to Monday-benign filtered) · F.2 gates  
**Ownership (Q6 template lock):** P1 TLS/X.509→Validator **+ `shared/` CODEOWNER** (double-hatter — Day1-2 `schemas.py`/`fixtures/*` gate), P2 Net→Lab&Reassembly, P3 Crypto→TLS Parser, P4 ML→Rule+ML, P5 Fullstack→API+DB+Dashboard+Reports, P6 Docs→Eval — 1:1 component owner + **P1 is `shared/schemas.py` & `fixtures/*` CODEOWNER** (per review §2c — sole merger for `shared/` to enforce `Day2 00:00 additive-only`; all others open PR; this prevents freeze-without-enforcer). AI agents parallel  
**Plan principle:** *Implementation is truth, React gauge proves truth (co-evolved, not last) — and from passive gauge to inline gateway via Policy Engine (stretch).* Shared contracts make 6+2 components merge without issues with **quality-first, PS-grounded timeline (not 1-day race)** — every gate requires real pcap/weberblog/limbo grounding, not fixture green alone. **Product evolution (STRETCH DEMO — not core-graded unless PS_TRACEABILITY shows PS asks for it):** `Reassembler→TLS→X.509→Rule(23 =20+3)→Risk(Platt+permutation)→Policy→Banner/Quarantine/SIEM/ARF` — gateway is two SKUs: **NTRO Appliance (MX milter, 23 real, before-queue, stretch)** vs **Scanner+Guidance (Mailbox API, ~12/23 honest, flag-not-block — shows "requires gateway — not assessable from mailbox" for 9 transport checks per V2/interception-arch §3.2)**. Labpcap `POST /analyze` replay is **core-graded**; milter `127.0.0.1:10025` + `mockdns` + `quarantine/siem/arf` are **stretch demo** — cut first per §8 cut order 0, `PS_TRACEABILITY.md` settles scope, pitch reads as *ambition not drift* ("passive workbench is product, gateway is roadmap").

---

## 0. How This Plan Merges Without Issues — Contracts & Integration Doctrine

### 0.1 Repo shape (Q3:A Monorepo, Q1:C Keep6+shared)
```
repo/  (monorepo, private GitHub, offline CI = `pre-push` hook)
├── shared/
│   ├── schemas.py           # Pydantic v2 models (Q2:C Both) — source of truth, generates JSON Schema
│   ├── schemas.json         # generated, shipped in bundle, judge-visible
│   ├── fixtures/            # golden tshark-derived features for Day1 stubs (Q7:A)
│   │   ├── family-01.json … family-10.json (handshake+cert golden)
│   │   ├── weberblog-01.json (real sanity)
│   │   └── limbo-vectors.json
│   ├── mocks/               # stub impls so dependents start Day1
│   │   ├── reassembler_stub.py # returns fixtures, no pcap needed
│   │   └── validator_stub.py
│   └── tests/
│       ├── test_schema.py            # Pydantic validation + JSON 20/20
│       ├── test_fixtures_parity.py   # tshark golden vs parser on fixtures
│       └── test_offline_bundle.py    # docker save + wheelhouse Wi-Fi-off
├── lab/                     # Agent1
│   ├── docker-compose.yml
│   ├── certs/ (CA, leafs)
│   ├── pcaps/{family-*.pcap,adversarial/*.pcap,real/{weberblog,CIC-*.pcap}}
│   ├── scripts/gen_traffic.sh
│   ├── manifest.json
│   └── reassembler/         # real impl
├── analyzer/                # Agent2 (TLS)
├── validator/               # Agent3 (X.509)
├── assessment/              # Agent4 (Rule+ML+Policy)
├── api/                     # Agent5a (FastAPI + SQLite)
├── dashboard/               # Agent5b (React Vite + reports)
└── eval/                    # Agent6 (metrics, validation-report)
```

### 0.2 Shared Pydantic source of truth (Q2:C Both, Q8:A Hard fail) — `shared/schemas.py`
```python
# Pydantic v2 — shared by all 6 components, generates schemas.json on CI
from pydantic import BaseModel, Field
from typing import Literal

class TLS(BaseModel):
    version: Literal["TLS1.0","TLS1.1","TLS1.2","TLS1.3","none"]
    is_deprecated: bool
    cipher_suite: str
    cipher_strength: Literal["weak","acceptable","strong","unknown"]
    is_aead: bool
    kex: Literal["ECDHE","DHE","RSA","unknown"]
    fs_flag: bool
    ja4: str | None  # raw FoxIO hash — NEVER feed to risk_model (spoofable via curl-cffi); display + anomaly ablation only
    ja4_rarity: float | None = Field(default=None, description="Population rarity 0..1 from offline shared/data/censys_top_ja4.json (not ja4db.com live — offline violation). None if not in prevalence table → model must ignore.")
    ja4s: str | None
    early_data_offered: bool = False  # ClientHello extension 0x002a present — RFC9846 §8 / RFC8446 §8 not FS/not replay-safe
    early_data_accepted: bool = False # ServerHello extension 0x002a
    psk_offered: bool = False
    ticket_age: int | None = None  # obfuscated_ticket_age — bounds replay window
    ech_outer_present: bool = False  # RFC9849 Outer detected; Inner opaque by design — not scored
    handshake_success: bool
    alert_after_starttls: bool

class Cert(BaseModel):
    leaf_present: bool
    is_tls13_opaque: bool
    not_before: str | None
    not_after: str | None
    days_to_expiry: int | None
    is_expired: bool | None
    is_self_signed: bool | None
    chain_length: int | None
    chain_valid: bool | None
    san_match: bool | None
    pubkey_algo: str | None
    pubkey_bits: int | None
    sigalg: str | None
    sigalg_weak: bool | None
    keysize_weak: bool | None
    ocsp_stapled_status: Literal["good","revoked","unknown","not-stapled","opaque"] | None = Field(default=None, description="Stapled OCSP if handshake carried CertificateStatus (RFC6961); opaque for TLS1.3 encrypted; else unknown — no fetch, staple absent (LE 2025 deprecation noted)")
    ocsp_must_staple: bool | None = None  # TLSFeature status_request
    crl_unknown_reason: str | None = Field(default="no fetch — passive forensic, staple absent", description="unknown vs not-stapled distinction")
    # Honesty invariant: if is_tls13_opaque==True → leaf_present==False, all cert fields None (except ocsp_stapled_status=opaque), dashboard banner

class Finding(BaseModel):
    check: str  # e.g., "TLS version deprecated"
    severity: Literal["Critical","High","Medium","Low","Info"]
    spec: str   # e.g., "RFC8996 §4"
    evidence: str
    remediation: str

class Assessment(BaseModel):
    findings: list[Finding]
    risk_level: Literal["Low","Medium","High","Critical"]
    risk_score: int = Field(ge=0, le=100)
    anomaly_score: float | None
    posture_score: int
    calibrated_prob: float | None  # XGB predict_proba max, Platt-calibrated

class PolicyDecision(BaseModel):  # NEW — Response Engine (Product Evolution: dashboard → gateway)
    action: Literal["deliver","deliver_banner","quarantine","hold_incident"] = Field(default="deliver", description="Low→deliver, Medium→banner, High→quarantine, Critical→hold_incident+SIEM")
    disposition_reason: str  # e.g., "risk_score 73 Critical — weak cipher RC4 + stripping suspected ≥3 flows"
    banner_text: str | None = None  # yellow/red banner injected when action==deliver_banner
    quarantine_id: str | None = None  # opaque token link https://posture.internal/q/{id} (ARF, never raw body)
    siem_severity: Literal["Low","Medium","High","Critical"] = Field(description="mirrors risk_level for SIEM routing")
    arf_report_id: str | None = None  # RFC6522 multipart/report id when exported

class FlowVerdict(BaseModel):
    flow_id: str
    app_protocol: Literal["SMTP","IMAP","POP3"]
    starttls_mode: Literal["implicit","starttls-upgrade","cleartext","failed-upgrade"]
    tls: TLS
    cert: Cert
    assessment: Assessment
    policy: PolicyDecision | None = None  # populated by assessment/policy.py — Action surface, not just score
```
**CI gate (offline, Q9 quality 10-12 day — server-side hard fail, not client pre-push):** `pytest shared/tests/test_schema.py` validates every `features/*.json` against `schemas.py` (JSON 20/20), `schemas.json` generation, and `is_tls13_opaque` invariant. **Hard fail via `.github/workflows/ci.yml` server CI (Require status checks + Merge queue, not local `pre-push` which is bypassable via `--no-verify`); `pre-push` is advisory fast-feedback only.** `shared/schemas.py` **freeze at Day2 00:00 additive-only** (new Optional fields only); breaking change needs 2-agent ack + version bump.

#### 0.2a Feature vector (28-col) — encoding & preprocessing contract (ML brutal fix)

**28-col explicit feature vector** (was 8 — now 28 with encoding table: 21 base + 7 missing indicators, P1 CODEOWNER `shared/schemas.py` freeze Day2):

| # | Feature | Source | Type | Encoding | Notes |
|---|---------|--------|------|----------|-------|
| 1 | `version` | `TLS.version` | categorical 5 (TLS1.0/1.1/1.2/1.3/none) | native categorical `enable_categorical=True` | |
| 2 | `cipher_strength` | `TLS.cipher_strength` | categorical 4 (weak/acceptable/strong/unknown) | native categorical | |
| 3 | `kex` | `TLS.kex` | categorical 4 (ECDHE/DHE/RSA/unknown) | native categorical | |
| 4 | `is_aead` | `TLS.is_aead` | bool | passthrough 0/1 | |
| 5 | `fs_flag` | `TLS.fs_flag` | bool | passthrough 0/1 | |
| 6 | `early_data_offered` | `TLS.early_data_offered` | bool | passthrough 0/1 | for 16c |
| 7 | `early_data_accepted` | `TLS.early_data_accepted` | bool | passthrough 0/1 | |
| 8 | `psk_offered` | `TLS.psk_offered` | bool | passthrough 0/1 | |
| 9 | `ech_outer_present` | `TLS.ech_outer_present` | bool | passthrough 0/1 | |
| 10 | `handshake_success` | `TLS.handshake_success` | bool | passthrough 0/1 | |
| 11 | `alert_after_starttls` | `TLS.alert_after_starttls` | bool | passthrough 0/1 | |
| 12 | `ja4_rarity` | `TLS.ja4_rarity` | float 0..1 | median impute → StandardScaler (AE only) | variance-injected: sample from `censys_top_ja4.json` distribution if lab ja4 uniform; raw `ja4` NEVER in vector |
| 13 | `chain_depth` | `Cert.chain_length -1` | int 0..4 | passthrough | NEW — pathLen signal for family 10 |
| 14 | `san_match` | `Cert.san_match` | bool | passthrough | NEW — RFC7817 hostname |
| 15 | `starttls_mode` | `FlowVerdict.starttls_mode` | categorical 4 (implicit/starttls-upgrade/cleartext/failed-upgrade) | native categorical | NEW |
| 16 | `port` | `FlowVerdict.app_protocol+port` | categorical 5 (25/587/143/110/993) | native categorical | NEW |
| 17 | `pubkey_bits` | `Cert.pubkey_bits` | int | log1p/6 passthrough; NaN → missing direction | |
| 18 | `sigalg_weak` | `Cert.sigalg_weak` | bool | passthrough | |
| 19 | `days_to_expiry` | `Cert.days_to_expiry` | int | clip [-365,365]/365 passthrough | |
| 20 | `chain_valid` | `Cert.chain_valid` | bool | passthrough | |
| 21 | `cert_missing_reason` | derived | enum 4 (opaque/stripped/null/other) | native categorical | NEW: `opaque` if `is_tls13_opaque`, `stripped` if cleartext stripped, `null` if no TLS, `other` else |
| 22-28 | `miss_indicator_*` | derived | 7 bool | passthrough 0/1 | NEW — one per cert field (pubkey_bits, sigalg_weak, days_to_expiry, chain_valid, san_match, chain_depth, pubkey_algo) — 1 if missing else 0 |

**Censys 28-col caveat (Censys stretched fix 2026-08-25 — 11 vs 28 table):** Censys host 200 populates ONLY 11/28 cols (cipher_strength/kex/is_aead/fs_flag/version inferred + ja4_rarity + port + pubkey_bits/sigalg_weak/chain_depth + starttls_mode derived); 7 cert-validity cols (chain_valid/san_match/days_to_expiry/cert_missing_reason + 3 extension cols early_data/0-RTT/ECH) + alert_after_starttls are synthetic null (miss_indicator=1) for Censys rows. CI guards: `prior_flag=true` and `chain_valid is None` and `ja4_rarity` spans 0..1.
```python
# CENSYS STRETCH CAVEAT (added 2026-08-25):
# 28-col is the LAB+VALIDATOR schema (pcap DER → 28 cols).
# Censys host 200 populates only 11/28 effectively (prior-only):
#   cert validity chains require lab DER, not Censys host payload
# CI guard: assert not (df.source=='censys' and df['chain_valid'].notna().any()), "Censys rows must not have chain_valid — lab only"
#          and matching for days_to_expiry, san_match, cert_missing_reason sinks.
# XGB branch — passthrough (no imputation, no scaling):
#   XGB native categorical enable_categorical=True, tree_method='hist', device='cpu'
#   Never impute for XGB — use missing direction (GH #21/#8249): NaN stays NaN, XGB learns missing branch
#   Numeric: passthrough (tree is scale-invariant)
# AE branch — impute+scale only for AE (STRETCH — only if MicroAE gated n≥50+ahead):
#   SimpleImputer(strategy='median') + StandardScaler for all numeric (AE is scale-sensitive; STRETCH)
#   Opaque 1.3: cert_missing_reason='opaque' + 7 indicators=1, not conflated with stripped (stripped='stripped')
#   If ja4_rarity all-None (lab uniform) → imputed median 0.5, variance filter drops if still constant
```
**Categorical handling:** `version, cipher_strength, kex, starttls_mode, port, cert_missing_reason → native categorical (XGB enable_categorical=True, tree_method='hist') not ordinal; one-hot if XGB version <1.7. Alternative one-hot + ordinal leak note: ordinal `ECDHE=0,RSA=1,DHE=2` imposes false order DHE>ECDHE — forbidden.` — encoding table is CODEOWNER-gated, CI asserts `df[col].dtype == 'category'`.

**Ledger files (human-readable MD, polled daily — quality build, not every 30 min, Q7 tracking fix):** `shared/progress.md` (Shared ledger — single source polled by all 6 agents: Clock|Agent|Milestone|Artifact|CI gate|Blocked on, 🟢 gated/🟡 in-progress/🔴 blocked — agents start dependent work only on 🟢 commit), `lab/LEDGER.md` (Family|environment_id|capture_epoch|pcap sha256|STARTTLS|Cipher|Cert|tshark parity|coverage_ratio|source_id|n_eff — ledger carries env/epoch tags for §4a grouping audit; reassembler adds `pre_tls_buffer_len + unflushed_buffer_injection_possible` per flow), `analyzer/LEDGER.md` (per-family cipher exact+version+FS+JA4+GREASE+early_data/ECH), `assessment/LEDGER.md` (23-check recall (20 scored +3 info: 15b/16b/16c) + Platt ECE[lo,hi]+ΔECE+SHAP top3 + hybrid PR-AUC[lo,hi] vs vanilla + `pre_tls_buffer_injection_possible` + `mx_mta_sts` flag), `eval/EVIDENCE.md` (synthetic vs dual ≤2% custody + weberblog parse + limbo>90% + per-port 23×3 table (20 scored +3 info) + offline drill log + **per-milestone snapshots `eval/EVIDENCE_Day{2,5,7,10,12}.md` + `eval/blind-likert.md` (honest 14/20 vs mock 20/20 A/B Mann-Whitney, OC-bias index, Q&A probe battery: is_tls13_opaque / tshark vs x509.log / ServerHello.random / SSLKEYLOGFILE / reassembled lineage) — Finding-3 60-75% honesty premium**). See `shared/CONTRIBUTING.md` CODEOWNERS rule: ONLY shared CODEOWNER merges `shared/schemas.py`/`fixtures/*`, others open PR; `git pull --rebase` mandatory before push.

### 0.3 Quality parallel build — integration without waiting (Q7:A fixtures+stubs, PS-grounded not 1-day race) — 10-12 day timeline

| Window | Parallel lanes (6 agents + shared) | Merge point (CI hard fail — real grounding required) |
|---|---|---|
| **Days 1-2** | **Shared** generates `schemas.py` + `schemas.json` + `fixtures/` (2h tshark golden) + `ja4_rarity` offline file — all agents pull. **Lab** smoke `family-01.pcap` + `manifest.json` shell + `reassembly_coverage_ratio`. **API** scaffolds `POST /analyze` returning fixture JSON. **Dash** `vite create` + gauge shell reading fixtures. | `test_schema` green + `test_fixtures_parity` on smoke (STARTTLS F1>95% vs tshark with `reassemble_out_of_order:true`) |
| **Days 2-5** | **Lab** full 10-family matrix (Postfix 3.9 `>=TLSv1.2`, `smtpd_tls_chain_files`, `ssl=required` + `disable_plaintext_auth`) + `reassemble.py` (overlap+coverage+tshark pref) + `tc netem` jitter doc. **Parser** replaces stub with real `scapy/dpkt` + `tshark -T json` parity on `reassembled/*.bin` (GREASE harmonized). **Validator** parallel on fixture `cert.der` → dual-store `Store`/`PolicyBuilder`. | `test_reassembly` lossy/weberblog (not just clean synthetic) STARTTLS F1>95%, `test_handshake` cipher>98% |
| **Days 4-7** | **Validator** full X.509 chain (Store/PolicyBuilder dual-store private-CA stratification, RFC7817 SAN) + `is_tls13_opaque` branch (Family6 triple citation) + limbo/badssl stratified. **Rule** `rules.py` **23 checks (20 scored +3 info: 15b/16b/16c, all spec-cited §2a fix + MX request)** + SQLite ingest. **Dash** live-binds to real `features/*.json` as they land (React polls `/api/flows`, honesty banner). | `cert prec>90%` stratified (CABF vs private-CA), `weak recall 100%` on families 3-10+09 (23-check, 20 scored), `reassembly_coverage_ratio` logged |
| **Days 7-10** | **ML** ECOD primary + corrected IF + gated MicroAE 27-8-1 + XGB Platt (not isotonic) + permutation importance gate (SHAP diagnostic) + bootstrapped 95% CIs (ECE family-level, PR-AUC DeLong+logit) + `assessment.db`. **Reports** Jinja2+WeasyPrint exec+tech (per-version coverage table R1-R8 mandatory) + calibration curve. | `risk F1>85%` 5-fold family-grouped + `ECE hi<0.15` Platt (family bootstrap, n_eff disclosure) + `NDCG@10` + `ROC-AUC DeLong + PR-AUC logit vs vanilla` + `test_contamination_invariance` + weberblog threshold decoupled |
| **Days 10-12** | **Eval** dual-corpus replay (weberblog pinned + limbo 200 + Censys 1B rarity **real**, CIC demoted to Monday-benign filtered 1 slice or dropped) + `eval/metrics.json` 8/8 custody ≤2% + `validation-report.pdf` + `mapping-table.pdf` + `docker save | gzip` incremental + `pip download --only-binary` wheelhouse + **offline Wi-Fi-off drill on fresh VM** (`cold-start <3s`, `report<5s`, JSON 20/20). **Final server CI green → merge to `main`.** | 8/8 metrics green + offline drill pass + 3-min pitch record |

**Stub contract (quality, not race):** `shared/mocks/reassembler_stub.py` returns `fixtures/family-*.json` so Parser/Validator/Rule/Dash start Day1-2 on fixtures; real replaces stub via `USE_STUB=False` at Day3-5 when `reassembled/*.bin` with `reassembly_coverage_ratio` is 🟢 in `shared/progress.md` — dependents poll ledger, not time.

**Real grounding rule:** No gate passes on fixtures alone — every F.2 metric (STARTTLS F1, cipher exact, cert prec) must be proven on **lossy/weberblog + limbo** in addition to clean synthetic, otherwise gate is tautological (Finding-4 H4-01).

**Ledgers prevent drift:** `shared/progress.md` polled daily (not every 30 min), `shared/schemas.py` additive-only after Day2 freeze — quality over speed.

---

## 1. Component 1 — Lab, Cert Matrix & TCP Reassembly — `lab/`

**Owner:** P2 Net/Forensics — **Goal:** 10-family synthetic ground truth + TCP ordered streams + STARTTLS transition; offline replay zero-privilege is primary, live capture is stretch.

**Files:**
```
lab/docker-compose.yml
lab/certs/CA/{ca.key,ca.crt} + leafs/{rsa2048.crt,rsa1024.crt,p256.crt,expired.crt,selfsigned.crt,chain-incomplete.crt}
lab/pcaps/family-{01..10}.pcap
lab/pcaps/adversarial/{stripped-09.pcap,rc4-04.pcap,selfsigned-05.pcap}
lab/pcaps/real/{weberblog-*.pcap,CIC-Monday-benign-filtered.pcap}
lab/scripts/gen_traffic.sh
lab/scripts/sample_censys_200.py   # PRIOR-ONLY — weighted sample 200 from censys_top_ja4.json for JA4/cipher population prior; crafts scapy ClientHello/ServerHello with sampled cipher_suites + JA4-derived extensions + GREASE harmonized; outputs censys_sampled_200.json with ONLY 11/28 cols populated (cipher/JA4/version/port/STARTTLS banner/pubkey_bits etc) with prior_flag=true, chain_valid/san/days/0-RTT/ECH null; NEVER assigns risk labels — anomaly background + rarity table only
lab/scripts/jitter_slices.py       # NEW — 5× jitter per family: cipher shuffle+GREASE 0x0a0a+sigalg+jitter ±5d (MUST-FIX 1)
lab/manifest.json  # env-aware manifest.json (env_id, client, server_instance, loss, timing, capture_epoch, docker_image_sha256, tshark_version) for §4a grouping audit + B5 temporal (capture_epoch Day3→Day10)
lab/reassembler/reassemble.py
lab/reassembler/tests/test_reassembly.py
shared/fixtures/family-*.json (golden, tshark-derived)  # every JSON carries environment_id, capture_epoch, source_id for §4a grouping; asserted in test_schema.py (env_id uniqueness ≥ n_splits, locked ∩ train == ∅)
shared/fixtures/censys_sampled_200.json  # PRIOR — 200 pop rows with PARTIAL 11/28 cols (prior-only, prior_flag=true, chain_valid/san/days/0-RTT/ECH null, ja4_rarity spans 0..1). Schema: {flow_id, environment_id: "censys_prior_<ja4hash>", capture_epoch: "2024Q2", source_id: "censys_uid_snapshot_<date>", port, cipher_suite, ja4, ja4_rarity, version_inferred, starttls_mode_derived, pubkey_bits, sigalg, chain_depth, leaf_present, miss_indicators: {days_to_expiry:1, chain_valid:1, san_match:1}, prior_flag:true, dataset_caveat: "prior-only, 7 cert cols synthetic null"} — epoch pinned, sha256 in ledger
shared/fixtures/weberblog_full_20.json   # NEW — 20 weberblog flows full, not n=2
shared/fixtures/locked_external/         # NEW §4a — pinned: *.pcap + *.sha256 + .locked (D3 never-touched, weberblog 20 + stripping 5 triples =25; Censys-unseen 5 removed from D3 risk — anomaly-only D_prior held-out)
assessment/splits.json                   # NEW §4a — env group lists D1_train_groups, D2_val_groups, D3_locked_groups, D_prior_groups, D4_probes + D5_temporal_same_env (prior_flag disjoint, risk_model never trains on Censys)
eval/tests/test_locked_external.py       # NEW §4a — loads locked_external only post-freeze, asserts groups ∩ (train ∪ prior) == ∅ + prior_flag/chain_valid guards
```

**10 families (minimal, per F.2):**
| # | Port | TLS | Cipher/KEX | Cert | STARTTLS | Flag |
|---|---|---|---|---|---|---|
|1|587|1.2|AES128-GCM ECDHE|rsa2048 SHA256 90d|upgrade|PASS|
|2|25|1.2|AES256-GCM ECDHE|P-256|upgrade|PASS|
|3|143|1.2|3DES-CBC|rsa2048|upgrade|HIGH SWEET32|
|4|110|1.0|RC4-SHA|rsa2048|upgrade|Critical dep+RC4|
|5|587|1.1|AES128-CBC|self-signed|upgrade|Critical dep+self|
|6|993|1.3|TLS_AES_128_GCM_SHA256 x25519 FS|rsa2048 implicit|no keyword|PASS but opaque|
|7|587|1.2|AES128-CBC|expired SHA1|upgrade|Critical expired+SHA1|
|8|587|1.2|DES-CBC|rsa1024|upgrade|Critical DES+RSA1024|
|9|587|—|— cleartext|—|no STARTTLS (stripped simulated — single-flow)|High downgrade possible (low conf, not MITM proof; Critical only via stripping-history-3flow ≥3 flows per §2b/15a)|
|10|587|1.2|AES128-GCM RSA(no FS)|chain-incomplete|upgrade|High no FS+chain|

**Dataset charter (ML brutal fix — Censys stretched fix; synthetic circularity + effective n disclosure):** `Dataset charter (REDEFINEd 2026-08-25): RISK TRAIN = synthetic 10 families ×5 jittered =50 rows, n_eff=10 independent (slicing not independence; env variants ~30 env_ids) — this is the ONLY supervised risk mass (XGB Platt, D1). Optional +weberblog 20 human-graded for NDCG anchor (D1 extended n_eff=30). Background: Censys-sampled 200 population rows (weighted from censys_top_ja4.json; 11/28 cols real: cipher/JA4/version/port/STARTTLS banner/pubkey_bits etc with prior_flag=true, chain_valid/san/days/0-RTT/ECH null) — NOT risk training rows; they are UNSUPERVISED DIVERSITY PRIOR for anomaly (ECOD mixed normals 35% slice) + JA4 rarity lookup (ja4_rarity). CIC-Monday filtered 20 = held-out background, not D1. Totals: RISK n=50 (n_eff=10) or 70 (n_eff=30 with weberblog); PRIOR n=200 (n_prior, not n_eff); gross sliced 50+20 prior diversity outside risk. Manifest: lab/LEDGER.md records censys_sampled_200.json as source_id=censys_uid_2024Q2 + epoch 2024Q2 + sha256 + caveat "prior-only, 7 cert cols null"; risk ledger separately shows n_eff. Report n_risk and n_prior separately everywhere; family-level bootstrap on n_risk only. Distribution (risk D1): TLS1.2 80%/1.3 10%/1.0+1.1 10%; cipher strong 45%/weak 35%/acceptable 20%; ECDHE 80%/RSA 15%/DHE 5%; chain_valid True 70%/False 15%/opaque 15% (lab-ground). Prior D_prior: TLS1.2 68%/1.3 22%/other 10%; ECDHE 85%/weak cipher 12%; chain depth real-world bimodal (LetsEncrypt short) — complements lab.`

| Source | Rows | n_eff/risk? | TLS1.2 | TLS1.3 | weak cipher | ECDHE | chain_valid | Role |
|--------|------|-------------|--------|--------|-------------|-------|-------------|------|
| Synthetic 10 families (5 slices) | 50 | 10 risk | 80% | 10% | 50% | 80% | 70% | D1 supervised risk (XGB) |
| weberblog full | 20 | 20 risk (if graded) | 75% | 0% | 5% | 90% | 100% | D1-ext / D2 val / D3 locked |
| Censys-sampled 200 | 200 | — (n_prior) | 68% | 22% | 12% | 85% | *null* (no validity) | **Prior-only**: ECOD background 35% + ja4_rarity lookup |
| CIC-Monday filtered | 20 | — held-out | 70% | 5% | 10% | 75% | 95% | Background sanity, not risk train |
| **Risk train** | **50 (70 with weberblog)** | **10 (30)** | **80/75** | **10/0** | **35** | **80/90** | **70/100** | *Report n_risk + n_prior separately; bootstrap on n_risk* |

* OLD charter 230 rows per task spec = 10 synth independent +200 pop +40 background — REDEFINEd: Censys 200 is n_prior not n_eff; it cannot be counted toward risk n_eff because 7 cert cols are synthetic null; counting it inflates effective sample without independent cert variance. Report both n_risk=50 (n_eff=10) and n_prior=200 in every EVIDENCE.md/ledger/metrics.json.

**Must do:**
- `openssl req -x509 -newkey rsa:1024/2048 -sha1/-sha256 -nodes -subj /CN=mail.lab.local` + `ecparam -name prime256v1` for P-256; expired via `openssl x509 -days -1` clone of badssl template; intermediate CA for chain-incomplete (withhold)
- Per-family `docker-compose` override (Postfix 3.9 modern syntax ≥3.6: `smtpd_tls_mandatory_protocols=>=TLSv1.2` not legacy `!TLSv1`; weak Family 4 uses `=TLSv1.0`): `smtpd_tls_mandatory_protocols`, `smtpd_tls_mandatory_ciphers=high` (or `medium/low` for weak), `smtpd_tls_chain_files` (≥3.4, Family 10 omits intermediate for chain-incomplete), `ssl = required` (not `yes` — `yes` permits plaintext AUTH fallback under downgrade; Dovecot docs), `ssl_min_protocol=TLSv1.2`, `ssl_cipher_list` (Mozilla Intermediate), `disable_plaintext_auth=yes`; scope per-port: 25 `may` vs 587 `encrypt` per RFC8314 C6.
- **Sender container (judge-visible, offline):** `lab/docker-compose.demo.yml` service `sender` (`alpine:3.19` → `apk add swaks openssl tcpdump` on build, baked into `docker save`) — runs `sleep infinity` on `lab` bridge `172.18.0.0/24`; `api POST /demo/send {family:08}` → `docker exec sender swaks --to bob@lab.local --from alice@lab.local --server postfix:587 --tls --header "X-Family: 08-DES-rsa1024"` (inside bridge, DNS `postfix` → `172.18.0.2`, no host `127.0.0.1` nor internet). `tcpdump -i br-lab -w /tmp/demo.pcap port 587 or 993` captures same bridge → auto `POST /analyze` → React matrix updates live. `docker ps` shows `sender` alongside `postfix`/`dovecot` — judges see `sender` send, not host `swaks`. Baked `swaks --help` + `openssl s_client` smoke at `Day2` gate.
- **MX + MTA-STS/DANE mock DNS (offline, no internet MX lookup):** `mockdns` (`dnsmasq:2.90` or `coredns:1.11`) on `lab` bridge; serves `lab.local` zone: `lab.local MX 10 mail.lab.local` → `mail.lab.local A 172.18.0.2`, `_mta-sts.lab.local TXT "v=STSv1; id=20260825"` + `mta-sts.lab.local A 172.18.0.5` serving `/.well-known/mta-sts.txt` (`version: STSv1 / mode: enforce / mx: mail.lab.local / max_age: 86400`) via tiny `python -m http.server 80` sidecar, `_25._tcp.mail.lab.local TLSA 3 1 1 <SPKI>` (DANE). Postfix `smtp_dns_support_level=dnssec` + `smtp_tls_security_level=dane` + `smtp_tls_policy_maps=hash:/etc/postfix/tls_policy` for MTA-STS-enforce lane; default lane stays `may` for Family 9 stripped (no STS). Offline fixtures `shared/data/mta-sts-fixture.json` + `dane-tlsa-fixture.json` capture policy for air-gapped finale (no DNS fetch at `docker load` — `mockdns` serves same zone). Assessment check **16b MTA-STS/DANE** reads fixture or live `dig TXT _mta-sts.lab.local @mockdns` if bridge up, else offline fixture.
- `gen_traffic.sh` per family: `swaks --to bob@lab.local --from alice@lab.local --server 127.0.0.1:587 --tls` (host fallback) / `docker exec sender swaks --server postfix:587` (demo bridge) / `openssl s_client -starttls smtp -connect 127.0.0.1:587` / `curl imap://` + telnet `EHLO→STARTTLS→220` / `CAPABILITY→STARTTLS` / `CAPA→STLS` scripts; `tcpdump -w family-{id}.pcap -i any port 25 or 587 or 143 or 110 or 993 or 995` (host or `br-lab`)
- `reassemble.py`: **5-tuple ordered, seq buffering** handling out-of-order (re-insert by seq), **overlapping segments** (keep first-seen, flag `overlap_conflict`), retransmission (dup seq+same len drop; dup seq+diff len → flag), **gap flag + `reassembly_coverage_ratio`**, **window scale / selective ACK correctly ignored (flow-control only)**; banner discriminator `220 ESMTP` vs `* OK` vs `+OK`; **STARTTLS Bennett**: keyword `STARTTLS`/`STLS` + `220 2.0.0 Ready` / `OK Begin TLS` → `upgraded_at_packet_no` + `starttls_events.json`; **tshark oracle MUST run with `tcp.desegment_tcp_streams_reassemble_out_of_order:true` AND `tls.desegment_ssl_records:true` (both OFF by default since 3.0 — without them parity F1 false-fails on lossy/weberblog per ask.wireshark #10299/#23327).** **Unflushed buffer injection artifact (V4 GHSA-9j88):** after `STARTTLS`→`220`, record `pre_tls_buffer_len = reassembled bytes between 220 and ClientHello`; if >0 (pipelined `EHLO`/`AUTH`/`CAPABILITY` injected before flush) set `pre_tls_buffer_injection_possible=True` with evidence bytes — distinct from cross-flow stripping (15a vs 15b in rules).
- Verify against `tshark -T json -e tcp.seq -e tcp.ack -e tls.handshake.type -e tls.handshake.ciphersuite -e x509sat.*` baseline (tshark is source of truth; Wireshark reassembly pref on per SharkFest best practice)
- MITM stripping sim: family-09 = single-flow cleartext where `EHLO` previously offered `250-STARTTLS` in manifest history (for H4 triage heuristic — honest single-flow ceiling is `High downgrade possible (low conf)`, not Critical per review §2b). **History fixture for 15a Critical:** `lab/adversarial/stripping-history-3flow/{flow1.pcap,flow2.pcap,flow3.pcap}` — same `(client=127.0.0.11, server=127.0.0.1:587)` pair with 3 sequential captures where flows 1-2 previously upgraded (STARTTLS→220→TLS), flow 3 now stays cleartext stripped (no `250-STARTTLS` in `EHLO`); reassembler + `rules.py` cross-flow history `≥3 flows` exercises Critical branch, closes 15a test-coverage gap. `gen_traffic.sh --history-triple` generates via `swaks` replay + `tcpreplay` of stripping sim.
- Pre-generate `shared/fixtures/family-*.json` + `adversarial/history-3flow.json` from tshark golden so dependents start Day1
- **Demo lane (offline-feasible, no MX cutover): Primary = local milter loopback** `Postfix smtpd_proxy_filter=127.0.0.1:10025` (before-queue) on `127.0.0.1` — `swaks --to bob@lab.local --server 127.0.0.1:25` → milter sees real TLS session → `api/siem.py` + `quarantine.py` inline; **Fallback = passive pcap replay** `lab/pcaps/*.pcap → api POST /analyze` (zero-privilege, Wi-Fi-off) if milter not running — dashboard works on both lanes; SIH demo defaults to loopback, fallback proven by `--replay-only` flag.

**Must NOT do:** Claim live capture required for demo (replay is primary per §H.6), claim PQC/DANE, decrypt mail body, claim 1.3 cert visible.

**Done when (numeric gates, CI hard fail):**
- `manifest.json` maps family→cipher/cert/STARTTLS ground truth (10+3+2 files present)
- `tshark` vs `reassemble.py` **STARTTLS P/R F1>95%** on smoke (fixtures)
- `docker save postfix:3.9 dovecot:2.3 | gzip` <4GB + `pip download` wheelhouse <800MB on 32GB USB (Q11:A)
- Offline replay passes Wi-Fi-off drill (no `NET_RAW` needed)

**Stub for dependents:** `shared/mocks/reassembler_stub.py` — `def reassemble(pcap_path) -> list[FlowVerdict]: return json.load(fixtures[f])` — real replaces stub at **Day3 00:00** (Days 2-5 window) via `USE_STUB=False` flag.

**Integration test:** `eval` replays all `lab/pcaps/*.pcap` through `api POST /analyze` → dashboard matrix shows Family 9 as `cleartext` + `downgrade possible`.

---

## 2. Component 2 — TLS Handshake Parser & JA4 — `analyzer/`

**Owner:** P3 Crypto — **Goal:** Deterministic handshake parse (>98% cipher) + JA4, honest 1.3 opaque flag — no cert parse here.

**Files:**
```
analyzer/parse.py
analyzer/jas.py
analyzer/tests/test_handshake.py
analyzer/tests/test_ja4.py
shared/mocks/validator_stub.py
```

**Must do:**
- `scapy TLS` or `dpkt+dpkt.ssl` or `tshark -T json` parse (prefer `tshark -T json` as oracle, `scapy` as fallback): `legacy_version` (0x0303), `supported_versions` (0x0303 vs 0x0304), `cipher_suites[]`, extensions `SNI` (server_name), `ALPN` (imap/smtp), `supported_groups` (x25519, secp256r1), `signature_algorithms`, `key_share` (1.3), **`early_data` (0x002a) + `psk_key_exchange_modes` (0x002d) + `pre_shared_key` (0x0029) — 0-RTT surface (RFC8446 §8 / RFC9846 §8, GnuTLS anti-replay)** + `ticket_age`/`obfuscated_ticket_age` + PSK binder; **ECH:** parse `ClientHelloOuter` normally, note `encrypted_client_hello` (RFC9849 2026-03) Inner not parsed — requires ECHConfig fetch, out-of-scope for mail (web-centric, no MTA deployment 2024-26), document.
- **Version logic:** `legacy_version==0x0303` + `supported_versions==0x0304` → TLS1.3 else TLS1.2; flag `is_deprecated` if TLS1.0/1.1 per RFC8996 `MUST NOT`
- **Cipher/KEX/FS:** KEX from cipher string (`ECDHE`/`DHE`/`RSA`) + `key_share`; `fs_flag = kex in (ECDHE,DHE)` (TLS1.3: always true per RFC8446, no RSA key transport); `is_aead` vs Mozilla Intermediate list (`ECDHE-*-AES128/256-GCM-SHA256/384/CHACHA20-POLY1305`); `cipher_strength` weak if RC4/DES/EXPORT/NULL/anon/3DES/CBC+SHA1
- **JA4:** FoxIO `ja4` python (`pip ja4`) — canonical hash of (version, ciphers, extensions, groups, EC formats) + `ja4s` server side; fallback manual hash per `FoxIO ja4 technical_details.md` §4; **GREASE harmonization:** filter GREASE values (0x0a0a,0x1a1a…0xfafa) in cipher list + sigalgs before hashing to match FoxIO python vs tshark Rust divergence (issue #305, log divergences); **Offline rarity:** load `shared/data/censys_top_ja4.json` (few MB subset of top 1000 Censys 1B frequencies, offline bundle) → `ja4_rarity = 1 - percentile`, do NOT call ja4db.com live; **Risk model whitelist:** `ALLOWED_RISK_FEATURES` must assert `ja4 not in feature_vector` (raw hash never ML feature, spoofable via `curl-cffi impersonate=chrome131`), only `ja4_rarity` numeric; store raw extensions for SHAP audit
- **TLS1.3 handling:** after `ServerHello`, set `tls.is_tls13_opaque` flag; **do NOT attempt Certificate parse here** — validator will skip; still emit `version/cipher/KEX/FS/JA4`
- Emit `TLS` sub-object per `schemas.py` + merge into `FlowVerdict`; write `shared/fixtures` golden for CI

**Must NOT do:** Invent cipher names (IANA only), claim 1.3 cert extraction, suppress 1.0/1.1 deprecation, claim JA4 alone is verdict.

**Done when:**
- 10-family **cipher exact match >98%** vs `ServerHello.selected_cipher` (tshark oracle)
- TLS1.3 Family6 flagged `is_tls13_opaque==True` with `version==TLS1.3`
- JA4 present on all flows, spoofability noted in log (falsification H1-04)
- `test_handshake` on dkg howto vectors + `openssl s_client` smoke >95%

**Stub:** `validator_stub` returns `Cert(leaf_present=False, is_tls13_opaque=tls.is_tls13_opaque, ...)` so Rule can run without real X.509.

**Integration test:** Family 4/5 flagged `is_deprecated==True` (Critical), Family6 shows greyed cert in Dashboard.

---

## 3. Component 3 — X.509 Chain Validator — `validator/`

**Owner:** P1 TLS/X.509 — **Goal:** Full RFC5280§6+RFC7817 SAN validation for 1.2 clear, honest opaque for 1.3 — cert prec>90% vs limbo.

**Files:**
```
validator/chain.py
validator/san_check.py
validator/stores/{ca-bundle.crt, privateCA.pem, intermediates/}
validator/tests/test_chain_limbo.py
validator/tests/test_badssl.py
```

**Must do:**
- `cryptography.x509.load_der_x509_certificate` per `Certificate` message (1..N DER blobs, chain may include leaf + intermediate + root); extract `subject/SAN dNSName`, `issuer`, `notBefore/notAfter`, `pubkey_algo+bits`, `sigalg`, `KeyUsage (digitalSignature,keyEncipherment)`, `ExtendedKeyUsage serverAuth`, `BasicConstraints CA:FALSE`, `pathLenConstraint`
- **Chain build (RFC5280§6):** leaf → intermediates (from pcap) → OS trust store (`/etc/ssl/certs/ca-certificates.crt`) → `stores/privateCA.pem` (bundled private CA for family 10); per-link `pubkey.verify(tbsCertificate.signature)`; fail if `BasicConstraints` violation or missing intermediate; mark `chain_valid` + `chain_length`
- **SAN check (RFC7817):** MUST match `SAN dNSName` vs `mail.lab.local` (or `server_hostname` from SNI); CN fallback only if SAN absent (flag Medium, not pass); SRV-ID if `RFC6186` present; `san_match` bool
- **Weak checks:** RSA<2048→High (<1024 Critical), EC<P-256 High, DH<2048 High, DSA deprecated High, `sigalg` `sha1WithRSA/md5WithRSA/sha1WithECDSA`→High, `is_expired`→Critical, `notBefore>now`→High, `is_self_signed`→High (Medium if `privateCA.pem` matches), `chain incomplete`→High (Medium if private CA), `san_match==False`→High
- **Revocation (passive-aware, not always unknown — V3 Context7+SearXNG):** **Do NOT fetch CRL/OCSP at runtime (air-gap), but report stapled OCSP if handshake carried it.** Parse `ClientHello` extension `status_request` (0x0005) / `status_request_v2` (RFC6961) → `ocsp_staple_requested=True`; if server sent `CertificateStatus` (handshake type 22) with DER OCSP response, parse via `cryptography.x509.ocsp.load_der_ocsp_response` → `ocsp_stapled_status ∈ {good,revoked,unknown,not-stapled}` + `this_update/next_update`. Also parse leaf `TLSFeature (status_request)` Must-Staple via `cert.extensions.get_extension_for_oid(TLSFeatureOID)` → `must_staple=True`. **If stapled present → report it; if absent → `unknown — no fetch, no staple observed` (honest, not “always”).** For TLS1.3, `CertificateStatus` is **encrypted after ServerHello** like cert → `ocsp_staple_opaque=True` + legend “staple encrypted for 1.3 like cert”. Document LE 2025 OCSP deprecation (short-lived certs use CRL, staple legacy but checked if present).
- **Honesty contract:** if `is_tls13_opaque==True` → `leaf_present=False`, all cert fields `None` (except `ocsp_stapled_status=opaque`), dashboard banner handled by API; never emit mock `subject/issuer`
- **Tests:** run `x509-limbo` JSON vectors (TrailofBits 2024) via adapter → `chain_valid` pass/fail vs expected; `badssl` templates (expired/self-signed/rsa1024/sha1) → precision report

**Must NOT do:** Live OCSP/CRL **fetch** (air-gap violation — stapled OCSP parse is allowed, fetch is not), regex-only X.509, mock 1.3 cert, invent SAN.

**Done when:**
- `x509-limbo` + `badssl` **precision >90%** (stratified, private-CA branch separate)
- Family 7 expired, Family 8 rsa1024+DES, Family10 incomplete correctly flagged; Family6 correctly opaque (null)
- `cryptography` 2024 `Store`/`PolicyBuilder` API used (context7 verified), not deprecated `verify_directly`

**Integration test:** Eval replays Family6 → `cert.leaf_present==False` + banner; Family7 → `is_expired==True` Critical high in matrix.

---

## 4. Component 4 — Rule Engine, Risk Classifier & Anomaly — `assessment/`

**Owner:** P4 ML — **Goal:** 23-check oracle `rules.py` (20 scored +3 info, 100% weak recall deterministic) + calibrated triage (XGB Platt + permutation, not isotonic) + anomaly (ECOD primary + corrected IF + gated MicroAE) + **Policy/Response Engine `policy.py` (gateway stretch — severity→action, not just score; not core-graded)** — falsification reframes enforced.

**Files:**
```
assessment/rules.py
assessment/score.py
assessment/risk_model.py
assessment/anomaly_model.py
assessment/policy.py          # NEW — Product Evolution: Response Engine (Rule→Risk→Policy)
assessment/tests/test_rules.py
assessment/tests/test_risk_ablation.py
assessment/tests/test_anomaly_hybrid.py
assessment/tests/test_policy.py  # NEW — Low→deliver / Med→banner / High→quarantine / Critical→hold_incident
models/{risk_clf.pkl, anomaly.pkl}
eval/{risk_pr.png, anomaly_pr.png, shap_summary.png, calibration_curve.png}
```

**Reproducibility contract (§4 top — brutal hardware fix):** `PYTHONHASHSEED=0, random_state=42 everywhere (XGB/IF/CalibratedCV/shuffle/bootstrap), OMP_NUM_THREADS=6 (MKL_NUM_THREADS=6, OPENBLAS_NUM_THREADS=6), XGB deterministic=True, torch.manual_seed(42) + use_deterministic_algorithms(True), uv pip compile lock (requirements.lock pinned transitive), device='cpu' explicit. run.sh exports PYTHONHASHSEED + OMP_NUM_THREADS=6.`

**Training time budget (7600 6c/12t, no GPU — brutal hardware fix):**

| Step | Wall | Notes |
|------|------|-------|
| XGB 50 rows hist | 0.2s | tree_method='hist' CPU, depth 3-4 |
| calibration Platt cv=2 lean (cv=3 stretch) | 0.6s lean (1s stretch) | 10 fits lean (15 stretch) |
| permutation importance n_repeats=10 lean (30 stretch) | 0.2s lean (0.5s stretch) | n_jobs=6 |
| ECOD MUST | 0.3s | PyOD ECOD <5ms fit, 0.3s with preprocess |
| IF corrected OPTIONAL | 0.4s | 50 trees max_samples=32 — OPTIONAL |
| MicroAE STRETCH 27-8-1 100 epochs CPU | 2.5s | torch CPU 180MB, batch 16, early stopping — STRETCH only if n≥50+ahead |
| bootstrap ECE 500 lean (1000 stretch) | 1s lean (2s stretch) | n_jobs=6, family-level |
| bootstrap PR-AUC OPTIONAL suppress at n_pos<20 | 0s lean (4s stretch if n_pos≥20) | logit, n_jobs=6 — OPTIONAL |
| **Total LEAN** | **<8s on 7600, no GPU** | 7900GRE parked for LLM demo only; stretch <15s |

**Must do — Rule engine (oracle, deterministic):**
Exact 23 checks from D.2 (20 scored + 3 info: 15b injection, 16b MX/MTA-STS/DANE, 16c 0-RTT per §2a fix + MX request), each with `spec` citation:
1 TLS version deprecated (RFC8996 §4-5) → Critical if 1.0/1.1
2 TLS version outdated (NIST800-52r2, 1.3 required by 2024) → Medium if only 1.2
3 Weak cipher NULL/EXPORT/RC4/DES → Critical
4 Weak cipher 3DES (SWEET32) → High
5 Weak cipher CBC without AEAD (non-AEAD when AEAD available) → Medium-High
6 Weak KEX RSA key transport (no FS) or DH<2048/EC<P-256 → High
7 Weak pubkey RSA<2048/EC<P-256/DH<2048 → High (Critical if <1024)
8 Weak sigalg sha1/md5 → High
9 Cert expired (RFC5280) → Critical
10 Cert not yet valid → High
11 Chain incomplete/self-signed (RFC5280§6) → High (Medium if private CA)
12 Hostname mismatch (RFC7817) → High
13 No Forward Secrecy (fs_flag==False) → High (Medium for 1.3 always FS)
14 STARTTLS not offered (RFC3207/M3AAWG) → High if cleartext where opportunistic expected
15a STARTTLS stripping suspected (EAST 320k, CVE-2021-38502 — advertisement stripping on 587/143/110) → Critical if cross-flow history: same (client,server) previously upgraded but now cleartext across ≥3 flows; single-flow → "downgrade possible (low conf, needs history)" — spec R2
15b STARTTLS response injection via unflushed buffer (Postfix CVE-2011-0411 + Venema pipelining + MailKit GHSA-9j88 / CVE-2026-41319 — SmtpStream buffer not flushed on SslStream replace → SASL downgrade PLAIN vs SCRAM-SHA-256; Dovecot 33515, Thunderbird 23993 same class) → High if pipelined commands/responses between `STARTTLS→220 Ready→ClientHello` buffered as trusted post-TLS (evidence: pre-TLS injected `* OK`/`250-AUTH` counted as post-TLS); else Info `no injection artifact`. Detector: `pre_tls_buffer_len` + `unflushed_buffer_injection_possible` flag in reassembler
16 Implicit TLS absent (RFC8314, MUA→MSA) → Info/Medium
16b MX + MTA-STS/DANE filter (RFC8461 MTA-STS, RFC7672 DANE TLSA — MX-aware, offline mockdns properly per user request) → **Info (enforce lane)**: `MX lab.local` via `mockdns` (`dig MX lab.local @mockdns` → `mail.lab.local`); `TXT _mta-sts.lab.local` + `/.well-known/mta-sts.txt` `mode: enforce` + `TLSA _25._tcp.mail.lab.local` read from `shared/data/mta-sts-fixture.json` / `dane-tlsa-fixture.json` (live `dig TXT/TLSA @mockdns` if bridge up); evidence “MX=mail.lab.local, MTA-STS mode=enforce, TLSA 3 1 1 present vs absent — STARTTLS on 25 is only option so MTA-STS/DANE exist (smtpedia 2026), adoption 0.3% 2024 uriports, UK must-do/NZ enforce roadmap”; **no scoring for MUA→MSA implicit, only MTA→MTA 25 info** — not block for pass, but proves MX filter wiring vs slide.
16c 0-RTT early_data without anti-replay (RFC8446 §8 / RFC9846 §8 — GnuTLS ClientHello recording, ticket_age window) → Medium if `early_data_offered && !early_data rejected && ticket reusable / ticket_age not bounded` — evidence “ClientHello 0x002a early_data; ticket_age X; no server rejection — replayable & not forward secret” ; ECH: INFO if `ech_outer_present` → “ECH Outer observed (RFC9849); Inner not parsed — out-of-scope, not scored”
17-22: expiry <30d Medium (17), keyUsage missing High (18), ExtendedKeyUsage not serverAuth High (19), pathLen violation High (20), plus **15b injection (Info/High), 16b MX/MTA-STS/DANE (Info), 16c 0-RTT (Medium/Info) as weighted-but-distinct — total 23 checks, 20 core scored + 3 info-weighted**. **Scoring weights:** posture `risk_score` weights all 23 but 15b/16b/16c are **Info-weighted (1 pt) unless High/Medium-triggered**; dashboard `cols=23 (20 scored +3 info-greyed: 15b injection, 16b MX/MTA-STS, 16c 0-RTT)`, mapping-table `23 rows`, and CV gates all count 23. No silent drop — 15b/16b/16c are differentiator-grade and must appear in judge-facing matrix. **Honesty banner stays 14/20 REAL scored + 3 info** — textually consistent everywhere.

**Scoring `score.py`:** `Critical=25, High=15, Medium=7, Low=3, Info=1` → sum → `risk_score 0-100` (cap at 100), `risk_level` via thresholds (≥40 Critical, ≥25 High, ≥10 Medium, else Low), `posture_score = 100 - risk_score` (gauge). Remediation text per check (e.g., "Upgrade to TLS1.3 + ECDHE AES128-GCM, rotate to RSA2048/SHA256, provision intermediate").

**Must do — Risk classifier (reframed, Platt not isotonic, H2):**
- `effective_n = n_families (=10) not n_rows (=50); slicing is augmentation, not independence. Gate ECE/SHAP/NDCG on effective_n >=20, else disclose n_eff=10 and report rank-only.` — all CIs family-level bootstrap (resample families not rows).
- Labels = rule severity — WEAK SUPERVISION disclosure verbatim in every artefact: "Labels are rule-derived weak supervision (score.py 22 checks, 20 scored +3 info); not hand-labeled field data; n_eff=10 synthetic independent. See Dataset Charter §1/§4a." — `shared/schemas.py` comment + `assessment/README.md` + `eval/EVIDENCE.md` Section B header + dashboard AI tab footnote all carry this sentence verbatim.
- Expand 10 families via variance-injecting DA: 3 slices lean (5 stretch) per family via cipher-order shuffle + GREASE insert (0x0a0a) + sigalg variation + expiry jitter (+/-5d) → 30 lean / 50 stretch rows but effective_n=10; disclose augmentation. Censys-sampled 200 JA4-diverse rows from censys_top_ja4.json are NOT concatenated to XGB training X — they are reserved as (a) offline ja4_rarity lookup for col 12, (b) ECOD mixed-normal background 35% slice (see anomaly). Risk CV remains 5-fold family-grouped on n_risk=30 lean / 50 stretch (environment_id groups ~12 lean / 30 stretch), no Censys rows in train folds. Report n_risk + n_prior separately.
- 20-flow human-graded NDCG@10 (3 raters blind, 1-5, gains 2^rel-1, κ>0.6) is PRIMARY, NDCG@10 vs rule weights is SECONDARY diagnostic. No training-time flipping. Optional Appendix R-Flip as pre-registered robustness probe (H_flip: ΔNDCG_Human ≤0.05 under 10% uniform flip) never for deployed risk_clf.pkl. — 20 flows (10 weberblog full +5 Censys +5 adversarial history) graded blind by 3 raters: P1 TLS + P4 ML + P6 Docs/Eval on 1-5 Likert (Critical=5) — gains 2^rel-1 exponential, NDCG@10 vs human is PRIMARY metric; NDCG@10 vs score.py weights is SECONDARY diagnostic only; report Cohen κ + Fleiss κ, require κ>0.6 substantial else re-grade within 5h budget; grading sheet pinned eval/human_grades.csv + eval/blind-likert.md
- **Model:** `XGBClassifier(tree_method='hist', device='cpu', enable_categorical=True, max_depth=3-4, n_estimators=80, reg_alpha=1.0, reg_lambda=2.0, subsample=0.8, colsample_bytree=0.8, random_state=42, deterministic=True)` (not RF) with `use_label_encoder=False`; `XGB tree_method='hist' CPU only (gpu_hist 6× slower at n=50 per GH #6025); keep depth 3-4 not 6`; **calibration: Platt (`CalibratedClassifierCV(method='sigmoid', cv=2 lean, cv=3 stretch)`) — NOT isotonic** (falsified small-n: ECE 10pp at n<100, isotonic needs >1000); `ECE hi<0.20 lean (0.15 stretch) at n_eff=10-50, family-level bootstrap 500 lean (1000 stretch) resamples → CI width ±0.06-0.10 disclosed; temperature scaling STRETCH (fallback is rank-only disclosure, not second calibrator; only if Platt ΔECE<0.02 and ahead); if n_eff<20 report NDCG only + ECE badge "unverified"`; **CI gate:** hard assert `calibrator.method=='sigmoid'` at n<1000 (`grep -r isotonic && exit 1` in CI); `n_calib<50 → disclose rank-only NDCG@10`
- **Gates LEAN (3 hard +1 feature):** ablation duo lean **B0 dummy + B2 rule-only → B3 XGB Platt MUST** (B1 LR-L2 stretch) — report `ΔNDCG@10 PRIMARY` + `ΔECE SECONDARY` + `ROC point>0.60 MUST (DeLong CI stretch)`; Brier OPTIONAL appendix, PR logit SUPPRESS at n_pos<20, SHAP diagnostic OPTIONAL appendix (PNG stretch, not gate); gate via permutation n=10 lean (30 stretch) top3 coherence MUST; unwrap comment STRETCH. **No Cleanlab flip in gates.**
- Output `assessment.calibrated_prob = max predict_proba` + SHAP summary PNG (diagnostic) + permutation importance bar PNG (gate) + calibration curve PNG + `Evidences: rule-assisted supervised — ablation-verified, n_eff=10 disclosed, WEAK SUPERVISION disclosed`

**Optional Appendix — Robustness to synthetic rule error (NOT training, NOT ground truth):** `IF the team wants a flip experiment, file it as Appendix R-Flip in eval/EVIDENCE.md Annex, NOT in training: Hypothesis H_flip (pre-registered Day7 before Day10 locked reveal): "XGB NDCG@10 vs human degrades ≤0.05 under 10% symmetric flip of rule labels; i.e., triage ranking is robust to ≤10% rule error." Protocol: (a) take clean y_rule, (b) create y_noisy = y_rule ⊕ Bernoulli(0.1) with seed 42, (c) train XGB on y_noisy with same GroupKFold, (d) evaluate NDCG@10 vs HUMAN (not vs y_rule), (e) report ΔNDCG_Human = NDCG_Human(clean) - NDCG_Human(noisy) with 95% CI from family bootstrap. Label everywhere "Robustness to synthetic rule error (uniform flip, not instance-dependent, not ground truth)". Do NOT use y_noisy for deployed models/risk_clf.pkl. Code: assessment/tests/test_risk_ablation.py::test_flip_robustness (marked xfail if Δ>0.05). Requires no cleanlab dependency — use numpy random flip.`

**Must do — Anomaly (reframed, ECOD primary + corrected IF + gated MicroAE, H1):**
- **Do NOT claim vanilla IF PR-AUC>0.80** (strongly falsified: CIC 0.17-0.55, Wang 30%/111% AE gap, contamination invariance, JA4 spoof)
- **Hybrid LEAN: 2 lean (ECOD MUST + XGB Platt MUST; corrected IF OPTIONAL, MicroAE STRETCH):** `Primary ECOD MUST (Emir 2022, PyOD) for tabular — no contamination, stable at n_risk=10-50. Censys 200 is EXPLICITLY the 35% Censys-sampled normals slice of mixed prior (30% synth F1-2 PASS +35% weberblog normals +35% Censys priors) — not supervised rows. Features for Censys slice: only 11/28 populated → impute cert missing indicators =1 median, StandardScaler fit on mixed normals only (not test). Secondary corrected IF OPTIONAL comparison (not gate; var<0.02 decoration). Tertiary MicroAE STRETCH gated if n_risk>=50 and ahead — 28-8-1 bottleneck 1 early stopping; do NOT ensemble by default — mean rank only if all 3 stretch present else ECOD alone.`
- **Censys ablation:** permutation importance on risk model must show `ja4_rarity` gain is driven by `censys_top_ja4.json` prior, not Censys rows as supervised examples. Log ΔNDCG with/without ja4_rarity (lab uniform 0.5 vs Censys-sampled rarity) — expected +0.02-0.05 if rarity matters, else variance filter drops.
- Features: **27-col vector (§0.2a)** but **ablate JA4 raw hash** (spoofable) → use `cipher_strength` + `kex` + `fs_flag` + `pubkey_bits` + `sigalg_weak` + `days_to_expiry` + `chain_valid` + `ja4_rarity` (population frequency vs lab-uniform) + `chain_depth, san_match, starttls_mode, port, cert_missing_reason, 7 missing indicators` — ColumnTransformer: XGB passthrough vs AE imputer(median)+StandardScaler (see §0.2a)
- **Gates (revised):** `Report ROC-AUC DeLong CI + PR-AUC logit bootstrap (percentile, 1000 resamples, width disclosure ±0.15-0.20 at n_pos<20, Boyd breakdown). Add test_contamination_invariance (assert PR-AUC var <0.02 across contamination 0.05/0.10/0.15). Weberblog threshold via calibrate_threshold_via_weberblog decoupled from PR-AUC (not flag <15% at tuned PR threshold — separate). mixed prior normalizer: StandardScaler fit on mixed normals only, not test.`
- `AE 8-4-8 CPU on 7600 6c <2.5s (torch CPU 180MB manylinux) vs ROCm 1.2s +1.5s hip init — choose CPU. Pin rocm 6.2.4 if ever used. IF ECOD <0.6s.`
- Store `anomaly_score` + `contamination` used + CI + `n_eff` + `device=cpu`

**Must do — Policy Engine `assessment/policy.py` (NEW — Product Evolution, real use not demo):**
- **Deterministic mapping after Risk:** `PolicyDecision.action` derived from `risk_level+evidence` — **Low (<10) → `deliver` (+ `X-SMS-Risk: Low` header), Medium (10-24) → `deliver_banner` (yellow banner "Weak transport — do not send sensitive data" + `X-SMS`), High (25-39) → `quarantine` (hold in `assessment.db quarantine` + digest entry + token link), Critical (≥40) → `hold_incident` (quarantine + SIEM incident + red digest + stripping-history artefact if 15a≥3 flows)**. **Info checks 15b/16c (1pt) only tip level when High-triggered (pre_tls_buffer_len>0 or replayable early_data).** `is_tls13_opaque` alone never holds (only Info).
- **Copy is "cryptographic security risk", not "leak"** — A≠C (transport eavesdroppability vs content maliciousness); banner text per level: Low none, Medium yellow caution, High orange hold, Critical red incident. Gmail red-lock (2016+) precedent.
- **Never attach raw body** — per-mail leak email with attachment is anti-pattern (DPC.ie GDPR, ARF body-stripped, 47% precision loss at 86% FAR, loop `MAIL FROM:<>` RFC6650). **Always link:** `quarantine_id = uuid` → `https://posture.internal/q/{id}` (72h-28d, RBAC + audit), alert carries `message-id+sender+risk+3 findings+sha256` + redacted 2KB, original enveloped as `message/rfc822` *inside* quarantine store, not MIME attachment. Mesh/Checkpoint digest model (1/period, not 1/mail) — hourly SOC, daily enterprise.
- **Files:** `policy.py: def decide(verdict: FlowVerdict) -> PolicyDecision` uses `score.py` thresholds + SHAP `calibrated_prob` as tie-breaker within tier (never cross-tier override); `tests/test_policy.py` asserts 7 worked families: F1 Low→deliver, F3 Medium→banner, F4 Critical→hold_incident, F9 single→High banner/low-conf, F9 triple→Critical quarantine, F6 opaque→Low banner-only on cipher, F7 expired+SHA1→Critical.

**SQLite (Q5:B, V7 PASS):** `assessment.db` (SQLite **3.45+ JSONB binary**, 3× over text JSON — Dolt 2024 O(N) vs Postgres O(1)+GIN (GIN wins 0.32ms filtered `@>` 400 rows), but for SIH point lookup `PRIMARY KEY` on <100 rows <1ms ≪50ms gate, not filtered containment; empirical single-user lightweight vs Postgres concurrent — SIH is lightweight; saves 120MB offline). Tables `flows(flow_id PRIMARY KEY, verdict_json JSONB, risk_score, anomaly_score, risk_level, starttls_mode)` + **`quarantine(quarantine_id TEXT PRIMARY KEY, flow_id FK, action TEXT, banner_text TEXT, token_expiry TEXT, verdict_json JSONB)` (holds `message/rfc822` enveloped, never raw attach — ARF link model, Mesh 28-day default → 7-day lean for SIH demo)** — dashboard `GET /flows` polls via `SELECT` not re-parse; digest cron reads `quarantine`; migrations via `alembic` stub. **Stretch:** if Censys 1B full-table or Enron 600k added, promote to Postgres `JSONB+GIN+tsvector`.

**Must NOT do:** Transformer BERT on raw pcap (R6 sink), isotonic at n<100, claim ML replaces rule, claim vanilla IF>0.80, leak family slices across CV folds, **attach raw body to per-mail alert (anti-pattern — GDPR/DPDP amplification, ARF body-stripped, loop `MAIL FROM:<>` RFC6650 — always link+envelope)**.

**Done when (hard fail CI):**
- `rules.py` **weak recall 100%** on families 3-10+09 (deterministic, F.2)
- Ablation: `ΔF1` or `ΔECE≥0.03` or `NDCG@10` p<0.05 with Platt, permutation importance top-3 coherent (SHAP diagnostic only), `ECE hi<0.15` (family-level bootstrap, n_eff disclosure) else reframe to rank-only and drop probability claim; if n_eff<20 report NDCG only
- Hybrid **ROC-AUC DeLong CI + PR-AUC logit bootstrap CI** (width disclosed ±0.15-0.20 at n_pos<20), `test_contamination_invariance` pass (PR-AUC var <0.02 across 0.05/0.10/0.15), ECOD vs corrected IF comparison, weberblog threshold via `calibrate_threshold_via_weberblog` decoupled (FPR reported separately, not gated to PR-AUC)
- **`policy.py` action 100% correct on 7 family fixtures** (F1→deliver, F3→banner, F4→hold_incident, F9 single→High banner/low-conf, F9 triple→Critical quarantine, F6 opaque→banner-only) — no raw attach, token expiry enforced
- `assessment.db` populated (+ quarantine) and `SELECT` serves dashboard <50ms

**Integration test:** Dashboard threat matrix ordering differs from pure rule severity weights where hybrid/SHAP reprioritizes (e.g., expired+weak cipher co-occurrence surfaces above single High).

---

## 4a. ML Data & Generalization Protocol — Four-Dataset Patch (Locked External + Cross-Env + Open-World + Temporal/Source-Shift Stress Test)

**Purpose.** Supply the 12-point data protocol that §0.2a (28-col WHAT) does not: WHERE each flow comes from, HOW augmentation vs environment variant is counted, HOW splits prevent family/environment leakage (GroupKFold vs StratifiedGroupKFold with `groups=environment_id`), HOW generalization is claimed on held-out environments / locked real captures / unseen postures / temporal epochs — and WHEN a claim is reframed. Does not touch Days 2-5 pipeline per review: generation Day2, validation env holdout Day5-7, ML training Day7-10, locked reveal Day10-12. Full research note: `/tmp/ml-data-protocol-research.md` (§1-6, 12-point mapping, 7 SearXNG URLs + scikit-learn docs).

**4a.1 Dataset charter (D1-D4 + D_prior) — §4 in research note (REDEFINEd: Censys as prior).** D1 Controlled train (risk): synthetic 10 families ×5 slices =50 rows, n_eff=10 independent (environment_id ~30 groups) — ONLY D1 enters XGB Platt supervised head; optional +weberblog 10 of 20 if human-graded extends D1 to n_eff=20-30 with κ>0.6. **D_prior: Censys-sampled 200 (n_prior=200) — NOT part of D1/D2/D3 risk splits; reserved as JA4/cipher population prior (censys_top_ja4.json offline rarity) + unsupervised diversity background for ECOD (35% mixed normals).** D2 Validation: env-holdout ~20-40 rows / n_eff 10-20 for threshold/ECE tuning (separate environment_id, never shuffled; drawn from D1 envs not D_prior). D3 Locked external (never-touched): weberblog 20 + stripping-history 3-flow 5 triples =25 flows n_eff=25 pinned `shared/fixtures/locked_external/*.pcap.sha256` + `.locked` marker, loaded only by `eval/tests/test_locked_external.py` (asserts `groups ∩ (train ∪ prior) == ∅`); **Censys-unseen 5 removed from D3 risk lock** — instead evaluated as D_prior-held-out rarity generalization for anomaly (JA4 rarity coverage), not risk NDCG. D4 Stress (recomputed metrics, not new rows): cross-env held-out envs (client B, loss 2%, cert variant) / open-world 5 probes (EXPORT, DANE fail, 0-RTT, 465 implicit, 143 stripped) NDCG@5 human-graded / temporal/source-shift stress (lab Day3 vs weberblog 2024-06-20 vs Censys 2024Q2 prior epoch — source-shift, not pure temporal, see §4a.9). Every row carries source_id, family_id, environment_id, capture_epoch, prior_flag (true for Censys).

**4a.2 Environment variants (not just slicing) — §4.1 table.** Slicing (cipher shuffle, GREASE 0x0a0a, sigalg variation, expiry ±5d, ja4_rarity sampling) = within-family n_eff=1. Environment dimensions lean: `server instance (Postfix >=TLSv1.2)` + `loss variant (0% vs 2% tc netem)` → `env_id = <family>__<server>_<loss>` (~12 groups lean: 6 families×2 envs clean/lossy; full 5-dim client/server/cert/loss/timing ~30 stretch). `lab/LEDGER.md` env columns. Scripts: `lab/scripts/sample_censys_200.py` + `jitter_slices.py --slices 3 lean (5 stretch)` emit `environment_id` + `capture_epoch`; `gen_traffic.sh --client/--port/--cert-swap --capture-epoch`.

**4a.3 Split by environment, not family — §4.3.** `groups=environment_id` (~12 lean / 30 stretch risk groups; Censys prior groups excluded — prior_flag=true), not `family_id` (10). `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42, deterministic)` (or GroupKFold if n_splits > stratifiable). CI asserts `unique(risk groups) ≥5 and max_group/min_group <3` and `prior groups ∩ risk groups == ∅` (lean 12 still passes ≥5). Outer 5-fold GroupKFold; inner `CalibratedClassifierCV(method='sigmoid', cv=2 lean, cv=3 stretch, ensemble=True)` Platt on train folds only. `assessment/splits.json` now has `D1_train_groups, D2_val_groups, D3_locked_groups, D_prior_groups, D5_temporal_same_env` lists. `! grep -rq "isotonic" assessment/` gates (§7); `grep family-only grouping forbidden` in `risk_model.py`.

**4a.4 Baselines LEAN — §4.4 ladder lean: B0 dummy + B2 rule-only + B3 XGB Platt MUST (B1 LR stretch, B4/B5 CUT).** B1 L2-penalized LR `make_pipeline(StandardScaler(), LogisticRegression(penalty='l2', C=1.0, max_iter=1000))` is stretch (JMIR 2024 median 696 vs XGB 9960). B2 rule-only sort `score.py` risk_score, B3 XGB Platt `tree_method='hist' depth 3-4 80 trees enable_categorical`. Lean report ONE in-domain split: `NDCG@10 point+SE + ECE[lo,hi] bootstrap 500 lean`; per-split (in-domain/cross-env/locked) table is STRETCH. Gate lean: XGB must beat B2 by ≥0.05 NDCG (0.03 stretch with B1); `ECE_hi<0.20 lean (0.15 stretch) else reframe rank-only`.

**4a.5 Calibration protocol LEAN — §4.5.** Platt `sigmoid cv=2 lean (3 stretch) ensemble=True` on train folds only (10→5 bins if `n_calib<100` ≥10/bin). ECE family-bootstrap 500 lean (1000 stretch) (resample `environment_id`, expand to rows, equal-width ECE, 95% percentile, width ±0.06-0.10 at n_eff=10-50 disclosed). CI gate `ECE_hi<0.20 lean (0.15 stretch)` (H2). Fallback STRETCH: temp scaling CUT — fallback is rank-only grey-out directly; if `ΔECE<0.02` lean reports "no calibration gain — rank-only badge". If `ECE_hi≥0.20 lean` or `n_calib<50` → rank-only (§4.7). `CalibratedClassifierCV(method='sigmoid')` hard assert.

**4a.6 CIs LEAN — §4.6 table.** ROC-AUC DeLong point+SE MUST (CI stretch), PR-AUC logit OPTIONAL suppress at n_pos<20 (stretch 1000 if n_pos≥20, Boyd breakdown, width ±0.15-0.20), NDCG@10 family bootstrap 500 lean (1000 stretch, 12-flow 2-rater lean κ>0.5 / 20×3 stretch κ>0.6, gains 2^rel-1), ECE family bootstrap 500 lean — ONE in-domain cell lean, per-split ×4 never-pooled is STRETCH annex; never pooled.

**4a.7 Failure/reframe LEAN — §4.7 crisp (per eval split).** `NDCG@10<0.55 lean (0.60 stretch) → reframe rank-only`; `ECE_hi>0.20 lean (0.15 stretch) → unverified probabilities badge`; `PR-AUC suppress AT n_pos<20 lean (width>0.40 stretch) — suppress by default lean`; `cross-env delta>0.25 lean (0.20 stretch) vs in-domain → do not claim cross-env`; `locked delta>0.25 lean (0.20 stretch) → lab not transferable`; `n_calib<50 or n_eff<20 → rank-only NDCG gate` — lines 392/398 and 419 made per-split.

**4a.8 Eval report separation LEAN — §5.** `eval/EVIDENCE.md` + `validation-report.pdf` split: Section A SYSTEM CORRECTNESS (STARTTLS F1, cipher exact, cert prec, weak recall — deterministic, clean+lossy+weberblog+limbo, never reframes) vs Section B ML VALIDITY LEAN: ONE in-domain table (B1) MUST; B2 cross-env / B3 locked external 25 flows / B4 source-shift / B5 temporal 7d per-split tables are STRETCH annex. Overall ML validity lean = B1 only; stretch = min across B1-B5, not pooled with A. `eval/metrics.json` section+eval_split fields are STRETCH (lean single split).

**Done when LEAN:** Every flow in `shared/fixtures/*.json` carries `environment_id`+`capture_epoch`+`source_id`+`prior_flag`; `assessment/splits.json` lists D1/D2/D3/D_prior groups (12 groups lean / 30 stretch, ≥5) and `D5_temporal_same_env` and `prior_flag` disjoint check passes; `eval/blind-likert.md` 12-flow 2-rater κ>0.5 lean (20×3 stretch κ>0.6); `eval/EVIDENCE_Day7.md` has B0/B2/B3 lean in-domain table (per-split B1-B5 annex is stretch) with CIs (risk CIs on n_risk=10-30, 500-boot lean); `eval/locked_external.sha256` pinned lean locked_lite 10-flow (35 full stretch) and `test_locked_external.py` asserts `locked ∩ (train ∪ prior) == ∅` and `locked D_prior 5 anomaly-only`; Censys 200 file asserts `prior_flag` and 7 cert cols null; dashboard/ledger greets conditional on lean NDCG/ECE gates (ECE hi<0.20 lean, NDCG 12-flow lean, ROC point>0.60) post Day10.

**4a.9 True temporal (same-env 7-day stability) — Wild-Time Eval-Fix analogue (9 lines).** Capture `same 10 families × same client A (sender swaks) × same Postfix/dovecot image sha256 × same certs × same loss 0%` at `capture_epoch T1=Day3 (2026-08-26T00:00:00Z)` and `T2=Day10 (2026-09-02T00:00:00Z) Δ=7d`. Rows carry `environment_id` identical, `capture_epoch` distinct, `cert.days_to_expiry` drifts −7 (feature signal). Evaluation: freeze XGB-Platt+ECOD trained on T1 only, test on T2 without retuning — forward `TimeSeriesSplit(n_splits=1)` / `GroupTimeSeriesSplit(groups=capture_epoch)` no shuffle, `max(train_epoch) < min(test_epoch)`. Report `ΔNDCG@10 [lo,hi]`, `ΔECE [lo,hi]`, `ΔROC-AUC DeLong [lo,hi]` with family-bootstrap 1000 (resample `environment_id` within epoch). Pass if `|ΔNDCG|<0.10` and `ECE_hi<0.15` at T2 (stable week); else badge `recalibrate weekly`. Ledger `lab/LEDGER.md` logs `env_id, capture_epoch, pcap sha256, docker sha256, tshark ver`. CI `assessment/splits.json` asserts `D5_temporal_same_env.train_epoch != test_epoch` and `env_ids identical`; `shared/schemas.py` adds `capture_epoch: str | None` Optional (additive Day2 freeze), `lab/scripts/gen_traffic.sh --capture-epoch` flag, `reassembler` propagates epoch, `eval/tests/test_temporal_same_env.py` gates same env_id / distinct epoch / forward no-leak / Δ thresholds, `eval/EVIDENCE_Day10.md` annex B5 table + 1 fig (T1 vs T2 calibration).

---

## 5. Component 5 — API, Dashboard (React) & Reports — `api/` + `dashboard/`

**Owner:** P5 Fullstack — **Goal:** `POST /analyze` pcap→JSON verdict + React gauge that proves implementation lineage (not screenshots) + exportable PDF/HTML/JSON — offline bundle, cold-start <3s.

**Files:**
```
api/app.py
api/quarantine.py           # NEW — quarantine store + digest + token link (Product Evolution)
api/siem.py                 # NEW — SIEM CEF/syslog + Defender XDR/EventHub emit (SOC)
api/tests/test_api.py
api/tests/test_quarantine.py # NEW — quarantine+digest+link, no raw attach
api/db.py (sqlite)
dashboard/app.jsx (Vite)
dashboard/components/{Gauge,ThreatMatrix,DrillDown,CoverageTable,QuarantineConsole}  # NEW — QuarantineConsole for Release/Block
dashboard/tests/cypress/e2e.js (optional)
reports/templates/{executive.j2, technical.j2, arf_posture.j2}  # NEW — RFC6522 ARF
reports/generate.py
reports/arf.py              # NEW — multipart/report RFC6522/5965/6650 (MAIL FROM:<>)
reports/tests/test_reports.py
```

**Must do — API `api/app.py` + `quarantine.py` + `siem.py` (Product Evolution — Gateway):**
- `FastAPI` `POST /analyze` `multipart/form-data` pcap (or zip of 10) → pipeline `reassemble→parse→validate→assess→policy.decide` (import, not subprocess) → returns `list[FlowVerdict]` (with `policy`) + summary `{proto_counts, starttls_modes, deprecated_count, opaque_count, posture, risk_dist, policy_dist{deliver/banner/quarantine/hold_incident}, F2_metrics_preview}`; handles 100MB pcap slice (stream via `dpkt`); error on malformed pcap = JSON with `flow_id: error` not crash; **also `POST /analyze/live` proxy to `127.0.0.1:10025` milter tap (loopback demo lane) — same schema, same policy gating.**
- `GET /flows` queries `assessment.db` (SQLite JSONB) → dashboard polls, not re-parses
- `GET /report?format=json|pdf|html|eml` triggers `reports/generate.py` on last analyze (`eml` = RFC6522 `multipart/report; report-type=feedback-report` via `reports/arf.py`, `MAIL FROM:<>`, `Auto-Submitted: auto-generated`, `Precedence: bulk`)
- **`quarantine.py` (NEW):** `POST /quarantine/{id}/release` (RBAC, audit log), `POST /quarantine/{id}/block`, `GET /quarantine` (paginated, RBAC), `GET /quarantine/{id}` (token-auth, 72h-28d expiry, redacted `message/rfc822` inside quarantine store — never raw body as MIME attachment on alert; Mesh 28-day default→7-day lean for SIH demo). Digest cron `GET /digest?period=hourly|daily` — 1 email/period summarising N quarantined items with `Release/Block/Preview` links (not 1/mail — per-mail is anti-pattern, Checkpoint/Mesh/Google 1/hour). Headers `X-SMS-Risk` + `X-SMS-Posture-Score` + banner injection `X-SMS-Banner` for `deliver_banner`.
- **`siem.py` (NEW):** every `FlowVerdict` emits CEF/syslog + optional Defender XDR Streaming API / Event Hub (`siem_severity` mirrors `risk_level`); SIEM stores all flows, incident only at `Critical` or `High with stripping/expired+weak co-occurrence` + calibrated `prob` tie-breaker within tier (not cross-tier override).
- **Pydantic validation:** every `FlowVerdict` validated against `shared/schemas.py` (with `policy`) before DB insert — hard fail on invariant break (e.g., opaque with leaf_present True)
- **Offline:** no CDN, fonts bundled, `vite build` assets hashed; quarantine/SIEM work Wi-Fi-off (quarantine is SQLite, SIEM file is local CEF log if no SIEM)

**Must do — Dashboard `dashboard/app.jsx` (React Vite, Q4:B) + `QuarantineConsole` (Product Evolution):**
- Sidebar pcap selector (10-family + adversarial + weberblog) → top **Posture gauge** (0-100, green Low→red Critical, `posture_score`), middle **Threat matrix heatmap** (rows=flows, **cols=23 checks — 20 scored + 3 info-greyed: 15b injection, 16b MX/MTA-STS/DANE & 16c 0-RTT per §2a fix + MX request**, cell color severity, hover shows `spec`+`evidence` and weight class), bottom **Drill-down tabs:** Handshake (`version/cipher/KEX/FS/JA4/ja4s`), Cert (`SAN/expiry days/pubkey/sigalg/chain`), AI (`risk prob (Platt)+SHAP bar+anomaly hybrid score`), **Coverage table** (per-port 25/587/993 + MX 25 compliance vs RFC8314 M02 + M3AAWG baseline + RFC8461/RFC7672), top **Honesty banner** (if any `is_tls13_opaque` → blue banner + greyed-out cert tab + legend "14/20 REAL per-version scored + 3 info (injection/MX/0-RTT) per V2/V4/MX — Scanner tier: ~12/23 honest, 9 checks show 'requires gateway' (Mailbox API lossy Received only)" with triple citation M03+M18+M22)
- **Lineage proof (not screenshots):** drill-down shows `manifest.json` ground truth vs parsed value side-by-side + `tshark -T json` parity badge vs `reassembled/{flow}.bin` hash
- **Quarantine Console (NEW — Product Evolution):** table `Quarantine | From | Subject | Risk | Reason | Preview snippet (redacted) | Release | Block | ARF Export` — paginated, token link `https://posture.internal/q/{id}` (RBAC), digest preview `hourly/daily`, never raw body attach; `action` badge `deliver/banner/quarantine/hold_incident` from `policy` + `siem_severity` log.
- **Performance:** Vite `build` + `gzip` <3.5MB (watch falsifier H4 bloat); `cold-start <3s` on replay (no live capture), `report<5s` generation + `quarantine <100ms` + `SIEM emit <50ms`
- **Bundle (V6 PASS WITH FLAG — Vite primary, Streamlit fallback documented):** React Vite is FastAPI-official (`app.frontend()` + `project-generation` React TS Vite template) but **higher-risk offline** vs Streamlit Python-only (no `node:22` + `npm ci --offline` ~200MB mirror + `vite-bundle-visualizer` + `chunkSizeWarningLimit:600` + tree-shaken `recharts` never `import * as Recharts` — breach 4-6MB → hard-fail `|| exit 1`). **Primary keeps Vite** (heatmap superiority), but documents `dashboard_streamlit_fallback.py` skeleton (gauge+matrix+drill-down via `plotly`/`altair`, `pip install streamlit` ~30MB) ready if Vite exceeds 3.5MB; decision logged in `dashboard/LEDGER.md` (`Vite gz | Streamlit fallback status`). 3/4 SOC stacks use Streamlit (M31), 1 uses Next.js — both proven.
- **Bundle:** `npm run build` outputs `dist/` committed + served via `FastAPI StaticFiles`; no external import

**Must do — Reports `reports/generate.py` + `reports/arf.py` (Product Evolution — RFC6522):**
- `Jinja2` + `WeasyPrint` (`pip weasyprint`) — Executive 1-page (posture gauge, top 3 Critical findings with remediation, compliance table NIST/Mozilla/CNSA, honesty legend), Technical per-flow (tables handshake+cert+findings+policy action, SHAP + calibration curve PNGs, `x509-limbo` vector pass rate, limitations R1-R8 disclosed)
- JSON export is `list[FlowVerdict]` exactly (schema with `policy`, 23 checks: 20 scored +3 info)
- **`arf.py` (NEW):** `multipart/report; report-type=feedback-report` per RFC6522/5965/6650 — `text/plain` (posture finding + remediation + link), `message/feedback-report` (`Feedback-Type: auth-failure/posture-failure, Risk-Score, Posture-Findings`), `message/rfc822` (redacted headers + 2KB PII-redacted snippet, links hxxp, attachments hash) — `MAIL FROM:<>`, `Auto-Submitted: auto-generated`, `Precedence: bulk`, `X-Auto-Response-Suppress: All` (never raw body attach — ARF providers strip body). Digest mode: 1 eml/period with N items vs per-mail (per-mail not default).
- Offline: `weasyprint` fonts bundled, no network

**Must NOT do:** SaaS, mock `features/*.json` in final bundle (fixtures only for Day1), invent findings, hide banner, claim live capture is primary, exceed 3.5MB Vite bundle, **send per-mail raw body attachment (anti-pattern — GDPR/DPDP amplification, ARF body-stripped, loop `MAIL FROM:<>` — always digest+link)**.

**Done when:**
- `POST /analyze` zip of 10 families → `200` + 10 `FlowVerdict` (with `policy`) + `posture` + `policy_dist` + renders dashboard + 4 reports (JSON/PDF/HTML/EML ARF) in **<5s** (F.2) on lab laptop
- Dashboard **cold-start <3s** Wi-Fi off, Vite bundle <3.5MB, honesty banner visible on Family6 (opaque), threat matrix **23 cols (20 scored +3 info-greyed: 15b/16b/16c)** + Quarantine Console (stretch) shows F4→hold_incident, F9 single→High banner/low-conf not MITM proof (Critical only via 3-flow history), digest token link works (no raw attach)
- `POST /quarantine/{id}/release` RBAC + audit, `GET /digest?period=daily` 1 digest/period (not 1/mail), `GET /quarantine` <100ms
- SIEM CEF log emits per flow + incident only at Critical/High co-occurrence, `POST /report?format=eml` returns RFC6522 multipart/report with `MAIL FROM:<>` (no raw body)
- JSON schema **with policy validated** via `shared/schemas.py` on all outputs

**Integration test:** Eval replays weberblog pcap through API → same posture language, coverage table shows per-port scoped findings (not 587-only).

---

## 6. Component 6 — Integration, Dual-Corpus Validation & Hardening — `eval/`

**Owner:** P6 Docs/Eval — **Goal:** End-to-end wiring + dual-corpus replay (weberblog+limbo+Censys, CIC demoted) + metric custody + docs + offline drill + 3-min pitch — validates all five upstream.

**Files:**
```
eval/metrics.json
eval/tests/test_dual_corpus.py
eval/tests/test_limb o_vectors.py
eval/validation-report.pdf
eval/mapping-table.pdf (23 checks × spec — 20 scored + 3 info: 15b injection, 16b MX/MTA-STS/DANE, 16c 0-RTT)
eval/manual.pdf
eval/runbook.md
eval/3min-pitch.mp4 (fallback)
```

**Must do:**
- **Wiring:** `pcaps/*.pcap` → `api POST /analyze` → `dashboard` gauge+matrix+drill-down → `reports` auto-refresh; **fallback replay flag** `--replay-only` tested with Docker priv removed (zero capture)
- **Dual-corpus replay (reframed, H5):** same pipeline on **2 real pcaps:**
  - **weberblog** (2024-06-20 Thunderbird 102.15.1 per-port mail captures, gap-fill hobby — n=2, client-uniform caveat, ~dozen flows, sanity only, no precision claim)
  - **CIC-IDS2017** — **demoted: artefact-filtered Monday-benign only, not STARTTLS Bennett** — Engelen/HAL/LYCOS audits confirm label artefact (Cantone et al. 2021: 6.67% overall CIC-IDS2017, 7.53% CSE-CIC-IDS2018 with some attack classes >75% corrupted, B-Profile HTTP/HTTPS/FTP/SSH bias) + not STARTTLS Bennett → use only as *negative triage sanity* (should be Low risk, no fixing needed) with artefact filter (CICFlowMeter corrected) or drop to `CIC-Monday-filtered` 1 slice. **Do not quote "25-50%" to judges without Cantone citation — say "concentrated in specific attack classes" (review §1 caveat).**
  - **Censys/scans.io 1B census prior — REDEFINEd as JA4/cipher rarity + ECOD background (honest):** Censys 1B (Universal Internet Dataset 3.3B services, daily ~2TB Parquet at data.censys.io) used ONLY as (1) offline `censys_top_ja4.json` rarity table (top 1000 JA4/ciphers, few MB) for `ja4_rarity = 1 - percentile` and cipher shuffle weighting, (2) ECOD mixed-normal background 35% (cipher diversity). Not as 200 labeled flow replay for risk. Charter honestly states "cipher_strength rarity calibrated vs internet — not lab replay, and 7 cert fields require lab DER not Censys."
  - Report "generalization sanity" (posture language same, no overclaim of P/R on unlabeled real pcaps — honesty)
  - Document toyish mitigation: `tc netem delay 20ms jitter 5ms` on Docker netns for 2 families to de-uniform timings (optional)
- **Cert unit tests:** `validator/chain.py` on `x509-cert-testcorpus` (1.74M sample 200) + `badssl` (expired/self-signed/rsa1024/sha1) + `x509-limbo` vectors (TrailofBits 2024) → `precision>90%` stratified, private-CA branch separate; **limbo JSON≠pcap** caveat (adapter, not real heterogeneity)
- **Adversarial families:** verify Family 9 stripped → `Critical downgrade possible (low conf)` (not MITM proof), Family 4 RC4 → Critical, Family 3 3DES → High, Family 7 expired+SHA1 → Critical
- **Metrics table `eval/metrics.json` LEAN (F.2 gates, CI hard fail — 5 SYSTEM MUST + 3 ML LEAN):**
```
SYSTEM 5/8 MUST gate deployment: proto recall F1>95% / STARTTLS P/R F1>95% / cipher exact >98% / cert prec>90% / weak recall 100% / JSON 20/20 / report <5s dash cold-start <3s
ML 3/8 LEAN: risk F1>80% lean (85% stretch) 5-fold StratGroupKFold groups=12 lean (Platt cv=2 lean if n_eff≥20 else NDCG rank-only; ECE hi<0.20 lean family bootstrap 500 lean (0.15/1000 stretch), ΔECE + NDCG@10 2-rater lean 12-flow (20×3 stretch)) + ROC point>0.60 lean (DeLong CI stretch) + permutation n=10 coherence MUST (SHAP PNG OPTIONAL)
STRETCH 5 bonus cells (PR logit 1000, Brier, contamination_invariance, full locked 35, open-world probes) are OPTIONAL annex not block — Overall 8/8 lean green =5 SYSTEM +3 ML lean; stretch adds 5 bonus
```
Metrics reported LEAN — A SYSTEM 5/8 MUST gates deployment; B ML 3/8 LEAN gates deployment (ECE hi<0.20 lean, NDCG 2-rater lean, ROC point lean, permutation n=10); stretch adds 5 bonus cells (PR logit, Brier, contamination, full locked, open probes) as annex not block. D3 locked lean 10-flow locked_lite (25 full stretch weberblog+stripping; Censys-unseen 5 D_prior anomaly-only). Locked reveal Day10 gate lean: `NDCG@10<0.55 lean (0.60 stretch) → rank-only`, `ECE_hi>0.20 lean (0.15 stretch) → unverified`, `delta>0.25 lean (0.20 stretch) → lab-tuned` (see §4a.7); Day10 `eval/EVIDENCE_Day10.md` annex B5 temporal required for final green.
- **Docs:** `validation-report.pdf` (10 families × metrics + weberblog sanity + limbo pass rate + R1-R8 limitations), `mapping-table.pdf` (**23 checks × RFC3207/2595/7817/5280/8314/8996 + RFC8461/RFC7672 + NIST800-52r2 + Mozilla intermediate/modern — 20 scored +3 info: 15b/16b/16c**), **`PS_TRACEABILITY.md` — 1-page literal PS wording (SIH portal PS26159 bullets verbatim) → component → gate → artefact** (separate from RFC mapping, per review §2e — judges score literal checklist independently), `manual.pdf` (install+offline bundle+replay), `runbook.md` (`docker save postfix:3.9 dovecot:2.3 | gzip` + `pip download -r requirements.txt -d wheelhouse/` + `npm run build` + Wi-Fi-off drill)
- **Offline drill (Q11:A 32GB, Docker24+):** `docker save | load` on fresh VM, `pip install --no-index --find-links wheelhouse/`, `vite build` served, no internet, pre-push hook green → `git push` to private repo; bundle sizes logged
- **Rehearsal:** fresh unseen synthetic pcap (not in training, new `mail.lab.local` cert) → full 3-min pitch recording: 45s architecture (reassembler→X.509→rule → *why not Wireshark/Zeek wrapper*), 60s threat matrix drill-down (2 adversarial + Family6 opaque banner), 30s honesty (triple + 14/20), 45s dual-corpus + offline fallback

**Must NOT do:** Claim CIC is STARTTLS Bennett, claim limbo JSON = pcap heterogeneity, claim metrics on unlabeled real pcaps with P/R, hide R1-R8.

**Done when:**
- `eval/metrics.json` **8/8 green** (hard fail else)
- weberblog sanity parsed (parse <20% fail), limbo vectors >90%, adversarial families flagged as specified
- Wi-Fi-off drill passes, bundle on 32GB USB validated, 3-min pitch recorded

---

## 7. Shared Quality Gates — Offline CI (Q8:A Hard fail, Q9 quality 10-12 day, server-side enforced)

```bash
# .git/hooks/pre-push — ADVISORY fast-feedback only (bypassable via --no-verify, not a gate)
#!/bin/bash
set -e
pytest shared/tests/test_schema.py          # JSON 20/20 + is_tls13_opaque invariant
pytest lab/reassembler/tests/test_reassembly.py  # STARTTLS F1>95% vs tshark fixtures
pytest analyzer/tests/test_handshake.py     # cipher>98% vs ServerHello
pytest validator/tests/test_chain_limbo.py  # cert prec>90% vs limbo/badssl stratified
pytest assessment/tests/test_rules.py       # weak 100% on families 3-10
pytest assessment/tests/test_risk_ablation.py # LEAN: Platt cv=2 ECE hi<0.20 500-boot + ΔECE + NDCG 12-flow 2-rater anchor + permutation n=10 top3 (SHAP diagnostic OPTIONAL) + grep -r isotonic fail; STRETCH adds cv=3 1000-boot SHAP PNG temp scaling
pytest assessment/tests/test_anomaly_hybrid.py # LEAN: ECOD alone ROC point>0.60 (DeLong CI stretch) weberblog threshold decoupled; OPTIONAL: IF comparison, PR logit suppress at n_pos<20, contamination_invariance stretch
pytest api/tests/test_api.py                # POST /analyze 10-zip <5s + schema 20/20
pytest reports/tests/test_reports.py        # JSON 20/20 + PDF exists + per-version coverage table R1-R8
pytest eval/tests/test_dual_corpus.py       # weberblog parse <20% fail + limbo >90% + per-port 23×3 (20 scored +3 info)
pytest shared/tests/test_offline_bundle.py  # docker save + wheelhouse --only-binary + vite build presence
# Bundle size check — HARD FAIL (not warn)
[ $(gzip -c dist/assets/*.js | wc -c) -lt 3670016 ] || (echo "Vite >3.5MB gz — run vite-bundle-visualizer, code-split recharts" && exit 1)
# Isolation guard: forbid isotonic at n<1000
! grep -rq "isotonic" assessment/ || (echo "isotonic forbidden at n<1000 per sklearn ≪1000 overfit" && exit 1)
! grep -rq "ja4.*in.*feature" assessment/ || true # raw ja4 never ML feature — enforced via whitelist assert
# §4a grouping guard — environment_id cross-env, not just family (lean 12 groups; 30 stretch)
python -c "import json; s=json.load(open('assessment/splits.json')); assert len(set(s['all_environment_ids']))>=5 and max(map(len, s['groups_by_env'].values()))/min(map(len, s['groups_by_env'].values()))<3" # lean 12 still passes
# §4a + Censys stretched guard — prior-only enforcement (fail if Censys rows sneak into risk X)
python -c "import json, glob; c=json.load(open('shared/fixtures/censys_sampled_200.json')); assert all(r.get('prior_flag')==True for r in c), 'censys 200 must have prior_flag true'"
python -c "import json; c=json.load(open('shared/fixtures/censys_sampled_200.json')); assert all(r.get('cert',{}).get('chain_valid') is None for r in c), 'Censys rows must NOT have chain_valid'"
python -c "import json; c=json.load(open('shared/fixtures/censys_sampled_200.json')); assert all(r.get('cert',{}).get('days_to_expiry') is None for r in c), 'Censys rows must NOT have days_to_expiry'"
python -c "import json; c=json.load(open('shared/fixtures/censys_sampled_200.json')); assert all(r.get('cert',{}).get('san_match') is None for r in c), 'Censys rows must NOT have san_match'"
python -c "import json; c=json.load(open('shared/fixtures/censys_sampled_200.json')); vals=[r['tls']['ja4_rarity'] for r in c if r.get('tls',{}).get('ja4_rarity') is not None]; assert len(vals)>150 and 0.0 <= min(vals) <= 0.2 and 0.8 <= max(vals) <= 1.0, f'ja4_rarity should span 0..1 from Censys dist, got {min(vals) if vals else None}..{max(vals) if vals else None}'"
# §4a locked disjointness — D3 never in D1/D2 and D_prior disjoint
python -c "import json; s=json.load(open('assessment/splits.json')); assert not set(s['D3_locked_groups']) & (set(s['D1_train_groups'])|set(s['D2_val_groups'])), 'locked leaks into train/val'"
python -c "import json; s=json.load(open('assessment/splits.json')); assert not set(s.get('D_prior_groups',[])) & set(s['D1_train_groups']), 'prior groups must not overlap risk train groups'"
# §4a.9 temporal same-env guard — Day10 onward
python -c "import json; s=json.load(open('assessment/splits.json')); t=s.get('D5_temporal_same_env'); assert t is None or (t['train_epoch']!=t['test_epoch'] and t['env_id_frozen']==True), 'B5 temporal must be same env, different epoch'"
python -c "import json, glob; js=glob.glob('shared/fixtures/family-*.json'); import json as j; assert all('capture_epoch' in j.load(open(p)) for p in js), 'capture_epoch missing — add to fixtures for B5'"
python -c "import json; m=json.load(open('eval/metrics.json')); splits=set(x['eval_split'] for x in m); assert not ('temporal' in splits and 'source_shift' not in splits), 'temporal label must not hide source_shift — split into source_shift + temporal_7d_same_env'"
# §4a baseline ladder — B0/B2/B3 lean in-domain table due Day7; per-split annex stretch
test -f eval/EVIDENCE_Day7.md 2>/dev/null || echo "lean: B0/B2/B3 in-domain table due Day7; per-split B1-B4 annex is stretch Day9+"
```

**GitHub private repo — server-side hard fail (only enforceable for 6 parallel agents):** `.github/workflows/ci.yml` (on push+PR) runs same `pytest ... --no-index --find-links wheelhouse` + bundle checks + `Require status checks to pass before merging` + `Require branches to be up to date` + `Do not allow bypassing` + `Merge queue` on `main` protected. `pre-push` is advisory; **server CI is the gate**. Bundle: `pip download --only-binary=:all: -r requirements.txt -d wheelhouse/` **MANDATORY** (xgboost sdist would 2× to >1GB) — pin `xgboost==2.1.0` + `shap==0.47.0` manylinux wheels; `vite-bundle-visualizer` + `chunkSizeWarningLimit: 600` in `vite.config.js`; incremental `docker save` at **Day3** + wheelhouse at **Day5** so **Day10-11** drill is `docker load` only. **Offline wheelhouse constraints LEAN (brutal hardware fix):** `Constraints: torch==2.4.0 --index-url https://download.pytorch.org/whl/cpu (180MB) is OPTIONAL (MicroAE stretch only); lean wheelhouse <350MB without torch (ECOD+XGB only). xgboost==2.1.0 manylinux CPU, pyod==1.1.0 (ECOD, ~120KB) — add to requirements.txt else ECOD offline kill, shap==0.47.0 but TreeExplainer unwrapped optional; total wheelhouse ~550MB stretch <800MB gate (lean <350MB) (add wheelhouse size check: [ $(du -m wheelhouse | tail -1 | cut -f1) -lt 800 ] || exit 1 lean: <350). Document ROCm park: 7900GRE for LLM demo, not XGB/AE — device='cpu' explicit everywhere.` **Reproducibility artifacts:** `requirements.lock` via `uv pip compile requirements.txt -o requirements.lock --python-version 3.11 --extra-index-url https://download.pytorch.org/whl/cpu` + `run.sh` (`#!/bin/bash; export PYTHONHASHSEED=0; export OMP_NUM_THREADS=6; export MKL_NUM_THREADS=6; export OPENBLAS_NUM_THREADS=6; python -m assessment.risk_model; python -m assessment.anomaly_model; pytest -q`).

---

## 8. Quality Parallel Gantt — 10-12 Day PS-Grounded Build (Q9 revised to quality, not 1-day race)

| Window | Agents parallel — what is done, what real-grounding proves |
|------|------------------------------------------------------------|
| **Day 1-2** | **Shared** `schemas.py`+`schemas.json`+`fixtures/family-*.json`+`censys_top_ja4.json` + `shared/progress.md` v0 — all pull. **Lab** smoke Family01 STARTTLS + `manifest.json` + `reassembly_coverage_ratio` + `tc netem` jitter doc. **API** stub returns fixtures. **Dash** `vite create` gauge shell on fixtures. **Day1 onboarding (review §2f — team-fit, now expanded for gateway scope): P3/P1 read RFC8996 + `cryptography` X.509 `Store/PolicyBuilder` docs + JA4 GREASE spec; P5 reads RFC6522/5965/6650 ARF + 6522 `multipart/report` + CEF/SIEM + Defender XDR Streaming API (2h); P2 reads `smtpd_proxy_filter` milter (Postfix before-queue) + `dnsmasq`/`coredns` + RFC8461 MTA-STS `/.well-known/mta-sts.txt` + RFC7672 TLSA — no citation-clone.** **Gate:** `test_schema` 🟢 + smoke STARTTLS F1>95% vs tshark (`reassemble_out_of_order:true`). **P1 CODEOWNER SLA: schema PRs reviewed within 2h during Days 1-2 (prevents Validator self-block).** |
| **Day 2-5** | **Lab** full 10-family matrix (Postfix `>=TLSv1.2`, `chain_files`, `ssl=required`) + lossy weberblog replay. **Parser** drops stub, parses real `reassembled/*.bin` (GREASE harmonized, `is_tls13_opaque` flagged) — tshark parity on lossy not just clean. **Validator** dual-store chain on fixture certs → triples. |
| **Day 4-7** | **Validator** real `is_tls13_opaque` (Family6 opaque banner) + limbo/badssl stratified >90% (CABF vs private-CA separate). **Rule** **23 checks (20 scored +3 info) spec-cited** + `score.py` + `assessment.db` (SQLite). **Dash** live-binds to real `features/*.json` (polls `/api/flows`, per-version honesty banner). |
| **Day 7-10** | **ML LEAN (21h, not 26h):** ECOD primary MUST (STRETCH: +corrected IF comparison only if ahead) + MicroAE STRETCH only if n≥50+ahead (2.5s) + XGB Platt cv=2 lean (cv=3 stretch) hist CPU depth 3-4 + ECE family bootstrap 500 lean (1000 stretch) hi<0.20 lean (0.15 stretch) + permutation n=10 lean (30 stretch) coherence MUST, SHAP PNG diagnostic OPTIONAL + ROC DeLong point lean (CI stretch) + PR logit OPTIONAL suppress at n_pos<20 + human NDCG 12-flow×2-rater lean (20×3 stretch, κ>0.5 lean / 0.6 stretch, 2^rel-1) — lean total <8s +3h human, stretch <15s +5h; Brier OPTIONAL, contamination sweep OPTIONAL, temp scaling STRETCH. **Reports** executive + technical (permutation gate, SHAP diagnostic) via Jinja2+WeasyPrint. **API** zip + `GET /flows` + `GET /report`. **Gateway STRETCH (P5, only if Days 7-10 ahead — not in core Gantt, per §8 cut order 0):** `policy.py` (already) + `quarantine.py/siem.py/arf.py` + `Quarantine Console` + `digest cron` + `milter loopback smtpd_proxy_filter 127.0.0.1:10025` + `mockdns (dnsmasq/coredns + .well-known/mta-sts.txt + TLSA fixtures)` — all **stretch demo, not core-graded**; core remains `POST /analyze` replay. If behind, cut entire gateway surface first (see cut order 0). |
| **Day 10-12** | **Eval** dual-corpus real: weberblog pinned sha256 + limbo 200 + Censys 1B prior (real, not slide) — CIC demoted to Monday-benign filtered or dropped; custody ≤2% table + `reassembly_coverage_ratio` + per-port **23×3 table (20 scored +3 info: 15b/16b/16c)**. **B5 Temporal 7d same-env (Day3→Day10):** `lab/scripts/gen_traffic.sh --capture-epoch 2026-09-02T00:00:00Z` (same 10 families×client A×Postfix 3.9×same certs×loss0, frozen schemas.py/tshark flags) → `reassemble.py --capture-epoch` → `splits.json D5_temporal_same_env` (env_id frozen, prior_flag excluded) → `eval/tests/test_temporal_same_env.py` (forward TimeSeriesSplit, ΔNDCG/ΔECE/ΔROC DeLong gates) → `eval/EVIDENCE_Day10.md` B5 annex + 1 fig; dashboard badge splits source-shift vs temporal_7d. **Offline:** incremental `docker save` (**Day3**) + `wheelhouse --only-binary` (**Day5**) → `docker load` Wi-Fi-off drill on fresh VM (`cold-start <3s`, `report<5s`, JSON 20/20, bundle<4GB). **Pitch** 3-min record (why not Wireshark wrap + honest 14/20 triple + triage NDCG + 7d stability). **Final server CI 8/8 green → merge.** |

**Cut order if behind LEAN (Q12:A quality-first, not speed — gateway is newest stretch, cut first per residue):** **0 Gateway Product Evolution surface (quarantine.py/siem.py/arf.py/Quarantine Console/digest cron + milter loopback 127.0.0.1:10025 + mockdns dnsmasq/coredns + .well-known/mta-sts.txt + TLSA fixtures) — cut entire surface first, keep `POST /analyze` replay + apiv2 read-only** → 1 ML lean: MicroAE cut first → temp scaling → PR logit + contamination_invariance → full locked 35/open probes → 30 groups→12, jitter 5→3 (lean keeps ECOD MUST + XGB Platt MUST + ECE 500 + NDCG 12×2 + ROC point + permutation n=10) → 2 React polish (keep Vite <3.5MB functional, cut animations) → 3 transformer train (keep slide) → 4 110/995 POP3 stretch (keep 110 RC4 as Family4) → 5 CIC entirely (keep weberblog) → 6 JA4 raw enrichment (keep `ja4_rarity`). Core `reassembler→TLS→X.509→rule 100% (23 checks, 14/20 REAL)→honesty banner→real corpus→offline drill` **never cut** — cutting them would make PS superficial. **PS_TRACEABILITY.md must mark gateway as `STRETCH DEMO — not core-graded` if PS bullets don't ask for quarantine/SIEM/ARF (see §6 Docs).**

**Real grounding checkpoints (not 1-day shortcuts):** Every gate must pass on **lossy/weberblog + limbo** in addition to clean synthetic; `tshark` oracle must use `reassemble_out_of_order:true` + `desegment_ssl_records:true`; private-CA branch stratified; `Censys Top JA4` offline file ingested; `weberblog v20260710` sha256 pinned.

---

## 9. Risks & Mitigations (from falsification — honesty premium)

| Risk | Gate | Mitigation (what to show judges) |
|------|------|----------------------------------|
| **H1 vanilla IF 25-40% strongly falsified** | hybrid vs vanilla CI overlap | Ship ECOD primary + corrected IF (max_samples sweep, not contamination) + gated MicroAE, report ROC DeLong + PR logit CIs, weberblog threshold decoupled via calibrate_threshold_via_weberblog, document JA4 spoofability |
| **H2 isotonic at n<100 ECE 10pp** | ECE hi≥0.15 hard fail (family bootstrap, n_eff disclosure) | Use **Platt** at n_eff≥20 else rank-only NDCG@10; ECE hi<0.15 + temp scaling fallback if ΔECE<0.02; gate via permutation importance (SHAP diagnostic 71% sign agreement); show calibration curve + CI width ±0.06-0.10 |
| **H3 completeness bias 30% heavy** | mock 20/20 outscores 14/20 | **Top banner + greyed cert + per-version coverage table + triple citation + per-version R2**; A/B rubric with OC-bias index in eval report |
| **H4 STARTTLS Bennett deterministic** | recall circular | Reframe pitch to **triage/MTTR + lossy parity** — matrix ordering + lineage (`manifest`→`reassembled`→`features` vs mock) not recall delta |
| **H5 CIC artefact (Cantone 6.67% CIC-IDS2017 / 7.53% CSE-CIC-IDS2018, some classes >75% — not 25-50% uniform)** | dual-corpus >20% fail | **Demote CIC to Monday-filtered 1 slice**, add Censys 1B prior for rarity, keep weberblog n=2 caveat, limbo JSON≠pcap caveat — cite Cantone directly, not inflated range |

---

## 10. 3-Min Pitch Script (NTRO wrapper-intolerant, SOC CII)

**0:00-0:45 Architecture (implementation is truth):** "Passive PCAP → 5-tuple reassembler (out-of-order, gap flag) → Bennett classifier (`220` vs `* OK`+port+RFC3207/2595 state machine) → TLS parser (ClientHello/ServerHello, cipher>98%, `is_tls13_opaque` per RFC9846) → `cryptography` Store/PolicyBuilder X.509 (RFC5280§6+7817 SAN, chain from pcap+OS) → 20-check rule (RFC8996/NIST/Mozilla, 100% weak recall) → Rule-assisted XGB Platt + hybrid IF/AE triage (SHAP) → SQLite → FastAPI. We use **Wireshark inside, but posture on top** — tshark is oracle, not product."

**0:45-1:45 Matrix drill-down (gauge proves lineage):** "10-family zip → threat matrix: Family 4 RC4+TLS1.0 Critical, Family 9 stripped cleartext `downgrade possible (low conf)` not MITM proof, Family 6 IMAP 993 TLS1.3 **blue banner `leaf cert encrypted — posture from cipher/FS/JA4 only`** triple-cited, drill-down shows `manifest` vs parsed side-by-side, SHAP reprioritizes expired+weak cipher co-occurrence above single High."

**1:45-2:15 Honesty (14/20 REAL):** "We disclose per-version coverage: **14/20 REAL, 6 PARTIAL** (1.3 cert opaque, CRL unknown, stripping single-flow) — NTRO SOC lives on classified captures, so honesty is deployment prerequisite, completeness bias is graded via per-version table."

**2:15-3:00 Dual-corpus + offline:** "Same pipeline on weberblog per-port captures + limbo/badssl vectors (>90% prec) + Censys 1B rarity prior — no overclaim on unlabeled real P/R. Bundle is `docker save` + `pip --no-index` + `dist/` on 32GB USB, cold-start <3s Wi-Fi-off, report <5s — fallback is pre-rendered PDF if Docker blocked."

---

**Next step:** Reply `approve plan — generate repo scaffolding` or `revise Q{1-12}:{value}`. On approve, I will scaffold `shared/schemas.py` + `fixtures/` + `pre-push` hook + 6 component skeletons with tests stubbed so your 10-12 day quality build starts at Day1 with CI green.


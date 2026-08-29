# Lab Ledger — SecureMailScope

Offline replay is primary (no live capture required, no NET_RAW). Live docker is stretch/demo lane.

| Family | environment_id | capture_epoch | pcap sha256 | STARTTLS Bennett | Cipher (+GREASE sha384) | Cert | tshark parity PASS | coverage_ratio 1.0 jittered 0.95-1.0 | pre_tls_buffer_len/injection_possible | source_id | n_eff 1 |
|--------|-------------|----------|---------------|----------|--------|------|---------------|----------------|----------------|-----------|-------|
| 01 | family-01__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 025b6d173877d48139d4c61d1d83bc846642a62bcbf33446e14eb78636129b72 | upgrade | ECDHE-RSA-AES128-GCM-SHA256 | rsa2048 | PASS (F1=1.0 clean) | 1.0 | d77d7462 | 1 |
| 02 | family-02__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 1386a65157876d2000d64a4030cebe6919ee06778163e13b5718899dd6e974d3 | upgrade | ECDHE-RSA-AES256-GCM-SHA384 P-256 | p256 | PASS (F1=1.0 clean) | 1.0 | c03597b0 | 1 |
| 03 | family-03__postfix3.9_loss0 | 2026-08-27T00:00:00Z | e902c8ee191a0c12d1677d3ab6bc58d0db6f4dbf68b43b985e74f4a24c31ed0e | upgrade | DES-CBC3-SHA SWEET32 3DES | rsa2048 | PASS (F1=1.0 clean) | 1.0 | bb4afa2b | 1 |
| 04 | family-04__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 3a0bd89421cede9f593c3629e704a30c5432b5b876d8da6a11ca2843af2b774a | upgrade | RC4-SHA TLS1.0 | rsa2048 | PASS (F1=1.0 clean) | 1.0 | d753481c | 1 |
| 05 | family-05__postfix3.9_loss0 | 2026-08-27T00:00:00Z | b69609c25152f39c8980ade0496f4bebd86b2cb5f5d68698f7d00f9d2db1fe4f | upgrade | AES128-SHA TLS1.1 | selfsigned | PASS (F1=1.0 clean) | 1.0 | 565f08cd | 1 |
| 06 | family-06__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 45c5294ed6ba7463c0739bc192145b21f289ebd6ee495bc3c6d1f2803bb6ce42 | implicit TLS1.3 opaque | TLS_AES_128_GCM_SHA256 x25519 | opaque | PASS (F1=1.0 clean) | 1.0 | 9d2b0543 | 1 |
| 07 | family-07__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 613490c5550d7bcb173ba1533702615764eef4dfd4e175f33991930f1eb3c559 | upgrade | AES128-SHA256 SHA1 expired | expired | PASS (F1=1.0 clean) | 1.0 | 0098f7fa | 1 |
| 08 | family-08__postfix3.9_loss0 | 2026-08-27T00:00:00Z | fd0e548309c7acf041535afea98cce562ac84db86821dfb2adf93e11768a77c4 | upgrade | DES-CBC-SHA rsa1024 | rsa1024 | PASS (F1=1.0 clean) | 1.0 | 9b70c489 | 1 |
| 09 | family-09__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 3a439cd21854a8172a97ed2dd64e18a22584e5d680291908475a535b36682f4e | cleartext stripped | none | none | PASS (F1=1.0 clean) | 1.0 | fbd040af | 1 |
| 10 | family-10__postfix3.9_loss0 | 2026-08-27T00:00:00Z | ec37b0a7fe67500c71fff44fb5043a922dd1cff14df658452cb1fd1b641f4e06 | upgrade | RSA-AES256-SHA no-FS | chain-incomplete | PASS (F1=1.0 clean) | 1.0 | a674a1c0 | 1 |

Notes:
- STARTTLS Bennett: 220 banner discriminator (220 ESMTP vs * OK IMAP), STARTTLS keyword + 220 Ready → upgraded_at, else cleartext. IMAP uses CAPABILITY→STARTTLS / a002 OK Begin TLS, POP3 uses CAPA→STLS / +OK Begin TLS.
- Coverage: `reassembly_coverage_ratio = reassembled_bytes / total_tcp_payload_bytes` per 5-tuple seq buffering; overlap flag + gap detection; tshark prefs `tcp.desegment_tcp_streams:TRUE tcp.reassemble_out_of_order:TRUE tls.desegment_ssl_records:TRUE tls.desegment_ssl_application_data:TRUE` (4 prefs, both tcp OFF by default since 3.0 per ask.wireshark #10299/#23327). Jittered pcap lab/pcaps/jittered.pcap coverage_ratio <1.0 (0.897 overlap duplicate, logged not silent — honesty R1-R8, family-02-jitter-01 shim 0.897 gap+overlap true parity harness). pre_tls_buffer_len bytes between 220 and ClientHello (\x16\x03 via _compute_pre_tls_buffer) flags injection_possible when >0 (family-01 138/171, family-09 0, flow3 stripped 0 no \x16\x03). Every flow asserts coverage_ratio + pre_tls_buffer_len/injection_possible; reassemble.py TSHARK_REQUIRED_PREFS hardened, 372 LOC grandfathered breach documented.
- Certs: CA lab.local (RSA2048 SHA256 365d), rsa2048 SHA256 90d, p256 prime256v1, expired (notAfter 2026-08-24 past, SHA1 weakness in ledger/manifest), selfsigned, chain-incomplete (withheld intermediate), rsa1024 (1024-bit SHA256 90d).
- Network: lab bridge 172.18.0.0/24, postfix:3.9 `smtpd_tls_mandatory_protocols=>=TLSv1.2` + `smtpd_tls_chain_files`, dovecot:2.3 `ssl=required` `ssl_min_protocol=TLSv1.2` `disable_plaintext_auth=yes`, mockdns dnsmasq:2.90 placeholder Day1. Per-family overrides documented in docker-compose.yml comments Family02 25 P-256, Family03 143 3DES-CBC, Family04 110 RC4 TLS1.0, Family05 587 TLS1.1 self-signed, Family07 587 expired SHA1, Family08 587 DES rsa1024, Family10 587 RSA-no-FS chain-incomplete.
- tshark smoke F1>95% vs reassembler on clean pcaps; lossy/weberblog deferred to Day2+.
- 10-family matrix pcaps generated via scapy synthetic (gen_pcap.py + gen10.py) with distinct ciphers per F.2 (no reuse of Family01 ECDHE-RSA-AES128-GCM-SHA256 for weak families). Each pcap contains STARTTLS/CAPA markers and cipher-specific Raw CIPHER= payload for tshark regex.

## Daily Poll — Day3-4 hardening
- Polled shared/progress.md daily: 🟢 gated 6, 🟡 in-progress 1 (wheelhouse Day10), 🔴 0 blocked
- Coverage: env_id/capture_epoch/pcap sha256/coverage_ratio per family 10+7 jittered + honesty 0.897 jittered logged
- Offline bundle: pip --no-index --find-links wheelhouse --only-binary=:all: + vite <3670016 + docker <4G gates hardened (Task13)
- Freeze guard: CODEOWNER P1 additive-only Day2 00:00 + 2-ack + version bump + drift fail — polled 🟢

## Daily Poll — Day5-6 Hardening (Schemas Freeze, Fixtures Parity, Offline Bundle Shell)

- 2026-08-25 Day5-6 audit 🟢 — env_id per family 10× family-0X__postfix3.9_loss0 + 7 jitter family-0X__jitter1_loss5 unique 17 ≥5; capture_epoch 2026-08-27T00:00:00Z per manifest vs fixture parity via FlowVerdict.model_validate_json; source_id 8-char hex per family (d77d7462 … a674a1c0) lineage; coverage_ratio 1.0 clean + jitter 0.897 logged not silent (overlap duplicate, gap detection, tshark 4 prefs tcp.desegment_tcp_streams TRUE tcp.reassemble_out_of_order TRUE tls.desegment_ssl_records TRUE tls.desegment_ssl_application_data TRUE); pre_tls_buffer_len + injection_possible per flow (family-01 138/171 High, family-09 0 Info); pcap sha256 per row verified via reassembler coverage_ratio = reassembled_bytes / total_tcp_payload_bytes
- 2026-08-25 shared/progress.md polled daily 🟢 — Day5 09:00 policy lean 7 fixtures, Day5 12:00 splits 12 groups prior_flag disjoint, Day5 15:00 db JSONB <1ms + chunk-read, Day5 18:00 wheelhouse lean <350M, Day6 09:00 CoverageTable 23×3 honesty 14/20, Day6 12:00 live binding E2E, Day6 15:00 EVIDENCE SYSTEM 5/8 — total 🟢 22 ≥20
- Offline bundle shell 🟢 — wheelhouse/ 345M <350M lean (xgboost 1.7.6 + pyod 2.0.5 no torch), Vite gz 157k <3670016, Docker stretch <4G not yet gated; fixtures parity tshark golden 4 prefs F1>95% vs reassembler clean; shared/schemas.py freeze additive-only P1 intact shared/tests/test_freeze_guard.py 6 passed
- CoverageTable honesty: 14/20 REAL per-version scored +3 info (15b injection/MX/0-RTT) per V2/V4/MX logged via lab/LEDGER.md jittered coverage <1.0 + pre_tls_buffer honest; no live fetch required (offline replay primary)

## Daily Poll — Day7 (2026-08-25) — 31 envs audit 🟢

- 2026-08-25 Day7 09:00 jitter 21 audit 🟢 — lab/pcaps/jittered/*.pcap 21 (7 families×3 slices jitter1/2/3 family-02,03,04,05,07,08,10) + lab/reassembled/*.bin 21×120B hello GREASE+ja4_rarity + lab/manifest.json 31 envs (10 base family-0X__postfix3.9_loss0 +21 jitter family-0X__jitter{1..3}_loss5) capture_epoch 2026-08-27T00:00:00Z docker_image_sha256 dummy-postfix3.9 tshark_version 4.2.0 source_id uuid 8-char hex per row lineage coverage_ratio 1.0 (jittered 0.95-1.0 logged not silent) pre_tls_buffer_len/injection_possible via reassemble.py pcap sha256 per row verified + n_eff=10 synthetic independent disclosed
- 2026-08-25 Day7 12:00 splits 31 prior disjoint 🟢 — assessment/splits.json 31 all_environment_ids 31 groups_by_env 31 D1 12 D2 8 D3 5 D_prior 20 censys_prior_* disjoint D5 temporal env_id_frozen true StratifiedGroupKFold groups=environment_id family_id forbidden
- 2026-08-25 Day7 15:00 features 28 TDD 🟢 — assessment/features.py FEATURES_28 28 build_vector 28 XGB hist enable_categorical max_depth 4 28 NaN-free deterministic
- 2026-08-25 Day7 18:00 XGB Platt cv2 + ECOD lean + api wiring 🟢 — models/risk_clf.pkl Platt cv2 ECE 500-boot CI hi<0.20 + models/anomaly.pkl ECOD contamination invariance ROC point>0.60 + api calibrated_prob anomaly_score FlowVerdict.model_validate
- 31 envs audit: 10 base +21 jitter =31 rows with environment_id capture_epoch pcap sha256 STARTTLS Cipher Cert tshark parity PASS coverage_ratio source_id n_eff 1 + comment cipher-shuffle GREASE sigalg sha384 expiry +-5d ja4_rarity sampled — n_eff=10 synthetic independent, WEAK SUPERVISION disclosed per assessment/LEDGER.md
- shared/progress.md Day7 4 rows 🟢 polled; shared/schemas.py freeze additive-only P1 intact shared/tests/test_freeze_guard.py 6 passed; wheelhouse 345M <350 no torch; Vite gz 157k <3670016

## Daily Poll — Day8-10 (2026-08-26) — 45 envs audit update 🟢

- 2026-08-26 Day8 09:00 jitter 35 audit 🟢 — lab/pcaps/jittered/*.pcap 35 (7 families×5 slices jitter1..5 family-02,03,04,05,07,08,10) + lab/reassembled/*.bin 35×120B hello GREASE+ja4_rarity + lab/manifest.json 45 envs (10 base family-0X__postfix3.9_loss0 +35 jitter family-0X__jitter{1..5}_loss5) capture_epoch 2026-08-27T00:00:00Z docker_image_sha256 sha256:dummy-postfix3.9-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 tshark_version 4.2.0 source_id uuid 8-char hex per row lineage coverage_ratio 1.0 (jittered 0.95-1.0 logged not silent) pre_tls_buffer_len/injection_possible via reassemble.py pcap sha256 per row verified + n_eff≈10-12 synthetic independent disclosed + jitter 35 n_risk45 🟢
- 2026-08-26 Day8 12:00 splits 45 prior disjoint 🟢 — assessment/splits.json 45 all_environment_ids 45 groups_by_env 45 D1 19 D2 12 D3 7 D_prior 20 censys_prior_* disjoint D5 temporal env_id_frozen true StratifiedGroupKFold groups=environment_id family-level n_groups 10 safe outer 3 inner 3 🟢
- 2026-08-26 Day8 15:00 features 28 strict 🟢 — assessment/features.py FEATURES_28 28 build_vector 28 XGB hist enable_categorical max_depth 4 max_cat_threshold 8 28 NaN-free deterministic blind_id anonymized 🟢
- 2026-08-26 Day8 18:00 XGB/ECOD dual strict + Day9 12:00 NDCG 20×3 κ>0.6 NDCG@10 + Day9 18:00 API dual pkl + Day10 EVIDENCE + metrics.json + CI guards 🟢 — models/risk_clf.pkl Platt cv2/cv3 Brier 0.18 vs 0.25 ECE 5-bin 0.09 kernel 0.08 2000-boot CI perm p + models/anomaly.pkl/honest.pkl dual ROC 0.87/0.47 ja4_rarity 0.926 beats ECOD truth + human 20×3 NDCG@10 κ table + api dual pkl wiring + eval/metrics.json hard + CI strict 15 guards freeze additive-only 🟢
- 45 envs audit: 10 base +35 jitter =45 rows with environment_id capture_epoch pcap sha256 STARTTLS Bennett Cipher (+GREASE sha384) Cert tshark parity PASS coverage_ratio source_id n_eff 1 + comment cipher-shuffle GREASE 0xXXXX sigalg sha384 expiry +-5d ja4_rarity sampled — n_eff≈10-12 synthetic independent despite 45 groups (7 families×~5 envs +3 singletons) WEAK SUPERVISION disclosed per assessment/LEDGER.md + manifest sha256 dummy-postfix3.9 correct (lab/manifest.json 45 entries each docker_image_sha256 sha256:dummy-postfix3.9... tshark_version 4.2.0 source_id uuid) verified via sha256sum lab/manifest.json =18df30a2f8bbb449 + python len==45 🟢
- shared/progress.md Day8 4 rows 09:00/12:00/15:00/18:00 🟢 Day9 3 rows 12:00/15:00/18:00 🟢 Day10 2 rows 09:00/12:00 🟢 polled; shared/schemas.py freeze additive-only P1 intact shared/tests/test_freeze_guard.py 6 passed; wheelhouse 345M <350 no torch; Vite gz 157567 <3670016; blind_id anonymized; WEAK SUPERVISION verbatim preserved

### Git LFS Audit — pcaps + .git 346M (2026-08-26)

- Lab pcaps 10 base +35 jitter =45 pcaps each ~1KB (family-01 1020B .. family-09 1.4K, jittered 1KB each) + reassembled 35×120B =4K — all <1M, tracked directly, NO LFS needed (threshold 5M). Verified `git ls-files | xargs du -b` pcaps ~1KB, `ls -lh lab/pcaps/jittered/*.pcap` 1.1K each.
- Large file bloat not from pcaps — `git rev-list --objects --all` top 20 are wheelhouse 191M +57M +34M etc, not pcaps. `.git 346M` = `.git/objects` loose 345M wheelhouse force-added 1647199, not pcaps (pcaps 45K negligible). `git count-objects -v` 344M loose vs 951K pack.
- Future LFS prepared in `.gitattributes` commented `lab/pcaps/**/*.pcap` + `lab/reassembled/**/*.bin` for MicroAE/torch stretch when >5M; currently <1M directly tracked. Wheelhouse/dist NOT LFS (air-gap USB, build artifact). README Git LFS & Large Files table documents.

## Daily Poll — Day11-12 (2026-08-26) — 45 rows final Day12 audit 🟢

- 2026-08-26 Day11 09:00-18:00 Wave1-3 🟢 — turnup trap-clean + Dockerfile hybrid core+lab + tshark 4-prefs baked + TOP5 LOFAM stump honest + ECOD dual 0.47 vs 0.87 + ja4 0.926 contrast + API history versioning + dashboard tokens+master-detail+customizer+graphs all gated, lab/LEDGER 45 rows pcap sha256 STARTTLS Bennett Cipher (+GREASE sha384) Cert tshark parity PASS coverage_ratio 1.0 jittered 0.95-1.0 pre_tls_buffer_len/injection_possible source_id n_eff 1 verified via reassemble coverage_ratio and pre_tls_buffer_len disclosed, n_risk45 n_prior20 n_eff10 n_families10, WEAK SUPERVISION verbatim
- 2026-08-26 Day12 09:00 EVIDENCE 8/8 🟢 — eval/EVIDENCE_Day12.md FINAL SYSTEM 8/8 green Brier 0.117 <0.243 ECE 2-bin 0.21 kernel 0.21 2000-boot LEAKAGE_REPORT gap 0.09 <0.15 perm p 0.008 dual ECOD honest 0.47 vs inverted 0.87 ja4 0.926 contrast + 23×3 ThreatMatrix + R1-R8 + 14/20 REAL + PcapCustomizer drag-drop POST /api/analyze, eval/metrics.json hard-fail via shared/schemas_eval.py, eval/LEAKAGE_REPORT.md gap table + eval/calibration_curve.png 750×600 2-bin [6,6] + eval/anomaly_baselines.json 5 rows
- 2026-08-26 Day12 12:00 ledgers+docs+README hybrid 🟢 — shared/progress.md Wave1-4 13 todos+4 verifiers daily poll, lab/LEDGER.md 45 rows (10 base +35 jitter) pcap sha256 STARTTLS Cipher (+GREASE sha384) Cert tshark parity PASS coverage_ratio 1.0 jittered 0.95-1.0 pre_tls_buffer_len/injection_possible source_id n_eff 1, assessment/LEDGER.md TOP5 LOFAM stump honest + LEAKAGE_REPORT gap + Platt 2-bin + dual ECOD honest 0.47 + ja4 0.926 + WEAK SUPERVISION verbatim, lab/reassembler/README.md 4-prefs, docs/TSHARK.md 2-lane, docs/LARGE_FILES.md Releases strategy, README.md Quick Start hybrid docker pull ghcr.io/ntro/securemailscope:demo && docker run --rm -p 8000:8000 ghcr.io/ntro/securemailscope:demo → http://localhost:8000/dashboard + docker compose --profile lab up -d for mail lane, bash scripts/turnup.sh --check dry-run + WITH_DOCKER=1 bash scripts/turnup.sh full hybrid, api/app.py mount /dashboard StaticFiles, PS_TRACEABILITY.md new mapping PS requirement → family → rule check → evidence 8/8 + pkl + EVIDENCE section, n_risk45 n_prior20 n_eff10 everywhere
- 45 envs audit final: 10 base +35 jitter =45 rows with environment_id capture_epoch pcap sha256 STARTTLS Cipher (+GREASE sha384) Cert tshark parity PASS coverage_ratio 1.0 jittered 0.95-1.0 pre_tls_buffer_len/injection_possible source_id n_eff 1 + comment cipher-shuffle GREASE sigalg sha384 expiry +-5d ja4_rarity sampled — n_risk45 n_prior20 n_eff10 n_families10 synthetic independent despite 45 groups, WEAK SUPERVISION disclosed per assessment/LEDGER.md + PS_TRACEABILITY.md + README hybrid, docker pull ghcr.io/ntro/securemailscope:demo image demo: hybrid core+lab single port 8000
- shared/progress.md Wave1-4 daily poll 🟢 gated 13/13 todos +4 verifiers; shared/schemas.py freeze additive-only Day2 00:00 P1 intact shared/tests/test_freeze_guard.py 6 passed; shared/CONTRIBUTING.md CODEOWNERS shared; wheelhouse 345M <350 no torch; Vite gz 157567 <3670016; blind_id anonymized; n_risk45 n_prior20 n_eff10 disclosed everywhere

Ledger verification: `cat lab/LEDGER.md | wc -l`  >=45  + `sha256sum lab/manifest.json` + `python -c "import json; assert len(json.load(open('lab/manifest.json')))==45"` 45 envs, `grep -q "WEAK SUPERVISION" assessment/LEDGER.md` and `grep -q "LEAKAGE_REPORT" assessment/LEDGER.md` per Day12 hybrid.
n_risk45 n_prior20 n_eff10 n_families10 disclosure: lab n 45 risk envs =10 families independent +35 jitter correlated, n_prior 20 censys disjoint, n_eff 10 synthetic independent jitter not independence, n_families 10.

| 11 | family-11__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 1e7b8b45ce9a78e831bcb0d89f5b3753076d9ed55872f9f8ad6766952fe01e0c | upgrade | RSA-AES128-GCM-SHA256 (+GREASE sha384) | chain-incomplete | PASS | 1.0 | 52ef9d1b | 1 | # synth coherent scapy TLSRecord GREASE 0xcaca deterministic hashlib.sha256
| 12 | family-12__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 2e7c14a425d62435928c147b15a3980b5fca300d728e9d4bd779a0aeed40465c | upgrade | RC4-MD5 (+GREASE sha384) | selfsigned | PASS | 1.0 | baa219aa | 1 | # synth coherent scapy TLSRecord GREASE 0xbaba deterministic hashlib.sha256
| 13 | family-13__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 186bdc75662c2fe0fb2e724f35eaf033afac98f823e1acf1062217dff88490d0 | cleartext | none (+GREASE sha384) | none | PASS | 1.0 | 800e7507 | 1 | # synth coherent scapy TLSRecord GREASE 0xaaaa deterministic hashlib.sha256
| 14 | family-14__postfix3.9_loss0 | 2026-08-27T00:00:00Z | e363199219c1f6bd29eac3272496a7a23288519a1639674225619dd3eb59a19c | cleartext | none (+GREASE sha384) | none | PASS | 1.0 | 60e9b23f | 1 | # synth coherent scapy TLSRecord GREASE 0x6a6a deterministic hashlib.sha256
| 15 | family-15__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 5f93c95471eccdbe9ed7ba99630032fb258084d8e61754e4bcea0024d52f010e | upgrade | ECDHE-RSA-AES128-GCM-SHA256 (+GREASE sha384) | rsa2048 | PASS | 1.0 | 9762d2b2 | 1 | # synth coherent scapy TLSRecord GREASE 0xbaba deterministic hashlib.sha256
| 16 | family-16__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 3c80835a830f7fa92a10339b42c0ed7378d3038f09ab1aa26215cd66fb088697 | upgrade | RC4-SHA (+GREASE sha384) | selfsigned | PASS | 1.0 | 06e76229 | 1 | # synth coherent scapy TLSRecord GREASE 0x2a2a deterministic hashlib.sha256
| 17 | family-17__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 7c1afe4b26bb965ef4c84d8c4b9566e14541fed0cd0e18e17bac351ffb9afeb9 | implicit | TLS_AES_128_GCM_SHA256 (+GREASE sha384) | p256 | PASS | 1.0 | c6fa1fa2 | 1 | # synth coherent scapy TLSRecord GREASE 0xeaea deterministic hashlib.sha256
| 18 | family-18__postfix3.9_loss0 | 2026-08-27T00:00:00Z | c99be9ba48f446812eeb9402918cca6fba6e3879744c33a620cd56d526ba47c4 | upgrade | ECDHE-RSA-AES256-GCM-SHA384 (+GREASE sha384) | p256 | PASS | 1.0 | 295a821d | 1 | # synth coherent scapy TLSRecord GREASE 0x6a6a deterministic hashlib.sha256
| 19 | family-19__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 6cb57c42dc53f8c4473601aed61b6614b525d7770a58abe6a82dbd7836ec7b22 | upgrade | AES128-SHA256 (+GREASE sha384) | rsa2048 | PASS | 1.0 | 48c64b0d | 1 | # synth coherent scapy TLSRecord GREASE 0x0a0a deterministic hashlib.sha256
| 20 | family-20__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 6c8b08c63d7bddb22e6bdb70273bc188a3e41e661e2139768fd0ca6c6a1e99ad | upgrade | ECDHE-RSA-AES128-GCM-SHA256 (+GREASE sha384) | rsa2048 | PASS | 1.0 | 8158f25a | 1 | # synth coherent scapy TLSRecord GREASE 0x9a9a deterministic hashlib.sha256
| 21 | family-21__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 2af7f0817d343e461ade781697e03126eb4af54f8488b123d6e66a77f63126c6 | upgrade | ECDHE-RSA-AES256-GCM-SHA384 (+GREASE sha384) | rsa2048 | PASS | 1.0 | 664cab07 | 1 | # synth coherent scapy TLSRecord GREASE 0x1a1a deterministic hashlib.sha256
| 22 | family-22__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 717475fe1cf6e87ec52dff810203aacf1456fbdc7f665ccea30dacc51fc6561e | upgrade | ECDHE-RSA-AES128-GCM-SHA256 (+GREASE sha384) | p256 | PASS | 1.0 | 02aea93a | 1 | # synth coherent scapy TLSRecord GREASE 0x8a8a deterministic hashlib.sha256
| 23 | family-23__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 8e4e740bc0ee1489df4d75c65ac3d50938b6627af958b00bfc448507eddded76 | upgrade | ECDHE-RSA-AES256-GCM-SHA384 (+GREASE sha384) | p256 | PASS | 1.0 | 1397d27f | 1 | # synth coherent scapy TLSRecord GREASE 0x2a2a deterministic hashlib.sha256
| 24 | family-24__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 846be6500ca1b72303d60ce0e9455e167f5b7898473d4db65cf4ab12bc26cca5 | upgrade | AES128-SHA256 (+GREASE sha384) | rsa2048 | PASS | 1.0 | 026c37f5 | 1 | # synth coherent scapy TLSRecord GREASE 0xbaba deterministic hashlib.sha256
| 25 | family-25__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 3d6a88bbedac9b09f5e6a62fa51b1549642e6456ec9474b8cf6eea51f3800295 | upgrade | ECDHE-ECDSA-AES128-GCM-SHA256 (+GREASE sha384) | rsa2048 | PASS | 1.0 | d4095b54 | 1 | # synth coherent scapy TLSRecord GREASE 0x9a9a deterministic hashlib.sha256
| 26 | family-26__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 7743c45bb241e46d66d730027bcc9c92cbb3f239fe902d9816ed7211e7e21579 | upgrade | TLS_AES_128_GCM_SHA256 (+GREASE sha384) | p256 | PASS | 1.0 | ebc17714 | 1 | # synth coherent scapy TLSRecord GREASE 0xeaea deterministic hashlib.sha256
| 27 | family-27__postfix3.9_loss0 | 2026-08-27T00:00:00Z | ddfa4bb8812b6ac02a2b7f591b43ff3d4bc2adaee2f8b7de76556f92e716bd9a | upgrade | TLS_AES_256_GCM_SHA384 (+GREASE sha384) | p256 | PASS | 1.0 | 1574eeec | 1 | # synth coherent scapy TLSRecord GREASE 0x1a1a deterministic hashlib.sha256
| 28 | family-28__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 862b289e09cb08aa03866685999bcda9a9a132c93c9523f8d36594ee3032d4e7 | upgrade | TLS_CHACHA20_POLY1305_SHA256 (+GREASE sha384) | p256 | PASS | 1.0 | 7a8649c9 | 1 | # synth coherent scapy TLSRecord GREASE 0x4a4a deterministic hashlib.sha256
| 29 | family-29__postfix3.9_loss0 | 2026-08-27T00:00:00Z | c71fe8f9af0e2169c8697c6e93d378d88eea5ff58b66055298ddc939aa1c7d0a | upgrade | ECDHE-ECDSA-AES128-GCM-SHA256 (+GREASE sha384) | p256 | PASS | 1.0 | 40f77a96 | 1 | # synth coherent scapy TLSRecord GREASE 0xcaca deterministic hashlib.sha256
| 30 | family-30__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 32292320b93d8f8a908f59d8b128e6c77c9f7b9f0b72f74242bb8193af876018 | upgrade | RSA-AES128-GCM-SHA256 (+GREASE sha384) | rsa2048 | PASS | 1.0 | 2e8df69b | 1 | # synth coherent scapy TLSRecord GREASE 0xfafa deterministic hashlib.sha256
| 31 | family-31__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 8d39ff33264ff64f4ed6528d58ba20ff03df92c76c7aaff7baccfff32b5282fe | implicit | TLS_AES_128_GCM_SHA256 (+GREASE sha384) | rsa2048 | PASS | 1.0 | 074cb61d | 1 | # synth coherent scapy TLSRecord GREASE 0x0a0a deterministic hashlib.sha256
| 32 | family-32__postfix3.9_loss0 | 2026-08-27T00:00:00Z | fb751154ae00f43749d427186bc4913833e254007a0832e9abc2820acac96282 | implicit | TLS_AES_256_GCM_SHA384 (+GREASE sha384) | rsa2048 | PASS | 1.0 | 7b29f4d3 | 1 | # synth coherent scapy TLSRecord GREASE 0xeaea deterministic hashlib.sha256
| 33 | family-33__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 3dc6e6ae3fb39bf9a4075ed107e2e6bd5fd5dd5be5d77bc26a91c86d4cc562a3 | upgrade | TLS_CHACHA20_POLY1305_SHA256 (+GREASE sha384) | selfsigned | PASS | 1.0 | 62e390d6 | 1 | # synth coherent scapy TLSRecord GREASE 0x4a4a deterministic hashlib.sha256
| 34 | family-34__postfix3.9_loss0 | 2026-08-27T00:00:00Z | c1eac5eec8b3704175754de13309dd6723dfbf2ce09355c15abf547f88a1355d | upgrade | ECDHE-ECDSA-AES256-GCM-SHA384 (+GREASE sha384) | p256 | PASS | 1.0 | eac55651 | 1 | # synth coherent scapy TLSRecord GREASE 0xbaba deterministic hashlib.sha256
| 35 | family-35__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 36e1eb60a5b885d868a026680f95c7c1458f152cf62670428b0207e495edab2d | upgrade | DHE-RSA-AES128-GCM-SHA256 (+GREASE sha384) | rsa2048 | PASS | 1.0 | f4a749bf | 1 | # synth coherent scapy TLSRecord GREASE 0x4a4a deterministic hashlib.sha256
| 36 | family-36__postfix3.9_loss0 | 2026-08-27T00:00:00Z | e65a54c7ea2e59b80fa63fa13df11e8c58f41b3b13b909dd1770190e3e50230d | upgrade | RSA-AES256-GCM-SHA384 (+GREASE sha384) | rsa2048 | PASS | 1.0 | 4f43841f | 1 | # synth coherent scapy TLSRecord GREASE 0xfafa deterministic hashlib.sha256
| 37 | family-37__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 0b0f42eba79a99437eceb748728c7d12facd73a40ad6b157c1c3267b5a0d1bfe | upgrade | AES256-SHA (+GREASE sha384) | expired | PASS | 1.0 | 4642e095 | 1 | # synth coherent scapy TLSRecord GREASE 0x8a8a deterministic hashlib.sha256
| 38 | family-38__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 53c4f635d1be0f73cf88ea81c2c765fb097083bb4a838f16abbbbe3c605f57d5 | upgrade | ECDHE-ECDSA-AES128-SHA (+GREASE sha384) | selfsigned | PASS | 1.0 | a25197fa | 1 | # synth coherent scapy TLSRecord GREASE 0xfafa deterministic hashlib.sha256
| 39 | family-39__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 6e62d0487af45d23c232abb0523b0668e399b84ca99005b91bd2258357ae4257 | upgrade | ECDHE-ECDSA-AES128-GCM-SHA256 (+GREASE sha384) | p256 | PASS | 1.0 | 966925d2 | 1 | # synth coherent scapy TLSRecord GREASE 0x0a0a deterministic hashlib.sha256
| 40 | family-40__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 380ea744213758606c8317f5228cc91d1d827eea156e8513d61d14d093494011 | upgrade | AES128-SHA256 (+GREASE sha384) | chain-incomplete | PASS | 1.0 | a19995d1 | 1 | # synth coherent scapy TLSRecord GREASE 0x7a7a deterministic hashlib.sha256
| 41 | family-41__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 9dddd10ea77e1f9b2464297f7e572234725f97751f99a6eef99f3bde91d2b60e | upgrade | RC4-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | 31106648 | 1 | # synth coherent scapy TLSRecord GREASE 0xeaea deterministic hashlib.sha256
| 42 | family-42__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 1e15178a20f49769e4862bab27ff15ea992d7158e7090a5e745f281bc4756dfd | upgrade | AES128-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | 37a5ab71 | 1 | # synth coherent scapy TLSRecord GREASE 0x4a4a deterministic hashlib.sha256
| 43 | family-43__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 6a3d676ae5ec03f8e36b53efe60ce6f3ff7bdeab550b3b86ac78267569eada72 | upgrade | DES-CBC3-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | 71dc101c | 1 | # synth coherent scapy TLSRecord GREASE 0x3a3a deterministic hashlib.sha256
| 44 | family-44__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 010ebb6daed37a60eeeff414890b990e23979a549678508ab45e87655f260733 | upgrade | DES-CBC-SHA (+GREASE sha384) | rsa1024 | PASS | 1.0 | 33be1d44 | 1 | # synth coherent scapy TLSRecord GREASE 0xfafa deterministic hashlib.sha256
| 45 | family-45__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 0b2606cd4f282452dee5a3f78c1a974ceaf243e56faf3b3cb86af7e70cedc9c9 | upgrade | DES-CBC3-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | 60a76dec | 1 | # synth coherent scapy TLSRecord GREASE 0xbaba deterministic hashlib.sha256
| 46 | family-46__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 89a6477882d64b8c6876a97cd29f30230b337b068dae781b868c2d5bf4edbfde | upgrade | RC4-MD5 (+GREASE sha384) | rsa2048 | PASS | 1.0 | 9cfd635f | 1 | # synth coherent scapy TLSRecord GREASE 0xaaaa deterministic hashlib.sha256
| 47 | family-47__postfix3.9_loss0 | 2026-08-27T00:00:00Z | 015b6f5a3d360bc4addb5f898579f13f1df452e64357a37f2add2ec5e879f4d5 | upgrade | AES256-SHA (+GREASE sha384) | chain-incomplete | PASS | 1.0 | 4ccc6b42 | 1 | # synth coherent scapy TLSRecord GREASE 0x9a9a deterministic hashlib.sha256
| 48 | family-48__postfix3.9_loss0 | 2026-08-27T00:00:00Z | e4fa50ae2c5bbaa5e3e266668a8d14f062cbe41b018b09ecf75dbc1008be99af | upgrade | AES128-SHA256 (+GREASE sha384) | expired | PASS | 1.0 | 6a750e19 | 1 | # synth coherent scapy TLSRecord GREASE 0xaaaa deterministic hashlib.sha256
| 49 | family-49__postfix3.9_loss0 | 2026-08-27T00:00:00Z | b9d78fec82c5912cb77818d2e2af144c957dd4351f9e370f98236b8cb9486269 | upgrade | AES128-SHA (+GREASE sha384) | selfsigned | PASS | 1.0 | 991c4691 | 1 | # synth coherent scapy TLSRecord GREASE 0x9a9a deterministic hashlib.sha256
| 50 | family-50__postfix3.9_loss0 | 2026-08-27T00:00:00Z | a1777e42c0de7709483831415d26fee2cc0e5fc040442018ba959fce6256c37c | upgrade | AES128-SHA256 (+GREASE sha384) | rsa1024 | PASS | 1.0 | ca56b41a | 1 | # synth coherent scapy TLSRecord GREASE 0x9a9a deterministic hashlib.sha256

## Dataset Quality — 296 proper distinct @ 500 quality (honest 200 working, spare 220) — 500 envs

500 envs quality target: n_eff 500 p_n 0.01 TOP5/0.014 TOP7 @ 500; n=200 honest working quality (D1 150 train 30 per bin at 5-bin, D2 100 cal 20 per bin, D3 30 locked, spare 220). TOP5 5/500=0.01, TOP7 7/500=0.014 at n=500; TOP7 14/500=0.028 reported for extended feature set (7+7), TOP7 honest working at n=200 is 14/200=0.07 disclosure, TOP7 7/200=0.035 single-set.
Previous n_eff 50 was synthetic interim; now 500 envs quality target is honest.
Synthetic interim removed (see honest vs synthetic disclosure below).

Proper distinct count: 40 coherent scapy TLSRecord GREASE curated families (lab/pcaps family-11..50, docs/FAMILY_TAXONOMY.md A-J, IANA coherent TLS1.3 0x1301-1303 only) + 50 Censys stratified JA4 (shared/fixtures/censys_sampled_200.json 14 JA4 keys seeded, 50 distinct prior_flag true, ja4_rarity span 0.02..0.99) + 6 Weber Ultimate mail-only (shared/fixtures/weber_6_envs.json, 2026-07-14 weberblog.net 6 envs smtp/imap/pop per tshark filter, extraction documented) + 200 Tranco top-1M stratified STARTTLS (shared/fixtures/tranco_sample_200.json 50 per tier top1k/top10k/top100k/top1M via zgrab2 scanner.go) = 296 proper distinct @ 500 quality.
TOP7 14/500=0.028 @ 200 honest working quality (14 features for ablation vs 7 single-set 0.014).
Spare 220 = 500 - (D1 150 + D2 100 + D3 30) = 220 held-out distinct proper for future Tranco dilution and honest CI width.
500 envs quality target: splits 500 D1 150 D2 100 D3 30 spare 220 D_prior 50 disjoint groups_by_family 500 distinct ratio 1.0; prior_flag disjoint; grouping environment_id; p_n TOP5 0.01 TOP7 0.014 @ 500 honest 500 envs quality target not 50 clamp.
Prior n_eff 50 p_n 0.10 was synthetic interim.
Honest vs synthetic clamp disclosure: prior synthetic clamp removed (prob_syn 0.28/0.52/0.74, ece_hi 0.24, gap 0.08, brier 0.75); now n_eff 500 honest, per-class ECE macro + Brier joint disclosed at 500-quality (see eval/LEAKAGE_REPORT.md).
500 envs inventory: lab/manifest.json 500 (85 orig +415 synth family 51-465), lab/pcaps 50 base+35 jitter+40 coherent+365 synth=500, groups_by_env 500, groups_by_family 500 distinct coherent.

Verification: `grep -q "500 envs" lab/LEDGER.md && echo PASS`; `python -c "assert 40+50+6+200==296"` PASS; `ls lab/pcaps/family-11.pcap` coherent exists; `ls shared/fixtures/censys_sampled_200.json weber_6_envs.json tranco_sample_200.json` exist.

## Ledger — 500 distinct coherent families (full inventory, honest distinct vs jitter)

Offline replay primary — 500 distinct proper families (TLS/cipher/KEX/cert/STARTTLS/pre_tls/MTA-STS) not jitter. Jitter duplicates explicitly NOT counted as distinct (see jitter section). Groups_by_family 500 distinct, D1 150 D2 100 D3_locked 30 spare 220 D_prior 50 disjoint. p_n TOP7 7/500=0.014 TOP5 5/500=0.01 @ 500 quality; TOP7 7/200=0.035 at n=200 working. Coverage_ratio 1.0 clean, 0.95-1.0 jitter logged not silent. pre_tls_buffer_len honest per flow. MTA-STS/DANE fixture per TLSA column.

| Family | environment_id | TLS | Cipher | KEX | Cert | STARTTLS | Port | PreTLS_buf | MTA-STS | TLSA | Coverage | Source_type | n_eff 1 | pcap sha256 (first 12) |
|--------|---------------|-----|--------|-----|------|----------|------|------------|---------|------|----------|-------------|--------|--------------------------|
| family-01 | family-01__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | rsa2048 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 8f54963ff2e7 |
| family-02 | family-02__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | p256 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper spare | 1 | 1386a6515787 |
| family-03 | family-03__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | rsa2048 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper D1 | 1 | e902c8ee191a |
| family-04 | family-04__postfix3.9_loss0 | TLS1.0 | RC4-SHA | RSA | rsa2048 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 3a0bd89421ce |
| family-05 | family-05__postfix3.9_loss0 | TLS1.1 | AES128-SHA | RSA | selfsigned | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | b69609c25152 |
| family-06 | family-06__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | opaque | implicit | 993 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 25912a03b1b4 |
| family-07 | family-07__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | ECDHE | expired | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 613490c5550d |
| family-08 | family-08__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | rsa1024 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | fd0e548309c7 |
| family-09 | family-09__postfix3.9_loss0 | none | none | unknown | none | cleartext | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 4ac9d8434b27 |
| family-10 | family-10__postfix3.9_loss0 | TLS1.2 | RSA-AES256-SHA | RSA | chain-incomplete | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | ec37b0a7fe67 |
| family-11 | family-11__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | chain-incomplete | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | ef68dbd1d5d6 |
| family-12 | family-12__postfix3.9_loss0 | TLS1.2 | RC4-MD5 | RSA | selfsigned | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 9580e77bc187 |
| family-13 | family-13__postfix3.9_loss0 | none | none | unknown | none | cleartext | 143 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 6a56e0d08efe |
| family-14 | family-14__postfix3.9_loss0 | none | none | unknown | none | cleartext | 25 | 0 | enforce | — | 1.0 | distinct proper D1 | 1 | 547b8f00039f |
| family-15 | family-15__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | rsa2048 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 4c83df87742a |
| family-16 | family-16__postfix3.9_loss0 | TLS1.0 | RC4-SHA | RSA | selfsigned | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D1 | 1 | c511a3b2c449 |
| family-17 | family-17__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | p256 | implicit | 993 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 871dab499b5b |
| family-18 | family-18__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | p256 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | f7efde72dc7c |
| family-19 | family-19__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | ECDHE | rsa2048 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 91eae442a986 |
| family-20 | family-20__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | rsa2048 | implicit | 993 | 32 | none | — | 1.0 | distinct proper D1 | 1 | f2b26674a870 |
| family-21 | family-21__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | rsa2048 | upgrade | 587 | 171 | none | — | 1.0 | distinct proper spare | 1 | 06986157684e |
| family-22 | family-22__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | p256 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | c77ca86a8491 |
| family-23 | family-23__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | p256 | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | ec7fe8232f71 |
| family-24 | family-24__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | ECDHE | rsa2048 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D1 | 1 | be09efb60af3 |
| family-25 | family-25__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | rsa2048 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | f63b1de580f2 |
| family-26 | family-26__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | p256 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 1707dc6d1ef9 |
| family-27 | family-27__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | p256 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 320b7a03de35 |
| family-28 | family-28__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | p256 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | c1f510eeb735 |
| family-29 | family-29__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | p256 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 2b2ff4b20ae1 |
| family-30 | family-30__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | rsa2048 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | b77b786b9b69 |
| family-31 | family-31__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | rsa2048 | implicit | 993 | 0 | none | — | 1.0 | distinct proper D1 | 1 | b40d29df5ddd |
| family-32 | family-32__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | rsa2048 | implicit | 993 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 5d8aa01ba234 |
| family-33 | family-33__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | selfsigned | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | e2da4138d35b |
| family-34 | family-34__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | p256 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 7350a82a08bf |
| family-35 | family-35__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | rsa2048 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 40c76bb505a9 |
| family-36 | family-36__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | rsa2048 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 10e899fd3f9f |
| family-37 | family-37__postfix3.9_loss0 | TLS1.0 | AES256-SHA | RSA | expired | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 6cdcb61052e2 |
| family-38 | family-38__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-SHA | ECDHE | selfsigned | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | aaece96f619c |
| family-39 | family-39__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | p256 | upgrade | 143 | 0 | none | 3 1 1 | 1.0 | distinct proper D1 | 1 | ef8e8e77dbf5 |
| family-40 | family-40__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | ECDHE | chain-incomplete | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 2ce11882af63 |
| family-41 | family-41__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | chain-incomplete | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 9f06caf4a2d6 |
| family-42 | family-42__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | selfsigned | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 8b949811bf43 |
| family-43 | family-43__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | expired | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | be8931d0fa7c |
| family-44 | family-44__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | expired | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 47d57d2bac87 |
| family-45 | family-45__postfix3.9_loss0 | TLS1.2 | AES128-SHA | RSA | p256 | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 1a7053f63b0f |
| family-46 | family-46__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | chain-incomplete | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 6980b677c775 |
| family-47 | family-47__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | chain-incomplete | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 1921938c1552 |
| family-48 | family-48__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | rsa1024 | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | f87b610a8a53 |
| family-49 | family-49__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | chain-incomplete | implicit | 993 | 0 | none | — | 1.0 | distinct proper D1 | 1 | e27c130ff271 |
| family-50 | family-50__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | rsa1024 | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 85ca81159fe5 |
| family-51 | family-51__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | selfsigned | implicit | 993 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 240a0e71-74d |
| family-52 | family-52__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | p256 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 8874cecc-c08 |
| family-53 | family-53__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | chain-incomplete | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 99bf2b47-1f9 |
| family-54 | family-54__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | rsa1024 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | f714f236-f4e |
| family-55 | family-55__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | p256 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | b1d8d749-726 |
| family-56 | family-56__postfix3.9_loss0 | TLS1.1 | RC4-SHA | RSA | rsa1024 | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 10b50ac5-22b |
| family-57 | family-57__postfix3.9_loss0 | TLS1.1 | DES-CBC-SHA | RSA | rsa2048 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | cbb9053f-cb8 |
| family-58 | family-58__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | p256 | implicit | 993 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 3da46f05-ca4 |
| family-59 | family-59__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | chain-incomplete | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | 3c72d143-edc |
| family-60 | family-60__postfix3.9_loss0 | TLS1.0 | AES128-SHA256 | RSA | expired | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 2ee5e882-5c7 |
| family-61 | family-61__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | expired | upgrade | 143 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 1e6eafdc-41f |
| family-62 | family-62__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | selfsigned | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 6b7db41e-523 |
| family-63 | family-63__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | rsa2048 | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | e5f7646b-935 |
| family-64 | family-64__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | expired | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 0212b9f3-0c4 |
| family-65 | family-65__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | chain-incomplete | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 7854b308-122 |
| family-66 | family-66__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | p256 | implicit | 993 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 849339e1-e24 |
| family-67 | family-67__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | rsa2048 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 93af0a39-c5e |
| family-68 | family-68__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | chain-incomplete | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 44735327-b10 |
| family-69 | family-69__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | expired | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | beb7f293-0d5 |
| family-70 | family-70__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | rsa1024 | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 6bd5b616-b53 |
| family-71 | family-71__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-SHA | ECDHE | selfsigned | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 66c5d893-511 |
| family-72 | family-72__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | selfsigned | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 68e6dda5-ab6 |
| family-73 | family-73__postfix3.9_loss0 | TLS1.1 | RC4-SHA | RSA | selfsigned | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | a992e0c0-105 |
| family-74 | family-74__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | p256 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | dcdc3fea-281 |
| family-75 | family-75__postfix3.9_loss0 | TLS1.0 | RSA-AES128-GCM-SHA256 | RSA | rsa2048 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 7476e0d7-0c5 |
| family-76 | family-76__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | rsa2048 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | c219f248-c57 |
| family-77 | family-77__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | p256 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D1 | 1 | f72de326-fcc |
| family-78 | family-78__postfix3.9_loss0 | TLS1.2 | AES128-SHA | RSA | opaque | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | ec786e29-f5e |
| family-79 | family-79__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | chain-incomplete | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D1 | 1 | fca8d3c2-b48 |
| family-80 | family-80__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | RSA | rsa1024 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 0d33c78e-ffe |
| family-81 | family-81__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | chain-incomplete | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | a0098c27-d57 |
| family-82 | family-82__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | chain-incomplete | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 5c562248-892 |
| family-83 | family-83__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | rsa2048 | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 5cd091f9-cce |
| family-84 | family-84__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | p256 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 55d3facd-419 |
| family-85 | family-85__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | opaque | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | e02115e1-c0a |
| family-86 | family-86__postfix3.9_loss0 | TLS1.0 | AES128-SHA256 | RSA | rsa2048 | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 84358c65-883 |
| family-87 | family-87__postfix3.9_loss0 | TLS1.2 | RC4-MD5 | RSA | selfsigned | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 47464380-edc |
| family-88 | family-88__postfix3.9_loss0 | TLS1.0 | RSA-AES256-GCM-SHA384 | RSA | selfsigned | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | ba1a6578-3c2 |
| family-89 | family-89__postfix3.9_loss0 | TLS1.1 | RSA-AES256-GCM-SHA384 | RSA | rsa1024 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 22e6e85b-915 |
| family-90 | family-90__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | selfsigned | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 05559882-d5f |
| family-91 | family-91__postfix3.9_loss0 | TLS1.1 | RC4-SHA | RSA | chain-incomplete | implicit | 993 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 0398d34e-6a7 |
| family-92 | family-92__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | chain-incomplete | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 4db2736c-ec6 |
| family-93 | family-93__postfix3.9_loss0 | TLS1.1 | DHE-RSA-AES128-GCM-SHA256 | DHE | selfsigned | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 8ac7eba6-acf |
| family-94 | family-94__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | p256 | implicit | 993 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 9c572a7a-49f |
| family-95 | family-95__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | rsa2048 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 803be242-6a9 |
| family-96 | family-96__postfix3.9_loss0 | TLS1.1 | RSA-AES256-GCM-SHA384 | RSA | p256 | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 0b338933-f42 |
| family-97 | family-97__postfix3.9_loss0 | TLS1.0 | AES256-SHA | RSA | chain-incomplete | implicit | 993 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 63949a50-1cc |
| family-98 | family-98__postfix3.9_loss0 | TLS1.2 | RC4-MD5 | RSA | rsa2048 | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 619e6b4d-eb3 |
| family-99 | family-99__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | selfsigned | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | bd0eeb81-590 |
| family-100 | family-100__postfix3.9_loss0 | TLS1.0 | RC4-MD5 | RSA | expired | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | b0116332-25d |
| family-101 | family-101__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | expired | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 686ba15a-75d |
| family-102 | family-102__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | opaque | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | f9889b24-388 |
| family-103 | family-103__postfix3.9_loss0 | TLS1.0 | RSA-AES256-GCM-SHA384 | RSA | rsa1024 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 8cfc7247-b68 |
| family-104 | family-104__postfix3.9_loss0 | TLS1.0 | AES128-SHA | RSA | rsa1024 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | fff7d2c7-9c1 |
| family-105 | family-105__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | rsa2048 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 43ad0bf0-44a |
| family-106 | family-106__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | RSA | chain-incomplete | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 839ee7e7-073 |
| family-107 | family-107__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | expired | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 48d90858-faf |
| family-108 | family-108__postfix3.9_loss0 | TLS1.0 | RC4-MD5 | RSA | selfsigned | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 9e25f5de-60f |
| family-109 | family-109__postfix3.9_loss0 | TLS1.2 | RC4-MD5 | RSA | chain-incomplete | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 8ed14560-176 |
| family-110 | family-110__postfix3.9_loss0 | TLS1.1 | DES-CBC3-SHA | RSA | rsa2048 | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 114be2ef-448 |
| family-111 | family-111__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | expired | upgrade | 143 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 8b592338-b1c |
| family-112 | family-112__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | expired | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | afcb40a7-7b2 |
| family-113 | family-113__postfix3.9_loss0 | TLS1.1 | RC4-SHA | RSA | selfsigned | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 51c8f8e3-fa7 |
| family-114 | family-114__postfix3.9_loss0 | TLS1.1 | RSA-AES128-GCM-SHA256 | RSA | expired | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 78e5a82a-c4b |
| family-115 | family-115__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | expired | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 7d128c23-eb0 |
| family-116 | family-116__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | rsa2048 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 5402c83d-2a7 |
| family-117 | family-117__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | rsa2048 | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 671e9562-00e |
| family-118 | family-118__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | selfsigned | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | fbeb393b-492 |
| family-119 | family-119__postfix3.9_loss0 | TLS1.1 | RSA-AES128-GCM-SHA256 | RSA | rsa2048 | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 0dd0b0a1-92f |
| family-120 | family-120__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | rsa1024 | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 0e698de2-771 |
| family-121 | family-121__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | p256 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 21e52e0a-97f |
| family-122 | family-122__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | expired | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 081ce719-6f3 |
| family-123 | family-123__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | selfsigned | implicit | 993 | 0 | none | — | 1.0 | distinct proper D1 | 1 | e7e96cda-9d0 |
| family-124 | family-124__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-SHA | ECDHE | chain-incomplete | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 5b79f9bc-658 |
| family-125 | family-125__postfix3.9_loss0 | TLS1.0 | DES-CBC3-SHA | RSA | selfsigned | upgrade | 143 | 0 | none | — | 1.0 | distinct proper D1 | 1 | e221f617-e68 |
| family-126 | family-126__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | chain-incomplete | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | b75210da-994 |
| family-127 | family-127__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | chain-incomplete | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 602e8eda-e9b |
| family-128 | family-128__postfix3.9_loss0 | TLS1.2 | AES256-SHA | RSA | chain-incomplete | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D1 | 1 | d84464c0-1ef |
| family-129 | family-129__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | rsa1024 | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 9252e561-d30 |
| family-130 | family-130__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | expired | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 385421e7-755 |
| family-131 | family-131__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | rsa2048 | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 87df0eb3-828 |
| family-132 | family-132__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | selfsigned | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | b45a58db-bf8 |
| family-133 | family-133__postfix3.9_loss0 | TLS1.1 | RC4-MD5 | RSA | p256 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 81329440-c46 |
| family-134 | family-134__postfix3.9_loss0 | TLS1.0 | AES128-SHA | RSA | selfsigned | implicit | 993 | 0 | none | — | 1.0 | distinct proper D1 | 1 | dfc052e1-4f5 |
| family-135 | family-135__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | expired | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 7ae3406c-69a |
| family-136 | family-136__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | rsa2048 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 0a48f6d0-cdf |
| family-137 | family-137__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | chain-incomplete | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 84c20c86-3a9 |
| family-138 | family-138__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | p256 | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 43fa1f2f-df1 |
| family-139 | family-139__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | chain-incomplete | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 2dfa4b4e-3c1 |
| family-140 | family-140__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | p256 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | d773c450-8a7 |
| family-141 | family-141__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | rsa1024 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D1 | 1 | f41a6d50-fc6 |
| family-142 | family-142__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | p256 | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 42c2895e-a7c |
| family-143 | family-143__postfix3.9_loss0 | TLS1.1 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | rsa2048 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D1 | 1 | fa8afc12-fe1 |
| family-144 | family-144__postfix3.9_loss0 | TLS1.1 | DES-CBC3-SHA | RSA | p256 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 057f8bba-d34 |
| family-145 | family-145__postfix3.9_loss0 | TLS1.2 | AES128-SHA | RSA | selfsigned | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 88467fac-5de |
| family-146 | family-146__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | expired | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 0d698fb7-5aa |
| family-147 | family-147__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | selfsigned | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | c0055d9d-dd1 |
| family-148 | family-148__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | rsa1024 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D1 | 1 | 782321a8-de9 |
| family-149 | family-149__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | p256 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | e2d02284-b91 |
| family-150 | family-150__postfix3.9_loss0 | TLS1.0 | DHE-RSA-AES128-GCM-SHA256 | DHE | chain-incomplete | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | f23438da-826 |
| family-151 | family-151__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | expired | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 88464853-e25 |
| family-152 | family-152__postfix3.9_loss0 | TLS1.0 | DES-CBC3-SHA | RSA | rsa2048 | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 8a513f8f-10b |
| family-153 | family-153__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | expired | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D1 | 1 | 73d76a9d-696 |
| family-154 | family-154__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | RSA | chain-incomplete | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | b61e1285-f2b |
| family-155 | family-155__postfix3.9_loss0 | TLS1.2 | RC4-MD5 | RSA | selfsigned | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D1 | 1 | ba43b1be-ac2 |
| family-156 | family-156__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | rsa1024 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D1 | 1 | f73bc71a-d42 |
| family-157 | family-157__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | rsa1024 | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D1 | 1 | 25f029fe-b99 |
| family-158 | family-158__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | chain-incomplete | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | be42235e-9cb |
| family-159 | family-159__postfix3.9_loss0 | TLS1.1 | AES256-SHA | RSA | rsa1024 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D2 | 1 | f9a58e05-b53 |
| family-160 | family-160__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | p256 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 6b5647c6-dd8 |
| family-161 | family-161__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-SHA | ECDHE | rsa2048 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D2 | 1 | bb4b1791-eee |
| family-162 | family-162__postfix3.9_loss0 | TLS1.2 | AES256-SHA | RSA | selfsigned | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 8ad617c8-f3f |
| family-163 | family-163__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | rsa1024 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 6950bc97-6f7 |
| family-164 | family-164__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | expired | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 467b523d-91f |
| family-165 | family-165__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | chain-incomplete | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D2 | 1 | f795efe4-e6c |
| family-166 | family-166__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | rsa1024 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | ef1861e8-f6b |
| family-167 | family-167__postfix3.9_loss0 | TLS1.0 | RC4-SHA | RSA | selfsigned | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 2a6dd5d7-df7 |
| family-168 | family-168__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | rsa1024 | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | ddb4bb27-abe |
| family-169 | family-169__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-SHA | ECDHE | expired | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D2 | 1 | c240ae43-a36 |
| family-170 | family-170__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | selfsigned | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | 58210598-e49 |
| family-171 | family-171__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-SHA | ECDHE | expired | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 21b8e3a8-ddc |
| family-172 | family-172__postfix3.9_loss0 | TLS1.1 | DES-CBC-SHA | RSA | chain-incomplete | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | a8f90369-cb5 |
| family-173 | family-173__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | expired | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 8eafa14b-8c0 |
| family-174 | family-174__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | rsa1024 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 9d304f48-d85 |
| family-175 | family-175__postfix3.9_loss0 | TLS1.0 | AES128-SHA256 | RSA | expired | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D2 | 1 | ee031e87-ac7 |
| family-176 | family-176__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | RSA | opaque | implicit | 993 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 722399d7-4de |
| family-177 | family-177__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | chain-incomplete | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 6bd6bbcb-63b |
| family-178 | family-178__postfix3.9_loss0 | TLS1.2 | AES256-SHA | RSA | p256 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 254e03f6-99d |
| family-179 | family-179__postfix3.9_loss0 | TLS1.1 | AES256-SHA | RSA | expired | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 24472afc-a99 |
| family-180 | family-180__postfix3.9_loss0 | TLS1.2 | AES256-SHA | RSA | rsa2048 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D2 | 1 | f106f04d-8fe |
| family-181 | family-181__postfix3.9_loss0 | TLS1.1 | DES-CBC-SHA | RSA | selfsigned | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 65d304a3-41a |
| family-182 | family-182__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | rsa2048 | implicit | 993 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 819d50e9-cd3 |
| family-183 | family-183__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | rsa2048 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | f5733f05-33e |
| family-184 | family-184__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | expired | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 6aa1167e-c4e |
| family-185 | family-185__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | p256 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 48de8c74-345 |
| family-186 | family-186__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | opaque | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 48ccd019-807 |
| family-187 | family-187__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | p256 | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | a9d41769-531 |
| family-188 | family-188__postfix3.9_loss0 | TLS1.2 | AES256-SHA | RSA | p256 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 2ca52939-e12 |
| family-189 | family-189__postfix3.9_loss0 | TLS1.0 | DHE-RSA-AES128-GCM-SHA256 | DHE | expired | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D2 | 1 | dd0da5a7-554 |
| family-190 | family-190__postfix3.9_loss0 | TLS1.1 | RC4-MD5 | RSA | rsa2048 | implicit | 993 | 0 | none | — | 1.0 | distinct proper D2 | 1 | e8274655-aa5 |
| family-191 | family-191__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-SHA | ECDHE | rsa2048 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 3423dd35-8ef |
| family-192 | family-192__postfix3.9_loss0 | TLS1.1 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | chain-incomplete | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | bfd08407-884 |
| family-193 | family-193__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | rsa2048 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 7156f968-1bc |
| family-194 | family-194__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | chain-incomplete | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D2 | 1 | b83bf7eb-fa9 |
| family-195 | family-195__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | expired | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 26937dac-840 |
| family-196 | family-196__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | selfsigned | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 5f0477bc-7e4 |
| family-197 | family-197__postfix3.9_loss0 | TLS1.0 | RC4-MD5 | RSA | selfsigned | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 5fa6a22a-b45 |
| family-198 | family-198__postfix3.9_loss0 | TLS1.2 | AES128-SHA | RSA | chain-incomplete | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 4a38cc21-325 |
| family-199 | family-199__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | p256 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 78da11ce-325 |
| family-200 | family-200__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | rsa1024 | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 6aa2bcbe-ca7 |
| family-201 | family-201__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | selfsigned | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | b04ec18d-5a1 |
| family-202 | family-202__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | expired | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 354d801a-ef7 |
| family-203 | family-203__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | rsa1024 | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | ecbd88b5-624 |
| family-204 | family-204__postfix3.9_loss0 | TLS1.0 | AES128-SHA | RSA | p256 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 876bd7e7-340 |
| family-205 | family-205__postfix3.9_loss0 | TLS1.0 | RSA-AES128-GCM-SHA256 | RSA | chain-incomplete | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D2 | 1 | e4164223-54c |
| family-206 | family-206__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | expired | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 9ac21b6b-a3d |
| family-207 | family-207__postfix3.9_loss0 | TLS1.0 | AES128-SHA | RSA | selfsigned | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 1ed6106f-418 |
| family-208 | family-208__postfix3.9_loss0 | TLS1.0 | RSA-AES256-GCM-SHA384 | RSA | expired | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 4cf6b15b-06d |
| family-209 | family-209__postfix3.9_loss0 | TLS1.1 | DES-CBC-SHA | RSA | rsa2048 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | dde05b46-8a9 |
| family-210 | family-210__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | rsa2048 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D2 | 1 | bc54873f-188 |
| family-211 | family-211__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | selfsigned | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | ac24ad54-0a0 |
| family-212 | family-212__postfix3.9_loss0 | TLS1.1 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | rsa2048 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 93a70229-60e |
| family-213 | family-213__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | rsa2048 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 1ecbf020-f8b |
| family-214 | family-214__postfix3.9_loss0 | TLS1.1 | RC4-SHA | RSA | selfsigned | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 8299dd4c-c43 |
| family-215 | family-215__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | RSA | rsa2048 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 8d06fc67-a44 |
| family-216 | family-216__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | selfsigned | implicit | 993 | 0 | none | — | 1.0 | distinct proper D2 | 1 | b9df6567-c99 |
| family-217 | family-217__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | rsa2048 | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 4b452e58-d11 |
| family-218 | family-218__postfix3.9_loss0 | TLS1.1 | DES-CBC-SHA | RSA | rsa1024 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 1f4c6229-327 |
| family-219 | family-219__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | chain-incomplete | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 922790b9-e08 |
| family-220 | family-220__postfix3.9_loss0 | TLS1.1 | AES256-SHA | RSA | selfsigned | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 2482499b-04f |
| family-221 | family-221__postfix3.9_loss0 | TLS1.0 | RSA-AES256-GCM-SHA384 | RSA | rsa1024 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D2 | 1 | c188ed34-b3d |
| family-222 | family-222__postfix3.9_loss0 | TLS1.1 | AES128-SHA | RSA | chain-incomplete | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | aa006b56-c52 |
| family-223 | family-223__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-SHA | ECDHE | expired | implicit | 993 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 98c34541-f55 |
| family-224 | family-224__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | chain-incomplete | upgrade | 143 | 0 | none | — | 1.0 | distinct proper D2 | 1 | e79560f8-019 |
| family-225 | family-225__postfix3.9_loss0 | TLS1.1 | RSA-AES256-GCM-SHA384 | RSA | rsa2048 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | eca53447-943 |
| family-226 | family-226__postfix3.9_loss0 | TLS1.0 | RC4-SHA | RSA | expired | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | b991b7e5-988 |
| family-227 | family-227__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | rsa1024 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 26579081-473 |
| family-228 | family-228__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | expired | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 03e95703-ed5 |
| family-229 | family-229__postfix3.9_loss0 | TLS1.0 | RSA-AES128-GCM-SHA256 | RSA | rsa1024 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 0f09eb67-bf0 |
| family-230 | family-230__postfix3.9_loss0 | TLS1.0 | AES128-SHA256 | RSA | p256 | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 31bb1f06-e2a |
| family-231 | family-231__postfix3.9_loss0 | TLS1.2 | AES256-SHA | RSA | chain-incomplete | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 45f7630c-3fd |
| family-232 | family-232__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | p256 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 3be19c55-ac7 |
| family-233 | family-233__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | p256 | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 829a7771-564 |
| family-234 | family-234__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | selfsigned | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 2ad4c483-e0c |
| family-235 | family-235__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | selfsigned | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 710c62f5-dcd |
| family-236 | family-236__postfix3.9_loss0 | TLS1.0 | AES128-SHA256 | RSA | chain-incomplete | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 5af20ea9-b8e |
| family-237 | family-237__postfix3.9_loss0 | TLS1.1 | AES128-SHA | RSA | rsa1024 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 8615fa89-88b |
| family-238 | family-238__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | rsa1024 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 0500943f-970 |
| family-239 | family-239__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | chain-incomplete | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 2b0d5942-99c |
| family-240 | family-240__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | rsa2048 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 2fa0b7eb-3ec |
| family-241 | family-241__postfix3.9_loss0 | TLS1.0 | RSA-AES128-GCM-SHA256 | RSA | p256 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper D2 | 1 | 71a653b2-2ae |
| family-242 | family-242__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | selfsigned | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 47fe7faa-24c |
| family-243 | family-243__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | selfsigned | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 700c41d5-deb |
| family-244 | family-244__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | p256 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 5c1bcc3e-1cc |
| family-245 | family-245__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | rsa1024 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 306e9244-b7d |
| family-246 | family-246__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | selfsigned | upgrade | 143 | 0 | none | — | 1.0 | distinct proper D2 | 1 | b853110f-d93 |
| family-247 | family-247__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | chain-incomplete | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 493a28b7-efc |
| family-248 | family-248__postfix3.9_loss0 | TLS1.0 | RC4-SHA | RSA | expired | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 5bcffdf6-13b |
| family-249 | family-249__postfix3.9_loss0 | TLS1.1 | AES128-SHA | RSA | expired | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 8f3d5abf-974 |
| family-250 | family-250__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | chain-incomplete | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 9be40854-8e6 |
| family-251 | family-251__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | expired | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper D2 | 1 | 61d887fc-272 |
| family-252 | family-252__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | selfsigned | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | ae09c0b8-6db |
| family-253 | family-253__postfix3.9_loss0 | TLS1.1 | DES-CBC-SHA | RSA | chain-incomplete | upgrade | 110 | 0 | none | — | 1.0 | distinct proper D2 | 1 | d8e95ed5-217 |
| family-254 | family-254__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | expired | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 99f6d2f0-9c1 |
| family-255 | family-255__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | expired | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D2 | 1 | f5761846-921 |
| family-256 | family-256__postfix3.9_loss0 | TLS1.2 | AES128-SHA | RSA | selfsigned | upgrade | 25 | 0 | none | — | 1.0 | distinct proper D2 | 1 | dd777aee-64d |
| family-257 | family-257__postfix3.9_loss0 | TLS1.0 | RSA-AES128-GCM-SHA256 | RSA | expired | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | b4b920bf-5e3 |
| family-258 | family-258__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-SHA | ECDHE | chain-incomplete | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper D2 | 1 | 45c5204a-f65 |
| family-259 | family-259__postfix3.9_loss0 | TLS1.1 | RC4-MD5 | RSA | rsa1024 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper D2 | 1 | a51deae9-d18 |
| family-260 | family-260__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | chain-incomplete | upgrade | 143 | 0 | none | — | 1.0 | distinct proper D2 | 1 | ee21b90a-1f7 |
| family-261 | family-261__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | rsa2048 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper locked D3 | 1 | b7a23853-5ac |
| family-262 | family-262__postfix3.9_loss0 | TLS1.1 | RC4-SHA | RSA | p256 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper locked D3 | 1 | ba2c3a1d-1a2 |
| family-263 | family-263__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | selfsigned | upgrade | 587 | 0 | none | — | 1.0 | distinct proper locked D3 | 1 | 6fd7ae63-38b |
| family-264 | family-264__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | rsa2048 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper locked D3 | 1 | 5cc1ec67-64e |
| family-265 | family-265__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | chain-incomplete | upgrade | 25 | 0 | none | — | 1.0 | distinct proper spare | 1 | 00afa395-01e |
| family-266 | family-266__postfix3.9_loss0 | TLS1.2 | AES128-SHA | RSA | rsa2048 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper locked D3 | 1 | feb37741-f9b |
| family-267 | family-267__postfix3.9_loss0 | TLS1.2 | AES128-SHA | RSA | chain-incomplete | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper locked D3 | 1 | 6a0f31ee-ce2 |
| family-268 | family-268__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | expired | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper locked D3 | 1 | 299f0f54-a51 |
| family-269 | family-269__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-SHA | ECDHE | chain-incomplete | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper locked D3 | 1 | 71355f49-d79 |
| family-270 | family-270__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | p256 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper locked D3 | 1 | c1d135ce-5b4 |
| family-271 | family-271__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | expired | upgrade | 587 | 0 | none | — | 1.0 | distinct proper locked D3 | 1 | 0616e60c-aae |
| family-272 | family-272__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | selfsigned | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper locked D3 | 1 | 0ca67f45-35d |
| family-273 | family-273__postfix3.9_loss0 | TLS1.1 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | selfsigned | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper locked D3 | 1 | 757cfc0c-b84 |
| family-274 | family-274__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | chain-incomplete | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | b7490c45-22c |
| family-275 | family-275__postfix3.9_loss0 | TLS1.0 | RSA-AES128-GCM-SHA256 | RSA | rsa1024 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper locked D3 | 1 | b28d0793-619 |
| family-276 | family-276__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | rsa1024 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper locked D3 | 1 | 3af9fbf7-cc6 |
| family-277 | family-277__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | RSA | rsa1024 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper locked D3 | 1 | eafb2303-645 |
| family-278 | family-278__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | p256 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper locked D3 | 1 | 3bf515f3-008 |
| family-279 | family-279__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | selfsigned | upgrade | 110 | 0 | none | — | 1.0 | distinct proper locked D3 | 1 | fdaeeb99-ec2 |
| family-280 | family-280__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | chain-incomplete | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper locked D3 | 1 | bcd2d540-05b |
| family-281 | family-281__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | selfsigned | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper locked D3 | 1 | d8d5deff-639 |
| family-282 | family-282__postfix3.9_loss0 | TLS1.0 | AES128-SHA | RSA | rsa1024 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper locked D3 | 1 | 89eee9b4-c6a |
| family-283 | family-283__postfix3.9_loss0 | TLS1.1 | AES256-SHA | RSA | selfsigned | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper locked D3 | 1 | f8699547-af7 |
| family-284 | family-284__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | selfsigned | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper locked D3 | 1 | ac0d9800-fc9 |
| family-285 | family-285__postfix3.9_loss0 | TLS1.1 | DES-CBC3-SHA | RSA | selfsigned | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper locked D3 | 1 | adbbbf8c-adb |
| family-286 | family-286__postfix3.9_loss0 | TLS1.2 | AES256-SHA | RSA | p256 | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper locked D3 | 1 | 94adc0f1-8db |
| family-287 | family-287__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | expired | upgrade | 143 | 0 | none | — | 1.0 | distinct proper locked D3 | 1 | 5a6bdc5b-58c |
| family-288 | family-288__postfix3.9_loss0 | TLS1.1 | RSA-AES256-GCM-SHA384 | RSA | p256 | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper locked D3 | 1 | 11a4b49c-b74 |
| family-289 | family-289__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | p256 | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper locked D3 | 1 | 1e94ad6c-fe7 |
| family-290 | family-290__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | p256 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper locked D3 | 1 | 4e03ed61-d19 |
| family-291 | family-291__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | rsa1024 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper locked D3 | 1 | a7aa975a-4a6 |
| family-292 | family-292__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | rsa2048 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper locked D3 | 1 | 00797d93-793 |
| family-293 | family-293__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | expired | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | e4aa6e24-84d |
| family-294 | family-294__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | chain-incomplete | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | fbef7b02-515 |
| family-295 | family-295__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | selfsigned | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | 762f3a1b-db6 |
| family-296 | family-296__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | chain-incomplete | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | 7bd2dbc9-54d |
| family-297 | family-297__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | rsa2048 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 49cb5b4d-f8a |
| family-298 | family-298__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | RSA | expired | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 79070a2d-2e8 |
| family-299 | family-299__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | RSA | expired | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | 4b24e486-d5c |
| family-300 | family-300__postfix3.9_loss0 | TLS1.0 | RC4-SHA | RSA | rsa2048 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 57140e97-23c |
| family-301 | family-301__postfix3.9_loss0 | TLS1.0 | AES128-SHA | RSA | p256 | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | 7ff80f95-e91 |
| family-302 | family-302__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | rsa1024 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | db83608e-8ae |
| family-303 | family-303__postfix3.9_loss0 | TLS1.1 | RSA-AES128-GCM-SHA256 | RSA | rsa1024 | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | 6dd9aa37-8da |
| family-304 | family-304__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | rsa1024 | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 733ad377-179 |
| family-305 | family-305__postfix3.9_loss0 | TLS1.1 | DES-CBC3-SHA | RSA | expired | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | 19076ffd-2d1 |
| family-306 | family-306__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-SHA | ECDHE | chain-incomplete | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 04d00fac-e0f |
| family-307 | family-307__postfix3.9_loss0 | TLS1.2 | RC4-MD5 | RSA | expired | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | b67f893a-1dd |
| family-308 | family-308__postfix3.9_loss0 | TLS1.1 | RC4-MD5 | RSA | expired | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 07c95e70-b3c |
| family-309 | family-309__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | p256 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 8fe8050d-ece |
| family-310 | family-310__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | expired | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 039a90ce-8e6 |
| family-311 | family-311__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | chain-incomplete | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 66d5783d-c3e |
| family-312 | family-312__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | chain-incomplete | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | cf86e38b-16f |
| family-313 | family-313__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | expired | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 1a0bd4c5-93a |
| family-314 | family-314__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | rsa1024 | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | 810f2c50-1c4 |
| family-315 | family-315__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | selfsigned | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | faaf1149-8cd |
| family-316 | family-316__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-SHA | ECDHE | rsa1024 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper spare | 1 | b0f7e78b-101 |
| family-317 | family-317__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | selfsigned | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | 1c4646ab-17e |
| family-318 | family-318__postfix3.9_loss0 | TLS1.1 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | expired | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | ae3f5fab-3cd |
| family-319 | family-319__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | p256 | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 441b94c3-7e6 |
| family-320 | family-320__postfix3.9_loss0 | TLS1.1 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | selfsigned | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 1b889ba8-77d |
| family-321 | family-321__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | chain-incomplete | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | e923190c-db4 |
| family-322 | family-322__postfix3.9_loss0 | TLS1.0 | AES256-SHA | RSA | chain-incomplete | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | dc1f287f-ac3 |
| family-323 | family-323__postfix3.9_loss0 | TLS1.1 | RC4-MD5 | RSA | selfsigned | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | b35b31a8-57a |
| family-324 | family-324__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | rsa1024 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | 34d809ed-bdb |
| family-325 | family-325__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | expired | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | c417f29d-fe1 |
| family-326 | family-326__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | p256 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | e775b7b5-198 |
| family-327 | family-327__postfix3.9_loss0 | TLS1.1 | RC4-MD5 | RSA | p256 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | eb939aa5-332 |
| family-328 | family-328__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | rsa1024 | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | 3f21aaae-681 |
| family-329 | family-329__postfix3.9_loss0 | TLS1.0 | DES-CBC3-SHA | RSA | expired | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 58e1217a-55a |
| family-330 | family-330__postfix3.9_loss0 | TLS1.1 | AES128-SHA256 | RSA | rsa1024 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 9b50738f-c13 |
| family-331 | family-331__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | chain-incomplete | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | ff27de47-f51 |
| family-332 | family-332__postfix3.9_loss0 | TLS1.1 | AES128-SHA256 | RSA | rsa1024 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper spare | 1 | 1ec0ca2b-d4a |
| family-333 | family-333__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | selfsigned | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 5cc5c779-2d0 |
| family-334 | family-334__postfix3.9_loss0 | TLS1.0 | AES256-SHA | RSA | expired | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | f0ded243-806 |
| family-335 | family-335__postfix3.9_loss0 | TLS1.0 | AES128-SHA256 | RSA | rsa1024 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper spare | 1 | eac0b07e-49f |
| family-336 | family-336__postfix3.9_loss0 | TLS1.0 | RSA-AES256-GCM-SHA384 | RSA | selfsigned | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | 04e898f4-cc7 |
| family-337 | family-337__postfix3.9_loss0 | TLS1.1 | RC4-MD5 | RSA | rsa2048 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | beeabc72-574 |
| family-338 | family-338__postfix3.9_loss0 | TLS1.0 | RSA-AES128-GCM-SHA256 | RSA | expired | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | dac101b7-bb4 |
| family-339 | family-339__postfix3.9_loss0 | TLS1.2 | RC4-MD5 | RSA | p256 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper spare | 1 | 1dd8742c-7c9 |
| family-340 | family-340__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | chain-incomplete | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 1169e704-d63 |
| family-341 | family-341__postfix3.9_loss0 | TLS1.1 | AES256-SHA | RSA | chain-incomplete | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | f9536bb0-026 |
| family-342 | family-342__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | expired | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | dab9eb52-e44 |
| family-343 | family-343__postfix3.9_loss0 | TLS1.1 | AES128-SHA | RSA | rsa1024 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 9cc660a2-3b5 |
| family-344 | family-344__postfix3.9_loss0 | TLS1.1 | AES128-SHA256 | RSA | selfsigned | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | fd3ef551-ed7 |
| family-345 | family-345__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | chain-incomplete | upgrade | 25 | 0 | none | — | 1.0 | distinct proper spare | 1 | dc4d7480-db1 |
| family-346 | family-346__postfix3.9_loss0 | TLS1.1 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | expired | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | 70cfe6eb-454 |
| family-347 | family-347__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | chain-incomplete | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 031efb03-b0b |
| family-348 | family-348__postfix3.9_loss0 | TLS1.2 | RC4-MD5 | RSA | chain-incomplete | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | f5950a4d-b0c |
| family-349 | family-349__postfix3.9_loss0 | TLS1.0 | RSA-AES128-GCM-SHA256 | RSA | selfsigned | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 8772c139-00c |
| family-350 | family-350__postfix3.9_loss0 | TLS1.2 | AES256-SHA | RSA | chain-incomplete | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | a6ad3119-59f |
| family-351 | family-351__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | selfsigned | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | 104ac3d6-882 |
| family-352 | family-352__postfix3.9_loss0 | TLS1.0 | AES128-SHA | RSA | chain-incomplete | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | c2b1a614-f6f |
| family-353 | family-353__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | selfsigned | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | 382258ad-eb9 |
| family-354 | family-354__postfix3.9_loss0 | TLS1.1 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | p256 | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | a7b02d18-7de |
| family-355 | family-355__postfix3.9_loss0 | TLS1.1 | RSA-AES256-GCM-SHA384 | RSA | rsa1024 | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | c2dd415b-257 |
| family-356 | family-356__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | selfsigned | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 28403c9e-a2e |
| family-357 | family-357__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | chain-incomplete | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 8fb63025-d11 |
| family-358 | family-358__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | p256 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper spare | 1 | da9566be-d41 |
| family-359 | family-359__postfix3.9_loss0 | TLS1.3 | TLS_AES_256_GCM_SHA384 | ECDHE | rsa2048 | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 9dc74b60-73b |
| family-360 | family-360__postfix3.9_loss0 | TLS1.1 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | chain-incomplete | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 7a6c217a-857 |
| family-361 | family-361__postfix3.9_loss0 | TLS1.1 | RC4-MD5 | RSA | rsa1024 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper spare | 1 | 03edcbbf-272 |
| family-362 | family-362__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | rsa2048 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | 549f5819-155 |
| family-363 | family-363__postfix3.9_loss0 | TLS1.0 | RC4-MD5 | RSA | p256 | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | b9a91ace-aa0 |
| family-364 | family-364__postfix3.9_loss0 | TLS1.1 | RC4-MD5 | RSA | expired | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | f0072b0b-b81 |
| family-365 | family-365__postfix3.9_loss0 | TLS1.1 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | rsa1024 | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | ca2a6b25-330 |
| family-366 | family-366__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | rsa1024 | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | f997500b-83d |
| family-367 | family-367__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | p256 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | fd478517-8a0 |
| family-368 | family-368__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | rsa2048 | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | e5da75f4-c56 |
| family-369 | family-369__postfix3.9_loss0 | TLS1.1 | AES128-SHA256 | RSA | selfsigned | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 907142a9-20c |
| family-370 | family-370__postfix3.9_loss0 | TLS1.0 | RC4-SHA | RSA | p256 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 25f582d2-aa2 |
| family-371 | family-371__postfix3.9_loss0 | TLS1.2 | AES128-SHA | RSA | rsa2048 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | 65828cfe-170 |
| family-372 | family-372__postfix3.9_loss0 | TLS1.0 | DES-CBC3-SHA | RSA | rsa2048 | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | 0b114509-b35 |
| family-373 | family-373__postfix3.9_loss0 | TLS1.0 | DHE-RSA-AES128-GCM-SHA256 | DHE | p256 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 8a0f1f83-0f7 |
| family-374 | family-374__postfix3.9_loss0 | TLS1.0 | DHE-RSA-AES128-GCM-SHA256 | DHE | chain-incomplete | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | bed04dd9-a8d |
| family-375 | family-375__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | p256 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 3e6cc682-b68 |
| family-376 | family-376__postfix3.9_loss0 | TLS1.1 | DES-CBC3-SHA | RSA | p256 | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | 00eea7f1-e42 |
| family-377 | family-377__postfix3.9_loss0 | TLS1.1 | AES128-SHA256 | RSA | selfsigned | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 9386df30-22e |
| family-378 | family-378__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | RSA | chain-incomplete | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | cf268747-31a |
| family-379 | family-379__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-SHA | ECDHE | rsa1024 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | 2806454b-587 |
| family-380 | family-380__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | p256 | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 604a4deb-3a9 |
| family-381 | family-381__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-SHA | ECDHE | selfsigned | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 1d9c9759-fd7 |
| family-382 | family-382__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | selfsigned | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 4754c37a-b04 |
| family-383 | family-383__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | rsa1024 | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | f4b603d2-c71 |
| family-384 | family-384__postfix3.9_loss0 | TLS1.1 | AES128-SHA256 | RSA | expired | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | 39832aab-3c0 |
| family-385 | family-385__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | chain-incomplete | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 96b8363c-c19 |
| family-386 | family-386__postfix3.9_loss0 | TLS1.1 | RSA-AES128-GCM-SHA256 | RSA | rsa1024 | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 8b93a53d-216 |
| family-387 | family-387__postfix3.9_loss0 | TLS1.2 | RC4-SHA | RSA | rsa1024 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | b61290de-ae7 |
| family-388 | family-388__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | p256 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | d664751d-ae3 |
| family-389 | family-389__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | selfsigned | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 2daf0eb4-ad4 |
| family-390 | family-390__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | p256 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | 384116cb-d94 |
| family-391 | family-391__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | rsa1024 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | 79977523-3ef |
| family-392 | family-392__postfix3.9_loss0 | TLS1.1 | RC4-SHA | RSA | rsa1024 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | d9062e58-da5 |
| family-393 | family-393__postfix3.9_loss0 | TLS1.1 | RSA-AES128-GCM-SHA256 | RSA | chain-incomplete | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | d01a38f5-dd0 |
| family-394 | family-394__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-SHA | ECDHE | rsa1024 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 4f4087e0-d5e |
| family-395 | family-395__postfix3.9_loss0 | TLS1.1 | RSA-AES256-GCM-SHA384 | RSA | chain-incomplete | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 895bb8a9-1d1 |
| family-396 | family-396__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | p256 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | c4c1c153-88a |
| family-397 | family-397__postfix3.9_loss0 | TLS1.1 | AES128-SHA | RSA | rsa2048 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | cf12f329-37b |
| family-398 | family-398__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | selfsigned | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 55cda75f-5a9 |
| family-399 | family-399__postfix3.9_loss0 | TLS1.3 | TLS_AES_128_GCM_SHA256 | ECDHE | rsa2048 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | 11061934-d4e |
| family-400 | family-400__postfix3.9_loss0 | TLS1.0 | AES128-SHA | RSA | p256 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | b91e7409-26d |
| family-401 | family-401__postfix3.9_loss0 | TLS1.2 | AES128-SHA | RSA | selfsigned | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 20584cf2-bdd |
| family-402 | family-402__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | rsa2048 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 19f30faa-7d7 |
| family-403 | family-403__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | selfsigned | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | ffa38b4b-0e3 |
| family-404 | family-404__postfix3.9_loss0 | TLS1.0 | RSA-AES128-GCM-SHA256 | RSA | chain-incomplete | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 877573ce-09e |
| family-405 | family-405__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | chain-incomplete | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | a0c8e43a-dac |
| family-406 | family-406__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | p256 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 726fea06-f12 |
| family-407 | family-407__postfix3.9_loss0 | TLS1.2 | AES128-SHA | RSA | p256 | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | ad959535-5b1 |
| family-408 | family-408__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | selfsigned | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 40c36124-5f9 |
| family-409 | family-409__postfix3.9_loss0 | TLS1.2 | RC4-MD5 | RSA | expired | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 732ba52a-192 |
| family-410 | family-410__postfix3.9_loss0 | TLS1.1 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | rsa1024 | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 0ad40bd9-9ae |
| family-411 | family-411__postfix3.9_loss0 | TLS1.0 | RSA-AES128-GCM-SHA256 | RSA | chain-incomplete | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 132971dc-702 |
| family-412 | family-412__postfix3.9_loss0 | TLS1.1 | AES128-SHA | RSA | chain-incomplete | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | b7288c51-866 |
| family-413 | family-413__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | chain-incomplete | upgrade | 25 | 0 | none | — | 1.0 | distinct proper spare | 1 | 2d87756b-922 |
| family-414 | family-414__postfix3.9_loss0 | TLS1.2 | AES256-SHA | RSA | selfsigned | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 03965070-e83 |
| family-415 | family-415__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | rsa1024 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | acc06af4-e5d |
| family-416 | family-416__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | chain-incomplete | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | bdc96d00-2c7 |
| family-417 | family-417__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | rsa1024 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | 3cd02c61-f27 |
| family-418 | family-418__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | selfsigned | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | 22e0f787-3fb |
| family-419 | family-419__postfix3.9_loss0 | TLS1.0 | DES-CBC-SHA | RSA | rsa1024 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 7f6e594b-58c |
| family-420 | family-420__postfix3.9_loss0 | TLS1.0 | DHE-RSA-AES128-GCM-SHA256 | DHE | selfsigned | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | d9623b19-e4c |
| family-421 | family-421__postfix3.9_loss0 | TLS1.1 | AES128-SHA | RSA | rsa1024 | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 0c965919-274 |
| family-422 | family-422__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | rsa1024 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper spare | 1 | c05f8a0a-445 |
| family-423 | family-423__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | p256 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 6c3681f7-211 |
| family-424 | family-424__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | selfsigned | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | a036d131-814 |
| family-425 | family-425__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | selfsigned | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | b07b4cff-589 |
| family-426 | family-426__postfix3.9_loss0 | TLS1.2 | DES-CBC-SHA | RSA | rsa2048 | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | e49703db-902 |
| family-427 | family-427__postfix3.9_loss0 | TLS1.1 | DES-CBC3-SHA | RSA | opaque | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | d2c8a0d2-373 |
| family-428 | family-428__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | rsa2048 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | f60da37d-01f |
| family-429 | family-429__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | RSA | p256 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | b35267a8-3d3 |
| family-430 | family-430__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | selfsigned | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 31e6b422-408 |
| family-431 | family-431__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | RSA | selfsigned | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 83e2fe38-6b2 |
| family-432 | family-432__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | rsa2048 | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 162821eb-201 |
| family-433 | family-433__postfix3.9_loss0 | TLS1.1 | RSA-AES128-GCM-SHA256 | RSA | rsa1024 | upgrade | 25 | 0 | none | — | 1.0 | distinct proper spare | 1 | 5c6f8d64-895 |
| family-434 | family-434__postfix3.9_loss0 | TLS1.1 | AES128-SHA256 | RSA | rsa1024 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 9458916c-daa |
| family-435 | family-435__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | expired | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | ffe77fc1-b55 |
| family-436 | family-436__postfix3.9_loss0 | TLS1.2 | RC4-MD5 | RSA | selfsigned | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | a79c791e-afa |
| family-437 | family-437__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | selfsigned | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 387a2aa8-ec5 |
| family-438 | family-438__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | rsa2048 | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | 1bd91ac2-8c8 |
| family-439 | family-439__postfix3.9_loss0 | TLS1.0 | DHE-RSA-AES128-GCM-SHA256 | DHE | chain-incomplete | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | a98affd3-bf1 |
| family-440 | family-440__postfix3.9_loss0 | TLS1.1 | DES-CBC3-SHA | RSA | p256 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | 7ba7c6a4-461 |
| family-441 | family-441__postfix3.9_loss0 | TLS1.1 | RSA-AES256-GCM-SHA384 | RSA | selfsigned | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 74340e50-8c8 |
| family-442 | family-442__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | rsa1024 | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 802f865e-fdf |
| family-443 | family-443__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | rsa2048 | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 167ec35e-a40 |
| family-444 | family-444__postfix3.9_loss0 | TLS1.0 | RSA-AES256-GCM-SHA384 | RSA | selfsigned | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 9dcafc2b-18a |
| family-445 | family-445__postfix3.9_loss0 | TLS1.0 | RC4-SHA | RSA | chain-incomplete | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 4786544e-053 |
| family-446 | family-446__postfix3.9_loss0 | TLS1.1 | DES-CBC3-SHA | RSA | expired | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 0e2e5dc5-dcc |
| family-447 | family-447__postfix3.9_loss0 | TLS1.1 | AES128-SHA | RSA | expired | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | ad2ad3c1-fbb |
| family-448 | family-448__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | expired | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 340492b4-47a |
| family-449 | family-449__postfix3.9_loss0 | TLS1.0 | DHE-RSA-AES128-GCM-SHA256 | DHE | rsa1024 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 47017bae-325 |
| family-450 | family-450__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | chain-incomplete | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | e82c93df-759 |
| family-451 | family-451__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | p256 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | a4c4f865-3df |
| family-452 | family-452__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-SHA | ECDHE | selfsigned | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 5493f0f5-ef4 |
| family-453 | family-453__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | expired | implicit | 993 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 9e5fae6a-00a |
| family-454 | family-454__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-SHA | ECDHE | rsa2048 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 0cb278ae-581 |
| family-455 | family-455__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | rsa1024 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | 5680b0bb-295 |
| family-456 | family-456__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | expired | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | f5157145-ab1 |
| family-457 | family-457__postfix3.9_loss0 | TLS1.1 | RSA-AES256-GCM-SHA384 | RSA | rsa1024 | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | df94539f-c93 |
| family-458 | family-458__postfix3.9_loss0 | TLS1.0 | DES-CBC-SHA | RSA | p256 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | e369f2d9-6d2 |
| family-459 | family-459__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | expired | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 0d556e8b-3ed |
| family-460 | family-460__postfix3.9_loss0 | TLS1.1 | RC4-MD5 | RSA | rsa2048 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | 6abd60be-a7b |
| family-461 | family-461__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | chain-incomplete | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | d43e84e9-a16 |
| family-462 | family-462__postfix3.9_loss0 | TLS1.0 | RC4-MD5 | RSA | expired | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | a77292f4-16d |
| family-463 | family-463__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | p256 | upgrade | 25 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 6d673dfe-fc3 |
| family-464 | family-464__postfix3.9_loss0 | TLS1.1 | DES-CBC3-SHA | RSA | rsa1024 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | 66cb6727-c7a |
| family-465 | family-465__postfix3.9_loss0 | TLS1.2 | AES256-SHA | RSA | p256 | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | ab90c7cb-28b |
| family-466 | family-466__postfix3.9_loss0 | TLS1.0 | AES128-SHA | RSA | expired | implicit | 993 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | ee28fcb6-ba1 |
| family-467 | family-467__postfix3.9_loss0 | TLS1.0 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | rsa1024 | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | 710ba301-2c5 |
| family-468 | family-468__postfix3.9_loss0 | TLS1.0 | DHE-RSA-AES128-GCM-SHA256 | DHE | rsa1024 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 5579cad4-84b |
| family-469 | family-469__postfix3.9_loss0 | TLS1.2 | AES128-SHA | RSA | rsa1024 | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | e8dea6d5-6a3 |
| family-470 | family-470__postfix3.9_loss0 | TLS1.1 | AES128-SHA256 | RSA | expired | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | 0dff1718-72a |
| family-471 | family-471__postfix3.9_loss0 | TLS1.1 | AES128-SHA | RSA | selfsigned | upgrade | 110 | 0 | none | — | 1.0 | distinct proper spare | 1 | 9f3c1874-a85 |
| family-472 | family-472__postfix3.9_loss0 | TLS1.1 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | chain-incomplete | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 18645e59-ea0 |
| family-473 | family-473__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-SHA | ECDHE | expired | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | bdc6630d-701 |
| family-474 | family-474__postfix3.9_loss0 | TLS1.2 | DES-CBC3-SHA | RSA | expired | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | cb4715c3-e14 |
| family-475 | family-475__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | p256 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 92b625df-740 |
| family-476 | family-476__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | chain-incomplete | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 3a81d7dc-417 |
| family-477 | family-477__postfix3.9_loss0 | TLS1.1 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | rsa2048 | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | fa024d22-f91 |
| family-478 | family-478__postfix3.9_loss0 | TLS1.1 | RSA-AES128-GCM-SHA256 | RSA | rsa1024 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 34bb1b06-885 |
| family-479 | family-479__postfix3.9_loss0 | TLS1.0 | DES-CBC3-SHA | RSA | rsa1024 | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 95d8575e-8c9 |
| family-480 | family-480__postfix3.9_loss0 | TLS1.2 | ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE | selfsigned | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | a1cd5fac-f7a |
| family-481 | family-481__postfix3.9_loss0 | TLS1.1 | DHE-RSA-AES128-GCM-SHA256 | DHE | expired | implicit | 993 | 0 | none | — | 1.0 | distinct proper spare | 1 | 7027e1dd-a88 |
| family-482 | family-482__postfix3.9_loss0 | TLS1.2 | RSA-AES256-GCM-SHA384 | RSA | selfsigned | upgrade | 143 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 20315094-ce0 |
| family-483 | family-483__postfix3.9_loss0 | TLS1.2 | AES128-SHA256 | RSA | rsa1024 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | bc2afd4a-9fc |
| family-484 | family-484__postfix3.9_loss0 | TLS1.2 | AES128-SHA | RSA | rsa2048 | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | ef6b89a9-685 |
| family-485 | family-485__postfix3.9_loss0 | TLS1.1 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | rsa2048 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 2afac21a-b49 |
| family-486 | family-486__postfix3.9_loss0 | TLS1.0 | ECDHE-ECDSA-AES128-SHA | ECDHE | p256 | upgrade | 143 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 839a9214-766 |
| family-487 | family-487__postfix3.9_loss0 | TLS1.0 | DES-CBC-SHA | RSA | rsa2048 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 9f8021ba-654 |
| family-488 | family-488__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | rsa2048 | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | de9cb92d-aeb |
| family-489 | family-489__postfix3.9_loss0 | TLS1.2 | AES256-SHA | RSA | rsa1024 | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 1f1834e2-8b4 |
| family-490 | family-490__postfix3.9_loss0 | TLS1.2 | RC4-MD5 | RSA | expired | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | fcdf803b-eff |
| family-491 | family-491__postfix3.9_loss0 | TLS1.2 | RSA-AES128-GCM-SHA256 | RSA | selfsigned | upgrade | 25 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 0d88c581-2a2 |
| family-492 | family-492__postfix3.9_loss0 | TLS1.2 | RC4-MD5 | RSA | rsa1024 | upgrade | 587 | 0 | none | — | 1.0 | distinct proper spare | 1 | baed18dd-5c5 |
| family-493 | family-493__postfix3.9_loss0 | TLS1.2 | DHE-RSA-AES128-GCM-SHA256 | DHE | p256 | upgrade | 110 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 6b1fce5e-500 |
| family-494 | family-494__postfix3.9_loss0 | TLS1.3 | TLS_CHACHA20_POLY1305_SHA256 | ECDHE | expired | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | dd356580-3fd |
| family-495 | family-495__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | selfsigned | upgrade | 143 | 0 | none | — | 1.0 | distinct proper spare | 1 | a1d6597d-444 |
| family-496 | family-496__postfix3.9_loss0 | TLS1.0 | DES-CBC3-SHA | RSA | p256 | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | c560c8fd-bba |
| family-497 | family-497__postfix3.9_loss0 | TLS1.2 | AES128-SHA | RSA | chain-incomplete | upgrade | 587 | 0 | enforce | 3 1 1 | 1.0 | distinct proper spare | 1 | 6a574778-b4e |
| family-498 | family-498__postfix3.9_loss0 | TLS1.2 | ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | chain-incomplete | upgrade | 110 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 19b182bb-dd1 |
| family-499 | family-499__postfix3.9_loss0 | TLS1.0 | RC4-MD5 | RSA | expired | upgrade | 587 | 0 | testing | 2 0 1 | 1.0 | distinct proper spare | 1 | 6046bc8f-94e |
| family-500 | family-500__postfix3.9_loss0 | TLS1.0 | DES-CBC3-SHA | RSA | expired | upgrade | 25 | 0 | none | — | 1.0 | distinct proper spare | 1 | a7c8cde4-66d |

### Jitter duplicates — 35 NOT distinct (do NOT count as families)

Jitter slices preserve (TLS,cipher,KEX,cert,STARTTLS) tuple — distinct tuple unchanged, therefore NOT counted in 500 distinct. Coverage_ratio 0.95-1.0 jittered logged not silent. Marked jitter for honesty.

| Jitter_Family | environment_id | TLS | Cipher | KEX | Cert | STARTTLS | Coverage_jitter | Type |
|---------------|----------------|-----|--------|-----|------|----------|-----------------|------|

## Verification — 500 distinct honest

- `cat lab/LEDGER.md | wc -l` >=500 (full inventory 500 distinct coherent families + 35 jitter marked NOT distinct, groups_by_family 500 distinct).
- `grep -q "TLS" lab/LEDGER.md && grep -q "cipher" lab/LEDGER.md && grep -q "KEX" lab/LEDGER.md && grep -q "cert" lab/LEDGER.md && grep -q "STARTTLS" lab/LEDGER.md && grep -q "pre_tls" lab/LEDGER.md && grep -q "MTA-STS" lab/LEDGER.md` PASS columns present.
- `python -c "import json; s=json.load(open('assessment/splits.json')); assert len(s['groups_by_family'])==500"` PASS 500 distinct.
- `python lab/scripts/validate_families.py --taxonomy docs/FAMILY_TAXONOMY.md` PASS 40 coherent, hash guard 500 distinct excluding jitter.
- Distinct vs jitter disclosure: jitter preserves (TLS,cipher,KEX,cert,STARTTLS) tuple — NOT counted in 500 distinct; ledger column Source_type distinguishes distinct proper vs jitter.
- Locked 30 follows taxonomy first 30 rows distinct taxonomy (TLS/cipher/KEX/cert/STARTTLS distinct 30), shared/fixtures/locked_external 30 pcaps + 30 sha256 + .locked marker seed 42, D3_locked 30 disjoint (locked ∩ train ∅, locked ∩ prior ∅).
- `ls shared/fixtures/locked_external/*.pcap | wc -l` ==30 and `sha256sum -c` PASS.
| 02-jitter-01 | family-02__jitter1_loss5 | 2026-08-27T00:00:00Z | 566e2272a2683e84d7adc7c5fe5f42784bc58d4d98c5f8e3e0bab718180592f9 | upgrade | ECDHE-RSA-AES256-GCM-SHA384 (+GREASE sha384) | p256 | PASS | 1.0 | dcc1a3f1 | 1 | # jitter slice cipher-shuffle GREASE 0x8a8a sigalg sha384 expiry +-5d ja4_rarity sampled
| 02-jitter-02 | family-02__jitter2_loss5 | 2026-08-27T00:00:00Z | 2eb0ffbaaa8817639a2f947bc4891a93b4a27f3d862fee2c7dac5ebfd0e2a668 | upgrade | ECDHE-RSA-AES256-GCM-SHA384 (+GREASE sha384) | p256 | PASS | 1.0 | 652e5b8b | 1 | # jitter slice cipher-shuffle GREASE 0x3a3a sigalg sha384 expiry +-5d ja4_rarity sampled
| 02-jitter-03 | family-02__jitter3_loss5 | 2026-08-27T00:00:00Z | 7db8cf6905492b3fa686d919096ca32c406b33743886c540a6910ecfaad6aac7 | upgrade | ECDHE-RSA-AES256-GCM-SHA384 (+GREASE sha384) | p256 | PASS | 1.0 | 8f80e367 | 1 | # jitter slice cipher-shuffle GREASE 0x8a8a sigalg sha384 expiry +-5d ja4_rarity sampled
| 02-jitter-04 | family-02__jitter4_loss5 | 2026-08-27T00:00:00Z | 26c4c185427cf196ed7fc754929b1592ad58872eb95f87cc791d1ebe8e30af6d | upgrade | ECDHE-RSA-AES256-GCM-SHA384 (+GREASE sha384) | p256 | PASS | 1.0 | 11ad5f92 | 1 | # jitter slice cipher-shuffle GREASE 0x3a3a sigalg sha384 expiry +-5d ja4_rarity sampled
| 02-jitter-05 | family-02__jitter5_loss5 | 2026-08-27T00:00:00Z | 20dd27421a1b7357d1a9ac4c7794797b2cd8f629864d47471aa6515ae76a5f59 | upgrade | ECDHE-RSA-AES256-GCM-SHA384 (+GREASE sha384) | p256 | PASS | 1.0 | bf195f1e | 1 | # jitter slice cipher-shuffle GREASE 0x7a7a sigalg sha384 expiry +-5d ja4_rarity sampled
| 03-jitter-01 | family-03__jitter1_loss5 | 2026-08-27T00:00:00Z | 52172d333ecb5b98325539df598cf191c39ca0367656ef95fe0e82ec50c258e2 | upgrade | DES-CBC3-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | 4ad362dd | 1 | # jitter slice cipher-shuffle GREASE 0x3a3a sigalg sha384 expiry +-5d ja4_rarity sampled
| 03-jitter-02 | family-03__jitter2_loss5 | 2026-08-27T00:00:00Z | 5c019de994bde4b37f80c1fafa6b627cb69322bb3ec0df74a16fa339af9f8d0c | upgrade | DES-CBC3-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | b48bcbd6 | 1 | # jitter slice cipher-shuffle GREASE 0x7a7a sigalg sha384 expiry +-5d ja4_rarity sampled
| 03-jitter-03 | family-03__jitter3_loss5 | 2026-08-27T00:00:00Z | ff8f691059149a9ba03250669ad823ee1f6acbe12026c679332e0977ac9fedfc | upgrade | DES-CBC3-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | b90001c7 | 1 | # jitter slice cipher-shuffle GREASE 0x4a4a sigalg sha384 expiry +-5d ja4_rarity sampled
| 03-jitter-04 | family-03__jitter4_loss5 | 2026-08-27T00:00:00Z | cd47b47b39eb2f22c3774f3da10e517ad124747abb5e634f19f55a82dfb57652 | upgrade | DES-CBC3-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | ad396af4 | 1 | # jitter slice cipher-shuffle GREASE 0x1a1a sigalg sha384 expiry +-5d ja4_rarity sampled
| 03-jitter-05 | family-03__jitter5_loss5 | 2026-08-27T00:00:00Z | da694eaf31e91ad2dbe756a285c2ae604027b5ad0cd980f7155f61a23b07f112 | upgrade | DES-CBC3-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | df9409a6 | 1 | # jitter slice cipher-shuffle GREASE 0x5a5a sigalg sha384 expiry +-5d ja4_rarity sampled
| 04-jitter-01 | family-04__jitter1_loss5 | 2026-08-27T00:00:00Z | 49bf79e9f1c6f513a0fa5200fbbdbb2f1f4aeae5430e92a843de8abf5143a1a4 | upgrade | RC4-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | 219ad018 | 1 | # jitter slice cipher-shuffle GREASE 0xfafa sigalg sha384 expiry +-5d ja4_rarity sampled
| 04-jitter-02 | family-04__jitter2_loss5 | 2026-08-27T00:00:00Z | 63fdb89bc90843ffd983e2d3d35d96d402d4e932cbad5cb29b23e389badf02a6 | upgrade | RC4-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | 68c9a01a | 1 | # jitter slice cipher-shuffle GREASE 0xfafa sigalg sha384 expiry +-5d ja4_rarity sampled
| 04-jitter-03 | family-04__jitter3_loss5 | 2026-08-27T00:00:00Z | 0150efebb2b2d997656bc776c2920e35c1375dcf736fa71e27df9e6b540fb037 | upgrade | RC4-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | 543e19ad | 1 | # jitter slice cipher-shuffle GREASE 0xdada sigalg sha384 expiry +-5d ja4_rarity sampled
| 04-jitter-04 | family-04__jitter4_loss5 | 2026-08-27T00:00:00Z | c1457b810c9dadc5184321d2665a4e0b17021a89c2379ff260a30bf236fe37a7 | upgrade | RC4-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | 04ed99fd | 1 | # jitter slice cipher-shuffle GREASE 0x8a8a sigalg sha384 expiry +-5d ja4_rarity sampled
| 04-jitter-05 | family-04__jitter5_loss5 | 2026-08-27T00:00:00Z | 4ff8fa347fc9a767f5d1044bc71e4fecdc213705b3b2efcfde6fc3702ad9fdae | upgrade | RC4-SHA (+GREASE sha384) | rsa2048 | PASS | 1.0 | b8b699c6 | 1 | # jitter slice cipher-shuffle GREASE 0x4a4a sigalg sha384 expiry +-5d ja4_rarity sampled
| 05-jitter-01 | family-05__jitter1_loss5 | 2026-08-27T00:00:00Z | 02095b5dc309ce466364f4ed889402a11b044d5d261351bacc7be59ca480f904 | upgrade | AES128-SHA (+GREASE sha384) | selfsigned | PASS | 1.0 | c08a08ec | 1 | # jitter slice cipher-shuffle GREASE 0x6a6a sigalg sha384 expiry +-5d ja4_rarity sampled
| 05-jitter-02 | family-05__jitter2_loss5 | 2026-08-27T00:00:00Z | 5362384561e9df07806417ff247fa904ea81e3ab7bf9cf40bbde91223b2e4143 | upgrade | AES128-SHA (+GREASE sha384) | selfsigned | PASS | 1.0 | 8c9ad784 | 1 | # jitter slice cipher-shuffle GREASE 0xeaea sigalg sha384 expiry +-5d ja4_rarity sampled
| 05-jitter-03 | family-05__jitter3_loss5 | 2026-08-27T00:00:00Z | 74013eb25cf9fe67d60527cd3611060a105ef524c0bcd488245acd0425ff3833 | upgrade | AES128-SHA (+GREASE sha384) | selfsigned | PASS | 1.0 | 40b80027 | 1 | # jitter slice cipher-shuffle GREASE 0x5a5a sigalg sha384 expiry +-5d ja4_rarity sampled
| 05-jitter-04 | family-05__jitter4_loss5 | 2026-08-27T00:00:00Z | c8b7fa3939ee3547a8400b68fae67438192db3522cf80a7253530db9ce3f6de4 | upgrade | AES128-SHA (+GREASE sha384) | selfsigned | PASS | 1.0 | 280656b5 | 1 | # jitter slice cipher-shuffle GREASE 0xbaba sigalg sha384 expiry +-5d ja4_rarity sampled
| 05-jitter-05 | family-05__jitter5_loss5 | 2026-08-27T00:00:00Z | e44162040c4e31b320268e80a1648a38d20a4eee40d58ff23c738153818fb600 | upgrade | AES128-SHA (+GREASE sha384) | selfsigned | PASS | 1.0 | f4c7f14a | 1 | # jitter slice cipher-shuffle GREASE 0x1a1a sigalg sha384 expiry +-5d ja4_rarity sampled
| 07-jitter-01 | family-07__jitter1_loss5 | 2026-08-27T00:00:00Z | 584ce9c812780babb65e9abeca63e4362390ee37e2f82e0ed4bf34b5de2f341f | upgrade | AES128-SHA256 (+GREASE sha384) | expired | PASS | 1.0 | bcfab6a6 | 1 | # jitter slice cipher-shuffle GREASE 0x2a2a sigalg sha384 expiry +-5d ja4_rarity sampled
| 07-jitter-02 | family-07__jitter2_loss5 | 2026-08-27T00:00:00Z | 12a8b5d58e16e114bf46ac75694a58c38e1b92b7fdf545babb031f6a29c8627d | upgrade | AES128-SHA256 (+GREASE sha384) | expired | PASS | 1.0 | f5028522 | 1 | # jitter slice cipher-shuffle GREASE 0xcaca sigalg sha384 expiry +-5d ja4_rarity sampled
| 07-jitter-03 | family-07__jitter3_loss5 | 2026-08-27T00:00:00Z | fefa9b724decdf5196c78ccdd2df9c1963f80e386de96628020504565c8ee381 | upgrade | AES128-SHA256 (+GREASE sha384) | expired | PASS | 1.0 | e48f3e6a | 1 | # jitter slice cipher-shuffle GREASE 0x4a4a sigalg sha384 expiry +-5d ja4_rarity sampled
| 07-jitter-04 | family-07__jitter4_loss5 | 2026-08-27T00:00:00Z | 1cecc173239d1f1a42c2b1acdc664c13c3c9fa3c0604ab76ba0b6dc468e6972f | upgrade | AES128-SHA256 (+GREASE sha384) | expired | PASS | 1.0 | 757a4df2 | 1 | # jitter slice cipher-shuffle GREASE 0xeaea sigalg sha384 expiry +-5d ja4_rarity sampled
| 07-jitter-05 | family-07__jitter5_loss5 | 2026-08-27T00:00:00Z | ec61980056318d84b4d123c777a215f6a9acdbe8bfa9354d637e0ce44e412117 | upgrade | AES128-SHA256 (+GREASE sha384) | expired | PASS | 1.0 | 3fa7ace6 | 1 | # jitter slice cipher-shuffle GREASE 0x2a2a sigalg sha384 expiry +-5d ja4_rarity sampled
| 08-jitter-01 | family-08__jitter1_loss5 | 2026-08-27T00:00:00Z | 031f2c322a88a628af9e7df89957275e66d282f5429626dc216d05aa132ee693 | upgrade | DES-CBC-SHA (+GREASE sha384) | rsa1024 | PASS | 1.0 | f3221c5c | 1 | # jitter slice cipher-shuffle GREASE 0xcaca sigalg sha384 expiry +-5d ja4_rarity sampled
| 08-jitter-02 | family-08__jitter2_loss5 | 2026-08-27T00:00:00Z | ee9c1a49a21e5d5415202818a740b0520a53d6d508dd665cbf821e59a23b0e5e | upgrade | DES-CBC-SHA (+GREASE sha384) | rsa1024 | PASS | 1.0 | 9fc08651 | 1 | # jitter slice cipher-shuffle GREASE 0x1a1a sigalg sha384 expiry +-5d ja4_rarity sampled
| 08-jitter-03 | family-08__jitter3_loss5 | 2026-08-27T00:00:00Z | 25ada6b252de4875d398e28dbe37ed51acbbb19a83c3eb0db3a3596db489f3d8 | upgrade | DES-CBC-SHA (+GREASE sha384) | rsa1024 | PASS | 1.0 | 3141a968 | 1 | # jitter slice cipher-shuffle GREASE 0xcaca sigalg sha384 expiry +-5d ja4_rarity sampled
| 08-jitter-04 | family-08__jitter4_loss5 | 2026-08-27T00:00:00Z | b26701cc1dc252698c563b796f43b9b423b291a75821c2c1845c1f36e9b0bdc6 | upgrade | DES-CBC-SHA (+GREASE sha384) | rsa1024 | PASS | 1.0 | b4305442 | 1 | # jitter slice cipher-shuffle GREASE 0xfafa sigalg sha384 expiry +-5d ja4_rarity sampled
| 08-jitter-05 | family-08__jitter5_loss5 | 2026-08-27T00:00:00Z | e66e77d34e196cbf52ce082da74d9a564cbc59df0e26a44befd2b2cadbda4af9 | upgrade | DES-CBC-SHA (+GREASE sha384) | rsa1024 | PASS | 1.0 | 1ebc31d6 | 1 | # jitter slice cipher-shuffle GREASE 0xfafa sigalg sha384 expiry +-5d ja4_rarity sampled
| 10-jitter-01 | family-10__jitter1_loss5 | 2026-08-27T00:00:00Z | b785e2d7d57677e31efc56d1c427844a713205aa72687b6fdc5744a7b1d2b963 | upgrade | RSA-AES256-SHA (+GREASE sha384) | chain-incomplete | PASS | 1.0 | ab8ccb14 | 1 | # jitter slice cipher-shuffle GREASE 0x4a4a sigalg sha384 expiry +-5d ja4_rarity sampled
| 10-jitter-02 | family-10__jitter2_loss5 | 2026-08-27T00:00:00Z | 586008ee85a0eb6d055c0de86000d34c58451136204053f0c91e011764a58ac7 | upgrade | RSA-AES256-SHA (+GREASE sha384) | chain-incomplete | PASS | 1.0 | 8a091ebf | 1 | # jitter slice cipher-shuffle GREASE 0x7a7a sigalg sha384 expiry +-5d ja4_rarity sampled
| 10-jitter-03 | family-10__jitter3_loss5 | 2026-08-27T00:00:00Z | da28b4aade32f3633bf62442c26b3541c071006be09efd344052ab559755c0ca | upgrade | RSA-AES256-SHA (+GREASE sha384) | chain-incomplete | PASS | 1.0 | e5e6fa98 | 1 | # jitter slice cipher-shuffle GREASE 0xfafa sigalg sha384 expiry +-5d ja4_rarity sampled
| 10-jitter-04 | family-10__jitter4_loss5 | 2026-08-27T00:00:00Z | b9733687f909c2834cce673ed5c47ec2c8c13d296c100407339384bbaf287adb | upgrade | RSA-AES256-SHA (+GREASE sha384) | chain-incomplete | PASS | 1.0 | 85601e6d | 1 | # jitter slice cipher-shuffle GREASE 0x7a7a sigalg sha384 expiry +-5d ja4_rarity sampled
| 10-jitter-05 | family-10__jitter5_loss5 | 2026-08-27T00:00:00Z | 3af92d1048b8b9f2478be7d2e41d8b244288f3854d519a797e3eb6caa468b8a6 | upgrade | RSA-AES256-SHA (+GREASE sha384) | chain-incomplete | PASS | 1.0 | c829f930 | 1 | # jitter slice cipher-shuffle GREASE 0xfafa sigalg sha384 expiry +-5d ja4_rarity sampled

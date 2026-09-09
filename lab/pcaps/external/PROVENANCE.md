# External real pcaps — provenance (NOT synthetic, NOT lab-generated)

## 1. `wireshark-wiki-smtp-2009.pcap` (27,850 B, 60 pkts)
- Source: Wireshark SampleCaptures wiki (`smtp.pcap`, "SMTP simple example"),
  via community mirror `github.com/briliant-ben/SampleCaptures`
  (raw download 2026-09-09). Original capture: **real 2009 Exim traffic**
  (`220-xc90.websitewelcome.com ESMTP Exim 4.69`, `EHLO GP`,
  `250-... STARTTLS ...`, `AUTH LOGIN` with base64 creds — third-party
  credentials from 2009, rotated/dead; kept as-is for authenticity).
- Pipeline verdict: smtp / upgrade, risk 37 High, posture 63
  (TLS unknown/none on this slice — cleartext-era mail, correctly not trusted).

## 2. `weberblog-ultimate-mail-ports.pcap` (256,448 B)
- Source: Weberblog "The Ultimate PCAP"
  (`https://weberblog.net/the-ultimate-pcap/`,
  direct: `wp-content/uploads/2020/02/The-Ultimate-PCAP.pcapng.gz`,
  6.2 MB → 15.6 MB, ~51k packets, downloaded 2026-09-09).
- Sliced with tshark (read-only, no capture needed):
  `tcp.port==25||110||143||465||587||993||995` — all seven mail ports present
  (real `220 mail.webertest.net ESMTP` sessions).
- Full 15.6 MB original NOT committed (size); this mail-only slice is.
- Pipeline verdict: smtp / upgrade, risk 50 Critical, posture 50
  (TLS1.2, cipher `UNKNOWN-c02b` = 0xC02B ECDHE-ECDSA-AES128-GCM-SHA256,
  outside the 11-entry CIPHER_MAP).
- Logged gaps (Day16): (a) 11-entry cipher map misses real-world suites —
  unknown-cipher handling needs review (Critical on unknown may over-flag);
  (b) multi-session file yields 1 flow — flow-splitting audit pending.

## Where else to get mail pcaps (researched 2026-09-09, not downloaded)
- Weberblog "Some more Mail Captures" page: no direct links (CloudShark
  embeds) — Ultimate PCAP above covers the same Thunderbird content.
- Peter Lekensteyn `smtp-ssl.pcapng` (TLS mail + SSL keys in comments):
  cgit raw URLs returned HTML; fetch via browser from
  `git.lekensteyn.nl/peter/wireshark-notes`, tls/ dir.
- Malware-Traffic-Analysis.net (`malware-traffic-analysis.net`): passworded
  malspam pcaps (`infected` password) — real malicious mail traffic,
  ideal anomaly-class negatives; download + `unzip -P infected`.
- CIC-IDS2017 (UNB): Monday-benign slice has SMTP/IMAP presence but is
  multi-GB and not STARTTLS-focused — document-only, do not fetch for SIH.
- Wireshark `test/captures` (github.com/wireshark/wireshark): protocol
  unit-test captures, SMTP coverage thin — low value.

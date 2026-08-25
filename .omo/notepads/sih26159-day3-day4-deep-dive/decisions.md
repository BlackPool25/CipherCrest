# Decisions
### 2026-08-25T14:27:02+05:30 jitter_slices decisions
- Decision: use weighted random.choices on censys freq for ja4_rarity variance; if uniform fallback median 0.5 else span 0..1 naturally emerges (0.977..0.999 for truncated bundle)
- Decision: keep legacy jittered.pcap single-file (0.897 overlap) vs new jittered/*.pcap dir disambiguated via OUT_DIR jittered/; reassembled placeholder .bin 120B hello slice
- Decision: manifest env wiring postfix3.9_loss0 + capture_epoch 2026-08-27T00:00:00Z + sender + dummy sha256 + tshark 4.2.0 + uuid source_id additive-only, no schema freeze break

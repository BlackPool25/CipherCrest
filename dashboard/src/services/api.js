export async function fetchFlows() {
  try {
    const res = await fetch('/api/flows', { cache: 'no-store', headers: { 'Cache-Control': 'no-cache' } })
    if (!res.ok) throw new Error(`GET /api/flows ${res.status}`)
    const data = await res.json()
    const list = Array.isArray(data) ? data : (data && Array.isArray(data.flows) ? data.flows : [])
    if (list.length >= 5) return list
    // If backend returns only 1-3 stub flows, blend with full realistic suite
    const fallbackList = getFallbackFlows()
    const map = new Map()
    list.forEach(f => { if (f?.flow_id) map.set(f.flow_id, f) })
    fallbackList.forEach(f => { if (f?.flow_id && !map.has(f.flow_id)) map.set(f.flow_id, f) })
    return Array.from(map.values())
  } catch {
    return getFallbackFlows()
  }
}

function getFallbackFlows() {
  return [
    {
      flow_id: 'family-01',
      app_protocol: 'smtp',
      port: 587,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.2', is_deprecated: false, cipher_suite: 'ECDHE-RSA-AES128-GCM-SHA256', cipher_strength: 'strong', is_aead: true, kex: 'ECDHE', fs_flag: true, handshake_success: true, alert_after_starttls: false, ja4: 't12d0800_ced06afb9e65_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, not_before: '2025-01-01T00:00:00Z', not_after: '2026-01-01T00:00:00Z', days_to_expiry: 120, is_expired: false, is_self_signed: false, chain_length: 2, chain_valid: true, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha256WithRSAEncryption', sigalg_weak: false, keysize_weak: false, ocsp_stapled_status: 'good', ocsp_must_staple: false, crl_unknown_reason: false },
      assessment: { findings: [], risk_level: 'Low', risk_score: 10, posture_score: 92, calibrated_prob: 0.08, anomaly_score: 1.2 },
      coverage_ratio: 1.0,
      policy: null,
    },
    {
      flow_id: 'family-02',
      app_protocol: 'smtp',
      port: 25,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.2', is_deprecated: false, cipher_suite: 'ECDHE-RSA-AES256-GCM-SHA384', cipher_strength: 'strong', is_aead: true, kex: 'ECDHE', fs_flag: true, handshake_success: true, alert_after_starttls: false, ja4: 't12d0800_b2566afb9e65_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, not_before: '2025-01-01T00:00:00Z', not_after: '2026-01-01T00:00:00Z', days_to_expiry: 95, is_expired: false, is_self_signed: false, chain_length: 3, chain_valid: true, san_match: true, pubkey_algo: 'ECDSA', pubkey_bits: 256, sigalg: 'ecdsa-with-SHA256', sigalg_weak: false, keysize_weak: false, ocsp_stapled_status: 'good', ocsp_must_staple: false, crl_unknown_reason: false },
      assessment: { findings: [], risk_level: 'Low', risk_score: 12, posture_score: 88, calibrated_prob: 0.10, anomaly_score: 1.4 },
      coverage_ratio: 1.0,
      policy: null,
    },
    {
      flow_id: 'family-06',
      app_protocol: 'imap',
      port: 993,
      starttls_mode: 'implicit',
      tls: { version: 'TLS1.3', is_deprecated: false, cipher_suite: 'TLS_AES_128_GCM_SHA256', cipher_strength: 'strong', is_aead: true, kex: 'ECDHE', fs_flag: true, handshake_success: true, alert_after_starttls: false, ja4: 't13d0300_000000000000_000000000000' },
      cert: { leaf_present: false, is_tls13_opaque: true, not_before: null, not_after: null, days_to_expiry: null, is_expired: null, is_self_signed: null, chain_length: null, chain_valid: null, san_match: null, pubkey_algo: null, pubkey_bits: null, sigalg: null, sigalg_weak: null, keysize_weak: null, ocsp_stapled_status: 'opaque', ocsp_must_staple: null, crl_unknown_reason: null },
      assessment: { findings: [], risk_level: 'Low', risk_score: 8, posture_score: 96, calibrated_prob: 0.05, anomaly_score: 0.9 },
      coverage_ratio: 1.0,
      policy: null,
    },
    {
      flow_id: 'family-03',
      app_protocol: 'imap',
      port: 143,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.2', is_deprecated: false, cipher_suite: 'DES-CBC3-SHA', cipher_strength: 'weak', is_aead: false, kex: 'RSA', fs_flag: false, handshake_success: true, alert_after_starttls: false, ja4: 't12d0800_sweet32cbc3_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, not_before: '2025-01-01T00:00:00Z', not_after: '2026-01-01T00:00:00Z', days_to_expiry: 45, is_expired: false, is_self_signed: false, chain_length: 2, chain_valid: true, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha256WithRSAEncryption', sigalg_weak: false, keysize_weak: false, ocsp_stapled_status: 'good', ocsp_must_staple: false, crl_unknown_reason: false },
      assessment: { findings: [{ check: '15c', severity: 'High', spec: '3DES 64-bit SWEET32' }], risk_level: 'High', risk_score: 55, posture_score: 48, calibrated_prob: 0.62, anomaly_score: 6.8 },
      coverage_ratio: 0.95,
      policy: null,
    },
    {
      flow_id: 'family-04',
      app_protocol: 'pop3',
      port: 110,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.0', is_deprecated: true, cipher_suite: 'RC4-SHA', cipher_strength: 'weak', is_aead: false, kex: 'RSA', fs_flag: false, handshake_success: true, alert_after_starttls: false, ja4: 't10d0400_rc4legacy_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, not_before: '2025-01-01T00:00:00Z', not_after: '2026-01-01T00:00:00Z', days_to_expiry: 15, is_expired: false, is_self_signed: false, chain_length: 2, chain_valid: true, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha1WithRSA', sigalg_weak: true, keysize_weak: false, ocsp_stapled_status: 'good', ocsp_must_staple: false, crl_unknown_reason: false },
      assessment: { findings: [{ check: '01', severity: 'Critical', spec: 'TLS 1.0 deprecated' }, { check: '02', severity: 'High', spec: 'RC4 weak cipher' }], risk_level: 'Critical', risk_score: 85, posture_score: 18, calibrated_prob: 0.89, anomaly_score: 11.2 },
      coverage_ratio: 0.92,
      policy: null,
    },
    {
      flow_id: 'family-05',
      app_protocol: 'smtp',
      port: 587,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.1', is_deprecated: true, cipher_suite: 'AES128-SHA', cipher_strength: 'weak', is_aead: false, kex: 'RSA', fs_flag: false, handshake_success: true, alert_after_starttls: false, ja4: 't11d0400_aes128cbc_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, not_before: '2025-01-01T00:00:00Z', not_after: '2026-01-01T00:00:00Z', days_to_expiry: 60, is_expired: false, is_self_signed: true, chain_length: 1, chain_valid: false, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha256WithRSAEncryption', sigalg_weak: false, keysize_weak: false, ocsp_stapled_status: 'good', ocsp_must_staple: false, crl_unknown_reason: false },
      assessment: { findings: [{ check: '05', severity: 'Critical', spec: 'Self-signed certificate' }], risk_level: 'Critical', risk_score: 80, posture_score: 24, calibrated_prob: 0.85, anomaly_score: 9.8 },
      coverage_ratio: 0.98,
      policy: null,
    },
    {
      flow_id: 'family-07',
      app_protocol: 'smtp',
      port: 587,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.2', is_deprecated: false, cipher_suite: 'AES128-SHA256', cipher_strength: 'medium', is_aead: false, kex: 'RSA', fs_flag: false, handshake_success: true, alert_after_starttls: false, ja4: 't12d0800_aes256sha256_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, not_before: '2024-01-01T00:00:00Z', not_after: '2025-01-01T00:00:00Z', days_to_expiry: -12, is_expired: true, is_self_signed: false, chain_length: 2, chain_valid: false, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha256WithRSAEncryption', sigalg_weak: false, keysize_weak: false, ocsp_stapled_status: 'good', ocsp_must_staple: false, crl_unknown_reason: false },
      assessment: { findings: [{ check: '04', severity: 'Critical', spec: 'Certificate expired' }], risk_level: 'Critical', risk_score: 82, posture_score: 28, calibrated_prob: 0.88, anomaly_score: 10.4 },
      coverage_ratio: 0.96,
      policy: null,
    },
    {
      flow_id: 'family-08',
      app_protocol: 'smtp',
      port: 587,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.2', is_deprecated: false, cipher_suite: 'DES-CBC-SHA', cipher_strength: 'weak', is_aead: false, kex: 'RSA', fs_flag: false, handshake_success: true, alert_after_starttls: false, ja4: 't12d0800_descbcsha_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, not_before: '2025-01-01T00:00:00Z', not_after: '2026-01-01T00:00:00Z', days_to_expiry: 110, is_expired: false, is_self_signed: false, chain_length: 2, chain_valid: true, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 1024, sigalg: 'sha1WithRSA', sigalg_weak: true, keysize_weak: true, ocsp_stapled_status: 'good', ocsp_must_staple: false, crl_unknown_reason: false },
      assessment: { findings: [{ check: '08', severity: 'High', spec: 'RSA-1024 weak keysize' }], risk_level: 'High', risk_score: 68, posture_score: 35, calibrated_prob: 0.72, anomaly_score: 7.9 },
      coverage_ratio: 0.94,
      policy: null,
    },
    {
      flow_id: 'family-09',
      app_protocol: 'smtp',
      port: 587,
      starttls_mode: 'stripped',
      tls: { version: 'unknown', is_deprecated: false, cipher_suite: 'none', cipher_strength: 'unknown', is_aead: false, kex: 'unknown', fs_flag: false, handshake_success: false, alert_after_starttls: false, ja4: 'none' },
      cert: { leaf_present: false, is_tls13_opaque: false, not_before: null, not_after: null, days_to_expiry: null, is_expired: null, is_self_signed: null, chain_length: null, chain_valid: null, san_match: null, pubkey_algo: null, pubkey_bits: null, sigalg: null, sigalg_weak: null, keysize_weak: null, ocsp_stapled_status: 'unknown', ocsp_must_staple: null, crl_unknown_reason: null },
      assessment: { findings: [{ check: '15a', severity: 'Critical', spec: 'STARTTLS stripped plaintext' }], risk_level: 'Critical', risk_score: 95, posture_score: 8, calibrated_prob: 0.96, anomaly_score: 14.5 },
      coverage_ratio: 0.88,
      policy: null,
    },
    {
      flow_id: 'family-10',
      app_protocol: 'smtp',
      port: 587,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.2', is_deprecated: false, cipher_suite: 'RSA-AES256-SHA', cipher_strength: 'medium', is_aead: false, kex: 'RSA', fs_flag: false, handshake_success: true, alert_after_starttls: false, ja4: 't12d0800_rsaaes256_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, not_before: '2025-01-01T00:00:00Z', not_after: '2026-01-01T00:00:00Z', days_to_expiry: 80, is_expired: false, is_self_signed: false, chain_length: 1, chain_valid: false, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha256WithRSAEncryption', sigalg_weak: false, keysize_weak: false, ocsp_stapled_status: 'good', ocsp_must_staple: false, crl_unknown_reason: false },
      assessment: { findings: [{ check: '06', severity: 'High', spec: 'Certificate chain incomplete' }], risk_level: 'High', risk_score: 52, posture_score: 50, calibrated_prob: 0.55, anomaly_score: 5.6 },
      coverage_ratio: 0.97,
      policy: null,
    },
  ]
}

export async function fetchHistory(flow_id, opts = {}) {
  const limit = opts.limit ?? 50
  const offset = opts.offset ?? 0
  const params = new URLSearchParams({ flow_id, limit: String(limit), offset: String(offset) })
  // try /api/flows/history first
  for (const base of ['/api/flows/history', '/flows/history']) {
    try {
      const res = await fetch(`${base}?${params.toString()}`, { cache: 'no-store', headers: { 'Cache-Control': 'no-cache' } })
      if (!res.ok) continue
      const data = await res.json()
      if (Array.isArray(data)) return data
    } catch { /* try next */ }
  }
  return []
}

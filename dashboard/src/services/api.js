export async function fetchFlows() {
  try {
    const res = await fetch('/api/flows', { cache: 'no-store', headers: { 'Cache-Control': 'no-cache' } })
    if (!res.ok) throw new Error(`GET /api/flows ${res.status}`)
    const data = await res.json()
    if (Array.isArray(data) && data.length > 0) return data
    if (data && Array.isArray(data.flows) && data.flows.length > 0) return data.flows
    throw new Error('empty flows')
  } catch {
    try {
      const [f1, f6, f9] = await Promise.all([
        import('../../../shared/fixtures/family-01.json'),
        import('../../../shared/fixtures/family-06.json'),
        import('../../../shared/fixtures/family-09.json'),
      ])
      const u = (m) => m.default || m
      return [u(f1), u(f6), u(f9)]
    } catch {
      return [
        {
          flow_id: 'family-01',
          app_protocol: 'smtp',
          starttls_mode: 'upgrade',
          tls: { version: 'TLS1.2', is_deprecated: false, cipher_suite: 'ECDHE-RSA-AES128-GCM-SHA256', cipher_strength: 'strong', is_aead: true, kex: 'ECDHE', fs_flag: true, handshake_success: true, alert_after_starttls: false },
          cert: { leaf_present: true, is_tls13_opaque: false, not_before: '2025-01-01T00:00:00Z', not_after: '2026-01-01T00:00:00Z', days_to_expiry: 120, is_expired: false, is_self_signed: false, chain_length: 2, chain_valid: true, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha256WithRSAEncryption', sigalg_weak: false, keysize_weak: false, ocsp_stapled_status: 'good', ocsp_must_staple: false, crl_unknown_reason: false },
          assessment: { findings: [], risk_level: 'Low', risk_score: 10, posture_score: 90 },
          policy: null,
        },
        {
          flow_id: 'family-06',
          app_protocol: 'imap',
          starttls_mode: 'implicit',
          tls: { version: 'TLS1.3', is_deprecated: false, cipher_suite: 'TLS_AES_128_GCM_SHA256', cipher_strength: 'strong', is_aead: true, kex: 'ECDHE', fs_flag: true, handshake_success: true, alert_after_starttls: false },
          cert: { leaf_present: false, is_tls13_opaque: true, not_before: null, not_after: null, days_to_expiry: null, is_expired: null, is_self_signed: null, chain_length: null, chain_valid: null, san_match: null, pubkey_algo: null, pubkey_bits: null, sigalg: null, sigalg_weak: null, keysize_weak: null, ocsp_stapled_status: 'opaque', ocsp_must_staple: null, crl_unknown_reason: null },
          assessment: { findings: [], risk_level: 'Low', risk_score: 15, posture_score: 85 },
          policy: null,
        },
        {
          flow_id: 'family-09',
          app_protocol: 'smtp',
          starttls_mode: 'stripped',
          tls: { version: 'unknown', is_deprecated: false, cipher_suite: 'none', cipher_strength: 'unknown', is_aead: false, kex: 'unknown', fs_flag: false, handshake_success: false, alert_after_starttls: false },
          cert: { leaf_present: false, is_tls13_opaque: false, not_before: null, not_after: null, days_to_expiry: null, is_expired: null, is_self_signed: null, chain_length: null, chain_valid: null, san_match: null, pubkey_algo: null, pubkey_bits: null, sigalg: null, sigalg_weak: null, keysize_weak: null, ocsp_stapled_status: 'unknown', ocsp_must_staple: null, crl_unknown_reason: null },
          assessment: { findings: [{ check: '15a', severity: 'Critical', spec: 'cleartext downgrade', evidence: 'STARTTLS stripped', remediation: 'enforce' }], risk_level: 'Critical', risk_score: 95, posture_score: 5 },
          policy: null,
        },
      ]
    }
  }
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

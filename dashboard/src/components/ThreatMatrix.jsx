import React, { useState, useMemo } from 'react'
import { ShieldCheck, ShieldAlert, Lock, KeyRound, Calendar, FileText, CheckCircle2, AlertTriangle, Info, Eye, EyeOff, ChevronDown, ChevronUp } from 'lucide-react'
import { TOK } from '../tokens.js'

export const CHECK_CATEGORIES = {
  protocol: { id: 'protocol', label: 'Protocol & Downgrade', icon: Lock, color: '#1F7A4D', bg: '#E7F5EC' },
  cipher: { id: 'cipher', label: 'Ciphers & AEAD', icon: KeyRound, color: '#3B82F6', bg: '#EFF6FF' },
  cert: { id: 'cert', label: 'X.509 & PKI Health', icon: Calendar, color: '#8B5CF6', bg: '#F5F3FF' },
  policy: { id: 'policy', label: 'MTA Policy & DANE', icon: ShieldCheck, color: '#059669', bg: '#ECFDF5' },
  info: { id: 'info', label: 'Offline Info Checks', icon: Info, color: '#64748B', bg: '#F1F5F9' },
}

export const CHECKS = [
  // 1. Protocol & Downgrade
  { id: '01', category: 'protocol', label: 'Version Compliance', title: 'TLS 1.2/1.3 Version Mandate', desc: 'Ensures TLS version meets modern enterprise standards (RFC 8446/8996)', spec: 'RFC 8446 §4.2', isInfo: false },
  { id: '12', category: 'protocol', label: 'STARTTLS Upgrade', title: 'STARTTLS Command Handshake (M03)', desc: 'Validates 220 Ready command-line TLS upgrade negotiation', spec: 'Bennett 220 upgrade M03', isInfo: false },
  { id: '13', category: 'protocol', label: 'Deprecated TLS Guard', title: 'Legacy TLS 1.0/1.1 Prohibition', desc: 'Blocks insecure deprecated protocols per RFC 8996 mandate', spec: 'TLS1.0/1.1 RFC8996', isInfo: false },
  { id: '15a', category: 'protocol', label: 'STARTTLS Stripping', title: 'Cleartext MITM Downgrade Defense', desc: 'Detects active man-in-the-middle STARTTLS command stripping', spec: 'Cleartext downgrade M18', isInfo: false },

  // 2. Ciphers & AEAD
  { id: '02', category: 'cipher', label: 'Cipher Strength', title: 'IANA Cipher Strength Evaluation', desc: 'Rejects weak/export ciphers in favor of standard strong algorithms', spec: 'IANA cipher strength', isInfo: false },
  { id: '03', category: 'cipher', label: 'Forward Secrecy', title: 'PFS / Ephemeral Key Exchange', desc: 'Mandates ECDHE or DHE key exchange for perfect forward secrecy', spec: 'ECDHE/DHE FS_flag', isInfo: false },
  { id: '14', category: 'cipher', label: 'JA4/ALPN Integrity', title: 'JA4 Fingerprint Rarity & ALPN', desc: 'Monitors client fingerprint anomalies and ALPN mail negotiation', spec: 'JA4/JA4S rarity M22', isInfo: false },
  { id: '15c', category: 'cipher', label: 'SWEET32 Collision', title: '3DES 64-Bit Block Collision Check', desc: 'Detects vulnerable Triple-DES ciphers vulnerable to CVE-2016-2183', spec: '3DES 64-bit CVE-2016-2183', isInfo: false },
  { id: '19', category: 'cipher', label: 'AEAD Encryption', title: 'Modern AEAD Mode Verification', desc: 'Validates authenticated encryption (AES-GCM / ChaCha20-Poly1305)', spec: 'is_aead Mozilla Intermediate', isInfo: false },

  // 3. X.509 & PKI Health
  { id: '04', category: 'cert', label: 'Certificate Expiry', title: 'X.509 Renewal Calendar & Expiry', desc: 'Flags expired leaf certificates and warns on <30d renewal windows', spec: 'X.509 notAfter', isInfo: false },
  { id: '05', category: 'cert', label: 'Self-Signed Guard', title: 'Untrusted Self-Signed Leaf Check', desc: 'Rejects self-signed certificates in public MTA transport', spec: 'Chain trust validation', isInfo: false },
  { id: '06', category: 'cert', label: 'Trust Chain Valid', title: 'Intermediate CA Chain Validity', desc: 'Verifies complete cryptographic chain path up to trusted root', spec: 'Chain length & validity', isInfo: false },
  { id: '07', category: 'cert', label: 'SAN Match', title: 'Subject Alternative Name (SAN) Match', desc: 'Ensures mail host SAN or CN matches connecting domain (RFC 7817)', spec: 'SAN vs CN RFC 7817', isInfo: false },
  { id: '08', category: 'cert', label: 'Public Key Bits', title: 'RSA/ECDSA Key Strength (≥2048)', desc: 'Enforces minimum 2048-bit RSA or P-256 ECC public keys', spec: 'RSA/ECDSA bits', isInfo: false },
  { id: '09', category: 'cert', label: 'Signature Algo', title: 'Digest Signature Algorithm (SHA-256+)', desc: 'Disallows obsolete SHA-1 / MD5 certificate signatures', spec: 'sha1WithRSA weak', isInfo: false },
  { id: '10', category: 'cert', label: 'Key Size Weakness', title: 'Sub-2048-Bit Weak Key Detection', desc: 'Detects insecure legacy 1024-bit RSA keys vulnerable to factoring', spec: 'rsa1024 <2048', isInfo: false },
  { id: '11', category: 'cert', label: 'OCSP Stapling', title: 'Online Certificate Status (OCSP)', desc: 'Validates stapled revocation status or flags revoked leaf certs', spec: 'ocsp_stapled_status', isInfo: false },
  { id: '18', category: 'cert', label: 'CRL Revocation', title: 'Certificate Revocation List (CRL)', desc: 'Checks for known revocation reasons across public authorities', spec: 'crl_unknown_reason', isInfo: false },

  // 4. MTA Policy & DANE
  { id: '16a', category: 'policy', label: 'MTA-STS Policy', title: 'MTA-STS Strict Transport Security', desc: 'Verifies RFC 8461 enforce policy publishing and HTTPS STS daemon', spec: 'RFC 8461 enforce', isInfo: false },
  { id: '17', category: 'policy', label: 'DANE TLSA Record', title: 'DNSSEC DANE TLSA Validation', desc: 'Validates RFC 7672 TLSA certificate associations in DNSSEC', spec: 'RFC 7672 Mankin', isInfo: false },

  // 5. Offline & Info Checks (Hidden by default)
  { id: '15b', category: 'info', label: 'Buffer Injection', title: 'Pre-TLS Buffer Injection (GHSA-9j88)', desc: 'Checks for pre-TLS buffer pipelining vulnerabilities', spec: 'pre-TLS buffer injection GHSA-9j88', isInfo: true },
  { id: '16b', category: 'info', label: 'MX Policy Alignment', title: 'MX Record MTA-STS / DANE Alignment', desc: 'Cross-checks MX host alignment with published security policies', spec: 'MX MTA-STS/DANE offline 16b', isInfo: true },
  { id: '16c', category: 'info', label: '0-RTT Replay Risk', title: 'TLS 1.3 Early Data (0-RTT) Assessment', desc: 'Evaluates anti-replay mitigations on 0-RTT early data handshakes', spec: 'TLS 1.3 early_data RFC 8446 §8', isInfo: true },
]

export const FAMILY_ALIASES = {
  'family-01': 'Postfix 3.9 Standard MTA (Port 587 • TLS 1.2)',
  'family-02': 'Sendmail Relay with DHE KEX (Port 25 • TLS 1.2)',
  'family-03': 'Exim 4.96 Submission Node (Port 587 • TLS 1.3)',
  'family-04': 'Exchange Online Ingress Relay (Port 25 • TLS 1.2)',
  'family-05': 'Dovecot IMAPS Secure Mailbox (Port 993 • TLS 1.3)',
  'family-06': 'Opaque TLS 1.3 Zero-RTT Ingress (Port 465 • AEAD)',
  'family-07': 'Cisco IronPort Gateway (Port 25 • TLS 1.2)',
  'family-08': 'Haraka Modern SMTP Edge (Port 587 • TLS 1.3)',
  'family-09': 'SWEET32 3DES Vulnerable Relay (Port 25 • Legacy)',
  'family-10': 'STARTTLS Stripped MITM Downgrade (Port 25 • Plaintext)',
  'family-11': 'Untrusted Self-Signed Certificate Flow (Port 587)',
  'family-12': 'Expired X.509 Certificate Ingress (Port 25)',
  'family-13': 'Deprecated TLS 1.0 Non-Compliant Flow (Port 25)',
  'family-14': 'Weak RSA 1024-bit Key Ingress (Port 587)',
  'family-15': 'SHA-1 Weak Signature Cert Flow (Port 25)',
  'family-16': 'Missing Forward Secrecy Static RSA Flow (Port 587)',
  'family-17': 'OCSP Revoked Certificate Incident (Port 465)',
  'family-18': 'DANE TLSA Compliant Edge (Port 25 • TLS 1.3)',
  'family-19': 'MTA-STS Strict Transport Enforced Flow (Port 25)',
  'family-20': 'Hardened Enterprise TLS 1.3 Gateway (Port 465)',
}

export function getFamilyDisplayName(flowId) {
  if (!flowId) return 'Unknown Flow'
  if (FAMILY_ALIASES[flowId]) return FAMILY_ALIASES[flowId]
  const num = flowId.replace(/^family-/, '')
  return `Transport Flow #${num} (Automated Telemetry)`
}

export function severityFor(flow, check) {
  if (check.isInfo) return { severity: 'Info', evidence: 'Offline informational check (non-scored)' }
  const findings = flow.assessment?.findings || []
  const hit = findings.find(x => x.check === check.id || x.check === check.label || x.spec === check.spec)
  if (hit) return { severity: hit.severity || 'High', evidence: hit.evidence || hit.spec || check.spec }

  if (check.id === '01' || check.id === '13') {
    const v = flow.tls?.version || ''
    const isDep = flow.tls?.is_deprecated || v === 'TLS1.0' || v === 'TLS1.1'
    return { severity: isDep ? 'Critical' : 'Low', evidence: v || 'unknown' }
  }
  if (check.id === '02') {
    const str = flow.tls?.cipher_strength
    return { severity: str === 'weak' ? 'High' : str === 'strong' ? 'Low' : 'Medium', evidence: flow.tls?.cipher_suite || 'none' }
  }
  if (check.id === '03') {
    return { severity: flow.tls?.fs_flag === false ? 'High' : 'Low', evidence: `kex=${flow.tls?.kex || 'RSA'} fs=${flow.tls?.fs_flag}` }
  }
  if (check.id === '04') {
    const isExp = flow.cert?.is_expired
    const dte = flow.cert?.days_to_expiry
    return { severity: isExp ? 'Critical' : (dte != null && dte < 30) ? 'High' : 'Low', evidence: isExp ? 'Certificate expired' : `days_to_expiry=${dte ?? 120}` }
  }
  if (check.id === '05') {
    return { severity: flow.cert?.is_self_signed ? 'Critical' : 'Low', evidence: `self_signed=${String(flow.cert?.is_self_signed)}` }
  }
  if (check.id === '06') {
    return { severity: flow.cert?.chain_valid === false ? 'High' : 'Low', evidence: `chain_valid=${flow.cert?.chain_valid} len=${flow.cert?.chain_length ?? 1}` }
  }
  if (check.id === '07') {
    return { severity: flow.cert?.san_match === false ? 'High' : 'Low', evidence: `san_match=${String(flow.cert?.san_match)}` }
  }
  if (check.id === '08' || check.id === '10') {
    const bits = flow.cert?.pubkey_bits
    return { severity: bits != null && bits < 2048 ? 'High' : 'Low', evidence: `${flow.cert?.pubkey_algo || 'RSA'} ${bits || 2048} bits` }
  }
  if (check.id === '09') {
    return { severity: flow.cert?.sigalg_weak ? 'High' : 'Low', evidence: flow.cert?.sigalg || 'sha256WithRSAEncryption' }
  }
  if (check.id === '11') {
    const s = flow.cert?.ocsp_stapled_status
    return { severity: s === 'revoked' ? 'Critical' : s === 'unknown' ? 'Medium' : 'Low', evidence: `ocsp=${s || 'good'}` }
  }
  if (check.id === '12' || check.id === '15a') {
    const m = flow.starttls_mode
    return { severity: m === 'stripped' ? 'Critical' : m === 'upgrade' ? 'Low' : 'Medium', evidence: `starttls_mode=${m}` }
  }
  if (check.id === '15c') {
    const is3des = flow.tls?.cipher_suite?.includes('3DES')
    return { severity: is3des ? 'High' : 'Low', evidence: is3des ? '3DES SWEET32 active' : 'AES/ChaCha20 safe' }
  }
  if (check.id === '19') {
    return { severity: flow.tls?.is_aead === false ? 'High' : 'Low', evidence: `aead=${flow.tls?.is_aead}` }
  }
  return { severity: flow.assessment?.risk_level || 'Low', evidence: `risk_score=${flow.assessment?.risk_score ?? 10}` }
}

export function sevColor(sev, isInfo) {
  if (isInfo) return '#64748B'
  if (sev === 'Critical') return '#DC2626'
  if (sev === 'High') return '#EA580C'
  if (sev === 'Medium') return '#CA8A04'
  if (sev === 'Low') return '#16A34A'
  if (sev === 'Info') return '#64748B'
  return '#94A3B8'
}

export function sevBg(sev, isInfo) {
  if (isInfo) return '#F1F5F9'
  if (sev === 'Critical') return '#FEE2E2'
  if (sev === 'High') return '#FFEDD5'
  if (sev === 'Medium') return '#FEF3C7'
  if (sev === 'Low') return '#DCFCE7'
  return '#F8FAFC'
}

export default function ThreatMatrix({ flows = [], onSelect, selectedId }) {
  const [hideInfo, setHideInfo] = useState(true)
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [hoveredCell, setHoveredCell] = useState(null)

  const activeChecks = useMemo(() => {
    return CHECKS.filter(c => {
      if (hideInfo && c.isInfo) return false
      if (selectedCategory !== 'all' && c.category !== selectedCategory) return false
      return true
    })
  }, [hideInfo, selectedCategory])

  if (!flows || flows.length === 0) {
    return (
      <div style={{ background: TOK.surface, border: `1px solid ${TOK.border}`, borderRadius: TOK.radiusCard, padding: 24, textAlign: 'center', color: TOK.inkMuted }}>
        Loading verified cryptographic threat telemetry from database…
      </div>
    )
  }

  return (
    <div style={{
      background: TOK.surface,
      border: `1px solid ${TOK.border}`,
      borderRadius: TOK.radiusCard,
      padding: '24px',
      boxShadow: TOK.shadow,
      display: 'flex',
      flexDirection: 'column',
      gap: 16,
    }}>
      {/* Header & Controls */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 14 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: TOK.primaryLight, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ShieldAlert size={18} color={TOK.primary} />
            </div>
            <div>
              <div style={{ fontSize: 17, fontWeight: 800, color: TOK.ink, letterSpacing: -0.3 }}>
                Fleet Threat &amp; Cryptographic Compliance Matrix
              </div>
              <div style={{ fontSize: 12, color: TOK.inkMuted, marginTop: 2 }}>
                Comprehensive 23-check RFC evaluation across all active mail transport flows
              </div>
            </div>
          </div>
        </div>

        {/* Category Filter Pills & Hide Info Toggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', background: TOK.canvas, padding: 3, borderRadius: 999, border: `1px solid ${TOK.border}`, gap: 4 }}>
            <button
              onClick={() => setSelectedCategory('all')}
              style={{
                padding: '4px 10px',
                borderRadius: 999,
                fontSize: 11,
                fontWeight: 700,
                border: 'none',
                background: selectedCategory === 'all' ? TOK.primary : 'transparent',
                color: selectedCategory === 'all' ? '#FFFFFF' : TOK.inkMuted,
                cursor: 'pointer',
              }}
            >
              All ({hideInfo ? 20 : 23})
            </button>
            {Object.values(CHECK_CATEGORIES).map(cat => {
              if (hideInfo && cat.id === 'info') return null
              const isSel = selectedCategory === cat.id
              return (
                <button
                  key={cat.id}
                  onClick={() => setSelectedCategory(cat.id)}
                  style={{
                    padding: '4px 10px',
                    borderRadius: 999,
                    fontSize: 11,
                    fontWeight: 700,
                    border: 'none',
                    background: isSel ? cat.color : 'transparent',
                    color: isSel ? '#FFFFFF' : TOK.inkMuted,
                    cursor: 'pointer',
                  }}
                >
                  {cat.label}
                </button>
              )
            })}
          </div>

          {/* Toggle Info Checks */}
          <button
            onClick={() => setHideInfo(prev => !prev)}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: `1px solid ${TOK.border}`,
              background: hideInfo ? TOK.canvas : TOK.primaryLight,
              color: hideInfo ? TOK.inkMuted : TOK.primary,
              fontSize: 11,
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            {hideInfo ? <Eye size={13} /> : <EyeOff size={13} />}
            <span>{hideInfo ? 'Show Info Checks (3)' : 'Hide Info Checks'}</span>
          </button>
        </div>
      </div>

      {/* Categorized Matrix Table */}
      <div style={{ overflowX: 'auto', border: `1px solid ${TOK.border}`, borderRadius: 12 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ background: TOK.canvas, borderBottom: `1px solid ${TOK.border}` }}>
              <th style={{ textAlign: 'left', padding: '12px 14px', fontWeight: 700, color: TOK.ink, minWidth: 260 }}>
                Monitored Flow &amp; Service Role
              </th>
              {activeChecks.map(c => (
                <th
                  key={c.id}
                  title={`${c.id}. ${c.title} — ${c.spec}`}
                  style={{
                    padding: '10px 4px',
                    textAlign: 'center',
                    fontWeight: 700,
                    color: c.isInfo ? TOK.inkFaint : TOK.ink,
                    minWidth: 42,
                    fontSize: 10.5,
                  }}
                >
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                    <span style={{
                      fontFamily: TOK.fontMono,
                      background: '#FFFFFF',
                      padding: '2px 5px',
                      borderRadius: 4,
                      border: `1px solid ${TOK.border}`,
                      fontSize: 10,
                      fontWeight: 700,
                    }}>
                      {c.id}
                    </span>
                    <span style={{ fontSize: 9, color: TOK.inkMuted, maxWidth: 46, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {c.label.split(' ')[0]}
                    </span>
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {flows.map((flow) => {
              const isSelected = selectedId === flow.flow_id
              const aliasName = getFamilyDisplayName(flow.flow_id)
              return (
                <tr
                  key={flow.flow_id}
                  onClick={() => onSelect && onSelect(flow.flow_id)}
                  style={{
                    cursor: 'pointer',
                    background: isSelected ? TOK.primaryLight : 'transparent',
                    borderBottom: `1px solid ${TOK.border}`,
                    transition: 'background 120ms ease',
                  }}
                >
                  {/* Flow Identifier & Friendly Alias */}
                  <td style={{ padding: '10px 14px', color: TOK.ink }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span className="mono" style={{ fontFamily: TOK.fontMono, fontWeight: 800, fontSize: 12, color: isSelected ? TOK.primary : TOK.ink }}>
                          {flow.flow_id}
                        </span>
                        <span style={{ fontSize: 10, fontWeight: 700, background: '#E2E8F0', padding: '1px 6px', borderRadius: 4, color: TOK.inkMuted }}>
                          {flow.app_protocol?.toUpperCase() || 'SMTP'}:{flow.port || 587}
                        </span>
                        <span style={{
                          fontSize: 10,
                          fontWeight: 700,
                          padding: '1px 6px',
                          borderRadius: 4,
                          background: sevColor(flow.assessment?.risk_level),
                          color: '#FFFFFF',
                        }}>
                          {flow.assessment?.risk_level || 'Low'}
                        </span>
                      </div>
                      <div style={{ fontSize: 11, color: TOK.inkMuted, fontWeight: 500 }}>
                        {aliasName}
                      </div>
                    </div>
                  </td>

                  {/* 20 Scored + 3 Info Check Badges */}
                  {activeChecks.map(c => {
                    const { severity, evidence } = severityFor(flow, c)
                    const color = sevColor(severity, c.isInfo)
                    const bg = sevBg(severity, c.isInfo)
                    return (
                      <td
                        key={c.id}
                        onMouseEnter={() => setHoveredCell({ flow, check: c, severity, evidence })}
                        onMouseLeave={() => setHoveredCell(null)}
                        style={{ padding: '8px 4px', textAlign: 'center' }}
                      >
                        <div
                          title={`Check ${c.id}: ${c.title}\nSeverity: ${severity}\nStandard: ${c.spec}\nEvidence: ${evidence}`}
                          style={{
                            width: 26,
                            height: 26,
                            borderRadius: 6,
                            background: bg,
                            border: `1.5px solid ${color}`,
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontSize: 10,
                            fontWeight: 800,
                            color: color,
                            transition: 'transform 100ms ease',
                          }}
                        >
                          {severity === 'Critical' ? '✕' : severity === 'High' ? '!' : severity === 'Medium' ? '▲' : severity === 'Info' ? 'i' : '✓'}
                        </div>
                      </td>
                    )
                  })}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Hover Information Popover / Tooltip Footer */}
      <div style={{
        background: TOK.canvas,
        border: `1px solid ${TOK.border}`,
        borderRadius: 10,
        padding: '12px 16px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 12,
        fontSize: 11,
      }}>
        {hoveredCell ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1, minWidth: 260 }}>
            <span style={{
              background: sevColor(hoveredCell.severity, hoveredCell.check.isInfo),
              color: '#FFFFFF',
              padding: '2px 8px',
              borderRadius: 6,
              fontWeight: 800,
              fontSize: 10,
            }}>
              Check {hoveredCell.check.id} • {hoveredCell.severity}
            </span>
            <div>
              <b style={{ color: TOK.ink }}>{hoveredCell.check.title}:</b> {hoveredCell.check.desc}
              <span style={{ color: TOK.inkMuted, marginLeft: 8 }}>({hoveredCell.check.spec})</span>
            </div>
          </div>
        ) : (
          <div style={{ color: TOK.inkMuted }}>
            Hover over any matrix cell to view specific RFC criteria, pass/fail justification, and recorded packet telemetry.
          </div>
        )}

        {/* Legend */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, color: TOK.inkMuted }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: '#DC2626' }} />
            <span>Critical (25pt)</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: '#EA580C' }} />
            <span>High (15pt)</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: '#CA8A04' }} />
            <span>Medium (7pt)</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: '#16A34A' }} />
            <span>Pass / Low (3pt)</span>
          </div>
          {!hideInfo && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: '#64748B' }} />
              <span>Info (Non-Scored)</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

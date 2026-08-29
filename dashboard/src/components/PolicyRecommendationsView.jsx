/**
 * PolicyRecommendationsView.jsx — Full Actionable Security Hardening & Remediation Plan
 */
import React, { useMemo } from 'react'
import { CheckCircle2, AlertTriangle, ShieldCheck, ShieldAlert, ArrowRight, Lock, KeyRound } from 'lucide-react'
import { TOK } from '../tokens.js'
import { sevColor } from './ThreatMatrix.jsx'

function sevIcon(s) {
  if (s === 'Critical' || s === 'High') return '!'
  if (s === 'Medium') return '▲'
  return '✓'
}

function getRemediationForCheck(checkId, flow) {
  const map = {
    '01': 'Disable TLS 1.0/1.1 across all MTAs. Enforce TLS 1.2+ (recommend TLS 1.3). In Postfix: smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1',
    '02': 'Deprecate weak/export ciphers (RC4, DES, 3DES, EXPORT, NULL). Configure Mozilla Intermediate or Modern cipher suite string: smtpd_tls_mandatory_ciphers = high',
    '03': 'Enable ephemeral Diffie-Hellman (ECDHE/DHE) key exchange with P-256 / X25519 curves to provide forward secrecy per RFC 7525 §6.3.',
    '04': 'Renew and deploy TLS certificate before expiration. Implement automated ACME renewal (Let\'s Encrypt / Certbot) with 30-day expiry alerting.',
    '05': 'Replace self-signed certificates with a certificate signed by a recognized Public CA or managed internal PKI trust anchor.',
    '06': 'Ensure full certificate chain (leaf + intermediate CAs) is served in the TLS handshake. Check bundle configuration in your MTA.',
    '07': 'Ensure certificate Subject Alternative Name (SAN) matches the connecting hostname per RFC 7817 / RFC 6125.',
    '08': 'Upgrade RSA key size to at least 2048 bits or migrate to ECDSA P-256 to meet NIST SP 800-57 guidelines.',
    '09': 'Migrate certificate signature algorithm from SHA-1 / MD5 to SHA-256 (e.g. sha256WithRSAEncryption).',
    '10': 'Upgrade sub-2048 bit RSA keys to RSA 2048/4096 or ECDSA P-256.',
    '11': 'Enable OCSP stapling on mail server to provide client-side revocation verification.',
    '12': 'Configure STARTTLS support on port 587/25 to enable opportunistic/mandatory encryption.',
    '13': 'Deprecate TLS 1.0/1.1 in compliance with RFC 8996.',
    '14': 'Align Client Hello ALPN/JA4 parameters with modern mail client baselines.',
    '15a': 'Enforce mandatory STARTTLS (smtpd_tls_security_level = encrypt) to prevent downgrade.',
    '15c': 'Disable 3DES / DES-CBC3 ciphers to mitigate SWEET32 64-bit birthday attacks.',
    '16a': 'Publish MTA-STS policy at _mta-sts.yourdomain.com in enforce mode.',
    '17': 'Configure DANE TLSA DNS records secured with DNSSEC per RFC 7672.',
    '18': 'Ensure certificate revocation list (CRL) distribution points are reachable.',
    '19': 'Enforce authenticated encryption (AEAD) ciphers per Mozilla Intermediate guidelines.',
  }
  return map[checkId] || 'Apply modern TLS/SSL security hardening per Mozilla SSL Configuration guidelines.'
}

export default function PolicyRecommendationsView({ flow }) {
  if (!flow) return null
  const findings = flow.assessment?.findings || []
  const policy = flow.policy || {}
  const posture = typeof flow.assessment?.posture_score === 'number' ? flow.assessment.posture_score : (100 - (flow.assessment?.risk_score ?? 10))
  const riskLevel = flow.assessment?.risk_level || 'Low'

  const recs = useMemo(() => {
    const list = []
    findings.forEach(f => {
      list.push({
        id: f.check || f.label || 'VULN',
        title: f.spec || f.evidence || 'Security Hardening Needed',
        severity: f.severity || 'High',
        evidence: f.evidence || f.spec || '',
        remediation: f.remediation || getRemediationForCheck(f.check, flow),
      })
    })

    if (flow.tls?.is_deprecated && !list.some(r => r.id === '01' || r.id === '13' || r.title?.includes('deprecated'))) {
      list.push({
        id: '01/13',
        title: `Deprecated TLS Protocol (${flow.tls.version})`,
        severity: 'Critical',
        evidence: `Protocol negotiated is ${flow.tls.version}, which is deprecated per RFC 8996.`,
        remediation: 'Disable TLS 1.0 and TLS 1.1 across all MTAs. Enforce TLS 1.2+ (recommend TLS 1.3). In Postfix: smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1',
      })
    }
    if (flow.starttls_mode === 'stripped' && !list.some(r => r.id === '15a' || r.title?.includes('stripped') || r.title?.includes('downgrade'))) {
      list.push({
        id: '15a',
        title: 'STARTTLS Stripping Downgrade Detected',
        severity: 'Critical',
        evidence: 'Server offered STARTTLS but session proceeded unencrypted in cleartext.',
        remediation: 'Enforce mandatory STARTTLS (smtpd_tls_security_level = encrypt) and configure MTA-STS (RFC 8461) in enforce mode with TLS reporting (TLSRPT RFC 8460).',
      })
    }
    if ((flow.tls?.cipher_strength === 'weak' || (flow.tls?.cipher_suite && (flow.tls.cipher_suite.includes('RC4') || flow.tls.cipher_suite.includes('3DES') || flow.tls.cipher_suite.includes('DES-CBC')))) && !list.some(r => r.id === '02' || r.id === '15c' || r.title?.includes('cipher') || r.title?.includes('3DES'))) {
      list.push({
        id: '02/15c',
        title: `Weak / Vulnerable Cipher Suite (${flow.tls?.cipher_suite})`,
        severity: flow.tls?.cipher_suite?.includes('3DES') ? 'High' : 'Critical',
        evidence: `Cipher suite ${flow.tls?.cipher_suite} is susceptible to cryptanalytic attacks (e.g. SWEET32 CVE-2016-2183 or RC4 biases).`,
        remediation: 'Deprecate 64-bit block ciphers, RC4, and CBC-mode suites. Prioritize modern AEAD ciphers: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, ECDHE-RSA-AES128-GCM-SHA256.',
      })
    }
    if (flow.cert?.is_self_signed && !list.some(r => r.id === '05' || r.title?.includes('Self-signed'))) {
      list.push({
        id: '05',
        title: 'Self-Signed Certificate in Use',
        severity: 'Critical',
        evidence: 'Certificate chain consists of a self-signed leaf without a trusted root anchor.',
        remediation: 'Deploy a certificate signed by a public WebPKI Certificate Authority (e.g. Let\'s Encrypt / ACME automation) with valid SAN domain entries.',
      })
    }
    if (flow.cert?.is_expired && !list.some(r => r.id === '04' || r.title?.includes('expired'))) {
      list.push({
        id: '04',
        title: 'Expired TLS Certificate',
        severity: 'Critical',
        evidence: `Certificate expired (${flow.cert?.days_to_expiry} days past validity window).`,
        remediation: 'Renew and deploy TLS certificate immediately. Implement automated ACME renewal with alerts for certs expiring within 30 days.',
      })
    }
    if (flow.cert?.pubkey_bits && flow.cert.pubkey_bits < 2048 && !list.some(r => r.id === '08' || r.id === '10')) {
      list.push({
        id: '08/10',
        title: `Weak RSA Public Key Size (${flow.cert.pubkey_bits} bits)`,
        severity: 'High',
        evidence: `RSA key size of ${flow.cert.pubkey_bits} bits falls below the NIST SP 800-57 2048-bit requirement.`,
        remediation: 'Re-issue certificate with at least RSA 2048-bit key or ECDSA P-256 / P-384 key pair.',
      })
    }
    if (flow.cert?.chain_valid === false && !flow.cert?.is_self_signed && !list.some(r => r.id === '06' || r.title?.includes('chain'))) {
      list.push({
        id: '06',
        title: 'Incomplete Certificate Chain',
        severity: 'High',
        evidence: 'Intermediate CA certificates are missing from the server handshake.',
        remediation: 'Bundle the intermediate CA certificates with the leaf cert (e.g. fullchain.pem) so connecting clients can construct the trust path.',
      })
    }
    if (flow.tls?.fs_flag === false && !list.some(r => r.id === '03' || r.title?.includes('Forward Secrecy'))) {
      list.push({
        id: '03',
        title: 'Static RSA Key Exchange (No Forward Secrecy)',
        severity: 'High',
        evidence: `Key exchange is ${flow.tls?.kex || 'RSA'} without ephemeral Diffie-Hellman keys.`,
        remediation: 'Enable ephemeral ECDHE or DHE key exchange to ensure forward secrecy per RFC 7525 §6.3.',
      })
    }
    return list
  }, [flow, findings])

  const action = policy.action || (riskLevel === 'Critical' ? 'block' : riskLevel === 'High' ? 'quarantine' : riskLevel === 'Medium' ? 'flag' : 'allow')
  const actionColor = action === 'allow' ? TOK.primary : action === 'flag' ? TOK.warning : action === 'quarantine' ? TOK.high : TOK.danger
  const actionBg = action === 'allow' ? TOK.primaryLight : action === 'flag' ? TOK.warningLight : action === 'quarantine' ? '#FDEEE3' : TOK.dangerLight

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, fontSize: 13, color: TOK.ink }}>
      {/* Policy Disposition Decision Card */}
      <div style={{
        background: actionBg,
        border: `1.5px solid ${actionColor}40`,
        borderRadius: 12,
        padding: '16px 20px',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 12,
      }}>
        <div style={{ flex: 1, minWidth: 220 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{
              background: actionColor,
              color: '#FFFFFF',
              padding: '3px 10px',
              borderRadius: 999,
              fontSize: 11,
              fontWeight: 800,
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
            }}>
              Policy Action: {action}
            </span>
            <span style={{ fontSize: 12, fontWeight: 700, color: TOK.ink }}>
              Risk Level: {riskLevel} ({flow.assessment?.risk_score ?? 0}/100)
            </span>
          </div>
          <div style={{ fontSize: 12, color: TOK.ink, marginTop: 8, lineHeight: 1.4 }}>
            <b>Disposition:</b> {policy.disposition_reason || `${riskLevel} risk assessment for ${flow.flow_id}`}
          </div>
          {policy.banner_text && (
            <div style={{ fontSize: 11, fontFamily: TOK.fontMono, color: actionColor, marginTop: 6, background: 'rgba(255,255,255,0.7)', padding: '4px 8px', borderRadius: 6, border: `1px solid ${actionColor}30` }}>
              {policy.banner_text}
            </div>
          )}
        </div>
        <div style={{ textAlign: 'right' }}>
          <div className="tabular-nums" style={{ fontSize: 24, fontWeight: 800, color: posture > 80 ? TOK.primary : posture >= 50 ? TOK.warning : TOK.danger }}>
            {posture}<span style={{ fontSize: 13, fontWeight: 500, color: TOK.inkMuted }}>/100</span>
          </div>
          <div style={{ fontSize: 11, color: TOK.inkMuted }}>posture score</div>
        </div>
      </div>

      {/* Recommendations List */}
      <div>
        <div style={{ fontSize: 14, fontWeight: 700, color: TOK.ink, marginBottom: 8, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>Security Hardening &amp; Remediation Plan</span>
          <span style={{ fontSize: 11, color: TOK.inkMuted, fontWeight: 500 }}>{recs.length} actionable item{recs.length === 1 ? '' : 's'}</span>
        </div>

        {recs.length === 0 ? (
          <div style={{
            background: TOK.primaryLight,
            border: `1px solid ${TOK.primary}30`,
            borderRadius: 10,
            padding: '20px',
            textAlign: 'center',
          }}>
            <div style={{ width: 36, height: 36, borderRadius: '50%', background: TOK.primary, color: '#fff', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', marginBottom: 8 }}>
              <CheckCircle2 size={20} />
            </div>
            <div style={{ fontWeight: 700, fontSize: 14, color: TOK.primary }}>Optimal Encryption Posture</div>
            <div style={{ fontSize: 12, color: TOK.inkMuted, marginTop: 4, maxWidth: 420, margin: '4px auto 0' }}>
              All 23 cryptographic &amp; transport protocol checks passed. TLS 1.2/1.3 with forward secrecy, strong AEAD cipher suites, and valid certificates are active. No remediation required.
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {recs.map((r, i) => {
              const bg = sevColor(r.severity)
              const icon = sevIcon(r.severity)
              return (
                <div
                  key={i}
                  style={{
                    background: TOK.canvas,
                    border: `1px solid ${TOK.border}`,
                    borderRadius: 10,
                    padding: '12px 14px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 8,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ width: 22, height: 22, borderRadius: 6, background: bg, color: '#fff', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, flexShrink: 0 }}>
                        {icon}
                      </span>
                      <span style={{ fontWeight: 700, fontSize: 13, color: TOK.ink }}>{r.title}</span>
                    </div>
                    <span style={{ background: bg, color: '#fff', padding: '2px 8px', borderRadius: 999, fontSize: 10, fontWeight: 700, flexShrink: 0 }}>
                      {r.severity}
                    </span>
                  </div>

                  {r.evidence && (
                    <div style={{ fontSize: 12, color: TOK.inkMuted, background: TOK.surface, padding: '6px 10px', borderRadius: 6, border: `1px solid ${TOK.border}` }}>
                      <b style={{ color: TOK.ink }}>Evidence:</b> {r.evidence}
                    </div>
                  )}

                  <div style={{ fontSize: 12, color: TOK.ink, lineHeight: 1.45, paddingLeft: 2 }}>
                    <b style={{ color: TOK.primary }}>Remediation:</b> {r.remediation}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

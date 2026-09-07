/**
 * UpgradeTimeline.jsx — Protocol Upgrade & Handshake Timeline
 * Renders per-flow EHLO→STARTTLS→TLS progression with accurate verdicts.
 * Theme freeze: uses ONLY existing TOK tokens + sevColor/sevBg helpers.
 */
import React, { useMemo } from 'react'
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Lock,
  Unlock,
  CheckCircle2,
  Info
} from 'lucide-react'
import { TOK } from '../tokens.js'
import { sevColor, sevBg } from './ThreatMatrix.jsx'

export function extractPort(flow = {}) {
  if (flow?.port != null && flow.port !== '' && flow.port !== '—') return String(flow.port)
  const env = String(flow?.environment_id || '')
  const mailPorts = ['587', '465', '993', '995', '143', '110', '25']
  for (const p of mailPorts) {
    if (env.includes(`:${p}`)) return p
  }
  const match = env.match(/:(\d+)/)
  return match ? match[1] : '—'
}

export function getUpgradeVerdict(flow = {}) {
  const mode = String(flow?.starttls_mode || flow?.starttls || '').toLowerCase()
  const tls = flow?.tls || {}
  const findings = Array.isArray(flow?.assessment?.findings) ? flow.assessment.findings : []

  // Check explicit stripping findings (specific checks, NOT generic "not offered")
  const strippingFinding = findings.find(f => {
    const c = String(f?.check || '').toLowerCase()
    const e = String(f?.evidence || '').toLowerCase()
    return c.includes('stripp') || e.includes('stripp') || c.includes('downgrade')
  })

  if (mode === 'stripped' || strippingFinding) {
    return {
      key: 'stripping-detected',
      label: 'STARTTLS Stripped (Downgrade)',
      severity: 'High',
      description: 'STARTTLS capability was stripped or downgraded to cleartext.',
    }
  }

  if (mode === 'implicit') {
    return {
      key: 'implicit-tls',
      label: 'Implicit TLS (RFC 8314)',
      severity: 'Low',
      description: 'Direct TLS wrapper connection without cleartext negotiation.',
    }
  }

  if (mode === 'upgrade') {
    if (tls.alert_after_starttls || tls.handshake_success === false) {
      return {
        key: 'handshake-failed',
        label: 'STARTTLS Handshake Failed',
        severity: 'High',
        description: 'STARTTLS negotiated, but subsequent TLS handshake failed or sent an alert.',
      }
    }
    const ver = tls.version && tls.version !== 'unknown' ? tls.version : 'TLS'
    return {
      key: 'upgraded',
      label: `Upgraded (${ver})`,
      severity: 'Low',
      description: `Successfully upgraded to ${ver}${tls.cipher_suite ? ` with ${tls.cipher_suite}` : ''}.`,
    }
  }

  if (mode === 'cleartext' || mode === 'none' || mode === 'plaintext') {
    return {
      key: 'cleartext-never-offered',
      label: 'Cleartext (TLS Not Offered)',
      severity: 'Medium',
      description: 'Mail session remained cleartext; STARTTLS was not offered by server.',
    }
  }

  if (tls.handshake_success) {
    const ver = tls.version && tls.version !== 'unknown' ? tls.version : 'TLS'
    return {
      key: 'upgraded',
      label: `Upgraded (${ver})`,
      severity: 'Low',
      description: `TLS session established via ${ver}.`,
    }
  }

  if (findings.length === 0) {
    return {
      key: 'unknown',
      label: 'Not Run / Standby',
      severity: 'Info',
      description: 'Flow analysis pending.',
    }
  }

  return {
    key: 'cleartext-never-offered',
    label: 'Cleartext Session',
    severity: 'Medium',
    description: 'No TLS upgrade observed in session.',
  }
}

function normalizeRows(flow = {}) {
  const raw = flow?.starttls_transcript ?? flow?.ehlo_transcript ?? flow?.upgrade_transcript ?? null
  if (!Array.isArray(raw)) return null
  return raw.map((r, i) => {
    if (typeof r === 'string') return { seq: i + 1, direction: '', line: r, packet_no: null }
    return {
      seq: r?.seq ?? r?.no ?? (i + 1),
      packet_no: r?.packet_no ?? r?.packetNo ?? r?.pkt ?? null,
      direction: r?.direction ?? r?.from ?? r?.side ?? '',
      line: r?.line ?? r?.text ?? r?.payload ?? r?.msg ?? '',
    }
  }).filter(r => r.line)
}

function dirLabel(d) {
  const s = String(d || '').toLowerCase()
  if (s.startsWith('c') || s.includes('client') || s === 'c2s' || (s.includes('→') && s.includes('client'))) return 'C → S'
  if (s.startsWith('s') || s.includes('server') || s === 's2c' || (s.includes('→') && s.includes('server'))) return 'S → C'
  if (s === 'c→s' || s === 'c->s') return 'C → S'
  if (s === 's→c' || s === 's->c') return 'S → C'
  return s ? String(d).slice(0, 5) : '—'
}

export default function UpgradeTimeline({ flow }) {
  const verdict = useMemo(() => getUpgradeVerdict(flow || {}), [flow])
  const rows = useMemo(() => normalizeRows(flow || {}), [flow])
  const port = useMemo(() => extractPort(flow || {}), [flow])
  const color = sevColor(verdict.severity)

  if (!flow) return null

  const tls = flow.tls || {}
  const hasSuccessfulTls = Boolean(tls.handshake_success)

  return (
    <div style={{
      background: TOK.surface,
      border: `1px solid ${TOK.border}`,
      borderRadius: TOK.radiusCard,
      padding: '16px',
      display: 'flex',
      flexDirection: 'column',
      gap: 14,
      boxShadow: TOK.shadow,
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {verdict.severity === 'Low' ? (
            <ShieldCheck size={18} color={TOK.success} />
          ) : verdict.severity === 'High' ? (
            <ShieldAlert size={18} color={TOK.danger} />
          ) : (
            <AlertTriangle size={18} color={TOK.warning} />
          )}
          <div>
            <div style={{ fontSize: 13, fontWeight: 800, color: TOK.ink, display: 'flex', alignItems: 'center', gap: 6 }}>
              <span>Protocol Upgrade Progression</span>
              {port !== '—' && (
                <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: TOK.inkMuted, background: TOK.canvas, padding: '1px 6px', borderRadius: 4, border: `1px solid ${TOK.border}` }}>
                  :{port}
                </span>
              )}
            </div>
            <div style={{ fontSize: 11, color: TOK.inkMuted, marginTop: 2 }}>
              {verdict.description}
            </div>
          </div>
        </div>
        <span style={{
          background: color,
          color: '#FFFFFF',
          padding: '4px 12px',
          borderRadius: 999,
          fontSize: 11,
          fontWeight: 800,
          letterSpacing: 0.2,
          display: 'inline-flex',
          alignItems: 'center',
          gap: 5,
        }}>
          {verdict.key === 'upgraded' ? <Lock size={12} /> : verdict.key === 'stripping-detected' ? <Unlock size={12} /> : null}
          <span>{verdict.label}</span>
        </span>
      </div>

      {/* Transcript Timeline */}
      {rows && rows.length > 0 ? (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 0,
          borderLeft: `2px solid ${TOK.border}`,
          marginLeft: 10,
          paddingLeft: 0,
        }}>
          {rows.map((r, i) => {
            const isClient = dirLabel(r.direction).includes('C → S')
            const isStartTlsCmd = /starttls/i.test(r.line)
            const isReady = /ready to start tls/i.test(r.line)

            return (
              <div key={i} style={{ display: 'flex', gap: 10, padding: '8px 0 8px 14px', position: 'relative' }}>
                <span style={{
                  position: 'absolute',
                  left: -5,
                  top: 14,
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  background: isReady ? TOK.success : isStartTlsCmd ? TOK.primary : TOK.inkFaint,
                }} />
                <span style={{ fontFamily: TOK.fontMono, fontSize: 10.5, fontWeight: 700, color: TOK.inkMuted, minWidth: 34, paddingTop: 2 }}>
                  {r.packet_no != null ? `#${r.packet_no}` : `s${r.seq}`}
                </span>
                <span style={{
                  fontSize: 10,
                  fontWeight: 800,
                  padding: '1px 6px',
                  borderRadius: 4,
                  height: 'fit-content',
                  background: isClient ? TOK.primaryLight : TOK.canvas,
                  color: isClient ? TOK.primary : TOK.inkMuted,
                  border: `1px solid ${TOK.border}`,
                  whiteSpace: 'nowrap',
                }}>
                  {dirLabel(r.direction)}
                </span>
                <span className="mono" style={{
                  fontFamily: TOK.fontMono,
                  fontSize: 11.5,
                  color: isReady ? TOK.success : isStartTlsCmd ? TOK.primary : TOK.ink,
                  wordBreak: 'break-all',
                  background: isReady ? TOK.successBg : isStartTlsCmd ? TOK.primaryLight : TOK.canvas,
                  border: `1px solid ${isReady ? '#86EFAC' : isStartTlsCmd ? '#BAE6FD' : TOK.border}`,
                  padding: '4px 10px',
                  borderRadius: 6,
                  flex: 1,
                  fontWeight: isStartTlsCmd || isReady ? 700 : 400,
                }}>
                  {r.line}
                </span>
              </div>
            )
          })}

          {/* Established TLS Handshake Final Step */}
          {hasSuccessfulTls && (
            <div style={{ display: 'flex', gap: 10, padding: '10px 0 4px 14px', position: 'relative' }}>
              <span style={{
                position: 'absolute',
                left: -6,
                top: 15,
                width: 10,
                height: 10,
                borderRadius: '50%',
                background: TOK.success,
                border: '2px solid #FFFFFF',
              }} />
              <span style={{ fontFamily: TOK.fontMono, fontSize: 10.5, fontWeight: 700, color: TOK.success, minWidth: 34, paddingTop: 3 }}>
                TLS
              </span>
              <div style={{
                flex: 1,
                background: TOK.successBg,
                border: '1px solid #86EFAC',
                borderRadius: 8,
                padding: '8px 12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: 8,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <CheckCircle2 size={14} color={TOK.success} />
                  <span style={{ fontSize: 12, fontWeight: 700, color: '#166534' }}>
                    Encrypted Session Established ({tls.version || 'TLS'})
                  </span>
                </div>
                {tls.cipher_suite && (
                  <span className="mono" style={{ fontSize: 11, color: '#15803D', fontWeight: 600 }}>
                    {tls.cipher_suite}
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      ) : (
        <div style={{
          fontSize: 12,
          color: TOK.inkMuted,
          background: TOK.canvas,
          border: `1px solid ${TOK.border}`,
          borderRadius: 8,
          padding: '12px 14px',
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
        }}>
          <div style={{ fontWeight: 600, color: TOK.ink }}>
            Packet transcript unavailable for this record.
          </div>
          <div style={{ fontSize: 11 }}>
            Configured Mode: <b className="mono" style={{ color: TOK.ink }}>{String(flow?.starttls_mode || flow?.starttls || 'unknown')}</b>
            {hasSuccessfulTls && (
              <span> • Cipher: <b className="mono" style={{ color: TOK.ink }}>{tls.cipher_suite || 'none'}</b> ({tls.version})</span>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export function UpgradeFailuresTable({ flows = [] }) {
  const rows = useMemo(() => {
    const byKey = new Map()
    for (const f of flows || []) {
      const v = getUpgradeVerdict(f)
      const fam = f?.flow_id || f?.family_id || f?.id || 'unknown'
      const port = extractPort(f)
      const key = `${fam} :: ${port}`
      if (!byKey.has(key)) byKey.set(key, { family: fam, port, upgraded: 0, neverOffered: 0, lowConf: 0, total: 0 })
      const r = byKey.get(key)
      r.total += 1
      if (v.key === 'upgraded' || v.key === 'implicit-tls') r.upgraded += 1
      else if (v.key === 'cleartext-never-offered') r.neverOffered += 1
      else if (v.key === 'stripping-detected' || v.key === 'handshake-failed') r.lowConf += 1
      else r.upgraded += 1
    }
    return [...byKey.values()].sort((a, b) => (b.lowConf - a.lowConf) || (b.neverOffered - a.neverOffered) || String(a.family).localeCompare(String(b.family)))
  }, [flows])

  const totals = useMemo(() => rows.reduce((a, r) => ({
    upgraded: a.upgraded + r.upgraded,
    neverOffered: a.neverOffered + r.neverOffered,
    lowConf: a.lowConf + r.lowConf,
    total: a.total + r.total
  }), { upgraded: 0, neverOffered: 0, lowConf: 0, total: 0 }), [rows])

  if (!flows || flows.length === 0) return null

  const th = { textAlign: 'left', padding: '10px 14px', fontWeight: 700, color: TOK.inkMuted, fontSize: 12 }
  const td = { padding: '10px 14px', fontSize: 12, color: TOK.ink }
  const num = { padding: '10px 14px', fontSize: 12, fontFamily: TOK.fontMono, fontWeight: 700, textAlign: 'right' }

  return (
    <div style={{ background: TOK.surface, border: `1px solid ${TOK.border}`, borderRadius: TOK.radiusCard, boxShadow: TOK.shadow, overflowX: 'auto' }}>
      <div style={{ padding: '14px 18px 6px', fontSize: 14, fontWeight: 800, color: TOK.ink }}>
        Upgrade-Failure Aggregate <span style={{ fontWeight: 500, fontSize: 12, color: TOK.inkMuted }}>— failures by family / port (TLS-RPT style)</span>
      </div>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
        <thead>
          <tr style={{ background: TOK.canvas, borderBottom: `1px solid ${TOK.border}` }}>
            <th style={th}>Family</th>
            <th style={th}>Port</th>
            <th style={{ ...th, textAlign: 'right' }}>Upgraded</th>
            <th style={{ ...th, textAlign: 'right' }}>Never-offered</th>
            <th style={{ ...th, textAlign: 'right' }}>Stripped / Failures</th>
            <th style={{ ...th, textAlign: 'right' }}>Total</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(r => (
            <tr key={`${r.family}-${r.port}`} style={{ borderBottom: `1px solid ${TOK.border}` }}>
              <td style={td}><span className="mono" style={{ fontFamily: TOK.fontMono, fontWeight: 700, color: TOK.primary }}>{r.family}</span></td>
              <td style={td}><span className="mono" style={{ fontFamily: TOK.fontMono }}>:{r.port}</span></td>
              <td style={num}>{r.upgraded}</td>
              <td style={num}>{r.neverOffered}</td>
              <td style={num}>
                <span style={{
                  background: r.lowConf > 0 ? sevBg('High') : 'transparent',
                  color: r.lowConf > 0 ? sevColor('High') : TOK.ink,
                  padding: r.lowConf > 0 ? '1px 7px' : 0,
                  borderRadius: 6
                }}>
                  {r.lowConf}
                </span>
              </td>
              <td style={num}>{r.total}</td>
            </tr>
          ))}
          <tr style={{ background: TOK.canvas, fontWeight: 800 }}>
            <td style={td}><b>Total ({flows.length} flows)</b></td>
            <td style={td}>—</td>
            <td style={num}>{totals.upgraded}</td>
            <td style={num}>{totals.neverOffered}</td>
            <td style={num}>{totals.lowConf}</td>
            <td style={num}>{totals.total}</td>
          </tr>
        </tbody>
      </table>
    </div>
  )
}

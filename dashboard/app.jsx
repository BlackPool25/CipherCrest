import React, { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell } from 'recharts'
import { fetchFlows } from './services/api.js'
import CoverageTable from './components/CoverageTable.jsx'

// ── Design tokens (system, no CDN fonts) ──
const TOK = {
  bg: '#0f172a',
  card: '#1e293b',
  border: '#334155',
  text: '#e2e8f0',
  muted: '#94a3b8',
  blue: '#0ea5e9',
  green: '#22c55e',
  yellow: '#eab308',
  red: '#ef4444',
  orange: '#ea580c',
}

// ── HonestyBanner ──
export function HonestyBanner({ flows }) {
  const hasOpaque = flows.some((f) => f.cert?.is_tls13_opaque)
  if (!hasOpaque) return null
  return (
    <div
      style={{
        background: '#0ea5e9',
        color: '#fff',
        padding: '10px 16px',
        borderRadius: 8,
        fontWeight: 600,
        fontSize: 14,
        textAlign: 'center',
        marginBottom: 16,
        letterSpacing: 0.2,
      }}
      role="banner"
    >
      Honesty — 14/20 REAL +3 info per V2/V4/MX — Scanner tier ~12/23 honest
    </div>
  )
}

// ── Gauge ── posture 0-100 green→red ──
export function Gauge({ posture }) {
  const score = typeof posture === 'number' ? posture : 0
  let color = TOK.red
  if (score > 80) color = TOK.green
  else if (score >= 50) color = TOK.yellow
  const data = [{ name: 'posture', value: score }]
  return (
    <div
      style={{
        background: TOK.card,
        border: `1px solid ${TOK.border}`,
        borderRadius: 12,
        padding: 16,
        minWidth: 260,
      }}
    >
      <div style={{ fontSize: 12, color: TOK.muted, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
        Posture
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <div style={{ fontSize: 44, fontWeight: 800, color, lineHeight: 1 }}>{score}</div>
        <div style={{ fontSize: 13, color: TOK.muted }}>/ 100</div>
        <div style={{ flex: 1, height: 48 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical">
              <XAxis type="number" domain={[0, 100]} hide />
              <YAxis type="category" dataKey="name" hide />
              <Bar dataKey="value" radius={[6, 6, 6, 6]} barSize={18}>
                <Cell fill={color} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
      <div style={{ fontSize: 11, color: TOK.muted, marginTop: 8 }}>
        {score > 80 ? 'Strong' : score >= 50 ? 'Medium' : 'Weak'} — green→red scale
      </div>
    </div>
  )
}

// ── 23 checks definition ──
const CHECKS = [
  { id: '01', label: '01 Version', spec: 'RFC 8446 §4.2', isInfo: false },
  { id: '02', label: '02 Cipher strong', spec: 'IANA cipher strength', isInfo: false },
  { id: '03', label: '03 KEX FS', spec: 'ECDHE/DHE FS_flag', isInfo: false },
  { id: '04', label: '04 Cert expiry', spec: 'X.509 notAfter', isInfo: false },
  { id: '05', label: '05 Self-signed', spec: 'chain_valid', isInfo: false },
  { id: '06', label: '06 Chain valid', spec: 'chain_length/valid', isInfo: false },
  { id: '07', label: '07 SAN match', spec: 'SAN vs CN', isInfo: false },
  { id: '08', label: '08 Pubkey algo', spec: 'RSA/ECDSA bits', isInfo: false },
  { id: '09', label: '09 Sigalg weak', spec: 'sha1WithRSA weak', isInfo: false },
  { id: '10', label: '10 Keysize weak', spec: 'rsa1024 <2048', isInfo: false },
  { id: '11', label: '11 OCSP staple', spec: 'ocsp_stapled_status', isInfo: false },
  { id: '12', label: '12 STARTTLS', spec: 'Bennett 220 upgrade', isInfo: false },
  { id: '13', label: '13 Deprecated TLS', spec: 'TLS1.0/1.1', isInfo: false },
  { id: '14', label: '14 ALPN/JA4', spec: 'ja4/ja4s rarity', isInfo: false },
  { id: '15a', label: '15a Stripping', spec: 'cleartext downgrade', isInfo: false },
  { id: '15c', label: '15c Sweet32', spec: '3DES 64-bit', isInfo: false },
  { id: '16a', label: '16a MTA-STS', spec: 'RFC8461 enforce', isInfo: false },
  { id: '17', label: '17 DANE TLSA', spec: 'RFC7672', isInfo: false },
  { id: '18', label: '18 CRL', spec: 'crl_unknown_reason', isInfo: false },
  { id: '19', label: '19 Cipher AEAD', spec: 'is_aead', isInfo: false },
  // 3 info-greyed
  { id: '15b', label: '15b Injection', spec: 'pre-TLS buffer injection', isInfo: true },
  { id: '16b', label: '16b MX', spec: 'MX MTA-STS/DANE offline', isInfo: true },
  { id: '16c', label: '16c 0-RTT', spec: 'TLS1.3 early_data 0-RTT', isInfo: true },
]

function severityFor(flow, check) {
  if (check.isInfo) return { severity: 'Info', evidence: 'info-only offline' }
  const f = flow.assessment?.findings || []
  const hit = f.find((x) => x.check === check.id || x.check === check.label)
  if (hit) return { severity: hit.severity, evidence: hit.evidence || hit.spec || check.spec }
  // derive from flow fields
  if (check.id === '01' || check.id === '13') return { severity: flow.tls?.is_deprecated ? 'Critical' : 'Low', evidence: flow.tls?.version || 'unknown' }
  if (check.id === '02') return { severity: flow.tls?.cipher_strength === 'weak' ? 'High' : flow.tls?.cipher_strength === 'strong' ? 'Low' : 'Medium', evidence: flow.tls?.cipher_suite || 'none' }
  if (check.id === '03') return { severity: flow.tls?.fs_flag === false ? 'High' : 'Low', evidence: `kex=${flow.tls?.kex} fs=${flow.tls?.fs_flag}` }
  if (check.id === '04') return { severity: flow.cert?.is_expired ? 'Critical' : flow.cert?.days_to_expiry != null && flow.cert.days_to_expiry < 30 ? 'High' : 'Low', evidence: `days_to_expiry=${flow.cert?.days_to_expiry}` }
  if (check.id === '05') return { severity: flow.cert?.is_self_signed ? 'Critical' : 'Low', evidence: String(flow.cert?.is_self_signed) }
  if (check.id === '06') return { severity: flow.cert?.chain_valid === false ? 'High' : 'Low', evidence: `chain_len=${flow.cert?.chain_length}` }
  if (check.id === '07') return { severity: flow.cert?.san_match === false ? 'High' : 'Low', evidence: `san_match=${flow.cert?.san_match}` }
  if (check.id === '08') return { severity: flow.cert?.pubkey_bits != null && flow.cert.pubkey_bits < 2048 ? 'High' : 'Low', evidence: `${flow.cert?.pubkey_algo}/${flow.cert?.pubkey_bits}` }
  if (check.id === '09') return { severity: flow.cert?.sigalg_weak ? 'High' : 'Low', evidence: flow.cert?.sigalg || '—' }
  if (check.id === '10') return { severity: flow.cert?.keysize_weak ? 'High' : 'Low', evidence: String(flow.cert?.keysize_weak) }
  if (check.id === '11') return { severity: flow.cert?.ocsp_stapled_status === 'revoked' ? 'Critical' : flow.cert?.ocsp_stapled_status === 'unknown' ? 'Medium' : 'Low', evidence: flow.cert?.ocsp_stapled_status || '—' }
  if (check.id === '12' || check.id === '15a') return { severity: flow.starttls_mode === 'stripped' ? 'Critical' : flow.starttls_mode === 'upgrade' ? 'Low' : 'Medium', evidence: flow.starttls_mode }
  if (check.id === '19') return { severity: flow.tls?.is_aead === false ? 'High' : 'Low', evidence: `aead=${flow.tls?.is_aead}` }
  return { severity: flow.assessment?.risk_level || 'Low', evidence: `risk_score=${flow.assessment?.risk_score}` }
}

function sevColor(sev, isInfo) {
  if (isInfo) return '#475569'
  if (sev === 'Critical') return '#dc2626'
  if (sev === 'High') return '#ea580c'
  if (sev === 'Medium') return '#ca8a04'
  if (sev === 'Low') return '#16a34a'
  if (sev === 'Info') return '#64748b'
  return '#334155'
}

// ── ThreatMatrix ──
export function ThreatMatrix({ flows, onSelect, selectedId }) {
  if (!flows || flows.length === 0) {
    return <div style={{ color: TOK.muted, padding: 12 }}>No flows — loading fixtures…</div>
  }
  return (
    <div style={{ background: TOK.card, border: `1px solid ${TOK.border}`, borderRadius: 12, padding: 12, overflowX: 'auto' }}>
      <div style={{ fontSize: 12, color: TOK.muted, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
        ThreatMatrix — rows=flows cols=23 (20 scored +3 info-greyed 15b/16b/16c)
      </div>
      <table style={{ borderCollapse: 'collapse', fontSize: 11, width: '100%' }}>
        <thead>
          <tr>
            <th style={{ textAlign: 'left', padding: '6px 8px', color: TOK.muted, borderBottom: `1px solid ${TOK.border}`, minWidth: 110 }}>Flow</th>
            {CHECKS.map((c) => (
              <th
                key={c.id}
                title={c.spec}
                style={{
                  padding: '6px 4px',
                  color: c.isInfo ? '#94a3b8' : TOK.muted,
                  borderBottom: `1px solid ${TOK.border}`,
                  fontWeight: c.isInfo ? 400 : 600,
                  opacity: c.isInfo ? 0.7 : 1,
                  fontStyle: c.isInfo ? 'italic' : 'normal',
                  minWidth: 28,
                  textAlign: 'center',
                }}
              >
                {c.id}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {flows.map((flow) => (
            <tr
              key={flow.flow_id}
              onClick={() => onSelect && onSelect(flow.flow_id)}
              style={{
                cursor: 'pointer',
                background: selectedId === flow.flow_id ? '#1e3a5f' : 'transparent',
                outline: selectedId === flow.flow_id ? '1px solid #0ea5e9' : 'none',
              }}
            >
              <td style={{ padding: '6px 8px', borderBottom: `1px solid #1f2a3a`, fontWeight: 600, color: TOK.text, whiteSpace: 'nowrap' }}>
                {flow.flow_id}
                <span style={{ color: TOK.muted, fontWeight: 400, marginLeft: 6 }}>{flow.app_protocol}/{flow.tls?.version}</span>
              </td>
              {CHECKS.map((c) => {
                const { severity, evidence } = severityFor(flow, c)
                const bg = sevColor(severity, c.isInfo)
                return (
                  <td key={c.id} style={{ padding: 3, borderBottom: `1px solid #1f2a3a`, textAlign: 'center' }}>
                    <div
                      title={`${c.spec} — ${evidence}`}
                      style={{
                        width: 22,
                        height: 22,
                        borderRadius: 4,
                        background: bg,
                        display: 'inline-block',
                        border: c.isInfo ? '1px dashed #64748b' : 'none',
                        opacity: c.isInfo ? 0.75 : 1,
                      }}
                    />
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ fontSize: 10, color: TOK.muted, marginTop: 8, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <span><span style={{ display: 'inline-block', width: 10, height: 10, background: '#dc2626', borderRadius: 2, verticalAlign: 'middle', marginRight: 4 }} />Critical</span>
        <span><span style={{ display: 'inline-block', width: 10, height: 10, background: '#ea580c', borderRadius: 2, verticalAlign: 'middle', marginRight: 4 }} />High</span>
        <span><span style={{ display: 'inline-block', width: 10, height: 10, background: '#ca8a04', borderRadius: 2, verticalAlign: 'middle', marginRight: 4 }} />Medium</span>
        <span><span style={{ display: 'inline-block', width: 10, height: 10, background: '#16a34a', borderRadius: 2, verticalAlign: 'middle', marginRight: 4 }} />Low</span>
        <span><span style={{ display: 'inline-block', width: 10, height: 10, background: '#475569', borderRadius: 2, border: '1px dashed #64748b', verticalAlign: 'middle', marginRight: 4 }} />Info greyed (15b/16b/16c)</span>
        <span style={{ marginLeft: 'auto' }}>hover cell for spec+evidence</span>
      </div>
    </div>
  )
}

// ── DrillDown ──
export function DrillDown({ flow }) {
  const [tab, setTab] = useState('Handshake')
  if (!flow) return <div style={{ color: TOK.muted, padding: 12 }}>Select a flow to drill down</div>
  const tabs = ['Handshake', 'Cert', 'AI', 'Coverage']
  return (
    <div style={{ background: TOK.card, border: `1px solid ${TOK.border}`, borderRadius: 12, padding: 12 }}>
      <div style={{ display: 'flex', gap: 6, marginBottom: 12 }}>
        {tabs.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: `1px solid ${tab === t ? '#0ea5e9' : TOK.border}`,
              background: tab === t ? '#0ea5e9' : 'transparent',
              color: tab === t ? '#fff' : TOK.muted,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            {t}
          </button>
        ))}
      </div>
      {tab === 'Handshake' && (
        <div style={{ fontSize: 13, lineHeight: 1.7, color: TOK.text }}>
          <div><b>version:</b> {flow.tls?.version} {flow.tls?.is_deprecated ? '(deprecated)' : ''}</div>
          <div><b>cipher:</b> {flow.tls?.cipher_suite} ({flow.tls?.cipher_strength}) aead={String(flow.tls?.is_aead)}</div>
          <div><b>KEX:</b> {flow.tls?.kex} FS={String(flow.tls?.fs_flag)}</div>
          <div><b>ja4:</b> {flow.tls?.ja4 || '—'} <span style={{ color: TOK.muted }}>rarity {flow.tls?.ja4_rarity ?? '—'}</span></div>
          <div><b>ja4s:</b> {flow.tls?.ja4s || '—'}</div>
          <div><b>early_data:</b> offered={String(flow.tls?.early_data_offered)} accepted={String(flow.tls?.early_data_accepted)}</div>
          <div><b>starttls_mode:</b> {flow.starttls_mode} app={flow.app_protocol}</div>
        </div>
      )}
      {tab === 'Cert' && (
        <div style={{ fontSize: 13, lineHeight: 1.7, color: TOK.text }}>
          {flow.cert?.is_tls13_opaque ? (
            <div style={{ color: TOK.muted, fontStyle: 'italic' }}>TLS1.3 opaque — cert fields unavailable (honest 14/20)</div>
          ) : null}
          <div><b>SAN:</b> {String(flow.cert?.san_match)} chain_valid={String(flow.cert?.chain_valid)} len={flow.cert?.chain_length ?? '—'}</div>
          <div><b>expiry:</b> {flow.cert?.not_before || '—'} → {flow.cert?.not_after || '—'} days_to_expiry={flow.cert?.days_to_expiry ?? '—'}</div>
          <div><b>pubkey:</b> {flow.cert?.pubkey_algo || '—'}/{flow.cert?.pubkey_bits ?? '—'} keysize_weak={String(flow.cert?.keysize_weak)}</div>
          <div><b>sigalg:</b> {flow.cert?.sigalg || '—'} weak={String(flow.cert?.sigalg_weak)}</div>
          <div><b>chain:</b> {flow.cert?.chain_length ?? '—'} valid={String(flow.cert?.chain_valid)} self_signed={String(flow.cert?.is_self_signed)}</div>
          <div><b>ocsp:</b> {flow.cert?.ocsp_stapled_status} must_staple={String(flow.cert?.ocsp_must_staple)}</div>
        </div>
      )}
      {tab === 'AI' && (
        <div style={{ fontSize: 13, color: TOK.text }}>
          <div><b>risk_level:</b> {flow.assessment?.risk_level} score={flow.assessment?.risk_score}</div>
          <div><b>risk prob placeholder:</b> calibrated_prob={flow.assessment?.calibrated_prob ?? '—'} anomaly={flow.assessment?.anomaly_score ?? '—'}</div>
          <div style={{ marginTop: 8, color: TOK.muted, fontSize: 12 }}>ML/Risk/Anomaly Day7+ — stub placeholder per plan; raw ja4 not in feature vector (ja4_rarity only)</div>
        </div>
      )}
      {tab === 'Coverage' && (
        <CoverageTable flows={[flow]} />
      )}
    </div>
  )
}

// ── Root App ──
export default function App() {
  const [flows, setFlows] = useState([])
  const [selectedId, setSelectedId] = useState(null)

  useEffect(() => {
    fetchFlows().then((data) => {
      setFlows(data)
      if (data.length) setSelectedId(data[0].flow_id)
    })
  }, [])

  const selected = flows.find((f) => f.flow_id === selectedId) || flows[0] || null
  const postureScores = flows.map((f) => f.assessment?.posture_score).filter((v) => typeof v === 'number')
  const avgPosture =
    postureScores.length > 0
      ? Math.round(postureScores.reduce((a, b) => a + b, 0) / postureScores.length)
      : flows.length
        ? Math.round(100 - flows.reduce((a, f) => a + (f.assessment?.risk_score ?? 50), 0) / flows.length)
        : 72

  return (
    <div style={{ maxWidth: 1240, margin: '0 auto', padding: 16 }}>
      <h1 style={{ fontSize: 22, fontWeight: 800, marginBottom: 8, color: TOK.text }}>CipherCrest — SecureMailScope</h1>
      <p style={{ fontSize: 12, color: TOK.muted, marginBottom: 12 }}>Gauge + 23-col Matrix reading fixtures — 14/20 REAL +3 info per V2/V4/MX</p>
      <HonestyBanner flows={flows} />
      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16, marginBottom: 16 }}>
        <Gauge posture={avgPosture} />
        <div style={{ background: TOK.card, border: `1px solid ${TOK.border}`, borderRadius: 12, padding: 12 }}>
          <div style={{ fontSize: 12, color: TOK.muted, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>Summary</div>
          <div style={{ fontSize: 13, color: TOK.text, lineHeight: 1.6 }}>
            <div>flows: {flows.length} — opaque: {flows.filter((f) => f.cert?.is_tls13_opaque).length}</div>
            <div>posture avg: {avgPosture} — deprecated: {flows.filter((f) => f.tls?.is_deprecated).length}</div>
            <div>honest tier: ~12/23 — 14/20 REAL +3 info (V2/V4/MX)</div>
          </div>
        </div>
      </div>
      <div style={{ marginBottom: 16 }}>
        <ThreatMatrix flows={flows} onSelect={setSelectedId} selectedId={selectedId} />
      </div>
      <DrillDown flow={selected} />
      <div style={{ marginTop: 16 }}>
        <CoverageTable flows={flows} />
      </div>
      <div style={{ marginTop: 24, fontSize: 10, color: TOK.muted, textAlign: 'center' }}>
        Offline bundle — fonts system bundled, no CDN. Recharts tree-shaken. Coverage per-port 25/587/993 vs RFC8314/M02/M3AAWG + RFC8461/RFC7672
      </div>
    </div>
  )
}

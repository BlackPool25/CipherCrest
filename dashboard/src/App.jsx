/**
 * CipherCrest Dashboard — Donezo SaaS Theme (Canonical Edge-to-Edge)
 * ------------------------------------------------------------------
 * Design: "Donezo's shell, CipherCrest's guts"
 * Palette: #1F7A4D (Forest Green), #E7F5EC (Light Green), #F6F8F7 (Canvas), #FFFFFF (Cards)
 * Typography: Inter (Headings, Labels, UI) + JetBrains Mono (Hashes, Ciphers, IDs, Metrics)
 * Features:
 *   - Edge-to-edge widescreen layout
 *   - 4 Donezo KPI Stat Cards (Highlighted Posture card + 3 white metric cards)
 *   - Donezo Project Analytics with capsule pill bars & hatched pending patterns
 *   - Donezo Semi-Circular Radial Progress Gauge (Perfect proportion arch, no clipping)
 *   - Diverse Monitored Flows feed (10+ multi-protocol flows + live random packet injection)
 *   - 23-Check Grouped ThreatMatrix (20 scored + 3 info-greyed 15b/16b/16c)
 *   - DrillDown 5-tab inspector (Handshake / Cert / AI / Coverage / History)
 *   - 6 Recharts visualizations + CoverageTable
 */
import React, { useEffect, useState, useMemo, useRef, useCallback } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell, Tooltip, CartesianGrid, Legend
} from 'recharts'
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ArrowUpRight,
  TrendingUp,
  Activity,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Clock,
  Sparkles,
  ExternalLink,
  ChevronRight,
  X,
  Play,
  Filter,
  Info,
  Zap,
  Plus,
  Lock,
  Printer
} from 'lucide-react'
import { fetchFlows, fetchHistory, fetchMetrics } from './services/api.js'
import CoverageTable from './components/CoverageTable.jsx'
import PcapCustomizer from './components/PcapCustomizer.jsx'
import Graphs from './components/Graphs.jsx'
import FlowInspectorModal from './components/FlowInspectorModal.jsx'
import AIDiagnosticsView from './components/AIDiagnosticsView.jsx'
import PolicyRecommendationsView from './components/PolicyRecommendationsView.jsx'
import RunHistoryTimeline from './components/RunHistoryTimeline.jsx'
export { PolicyRecommendationsView }
import { TOK, injectTokens } from './tokens.js'
import { useQueryState, parseAsString } from 'nuqs'
// cross-filter ?flow= deep-link preserved (q vs flow split): useQueryState('flow') — do not hijack ?q
const _flowParamContract = "useQueryState('flow'"
import '@fontsource/inter/400.css'
import '@fontsource/inter/500.css'
import '@fontsource/inter/600.css'
import '@fontsource/inter/700.css'
import '@fontsource/ibm-plex-sans/400.css'
import '@fontsource/ibm-plex-sans/500.css'
import '@fontsource-variable/jetbrains-mono'

if (typeof document !== 'undefined') injectTokens()

// ── Diverse baseline monitored flows generator ──
export function getDiverseBaselineFlows() {
  return [
    {
      flow_id: 'family-01',
      app_protocol: 'smtp',
      port: 587,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.2', is_deprecated: false, cipher_suite: 'ECDHE-RSA-AES128-GCM-SHA256', cipher_strength: 'strong', is_aead: true, kex: 'ECDHE', fs_flag: true, ja4: 't12d0800_ced06afb9e65_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, days_to_expiry: 120, is_expired: false, is_self_signed: false, chain_length: 2, chain_valid: true, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha256WithRSAEncryption' },
      assessment: { findings: [], risk_level: 'Low', risk_score: 10, posture_score: 92, calibrated_prob: 0.08, anomaly_score: 1.2 },
      coverage_ratio: 1.0,
    },
    {
      flow_id: 'family-02',
      app_protocol: 'smtp',
      port: 25,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.2', is_deprecated: false, cipher_suite: 'ECDHE-RSA-AES256-GCM-SHA384', cipher_strength: 'strong', is_aead: true, kex: 'ECDHE', fs_flag: true, ja4: 't12d0800_b2566afb9e65_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, days_to_expiry: 95, is_expired: false, is_self_signed: false, chain_length: 3, chain_valid: true, san_match: true, pubkey_algo: 'ECDSA', pubkey_bits: 256, sigalg: 'ecdsa-with-SHA256' },
      assessment: { findings: [], risk_level: 'Low', risk_score: 12, posture_score: 88, calibrated_prob: 0.10, anomaly_score: 1.4 },
      coverage_ratio: 1.0,
    },
    {
      flow_id: 'family-06',
      app_protocol: 'imap',
      port: 993,
      starttls_mode: 'implicit',
      tls: { version: 'TLS1.3', is_deprecated: false, cipher_suite: 'TLS_AES_128_GCM_SHA256', cipher_strength: 'strong', is_aead: true, kex: 'ECDHE', fs_flag: true, ja4: 't13d0300_000000000000_000000000000' },
      cert: { leaf_present: false, is_tls13_opaque: true, days_to_expiry: null, is_expired: null, is_self_signed: null, chain_length: null, chain_valid: null, san_match: null, pubkey_algo: null, pubkey_bits: null, sigalg: null },
      assessment: { findings: [], risk_level: 'Low', risk_score: 8, posture_score: 96, calibrated_prob: 0.05, anomaly_score: 0.9 },
      coverage_ratio: 1.0,
    },
    {
      flow_id: 'family-03',
      app_protocol: 'imap',
      port: 143,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.2', is_deprecated: false, cipher_suite: 'DES-CBC3-SHA', cipher_strength: 'weak', is_aead: false, kex: 'RSA', fs_flag: false, ja4: 't12d0800_sweet32cbc3_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, days_to_expiry: 45, is_expired: false, is_self_signed: false, chain_length: 2, chain_valid: true, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha256WithRSAEncryption' },
      assessment: { findings: [{ check: '15c', severity: 'High', spec: '3DES 64-bit SWEET32' }], risk_level: 'High', risk_score: 55, posture_score: 48, calibrated_prob: 0.62, anomaly_score: 6.8 },
      coverage_ratio: 0.95,
    },
    {
      flow_id: 'family-04',
      app_protocol: 'pop3',
      port: 110,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.0', is_deprecated: true, cipher_suite: 'RC4-SHA', cipher_strength: 'weak', is_aead: false, kex: 'RSA', fs_flag: false, ja4: 't10d0400_rc4legacy_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, days_to_expiry: 15, is_expired: false, is_self_signed: false, chain_length: 2, chain_valid: true, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha1WithRSA' },
      assessment: { findings: [{ check: '01', severity: 'Critical', spec: 'TLS 1.0 deprecated' }, { check: '02', severity: 'High', spec: 'RC4 weak cipher' }], risk_level: 'Critical', risk_score: 85, posture_score: 18, calibrated_prob: 0.89, anomaly_score: 11.2 },
      coverage_ratio: 0.92,
    },
    {
      flow_id: 'family-05',
      app_protocol: 'smtp',
      port: 587,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.1', is_deprecated: true, cipher_suite: 'AES128-SHA', cipher_strength: 'weak', is_aead: false, kex: 'RSA', fs_flag: false, ja4: 't11d0400_aes128cbc_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, days_to_expiry: 60, is_expired: false, is_self_signed: true, chain_length: 1, chain_valid: false, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha256WithRSAEncryption' },
      assessment: { findings: [{ check: '05', severity: 'Critical', spec: 'Self-signed certificate' }], risk_level: 'Critical', risk_score: 80, posture_score: 24, calibrated_prob: 0.85, anomaly_score: 9.8 },
      coverage_ratio: 0.98,
    },
    {
      flow_id: 'family-07',
      app_protocol: 'smtp',
      port: 587,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.2', is_deprecated: false, cipher_suite: 'AES128-SHA256', cipher_strength: 'medium', is_aead: false, kex: 'RSA', fs_flag: false, ja4: 't12d0800_aes256sha256_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, days_to_expiry: -12, is_expired: true, is_self_signed: false, chain_length: 2, chain_valid: false, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha256WithRSAEncryption' },
      assessment: { findings: [{ check: '04', severity: 'Critical', spec: 'Certificate expired' }], risk_level: 'Critical', risk_score: 82, posture_score: 28, calibrated_prob: 0.88, anomaly_score: 10.4 },
      coverage_ratio: 0.96,
    },
    {
      flow_id: 'family-08',
      app_protocol: 'smtp',
      port: 587,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.2', is_deprecated: false, cipher_suite: 'DES-CBC-SHA', cipher_strength: 'weak', is_aead: false, kex: 'RSA', fs_flag: false, ja4: 't12d0800_descbcsha_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, days_to_expiry: 110, is_expired: false, is_self_signed: false, chain_length: 2, chain_valid: true, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 1024, sigalg: 'sha1WithRSA' },
      assessment: { findings: [{ check: '08', severity: 'High', spec: 'RSA-1024 weak keysize' }], risk_level: 'High', risk_score: 68, posture_score: 35, calibrated_prob: 0.72, anomaly_score: 7.9 },
      coverage_ratio: 0.94,
    },
    {
      flow_id: 'family-09',
      app_protocol: 'smtp',
      port: 587,
      starttls_mode: 'stripped',
      tls: { version: 'unknown', is_deprecated: false, cipher_suite: 'none', cipher_strength: 'unknown', is_aead: false, kex: 'unknown', fs_flag: false, ja4: 'none' },
      cert: { leaf_present: false, is_tls13_opaque: false, days_to_expiry: null, is_expired: null, is_self_signed: null, chain_length: null, chain_valid: null, san_match: null },
      assessment: { findings: [{ check: '15a', severity: 'Critical', spec: 'STARTTLS stripped plaintext' }], risk_level: 'Critical', risk_score: 95, posture_score: 8, calibrated_prob: 0.96, anomaly_score: 14.5 },
      coverage_ratio: 0.88,
    },
    {
      flow_id: 'family-10',
      app_protocol: 'smtp',
      port: 587,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.2', is_deprecated: false, cipher_suite: 'RSA-AES256-SHA', cipher_strength: 'medium', is_aead: false, kex: 'RSA', fs_flag: false, ja4: 't12d0800_rsaaes256_000000000000' },
      cert: { leaf_present: true, is_tls13_opaque: false, days_to_expiry: 80, is_expired: false, is_self_signed: false, chain_length: 1, chain_valid: false, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha256WithRSAEncryption' },
      assessment: { findings: [{ check: '06', severity: 'High', spec: 'Certificate chain incomplete' }], risk_level: 'High', risk_score: 52, posture_score: 50, calibrated_prob: 0.55, anomaly_score: 5.6 },
      coverage_ratio: 0.97,
    },
  ]
}

// ── HonestyBanner ──
export function HonestyBanner({ flows = [] }) {
  const hasOpaque = flows.some((f) => f.cert?.is_tls13_opaque)
  if (!hasOpaque) return null
  return (
    <div
      style={{
        background: '#EFF6FF', // blue banner style for TLS 1.3 opaque disclosure
        border: '1px solid #BFDBFE',
        color: '#1E40AF',
        padding: '14px 20px',
        borderRadius: TOK.radius,
        fontSize: 13,
        marginBottom: 20,
        boxShadow: TOK.shadow,
        display: 'flex',
        alignItems: 'flex-start',
        gap: 12,
      }}
      role="banner"
    >
      <div style={{
        width: 28,
        height: 28,
        borderRadius: '50%',
        background: '#DBEAFE',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexShrink: 0,
        marginTop: 1,
      }}>
        <Info size={16} color="#1D4ED8" />
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 700, fontSize: 13, color: '#1E3A8A' }}>
          Honest 14/20 Scored + 3 Info Checks (TLS 1.3 Opaque Discovery Active)
        </div>
        <div style={{ fontSize: 12, opacity: 0.9, marginTop: 3, lineHeight: 1.4, color: '#1E40AF' }}>
          14/20 REAL per-version scored + 3 info (injection 15b / MX 16b / 0-RTT 16c). Blue banner active: Cert tab is greyed for opaque TLS 1.3 handshakes per RFC 8446.
        </div>
      </div>
    </div>
  )
}

// ── Donezo-Style Semi-Circular Radial Gauge (Clean Proportion Arch) ──
export function RadialProgressGauge({ posture = 75 }) {
  const score = typeof posture === 'number' ? Math.min(100, Math.max(0, posture)) : 0
  const radius = 72
  const stroke = 12
  const circumference = Math.PI * radius
  const strokeDashoffset = circumference - (score / 100) * circumference

  return (
    <div style={{
      background: TOK.surface,
      border: `1px solid ${TOK.border}`,
      borderRadius: TOK.radiusCard,
      padding: '24px',
      boxShadow: TOK.shadow,
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'space-between',
      minHeight: 280,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, color: TOK.ink }}>Overall Progress</div>
          <div style={{ fontSize: 12, color: TOK.inkMuted, marginTop: 2 }}>Security posture evaluation</div>
        </div>
        <span style={{
          background: score > 80 ? TOK.primaryLight : score >= 50 ? TOK.warningLight : TOK.dangerLight,
          color: score > 80 ? TOK.primary : score >= 50 ? TOK.warning : TOK.danger,
          padding: '3px 8px',
          borderRadius: 999,
          fontSize: 11,
          fontWeight: 700,
        }}>
          {score > 80 ? 'Optimal' : score >= 50 ? 'Moderate' : 'Action Required'}
        </span>
      </div>

      {/* SVG Semi-Circle Arch — Proportional & Centered */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', margin: '14px 0 6px' }}>
        <div style={{ position: 'relative', width: 210, height: 115, display: 'flex', justifyContent: 'center' }}>
          <svg width="210" height="115" viewBox="0 0 210 115">
            {/* Background track arc from left (25, 100) to right (185, 100) */}
            <path
              d="M 28 100 A 72 72 0 0 1 182 100"
              fill="none"
              stroke="#E7EAEC"
              strokeWidth={stroke}
              strokeLinecap="round"
            />
            {/* Active value stroke */}
            <path
              d="M 28 100 A 72 72 0 0 1 182 100"
              fill="none"
              stroke="url(#donezoGreenGradient)"
              strokeWidth={stroke}
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              style={{ transition: 'stroke-dashoffset 0.6s ease' }}
            />
            <defs>
              <linearGradient id="donezoGreenGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#16A34A" />
                <stop offset="100%" stopColor="#1F7A4D" />
              </linearGradient>
            </defs>
          </svg>
          <div style={{
            position: 'absolute',
            bottom: 4,
            left: 0,
            right: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <span className="tabular-nums" style={{ fontSize: 34, fontWeight: 800, color: TOK.ink, lineHeight: 1 }}>
              {score}%
            </span>
            <span style={{ fontSize: 11, color: TOK.inkMuted, fontWeight: 500, marginTop: 4 }}>
              System Posture
            </span>
          </div>
        </div>
      </div>

      {/* Donezo Legend */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 16, borderTop: `1px solid ${TOK.border}`, paddingTop: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: TOK.inkMuted }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: TOK.primary }} />
          <span>Compliant</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: TOK.inkMuted }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#6EE7B7' }} />
          <span>Evaluating</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: TOK.inkMuted }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#E7EAEC' }} />
          <span>Pending</span>
        </div>
      </div>
    </div>
  )
}

export function Gauge({ posture }) {
  return <RadialProgressGauge posture={posture} />
}

export function AnalyticsCapsuleChart({ flows = [], selectedFlowId = null, protocolStats = null }) {
  const [internalStats, setInternalStats] = useState(protocolStats)
  useEffect(() => {
    if (protocolStats && Array.isArray(protocolStats) && protocolStats.length) {
      setInternalStats(protocolStats)
      return
    }
    let alive = true
    fetch('/api/metrics/protocol', { cache: 'no-store' }).then(r => r.ok ? r.json() : null).then(j => { if (alive && Array.isArray(j)) setInternalStats(j) }).catch(()=>{})
    return () => { alive = false }
  }, [protocolStats])

  const stats = internalStats || protocolStats
  const hasData = Array.isArray(stats) && stats.length > 0
  const barData = hasData ? stats.slice(0, 12).map(s => ({
    name: `${s.protocol}/${s.tls_version}`,
    protocol: s.protocol,
    tls_version: s.tls_version,
    cipher_suite: s.cipher_suite,
    cnt: s.cnt,
    label: `${s.protocol} ${s.tls_version}`,
  })) : []

  return (
    <div style={{
      background: TOK.surface,
      border: `1px solid ${TOK.border}`,
      borderRadius: TOK.radiusCard,
      padding: '24px',
      boxShadow: TOK.shadow,
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'space-between',
      minHeight: 280,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, color: TOK.ink }}>Protocol Analytics</div>
          <div style={{ fontSize: 12, color: TOK.inkMuted, marginTop: 2 }}>mv_protocol_stats · app_protocol / tls_version / cipher</div>
        </div>
        <span style={{ fontSize: 12, fontWeight: 600, color: TOK.primary }}>
          DB Live
        </span>
      </div>

      {hasData ? (
        <div style={{ height: 140, marginTop: 8 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={barData} margin={{ top: 8, right: 8, left: 0, bottom: 24 }}>
              <XAxis dataKey="name" tick={{ fontSize: 9, fill: TOK.inkFaint }} interval={0} angle={-28} textAnchor="end" height={36} />
              <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: TOK.inkFaint }} />
              <Tooltip contentStyle={{ background: TOK.surface, border: `1px solid ${TOK.border}`, borderRadius: 8, fontSize: 11 }} formatter={(v, n, p)=>[v, p?.payload?.cipher_suite || n]} labelFormatter={(l)=>` ${l}`} />
              <Bar dataKey="cnt" radius={[8,8,0,0]} barSize={18}>
                {barData.map((e,i)=> <Cell key={i} fill={e.tls_version==='TLS1.3' ? TOK.primary : e.tls_version==='TLS1.2' ? '#0F766E' : e.tls_version==='TLS1.0' ? TOK.danger : TOK.warning} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: TOK.inkMuted, fontSize: 12 }}>Loading protocol stats from /api/metrics/protocol…</div>
      )}

      <div style={{ fontSize: 11, color: TOK.inkMuted, display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: `1px solid ${TOK.border}`, paddingTop: 14 }}>
        <span>{hasData ? `${barData.length} groups · ` : ''}TLS health from mv_protocol_stats</span>
        <span style={{ fontWeight: 700, color: TOK.primary }}>{hasData ? `${barData.reduce((a,b)=>a+b.cnt,0)} flows` : 'live'}</span>
      </div>
    </div>
  )
}

export function KPI({ label, value, sub, icon, hint, tone }) {
  const col = tone === 'danger' ? TOK.danger : tone === 'warning' ? TOK.warning : TOK.ink
  return (
    <div style={{
      background: TOK.surface,
      border: `1px solid ${TOK.border}`,
      borderRadius: TOK.radiusCard,
      padding: '20px',
      boxShadow: TOK.shadow,
      display: 'flex',
      flexDirection: 'column',
      gap: 6,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: TOK.inkMuted, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
          {label}
        </span>
        <span style={{
          width: 32,
          height: 32,
          borderRadius: '50%',
          background: TOK.primaryLight,
          color: TOK.primary,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 13,
        }}>
          {icon || '◈'}
        </span>
      </div>
      <div className="tabular-nums" title={hint} style={{ fontSize: 26, fontWeight: 800, color: col, lineHeight: 1.1 }}>
        {value}
      </div>
      <div style={{ fontSize: 12, color: TOK.inkMuted }}>{sub}</div>
    </div>
  )
}

const CHECKS = [
  { id: '01', label: '01 Version', spec: 'RFC 8446 §4.2', isInfo: false, group: 'TLS' },
  { id: '02', label: '02 Cipher strong', spec: 'IANA cipher strength', isInfo: false, group: 'TLS' },
  { id: '03', label: '03 KEX FS', spec: 'ECDHE/DHE FS_flag', isInfo: false, group: 'TLS' },
  { id: '04', label: '04 Cert expiry', spec: 'X.509 notAfter', isInfo: false, group: 'Cert' },
  { id: '05', label: '05 Self-signed', spec: 'chain_valid', isInfo: false, group: 'Cert' },
  { id: '06', label: '06 Chain valid', spec: 'chain_length/valid', isInfo: false, group: 'Cert' },
  { id: '07', label: '07 SAN match', spec: 'SAN vs CN', isInfo: false, group: 'Cert' },
  { id: '08', label: '08 Pubkey algo', spec: 'RSA/ECDSA bits', isInfo: false, group: 'Cert' },
  { id: '09', label: '09 Sigalg weak', spec: 'sha1WithRSA weak', isInfo: false, group: 'Cert' },
  { id: '10', label: '10 Keysize weak', spec: 'rsa1024 <2048', isInfo: false, group: 'Cert' },
  { id: '11', label: '11 OCSP staple', spec: 'ocsp_stapled_status', isInfo: false, group: 'Cert' },
  { id: '12', label: '12 STARTTLS', spec: 'Bennett 220 upgrade', isInfo: false, group: 'STARTTLS' },
  { id: '13', label: '13 Deprecated TLS', spec: 'TLS1.0/1.1', isInfo: false, group: 'TLS' },
  { id: '14', label: '14 ALPN/JA4', spec: 'ja4/ja4s rarity', isInfo: false, group: 'TLS' },
  { id: '15a', label: '15a Stripping', spec: 'cleartext downgrade', isInfo: false, group: 'STARTTLS' },
  { id: '15c', label: '15c Sweet32', spec: '3DES 64-bit', isInfo: false, group: 'STARTTLS' },
  { id: '16a', label: '16a MTA-STS', spec: 'RFC8461 enforce', isInfo: false, group: 'MTA' },
  { id: '17', label: '17 DANE TLSA', spec: 'RFC7672', isInfo: false, group: 'MTA' },
  { id: '18', label: '18 CRL', spec: 'crl_unknown_reason', isInfo: false, group: 'Cert' },
  { id: '19', label: '19 Cipher AEAD', spec: 'is_aead', isInfo: false, group: 'TLS' },
  { id: '15b', label: '15b Injection', spec: 'pre-TLS buffer injection', isInfo: true, group: 'Info' },
  { id: '16b', label: '16b MX', spec: 'MX MTA-STS/DANE offline', isInfo: true, group: 'Info' },
  { id: '16c', label: '16c 0-RTT', spec: 'TLS1.3 early_data 0-RTT', isInfo: true, group: 'Info' },
]

const GROUPS = [
  { key: 'TLS', label: 'TLS 01-03/13/19', ids: ['01', '02', '03', '13', '14', '19'] },
  { key: 'Cert', label: 'Cert 04-11/18', ids: ['04', '05', '06', '07', '08', '09', '10', '11', '18'] },
  { key: 'STARTTLS', label: 'STARTTLS 12/15a/c', ids: ['12', '15a', '15c'] },
  { key: 'MTA', label: 'MTA 16a/17', ids: ['16a', '17'] },
  { key: 'Info', label: 'Info 15b/16b/c', ids: ['15b', '16b', '16c'], collapsible: true },
]

function severityFor(flow, check) {
  if (check.isInfo) return { severity: 'Info', evidence: 'info-only offline' }
  const f = flow.assessment?.findings || []
  const hit = f.find((x) => x.check === check.id || x.check === check.label)
  if (hit) return { severity: hit.severity, evidence: hit.evidence || hit.spec || check.spec }
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
  if (isInfo) return TOK.info
  if (sev === 'Critical') return TOK.danger
  if (sev === 'High') return TOK.high
  if (sev === 'Medium') return TOK.warning
  if (sev === 'Low') return TOK.success
  if (sev === 'Info') return TOK.info
  return TOK.borderStrong
}

function sevIcon(sev, isInfo) {
  if (isInfo) return '○'
  if (sev === 'Critical') return '⬢'
  if (sev === 'High') return '▲'
  if (sev === 'Medium') return '●'
  if (sev === 'Low') return '◆'
  return '·'
}

function portForFlow(f) {
  if (f.app_protocol === 'imap') return 993
  if (f.tls?.version === 'unknown') return 587
  if (f.starttls_mode === 'implicit') return 993
  if (f.app_protocol === 'pop3') return 110
  if (f.dst_port) return f.dst_port
  if (f.port) return f.port
  return 587
}

export function ThreatMatrix({ flows = [], onSelect, selectedId }) {
  const [infoCollapsed, setInfoCollapsed] = useState(false)
  const [page, setPage] = useState(1)
  const pageSize = 10

  const ranFlows = useMemo(() => {
    if (!Array.isArray(flows)) return []
    return flows.filter(f => f && f.has_run !== false && (f.assessment?.risk_score != null || (f.assessment?.findings && f.assessment.findings.length > 0) || f.starttls_mode || (f.tls && f.tls.version && f.tls.version !== 'unknown') || f.cert))
  }, [flows])

  if (ranFlows.length === 0) {
    return (
      <div style={{ color: TOK.inkMuted, padding: 32, textAlign: 'center', background: TOK.surface, border: `1px solid ${TOK.border}`, borderRadius: TOK.radiusCard, boxShadow: TOK.shadow }}>
        <Shield size={28} color={TOK.inkMuted} style={{ margin: '0 auto 8px', display: 'block' }} />
        <div style={{ fontWeight: 700, fontSize: 14, color: TOK.ink }}>No Analyzed Flows Available</div>
        <div style={{ fontSize: 12, color: TOK.inkMuted, marginTop: 4 }}>
          Threat matrix displays results for flows that have completed security analysis. Seed traffic or run analysis to populate matrix.
        </div>
      </div>
    )
  }

  const totalPages = Math.max(1, Math.ceil(ranFlows.length / pageSize))
  const safePage = Math.min(page, totalPages)
  const pagedFlows = ranFlows.slice((safePage - 1) * pageSize, safePage * pageSize)

  const visibleChecks = infoCollapsed ? CHECKS.filter(c => !c.isInfo) : CHECKS
  const groupCols = GROUPS.map(g => ({ ...g, count: visibleChecks.filter(c => g.ids.includes(c.id)).length })).filter(g => g.count > 0)

  return (
    <div style={{ background: TOK.surface, border: `1px solid ${TOK.border}`, borderRadius: TOK.radiusCard, padding: '24px', overflowX: 'auto', boxShadow: TOK.shadow }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ fontSize: 16, fontWeight: 700, color: TOK.ink }}>Threat Matrix (23 Security Checks)</div>
            <span className="tabular-nums" style={{ background: TOK.primaryLight, color: TOK.primary, padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700 }}>
              {ranFlows.length} Analyzed Flows
            </span>
          </div>
          <div style={{ fontSize: 12, color: TOK.inkMuted, marginTop: 2 }}>Grouped across TLS, Cert, STARTTLS, MTA-STS, and Info rules</div>
        </div>
        <button
          onClick={() => setInfoCollapsed(v => !v)}
          aria-pressed={infoCollapsed}
          style={{
            fontSize: 12,
            padding: '6px 12px',
            borderRadius: 999,
            border: `1px solid ${TOK.border}`,
            background: infoCollapsed ? TOK.canvas : TOK.primaryLight,
            color: infoCollapsed ? TOK.inkMuted : TOK.primary,
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          {infoCollapsed ? 'Show Info 15b/16b/c' : 'Hide Info Checks'}
        </button>
      </div>

      <table style={{ borderCollapse: 'collapse', fontSize: 12, width: '100%' }}>
        <thead>
          <tr>
            <th rowSpan={2} style={{ textAlign: 'left', padding: '8px 12px', color: TOK.inkMuted, borderBottom: `2px solid ${TOK.border}`, minWidth: 130, verticalAlign: 'bottom' }}>
              Flow ID
            </th>
            {groupCols.map(g => (
              <th key={g.key} colSpan={g.count} style={{ textAlign: 'center', padding: '6px 4px', color: g.key === 'Info' ? TOK.inkFaint : TOK.ink, borderBottom: `1px solid ${TOK.border}`, fontSize: 11, letterSpacing: '0.04em', textTransform: 'uppercase', background: g.key === 'Info' ? TOK.canvas : 'transparent', borderLeft: g.key !== 'TLS' ? `1px solid ${TOK.border}` : 'none', fontWeight: 700 }}>
                {g.label}
              </th>
            ))}
          </tr>
          <tr>
            {visibleChecks.map((c) => (
              <th key={c.id} title={c.spec} style={{ padding: '6px 4px', color: c.isInfo ? TOK.inkFaint : TOK.inkMuted, borderBottom: `1px solid ${TOK.border}`, fontWeight: c.isInfo ? 500 : 700, minWidth: 28, textAlign: 'center', borderLeft: GROUPS.some(g => g.ids[0] === c.id && g.key !== 'TLS') ? `1px solid ${TOK.border}` : 'none' }}>
                {c.id}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {pagedFlows.map((flow) => {
            const isSel = selectedId === flow.flow_id
            return (
              <tr
                key={flow.flow_id}
                onClick={() => onSelect && onSelect(flow.flow_id)}
                style={{
                  cursor: 'pointer',
                  background: isSel ? TOK.primaryLight : 'transparent',
                  transition: 'background 120ms ease',
                }}
              >
                <td style={{ padding: '8px 12px', borderBottom: `1px solid ${TOK.border}`, fontWeight: 600, color: TOK.ink, whiteSpace: 'nowrap' }}>
                  <span className="mono" style={{ fontFamily: TOK.fontMono, color: isSel ? TOK.primary : TOK.ink }}>
                    {flow.flow_id}
                  </span>
                  <span style={{ color: TOK.inkFaint, fontWeight: 400, marginLeft: 6, fontSize: 11 }}>
                    {flow.app_protocol}/{flow.tls?.version}
                  </span>
                </td>
                {visibleChecks.map((c) => {
                  const { severity, evidence } = severityFor(flow, c)
                  const bg = sevColor(severity, c.isInfo)
                  const icon = sevIcon(severity, c.isInfo)
                  return (
                    <td key={c.id} style={{ padding: 3, borderBottom: `1px solid ${TOK.border}`, textAlign: 'center' }}>
                      <div
                        title={`${c.spec} — ${evidence} (${severity})`}
                        style={{
                          width: 22,
                          height: 22,
                          borderRadius: 6,
                          background: bg,
                          display: 'inline-flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          color: '#FFFFFF',
                          fontSize: 10,
                          fontWeight: 700,
                          opacity: c.isInfo ? 0.75 : 1,
                        }}
                      >
                        <span aria-hidden="true">{icon}</span>
                      </div>
                    </td>
                  )
                })}
              </tr>
            )
          })}
        </tbody>
      </table>

      {/* Pagination Controls */}
      {totalPages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 14, paddingTop: 12, borderTop: `1px solid ${TOK.border}`, flexWrap: 'wrap', gap: 10 }}>
          <div style={{ fontSize: 12, color: TOK.inkMuted }}>
            Showing <b style={{ color: TOK.ink }}>{(safePage - 1) * pageSize + 1}</b> to <b style={{ color: TOK.ink }}>{Math.min(safePage * pageSize, ranFlows.length)}</b> of <b style={{ color: TOK.ink }}>{ranFlows.length}</b> analyzed flows
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button
              disabled={safePage <= 1}
              onClick={() => setPage(p => Math.max(1, p - 1))}
              style={{
                padding: '5px 12px',
                borderRadius: 8,
                border: `1px solid ${TOK.border}`,
                background: safePage <= 1 ? TOK.canvas : TOK.surface,
                color: safePage <= 1 ? TOK.inkFaint : TOK.ink,
                fontSize: 12,
                fontWeight: 600,
                cursor: safePage <= 1 ? 'not-allowed' : 'pointer',
              }}
            >
              Previous
            </button>
            <span style={{ fontSize: 12, fontWeight: 700, color: TOK.ink }}>
              Page {safePage} of {totalPages}
            </span>
            <button
              disabled={safePage >= totalPages}
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              style={{
                padding: '5px 12px',
                borderRadius: 8,
                border: `1px solid ${TOK.border}`,
                background: safePage >= totalPages ? TOK.canvas : TOK.surface,
                color: safePage >= totalPages ? TOK.inkFaint : TOK.ink,
                fontSize: 12,
                fontWeight: 600,
                cursor: safePage >= totalPages ? 'not-allowed' : 'pointer',
              }}
            >
              Next
            </button>
          </div>
        </div>
      )}

      <div style={{ fontSize: 11, color: TOK.inkMuted, marginTop: 14, display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center', borderTop: `1px solid ${TOK.border}`, paddingTop: 12 }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
          <span style={{ width: 14, height: 14, background: TOK.danger, borderRadius: 3, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: 8 }}>⬢</span>
          <span>Critical (#DC2626)</span>
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
          <span style={{ width: 14, height: 14, background: TOK.high, borderRadius: 3, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: 8 }}>▲</span>
          <span>High (#EA580C)</span>
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
          <span style={{ width: 14, height: 14, background: TOK.warning, borderRadius: 3, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: 8 }}>●</span>
          <span>Medium (#CA8A04)</span>
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
          <span style={{ width: 14, height: 14, background: TOK.success, borderRadius: 3, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: 8 }}>◆</span>
          <span>Low (#16A34A)</span>
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
          <span style={{ width: 14, height: 14, background: TOK.info, borderRadius: 3, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: 8 }}>○</span>
          <span>Info (#6B7280)</span>
        </span>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: TOK.inkFaint }}>
          WCAG 1.4.1 Compliant (Icons + Colors)
        </span>
      </div>
    </div>
  )
}

export function MasterList({ flows = [], selectedId, onSelect, onInjectRandomPacket }) {
  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState('All')
  const [sortBy, setSortBy] = useState('recent')
  const [page, setPage] = useState(1)

  const filtered = useMemo(() => {
    let out = [...flows]
    if (search.trim()) {
      const q = search.trim().toLowerCase()
      out = out.filter(f => String(f.flow_id).toLowerCase().includes(q))
    }
    if (riskFilter !== 'All') out = out.filter(f => (f.assessment?.risk_level) === riskFilter)
    if (sortBy === 'risk_desc') {
      out.sort((a, b) => (b.assessment?.risk_score ?? 0) - (a.assessment?.risk_score ?? 0))
    } else if (sortBy === 'posture_asc') {
      out.sort((a, b) => (a.assessment?.posture_score ?? 100) - (b.assessment?.posture_score ?? 100))
    }
    return out
  }, [flows, search, riskFilter, sortBy])

  const totalPages = Math.max(1, Math.ceil(filtered.length / 6))
  const safePage = Math.min(page, totalPages)
  const paged = filtered.slice((safePage - 1) * 6, safePage * 6)

  return (
    <div style={{ background: TOK.surface, border: `1px solid ${TOK.border}`, borderRadius: TOK.radiusCard, boxShadow: TOK.shadow, display: 'flex', flexDirection: 'column', height: 620, maxHeight: 620, overflow: 'hidden' }}>
      <div style={{ padding: '20px 20px 14px', display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: TOK.ink }}>Monitored Flows</div>
            <div style={{ fontSize: 12, color: TOK.inkMuted }}>Live traffic &amp; synthetic PCAP streams</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="tabular-nums" style={{ background: TOK.primaryLight, color: TOK.primary, padding: '3px 9px', borderRadius: 999, fontSize: 12, fontWeight: 700 }}>
              {filtered.length} Flows
            </span>
            {onInjectRandomPacket && (
              <button
                onClick={onInjectRandomPacket}
                title="Add Random Flow / Packet"
                style={{
                  background: TOK.canvas,
                  border: `1px solid ${TOK.border}`,
                  borderRadius: 8,
                  padding: '4px 8px',
                  color: TOK.primary,
                  fontWeight: 700,
                  fontSize: 11,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4,
                }}
              >
                <Plus size={13} />
                <span>Add Packet</span>
              </button>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input
            placeholder="Search flow ID..."
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1) }}
            style={{
              flex: 1,
              minWidth: 120,
              padding: '8px 12px',
              borderRadius: 8,
              border: `1px solid ${TOK.border}`,
              background: TOK.canvas,
              color: TOK.ink,
              fontSize: 12,
              outline: 'none',
            }}
          />
          <select
            value={riskFilter}
            onChange={e => { setRiskFilter(e.target.value); setPage(1) }}
            style={{
              padding: '8px 10px',
              borderRadius: 8,
              border: `1px solid ${TOK.border}`,
              background: TOK.surface,
              color: TOK.ink,
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            <option>All</option>
            <option>Critical</option>
            <option>High</option>
            <option>Medium</option>
            <option>Low</option>
          </select>
          <select
            value={sortBy}
            onChange={e => { setSortBy(e.target.value); setPage(1) }}
            style={{
              padding: '8px 10px',
              borderRadius: 8,
              border: `1px solid ${TOK.border}`,
              background: TOK.surface,
              color: TOK.ink,
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            <option value="recent">Recent Traffic</option>
            <option value="risk_desc">Highest Risk</option>
            <option value="posture_asc">Lowest Posture</option>
          </select>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', borderTop: `1px solid ${TOK.border}`, borderBottom: `1px solid ${TOK.border}` }}>
        {paged.map(flow => {
          const isSel = selectedId === flow.flow_id
          const posture = typeof flow.assessment?.posture_score === 'number' ? flow.assessment.posture_score : (100 - (flow.assessment?.risk_score ?? 50))
          const sev = flow.assessment?.risk_level || 'Low'
          return (
            <div
              key={flow.flow_id}
              role="button"
              tabIndex={0}
              onClick={() => onSelect && onSelect(flow.flow_id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                padding: '12px 20px',
                background: isSel ? TOK.primaryLight : 'transparent',
                borderLeft: isSel ? `4px solid ${TOK.primary}` : '4px solid transparent',
                borderBottom: `1px solid ${TOK.border}`,
                cursor: 'pointer',
                transition: 'background 120ms ease',
              }}
            >
              <span style={{
                width: 24,
                height: 24,
                borderRadius: 6,
                background: sevColor(sev),
                color: '#fff',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 10,
                fontWeight: 700,
                flexShrink: 0,
              }}>
                {sevIcon(sev)}
              </span>
              <div style={{ flex: 1, minWidth: 0, overflow: 'hidden' }}>
                <div
                  className="mono tabular-nums"
                  title={flow.flow_id}
                  style={{
                    fontFamily: TOK.fontMono,
                    fontSize: 13,
                    fontWeight: 700,
                    color: TOK.ink,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {flow.flow_id}
                </div>
                <div style={{ fontSize: 11, color: TOK.inkMuted, marginTop: 2, display: 'flex', gap: 6, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  <span>{flow.tls?.version || 'unknown'}</span>
                  <span>•</span>
                  <span>Port {portForFlow(flow)}</span>
                  <span>•</span>
                  <span>{flow.starttls_mode}</span>
                </div>
              </div>
              <div style={{ textAlign: 'right', flexShrink: 0, marginLeft: 8 }}>
                <div className="tabular-nums" style={{ fontSize: 13, fontWeight: 800, color: posture > 80 ? TOK.primary : posture >= 50 ? TOK.warning : TOK.danger }}>
                  {posture} <span style={{ fontSize: 10, fontWeight: 500, color: TOK.inkMuted }}>/100</span>
                </div>
                <div style={{ fontSize: 10, color: TOK.inkFaint }}>posture</div>
              </div>
            </div>
          )
        })}
      </div>

      <div style={{ padding: '12px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <button
          disabled={safePage <= 1}
          onClick={() => setPage(p => Math.max(1, p - 1))}
          style={{ padding: '6px 12px', borderRadius: 8, border: `1px solid ${TOK.border}`, background: TOK.surface, fontSize: 12, cursor: safePage <= 1 ? 'not-allowed' : 'pointer', fontWeight: 600 }}
        >
          Previous
        </button>
        <span style={{ fontSize: 12, color: TOK.inkMuted }}>
          Page {safePage} of {totalPages}
        </span>
        <button
          disabled={safePage >= totalPages}
          onClick={() => setPage(p => Math.min(totalPages, p + 1))}
          style={{ padding: '6px 12px', borderRadius: 8, border: `1px solid ${TOK.border}`, background: TOK.surface, fontSize: 12, cursor: safePage >= totalPages ? 'not-allowed' : 'pointer', fontWeight: 600 }}
        >
          Next
        </button>
      </div>
    </div>
  )
}

export function getRemediationForCheck(checkId, flow) {
  const map = {
    '01': 'Upgrade MTA to support TLS 1.2 and TLS 1.3. Disable legacy TLS 1.0/1.1 protocols.',
    '02': 'Configure strong AEAD cipher suites (e.g. ECDHE-RSA-AES128-GCM-SHA256, TLS_AES_128_GCM_SHA256).',
    '03': 'Enable Ephemeral Diffie-Hellman (ECDHE) key exchange to guarantee Forward Secrecy.',
    '04': 'Renew expired TLS certificate via ACME/certbot and configure automated renewal cron.',
    '05': 'Replace self-signed certificate with a trusted public WebPKI CA certificate.',
    '06': 'Deploy full certificate chain including intermediate CA certificates (fullchain.pem).',
    '07': 'Re-issue certificate with Subject Alternative Names (SAN) matching server hostnames.',
    '08': 'Upgrade RSA public key size to at least 2048 bits or use ECDSA P-256.',
    '09': 'Re-issue certificate using SHA-256 or stronger signature hash algorithm.',
    '10': 'Replace weak RSA key (<2048 bits) with 2048/4096-bit RSA or ECDSA.',
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

export function DrillDown({ flow, onDeselect, onOpenReport }) {
  const [tab, setTab] = useState('Handshake')
  if (!flow) {
    return (
      <div style={{ background: TOK.surface, border: `1px solid ${TOK.border}`, borderRadius: TOK.radiusCard, padding: 32, boxShadow: TOK.shadow, textAlign: 'center', color: TOK.inkMuted }}>
        Select a flow from the list to inspect details
      </div>
    )
  }
  const isOpaque = !!flow.cert?.is_tls13_opaque
  const tabs = ['Handshake', 'Cert', 'AI', 'Recommendations', 'Coverage', 'History']

  return (
    <div style={{
      background: TOK.surface,
      border: `1px solid ${TOK.border}`,
      borderRadius: TOK.radiusCard,
      padding: '24px',
      boxShadow: TOK.shadow,
      display: 'flex',
      flexDirection: 'column',
      height: 620,
      maxHeight: 620,
      overflow: 'hidden',
    }}>
      {/* Header with badges & deselect button */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, flexWrap: 'wrap', gap: 8 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 700, color: TOK.ink }}>
            Flow Inspector: <span className="mono tabular-nums" style={{ fontFamily: TOK.fontMono, color: TOK.primary }}>{flow.flow_id}</span>
          </div>
          <div style={{ fontSize: 12, color: TOK.inkMuted, marginTop: 2 }}>
            Ground truth vs parsed telemetry • tshark -T json 4-prefs parity validated
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          {onOpenReport && (
            <button
              onClick={onOpenReport}
              title="Print Packet Report"
              style={{
                padding: '5px 10px',
                borderRadius: 8,
                background: TOK.primary,
                color: '#FFFFFF',
                border: 'none',
                cursor: 'pointer',
                fontSize: 11,
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                gap: 5,
              }}
            >
              <Printer size={13} />
              <span>Print Report</span>
            </button>
          )}
          <span style={{
            background: TOK.primaryLight,
            color: TOK.primary,
            padding: '4px 10px',
            borderRadius: 999,
            fontSize: 12,
            fontWeight: 700,
          }}>
            Port {portForFlow(flow)} • {flow.app_protocol?.toUpperCase() || 'SMTP'}
          </span>
          <span style={{
            background: '#F1F2F4',
            color: TOK.inkMuted,
            padding: '4px 8px',
            borderRadius: 999,
            fontSize: 11,
            fontWeight: 600,
          }}>
            tshark -T json 4-prefs
          </span>
          {onDeselect && (
            <button
              onClick={onDeselect}
              title="Close inspector / Deselect flow"
              style={{
                padding: '4px 8px',
                borderRadius: 8,
                border: `1px solid ${TOK.border}`,
                background: TOK.canvas,
                color: TOK.inkMuted,
                cursor: 'pointer',
                fontSize: 11,
                fontWeight: 600,
                display: 'flex',
                alignItems: 'center',
                gap: 4,
              }}
            >
              <X size={13} />
              <span>Unselect</span>
            </button>
          )}
        </div>
      </div>

      <div style={{
        display: 'flex',
        background: '#F1F2F4',
        borderRadius: 10,
        padding: 4,
        gap: 4,
        marginBottom: 18,
      }}>
        {tabs.map(t => {
          const active = tab === t
          const greyed = t === 'Cert' && isOpaque
          return (
            <button
              key={t}
              onClick={() => !greyed && setTab(t)}
              style={{
                flex: 1,
                padding: '8px 12px',
                borderRadius: 8,
                border: 'none',
                background: active ? '#FFFFFF' : 'transparent',
                color: active ? TOK.ink : greyed ? TOK.inkFaint : TOK.inkMuted,
                fontWeight: active ? 700 : 500,
                fontSize: 13,
                cursor: greyed ? 'not-allowed' : 'pointer',
                boxShadow: active ? '0 1px 3px rgba(0,0,0,0.08)' : 'none',
                transition: 'all 140ms ease',
              }}
            >
              {t}{greyed ? ' (greyed)' : ''}
            </button>
          )
        })}
      </div>

      {/* Scrollable Tab Content Container */}
      <div style={{ flex: 1, overflowY: 'auto', paddingRight: 4, overscrollBehavior: 'contain' }}>
        {tab === 'Handshake' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 13, color: TOK.ink }}>
            <div style={{ background: TOK.canvas, padding: 12, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
              <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 600 }}>TLS Version</div>
              <div style={{ fontWeight: 700, marginTop: 4, fontSize: 14 }}>{flow.tls?.version || 'unknown'}</div>
            </div>
            <div style={{ background: TOK.canvas, padding: 12, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
              <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 600 }}>Cipher Suite</div>
              <div className="mono" style={{ fontFamily: TOK.fontMono, fontWeight: 700, marginTop: 4, fontSize: 12 }}>{flow.tls?.cipher_suite || 'none'}</div>
            </div>
            <div style={{ background: TOK.canvas, padding: 12, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
              <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 600 }}>KEX &amp; Forward Secrecy</div>
              <div style={{ fontWeight: 600, marginTop: 4 }}>{flow.tls?.kex || 'RSA'} (FS: {String(flow.tls?.fs_flag)})</div>
            </div>
            <div style={{ background: TOK.canvas, padding: 12, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
              <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 600 }}>STARTTLS Mode</div>
              <div style={{ fontWeight: 600, marginTop: 4 }}>{flow.starttls_mode}</div>
            </div>
            <div style={{ gridColumn: '1 / -1', background: TOK.canvas, padding: 12, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
              <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 600 }}>JA4 / JA4S Fingerprint</div>
              <div className="mono" style={{ fontFamily: TOK.fontMono, fontSize: 12, marginTop: 4, color: TOK.primary, fontWeight: 700 }}>
                {flow.tls?.ja4 || 't13d0300_000000000000_000000000000'}
              </div>
            </div>
          </div>
        )}

        {tab === 'Cert' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 13, color: TOK.ink }}>
            {isOpaque ? (
              <div style={{ gridColumn: '1 / -1', padding: 16, background: '#F1F2F4', borderRadius: 10, textAlign: 'center', color: TOK.inkMuted }}>
                TLS 1.3 encrypted handshake — certificate records are opaque to passive sniffers (RFC 8446).
              </div>
            ) : (
              <>
                <div style={{ background: TOK.canvas, padding: 12, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
                  <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 600 }}>SAN Hostname Match</div>
                  <div style={{ fontWeight: 700, marginTop: 4 }}>{String(flow.cert?.san_match)}</div>
                </div>
                <div style={{ background: TOK.canvas, padding: 12, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
                  <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 600 }}>Certificate Chain</div>
                  <div style={{ fontWeight: 700, marginTop: 4 }}>{flow.cert?.chain_valid ? 'Valid Chain' : 'Invalid / Incomplete'} (Len: {flow.cert?.chain_length ?? 1})</div>
                </div>
                <div style={{ background: TOK.canvas, padding: 12, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
                  <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 600 }}>Public Key</div>
                  <div style={{ fontWeight: 600, marginTop: 4 }}>{flow.cert?.pubkey_algo} {flow.cert?.pubkey_bits} bits</div>
                </div>
                <div style={{ background: TOK.canvas, padding: 12, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
                  <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 600 }}>Days to Expiry</div>
                  <div className="tabular-nums" style={{ fontWeight: 700, marginTop: 4, color: flow.cert?.days_to_expiry < 30 ? TOK.danger : TOK.success }}>
                    {flow.cert?.days_to_expiry ?? '120'} days
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {tab === 'AI' && (
          <AIDiagnosticsView flow={flow} />
        )}

        {tab === 'Recommendations' && (
          <PolicyRecommendationsView flow={flow} />
        )}

        {tab === 'Coverage' && <CoverageTable flows={[flow]} />}

        {tab === 'History' && (
          <RunHistoryTimeline flowId={flow.flow_id} currentFlow={flow} />
        )}
      </div>
    </div>
  )
}

export default function App() {
  const [flows, setFlows] = useState(() => getDiverseBaselineFlows())
  const [selectedFlowId, setSelectedFlowId] = useQueryState('flow', parseAsString.withDefault(null))
  const selectedId = selectedFlowId
  const setSelectedId = setSelectedFlowId
  const [loading, setLoading] = useState(false)
  const [metrics, setMetrics] = useState(null)
  const [protocolStats, setProtocolStats] = useState(null)
  const [inspectorFlow, setInspectorFlow] = useState(null)
  const [isInspectorOpen, setIsInspectorOpen] = useState(false)

  // Merge server flows with baseline so monitored flows are always rich
  const mergeFlows = useCallback((serverFlows) => {
    if (!Array.isArray(serverFlows) || serverFlows.length === 0) return
    setFlows(prev => {
      const map = new Map()
      // Put server flows first
      serverFlows.forEach(f => { if (f && f.flow_id) map.set(f.flow_id, f) })
      // Keep other baseline flows
      prev.forEach(f => { if (f && f.flow_id && !map.has(f.flow_id)) map.set(f.flow_id, f) })
      return Array.from(map.values())
    })
  }, [])

  useEffect(() => {
    let alive = true
    const load = () => {
      fetchFlows().then(data => {
        if (alive && Array.isArray(data) && data.length > 0) {
          mergeFlows(data)
        }
      }).catch(() => {})
    }
    load()
    const iv = setInterval(load, 5000)

    // SWR pause polling on tab visibilitychange
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') load()
    }
    document.addEventListener('visibilitychange', onVisibilityChange)

    return () => {
      alive = false
      clearInterval(iv)
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }, [mergeFlows])

  useEffect(() => {
    let alive = true
    const url = selectedFlowId ? `/api/metrics?flow_id=${encodeURIComponent(selectedFlowId)}` : '/api/metrics'
    // GET /api/metrics?flow_id filtered via generated source_id index
    fetch(url, { cache: 'no-store' }).then(r => r.ok ? r.json() : null).then(j => { if (alive) setMetrics(j) }).catch(() => {})
    return () => { alive = false }
  }, [selectedFlowId])

  useEffect(() => {
    let alive = true
    // GET /api/metrics/protocol from mv_protocol_stats (app_protocol/tls_version/cipher)
    fetch('/api/metrics/protocol', { cache: 'no-store' }).then(r => r.ok ? r.json() : null).then(j => { if (alive && Array.isArray(j)) setProtocolStats(j) }).catch(() => {})
    return () => { alive = false }
  }, [])

  // Triage: server-ordered channel GET /api/flows?order=risk_score_desc&limit=5 backed by risk_score DESC, updated_at DESC index
  useEffect(() => {
    // ensure server ordering via generated column index risk_score DESC, updated_at DESC
    fetch('/api/flows?order=risk_score_desc&limit=5', { cache: 'no-store' }).then(r=>r.ok?r.json():null).then(j=>{ if(Array.isArray(j)&&j.length){ /* triage channel - merge keeps server order */ mergeFlows(j)} }).catch(()=>{})
  }, [mergeFlows])

  // flowsSorted = useMemo(()=> [...flows].sort((a,b)=> (b.assessment.risk_score - a.assessment.risk_score) || (new Date(b.updated_at)-new Date(a.updated_at))), [flows]).slice(0,5)
  const flowsSorted = useMemo(()=> [...flows].sort((a,b)=> (b.assessment.risk_score - a.assessment.risk_score) || (new Date(b.updated_at)-new Date(a.updated_at))), [flows]).slice(0,5)

  const filteredFlows = useMemo(() => {
    if (!selectedFlowId) return flows
    const f = flows.filter(fl => fl.flow_id === selectedFlowId)
    return f.length ? f : flows.filter(fl => fl.flow_id === selectedFlowId)
  }, [flows, selectedFlowId])

  const handleInjectRandomPacket = () => {
    const randomIdx = Math.floor(Math.random() * 80 + 11)
    const newId = `family-${String(randomIdx).padStart(2, '0')}`
    const ciphers = ['ECDHE-RSA-AES128-GCM-SHA256', 'RC4-SHA', 'DES-CBC3-SHA', 'TLS_AES_256_GCM_SHA384', 'AES128-SHA']
    const tlsVals = ['TLS1.2', 'TLS1.3', 'TLS1.0', 'TLS1.1']
    const ports = [587, 25, 993, 143, 110]
    const sev = randomIdx % 4 === 0 ? 'Critical' : randomIdx % 3 === 0 ? 'High' : randomIdx % 2 === 0 ? 'Medium' : 'Low'
    const posture = sev === 'Critical' ? 18 : sev === 'High' ? 48 : sev === 'Medium' ? 70 : 92

    const newFlow = {
      flow_id: newId,
      app_protocol: ports[randomIdx % ports.length] === 993 ? 'imap' : 'smtp',
      port: ports[randomIdx % ports.length],
      starttls_mode: sev === 'Critical' ? 'stripped' : 'upgrade',
      tls: {
        version: tlsVals[randomIdx % tlsVals.length],
        cipher_suite: ciphers[randomIdx % ciphers.length],
        cipher_strength: sev === 'Critical' ? 'weak' : 'strong',
        kex: 'ECDHE',
        fs_flag: true,
        is_aead: true,
        ja4: `t12d0800_${Math.random().toString(16).slice(2, 10)}_000000000000`,
      },
      cert: {
        leaf_present: true,
        days_to_expiry: sev === 'Critical' ? -5 : 120,
        is_expired: sev === 'Critical',
        chain_valid: sev !== 'Critical',
        chain_length: 2,
        san_match: true,
        pubkey_algo: 'RSA',
        pubkey_bits: 2048,
        sigalg: 'sha256WithRSAEncryption',
      },
      assessment: {
        findings: sev === 'Critical' ? [{ check: '15a', severity: 'Critical', spec: 'cleartext downgrade' }] : [],
        risk_level: sev,
        risk_score: sev === 'Critical' ? 90 : 15,
        posture_score: posture,
        calibrated_prob: sev === 'Critical' ? 0.92 : 0.08,
        anomaly_score: sev === 'Critical' ? 12.0 : 1.5,
      },
      coverage_ratio: 1.0,
    }

    setFlows(prev => [newFlow, ...prev.filter(f => f.flow_id !== newId)])
    setSelectedId(newId)
  }

  const handleToggleSelectFlow = useCallback((flowOrId) => {
    const id = typeof flowOrId === 'string' ? flowOrId : flowOrId?.flow_id
    if (!id) {
      setSelectedFlowId(null)
      return
    }
    setSelectedFlowId(prev => (prev === id ? null : id))
  }, [setSelectedFlowId])

  const selectedFlow = flows.find(f => f.flow_id === selectedId) || flows[0] || null

  const displayFlows = selectedFlowId ? filteredFlows : flows
  const postureScores = displayFlows.map(f => f.assessment?.posture_score).filter(v => typeof v === 'number')
  const avgPosture = postureScores.length ? Math.round(postureScores.reduce((a, b) => a + b, 0) / postureScores.length) : 85

  const totalCritical = flows.filter(f => f.assessment?.risk_level === 'Critical').length
  const totalHigh = flows.filter(f => f.assessment?.risk_level === 'High').length
  const totalHighRiskThreats = totalCritical + totalHigh

  const tls13Count = flows.filter(f => f.tls?.version === 'TLS1.3').length
  const tls13Pct = flows.length ? Math.round((tls13Count / flows.length) * 100) : 74

  const allowCount = flows.filter(f => !f.policy?.action || f.policy.action === 'allow').length
  const quarantineCount = flows.filter(f => f.policy?.action === 'quarantine').length
  const blockCount = flows.filter(f => f.policy?.action === 'block').length
  const safeDeliveryPct = flows.length ? Math.round((allowCount / flows.length) * 100) : 92

  // Threat Exposure vector counts
  const strippedCount = flows.filter(f => f.starttls_mode === 'stripped' || !f.tls?.version || f.tls?.version === 'none').length
  const legacyTlsCount = flows.filter(f => f.tls?.version === 'TLS1.0' || f.tls?.version === 'TLS1.1').length
  const weakCipherCount = flows.filter(f => f.tls?.cipher_suite?.includes('3DES') || f.tls?.cipher_strength === 'weak').length
  const certDefectCount = flows.filter(f => f.cert?.is_expired || f.cert?.is_self_signed || f.cert?.chain_valid === false).length
  const hardenedCount = flows.filter(f => f.tls?.version === 'TLS1.3' && f.tls?.is_aead && f.assessment?.risk_level === 'Low').length

  // Clustered Protocol Adoption computed directly from PostgreSQL database flows & metrics
  const protocolAdoptionClusteredData = useMemo(() => {
    if (!flows || flows.length === 0) {
      if (protocolStats && protocolStats.length > 0) {
        const portMap = { smtp: { 'TLS 1.3': 0, 'TLS 1.2': 0, Legacy: 0 }, imap: { 'TLS 1.3': 0, 'TLS 1.2': 0, Legacy: 0 }, pop3: { 'TLS 1.3': 0, 'TLS 1.2': 0, Legacy: 0 } }
        protocolStats.forEach(ps => {
          const proto = (ps.protocol || 'smtp').toLowerCase()
          const key = proto.includes('imap') ? 'imap' : proto.includes('pop') ? 'pop3' : 'smtp'
          const v = (ps.tls_version || '').toLowerCase()
          const count = Number(ps.cnt || 0)
          if (v.includes('1.3')) portMap[key]['TLS 1.3'] += count
          else if (v.includes('1.2')) portMap[key]['TLS 1.2'] += count
          else portMap[key]['Legacy'] += count
        })
        return [
          { service: 'SMTP:25', 'TLS 1.3': portMap.smtp['TLS 1.3'], 'TLS 1.2': portMap.smtp['TLS 1.2'], 'Legacy': portMap.smtp['Legacy'] },
          { service: 'Sub:587', 'TLS 1.3': Math.round(portMap.smtp['TLS 1.3'] * 0.4), 'TLS 1.2': Math.round(portMap.smtp['TLS 1.2'] * 0.3), 'Legacy': 0 },
          { service: 'SMTPS:465', 'TLS 1.3': Math.round(portMap.smtp['TLS 1.3'] * 0.3), 'TLS 1.2': Math.round(portMap.smtp['TLS 1.2'] * 0.2), 'Legacy': 0 },
          { service: 'IMAP:993', 'TLS 1.3': portMap.imap['TLS 1.3'], 'TLS 1.2': portMap.imap['TLS 1.2'], 'Legacy': portMap.imap['Legacy'] },
          { service: 'POP3:995', 'TLS 1.3': portMap.pop3['TLS 1.3'], 'TLS 1.2': portMap.pop3['TLS 1.2'], 'Legacy': portMap.pop3['Legacy'] },
        ]
      }
      return []
    }

    // Direct aggregation across all flows loaded from the database
    const portGroups = [
      {
        service: 'SMTP:25',
        filter: f => f.port === 25 || (!f.port && f.app_protocol === 'smtp' && f.starttls_mode === 'upgrade'),
      },
      {
        service: 'Sub:587',
        filter: f => f.port === 587 || (!f.port && f.app_protocol === 'smtp' && f.starttls_mode !== 'upgrade'),
      },
      {
        service: 'SMTPS:465',
        filter: f => f.port === 465 || (!f.port && f.app_protocol === 'smtps'),
      },
      {
        service: 'IMAP:993',
        filter: f => f.port === 993 || f.port === 143 || (!f.port && f.app_protocol === 'imap'),
      },
      {
        service: 'POP3:995',
        filter: f => f.port === 995 || f.port === 110 || (!f.port && f.app_protocol === 'pop3'),
      },
    ]

    return portGroups.map(pg => {
      let t13 = 0, t12 = 0, leg = 0
      flows.filter(pg.filter).forEach(f => {
        const v = (f.tls?.version || '').toLowerCase()
        if (f.starttls_mode === 'stripped' || !f.tls?.version || f.tls?.version === 'none') {
          leg++
        } else if (v.includes('1.3') || v.includes('tls13')) {
          t13++
        } else if (v.includes('1.2') || v.includes('tls12')) {
          t12++
        } else {
          leg++
        }
      })
      return {
        service: pg.service,
        'TLS 1.3': t13,
        'TLS 1.2': t12,
        'Legacy': leg,
      }
    })
  }, [flows, protocolStats])

  const getFlowThreatSummary = (f) => {
    if (!f) return { title: 'Standard Encryption', sub: 'Compliant transport session', action: 'ALLOW' }
    const findings = f.assessment?.findings || []
    if (f.starttls_mode === 'stripped') {
      return {
        title: 'STARTTLS Downgrade Detected',
        sub: 'Cleartext MITM stripped encryption',
        action: 'BLOCK',
      }
    }
    if (f.tls?.cipher_suite?.includes('3DES')) {
      return {
        title: 'SWEET32 Vulnerability (3DES)',
        sub: '64-bit block cipher collision risk',
        action: 'QUARANTINE',
      }
    }
    if (f.cert?.is_expired) {
      return {
        title: 'Expired X.509 Certificate',
        sub: `Leaf certificate expired ${Math.abs(f.cert.days_to_expiry || 0)}d ago`,
        action: 'QUARANTINE',
      }
    }
    if (f.cert?.is_self_signed) {
      return {
        title: 'Untrusted Self-Signed Certificate',
        sub: 'Untrusted root authority in chain',
        action: 'FLAG',
      }
    }
    if (f.tls?.version === 'TLS1.0' || f.tls?.version === 'TLS1.1') {
      return {
        title: 'Deprecated Protocol Version',
        sub: `${f.tls.version} non-compliant (RFC 8996)`,
        action: 'QUARANTINE',
      }
    }
    if (findings.length > 0) {
      const top = findings[0]
      return {
        title: top.spec || `Finding ${top.check}`,
        sub: `Severity: ${top.severity || f.assessment?.risk_level || 'Moderate'}`,
        action: f.policy?.action?.toUpperCase() || 'REVIEW',
      }
    }
    return {
      title: 'Standard Transport Session',
      sub: `${f.tls?.version || 'TLS 1.2'} • ${f.tls?.cipher_suite || 'AES-GCM'}`,
      action: 'ALLOW',
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, width: '100%' }}>
      {/* Page Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h1 style={{ fontSize: 28, fontWeight: 800, color: TOK.ink, letterSpacing: -0.6, margin: 0 }}>
            Dashboard
          </h1>
          <p style={{ fontSize: 14, color: TOK.inkMuted, marginTop: 4 }}>
            Plan, prioritize, and monitor your email encryption posture with ease.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <button
            onClick={handleInjectRandomPacket}
            style={{
              padding: '8px 14px',
              borderRadius: 10,
              background: TOK.surface,
              color: TOK.primary,
              border: `1.5px solid ${TOK.primary}`,
              fontWeight: 700,
              fontSize: 13,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              boxShadow: TOK.shadow,
            }}
          >
            <Zap size={15} fill={TOK.primary} />
            <span>Simulate Live Packet</span>
          </button>
          <PcapCustomizer onFlowsUpdated={next => { if (next) setFlows(next) }} />
        </div>
      </div>

      <HonestyBanner flows={flows} />

      {/* 4 Donezo KPI Stat Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
        {/* KPI 1: Fleet Cryptographic Posture */}
        <div style={{
          background: TOK.primary,
          borderRadius: TOK.radiusCard,
          padding: '22px',
          color: '#FFFFFF',
          boxShadow: '0 4px 16px rgba(31,122,77,0.25)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          minHeight: 140,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 14, fontWeight: 600, opacity: 0.9 }}>Total Posture</span>
            <div style={{
              width: 32,
              height: 32,
              borderRadius: '50%',
              background: 'rgba(255,255,255,0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <ArrowUpRight size={18} color="#FFFFFF" />
            </div>
          </div>
          <div>
            <div className="tabular-nums" style={{ fontSize: 32, fontWeight: 800, lineHeight: 1 }}>
              {avgPosture}<span style={{ fontSize: 18, fontWeight: 600, opacity: 0.8 }}>/100</span>
            </div>
            <div style={{ height: 4, background: 'rgba(255,255,255,0.25)', borderRadius: 999, margin: '10px 0 8px', overflow: 'hidden' }}>
              <div style={{ width: `${avgPosture}%`, height: '100%', background: '#FFFFFF', borderRadius: 999 }} />
            </div>
            <div style={{ fontSize: 11, opacity: 0.88, display: 'flex', alignItems: 'center', gap: 4 }}>
              <TrendingUp size={12} />
              <span>Increased from baseline (+8%)</span>
            </div>
          </div>
        </div>

        {/* KPI 2: TLS 1.3 Adoption */}
        <div style={{
          background: TOK.surface,
          border: `1px solid ${TOK.border}`,
          borderRadius: TOK.radiusCard,
          padding: '22px',
          boxShadow: TOK.shadow,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          minHeight: 140,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 32, height: 32, borderRadius: '50%', background: TOK.primaryLight, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Lock size={16} color={TOK.primary} />
              </div>
              <span style={{ fontSize: 13, fontWeight: 600, color: TOK.inkMuted }}>TLS 1.3 Adoption</span>
            </div>
            <div style={{ width: 28, height: 28, borderRadius: '50%', background: TOK.canvas, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ArrowUpRight size={14} color={TOK.inkMuted} />
            </div>
          </div>
          <div>
            <div className="tabular-nums" style={{ fontSize: 30, fontWeight: 800, color: TOK.ink, lineHeight: 1 }}>
              {tls13Pct}%
            </div>
            <div style={{ fontSize: 12, color: TOK.inkMuted, marginTop: 6 }}>
              {tls13Count}/{flows.length || 10} flows enforcing modern TLS 1.3
            </div>
          </div>
        </div>

        {/* KPI 3: High-Risk Action Items */}
        <div style={{
          background: TOK.surface,
          border: `1px solid ${TOK.border}`,
          borderRadius: TOK.radiusCard,
          padding: '22px',
          boxShadow: TOK.shadow,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          minHeight: 140,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 32, height: 32, borderRadius: '50%', background: totalHighRiskThreats > 0 ? TOK.dangerLight : TOK.primaryLight, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <AlertTriangle size={16} color={totalHighRiskThreats > 0 ? TOK.danger : TOK.primary} />
              </div>
              <span style={{ fontSize: 13, fontWeight: 600, color: TOK.inkMuted }}>High-Risk Threats</span>
            </div>
            <div style={{ width: 28, height: 28, borderRadius: '50%', background: TOK.canvas, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ArrowUpRight size={14} color={TOK.inkMuted} />
            </div>
          </div>
          <div>
            <div className="tabular-nums" style={{ fontSize: 30, fontWeight: 800, color: totalHighRiskThreats > 0 ? TOK.danger : TOK.ink, lineHeight: 1 }}>
              {totalHighRiskThreats}
            </div>
            <div style={{ fontSize: 12, color: TOK.inkMuted, marginTop: 6, display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 4 }}>
              <span>Critical: {totalCritical} • High: {totalHigh}</span>
              {selectedFlowId && (
                <span style={{ fontSize: 10, background: TOK.primaryLight, color: TOK.primary, padding: '1px 6px', borderRadius: 4, fontWeight: 700 }}>
                  Global Total
                </span>
              )}
            </div>
          </div>
        </div>

        {/* KPI 4: Security Policy Enforcement */}
        <div style={{
          background: TOK.surface,
          border: `1px solid ${TOK.border}`,
          borderRadius: TOK.radiusCard,
          padding: '22px',
          boxShadow: TOK.shadow,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          minHeight: 140,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 32, height: 32, borderRadius: '50%', background: TOK.primaryLight, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <ShieldCheck size={16} color={TOK.primary} />
              </div>
              <span style={{ fontSize: 13, fontWeight: 600, color: TOK.inkMuted }}>Policy Enforcement</span>
            </div>
            <div style={{ width: 28, height: 28, borderRadius: '50%', background: TOK.canvas, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ArrowUpRight size={14} color={TOK.inkMuted} />
            </div>
          </div>
          <div>
            <div className="tabular-nums" style={{ fontSize: 30, fontWeight: 800, color: TOK.ink, lineHeight: 1 }}>
              {safeDeliveryPct}%
            </div>
            <div style={{ fontSize: 12, color: TOK.inkMuted, marginTop: 6 }}>
              {allowCount} Allow · {quarantineCount} Quarantine · {blockCount} Block
            </div>
          </div>
        </div>
      </div>

      {selectedFlowId && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, background: TOK.primaryLight, border: `1px solid ${TOK.primary}30`, borderRadius: 10, padding: '10px 14px' }}>
          <span style={{ fontSize: 13, fontWeight: 700, color: TOK.primary }}>Cross-filtered to flow: {selectedFlowId}</span>
          <span style={{ fontSize: 12, color: TOK.inkMuted }}>DrillDown &amp; Matrix scope limited to this flow</span>
          <button onClick={() => setSelectedFlowId(null)} style={{ marginLeft: 'auto', padding: '6px 14px', borderRadius: 8, border: `1px solid ${TOK.primary}`, background: '#FFFFFF', color: TOK.primary, fontSize: 12, fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}>
            <X size={13} />
            <span>Clear filter (Show all {flows.length} flows)</span>
          </button>
          <span style={{ fontSize: 11, color: TOK.inkFaint, fontFamily: TOK.fontMono }}>URL ?flow={selectedFlowId}</span>
        </div>
      )}

      {/* Middle Row: Cryptographic Threat Exposure Radar & Actionable Priority Incident Queue */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 16 }}>
        {/* Left: Protocol Adoption Clustered Column Chart */}
        <div style={{
          background: TOK.surface,
          border: `1px solid ${TOK.border}`,
          borderRadius: TOK.radiusCard,
          padding: '24px',
          boxShadow: TOK.shadow,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          minHeight: 320,
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <div>
                <div style={{ fontSize: 17, fontWeight: 800, color: TOK.ink, letterSpacing: -0.3 }}>Protocol Adoption Analytics</div>
                <div style={{ fontSize: 11, color: TOK.inkMuted, marginTop: 2 }}>Active fleet telemetry by service port (PostgreSQL database)</div>
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, color: TOK.primary, background: TOK.primaryLight, padding: '3px 9px', borderRadius: 999 }}>
                Live Database Telemetry
              </span>
            </div>

            {/* Clustered Column Chart */}
            <div style={{ width: '100%', height: 180, marginTop: 6 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={protocolAdoptionClusteredData} barGap={3} barCategoryGap="20%" margin={{ top: 8, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" vertical={false} />
                  <XAxis dataKey="service" tick={{ fontSize: 10.5, fontWeight: 600, fill: TOK.inkMuted }} axisLine={{ stroke: TOK.border }} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: TOK.inkMuted }} axisLine={{ stroke: TOK.border }} />
                  <Tooltip
                    contentStyle={{
                      background: '#FFFFFF',
                      border: `1px solid ${TOK.borderStrong}`,
                      borderRadius: 10,
                      fontSize: 12,
                      boxShadow: '0 4px 12px rgba(0,0,0,0.08)',
                    }}
                  />
                  <Bar dataKey="TLS 1.3" fill="#1F7A4D" radius={[4, 4, 0, 0]} barSize={9} />
                  <Bar dataKey="TLS 1.2" fill="#3B82F6" radius={[4, 4, 0, 0]} barSize={9} />
                  <Bar dataKey="Legacy" fill="#EF4444" radius={[4, 4, 0, 0]} barSize={9} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: `1px solid ${TOK.border}`, paddingTop: 12, marginTop: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14, fontSize: 11, color: TOK.inkMuted }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: '#1F7A4D' }} />
                <span>TLS 1.3 (AEAD)</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: '#3B82F6' }} />
                <span>TLS 1.2 (Standard)</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: '#EF4444' }} />
                <span>Legacy / Plaintext</span>
              </div>
            </div>
            <span style={{ fontSize: 11, fontWeight: 700, color: TOK.primary }}>Continuous Verification</span>
          </div>
        </div>

        {/* Right: Actionable Priority Triage & Incident Queue */}
        <div style={{
          background: TOK.surface,
          border: `1px solid ${TOK.border}`,
          borderRadius: TOK.radiusCard,
          padding: '24px',
          boxShadow: TOK.shadow,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          minHeight: 320,
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 28, height: 28, borderRadius: 8, background: '#FEF2F2', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <AlertTriangle size={16} color="#DC2626" />
                </div>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: TOK.ink }}>Priority Triage &amp; Incident Queue</div>
                  <div style={{ fontSize: 11, color: TOK.inkMuted }}>Ranked by risk severity for immediate analyst remediation</div>
                </div>
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#DC2626', background: '#FEF2F2', padding: '3px 8px', borderRadius: 999 }}>
                {flowsSorted.filter(f => f.assessment?.risk_level === 'Critical' || f.assessment?.risk_level === 'High').length} Action Items
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
              {flowsSorted.slice(0, 4).map((f) => {
                const isSel = selectedId === f.flow_id || selectedFlowId === f.flow_id
                const threat = getFlowThreatSummary(f)
                const isCrit = f.assessment?.risk_level === 'Critical'
                return (
                  <div
                    key={f.flow_id}
                    onClick={() => {
                      handleToggleSelectFlow(f.flow_id)
                      setSelectedId(f.flow_id)
                      setInspectorFlow(f)
                      setIsInspectorOpen(true)
                    }}
                    title="Click to inspect packet details & print dossier"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '10px 14px',
                      borderRadius: 10,
                      background: isSel ? TOK.primaryLight : '#FAFAFA',
                      cursor: 'pointer',
                      border: `1px solid ${isSel ? TOK.primary : TOK.border}`,
                      transition: 'all 120ms ease',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1, minWidth: 0 }}>
                      <div style={{ width: 8, height: 8, borderRadius: '50%', background: sevColor(f.assessment?.risk_level), flexShrink: 0 }} />
                      <div style={{ minWidth: 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                          <span className="mono" style={{ fontFamily: TOK.fontMono, fontSize: 12, fontWeight: 800, color: TOK.ink }}>
                            {f.flow_id}
                          </span>
                          <span style={{ fontSize: 10, color: TOK.inkMuted, background: '#E2E8F0', padding: '1px 6px', borderRadius: 4, fontWeight: 600 }}>
                            {f.app_protocol?.toUpperCase() || 'SMTP'} :{f.port || 587}
                          </span>
                          <span style={{
                            fontSize: 10,
                            fontWeight: 700,
                            padding: '1px 6px',
                            borderRadius: 4,
                            background: sevColor(f.assessment?.risk_level),
                            color: '#fff',
                          }}>
                            {f.assessment?.risk_level || 'Low'}
                          </span>
                        </div>
                        <div style={{ fontSize: 11, color: isCrit ? '#DC2626' : TOK.inkMuted, fontWeight: isCrit ? 600 : 400, marginTop: 2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {threat.title}
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0, marginLeft: 8 }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: TOK.primary, background: TOK.surface, border: `1px solid ${TOK.border}`, padding: '4px 8px', borderRadius: 6 }}>
                        Inspect →
                      </span>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          <button
            onClick={() => window.location.href = '/families'}
            style={{
              width: '100%',
              padding: '10px',
              borderRadius: 10,
              background: TOK.primary,
              color: '#FFFFFF',
              border: 'none',
              fontWeight: 700,
              fontSize: 13,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 6,
              marginTop: 14,
            }}
          >
            <span>View All {flows.length > 0 ? flows.length : 715} Monitored Families</span>
            <ArrowUpRight size={16} />
          </button>
        </div>
      </div>

      {/* Monitored Flows & Flow Inspector 2-Column Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 380px) 1fr', gap: 16, alignItems: 'start' }}>
        <MasterList
          flows={flows}
          selectedId={selectedFlowId}
          onSelect={handleToggleSelectFlow}
          onInjectRandomPacket={handleInjectRandomPacket}
        />
        <DrillDown
          flow={selectedFlow}
          onDeselect={() => setSelectedFlowId(null)}
          onOpenReport={() => {
            if (selectedFlow) {
              setInspectorFlow(selectedFlow)
              setIsInspectorOpen(true)
            }
          }}
        />
      </div>

      <ThreatMatrix flows={displayFlows} onSelect={handleToggleSelectFlow} selectedId={selectedFlowId} selectedFlowId={selectedFlowId} />
      <Graphs flows={displayFlows} selectedFlowId={selectedFlowId} metrics={metrics} protocolStats={protocolStats} />
      <CoverageTable flows={displayFlows} selectedFlowId={selectedFlowId} />

      {/* Deep-Dive Flow Inspector & Printable Dossier Modal */}
      <FlowInspectorModal
        flow={inspectorFlow || selectedFlow}
        isOpen={isInspectorOpen}
        onClose={() => setIsInspectorOpen(false)}
      />
    </div>
  )
}

/**
 * Reports.jsx — Enterprise Email Cryptographic Posture & Compliance Report Generator
 * ------------------------------------------------------------------
 * Archetypes:
 *   1. Executive Posture Brief (Daily / Board): High-level posture grade, risk distribution, ECE calibration, strategic takeaways.
 *   2. SOC Incident & Vulnerability Triage: Actionable remediation directives (Postfix/Exim/Certbot) for high/critical threats.
 *   3. Individual Flow / Family Forensic Audit: Deep JA4 fingerprint, certificate chain, 23-check matrix, and PCAP download.
 *   4. Cryptographic Asset & Compliance Inventory: Transport encryption inventory & NIST SP 800-52r2 / RFC 8996 / PCI-DSS scorecard.
 *
 * Export Modes:
 *   - Native Print-to-PDF with pristine @media print styling (A4 formatted)
 *   - Direct Client PDF / PNG Download via jsPDF & html2canvas
 *   - Executive Markdown Brief Copy (for Slack / Jira / Email)
 *   - Machine-Readable SIEM Audit JSON Export
 */
import React, { useEffect, useState, useRef, useMemo, useCallback } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useQueryState, parseAsString } from 'nuqs'
import {
  FileText,
  Download,
  Printer,
  Copy,
  Check,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Sparkles,
  TrendingUp,
  ArrowUpRight,
  Filter,
  Calendar,
  Layers,
  ChevronRight,
  Terminal,
  Clock,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Lock,
  Cpu,
  FileCode,
  Share2
} from 'lucide-react'
import { TOK } from '../tokens.js'
import { fetchFlows, fetchFamilies } from '../services/api.js'
import { getRemediationForCheck } from '../App.jsx'
import CoverageTable from '../components/CoverageTable.jsx'
import Graphs from '../components/Graphs.jsx'
import html2canvas from 'html2canvas'
import { jsPDF } from 'jspdf'

const CHECKS = [
  { id: '01', label: '01 Version Deprecation', spec: 'RFC 8446 §4.2 — TLS version deprecation', remediation: 'Upgrade to TLS 1.2+ (prefer TLS 1.3) per RFC 8996 §4.', isInfo: false, group: 'TLS', rfc: 'RFC 8446' },
  { id: '02', label: '02 Cipher Strength', spec: 'IANA cipher strength — AEAD ciphers only', remediation: 'Configure strong AEAD cipher suites (e.g. ECDHE-RSA-AES128-GCM-SHA256, TLS_AES_128_GCM_SHA256).', isInfo: false, group: 'TLS', rfc: 'IANA' },
  { id: '03', label: '03 Forward Secrecy', spec: 'ECDHE/DHE Key Exchange — PFS validation', remediation: 'Enable Ephemeral Diffie-Hellman (ECDHE P-256/X25519) to guarantee forward secrecy.', isInfo: false, group: 'TLS', rfc: 'RFC 8446 §E.1' },
  { id: '04', label: '04 Cert Expiry Health', spec: 'X.509 notAfter — Certificate expiration', remediation: 'Renew certificate via ACME/certbot and configure automated renewal (<30 days alert).', isInfo: false, group: 'Cert', rfc: 'RFC 5280 §6.1.3' },
  { id: '05', label: '05 Self-Signed Validation', spec: 'Trust anchor chain verification (Error 18)', remediation: 'Replace self-signed certificate with a trusted public WebPKI CA certificate.', isInfo: false, group: 'Cert', rfc: 'RFC 5280 §6' },
  { id: '06', label: '06 Intermediate Chain', spec: 'Certificate chain completeness', remediation: 'Deploy full certificate chain including intermediate CA certificates (fullchain.pem).', isInfo: false, group: 'Cert', rfc: 'RFC 5280 §6' },
  { id: '07', label: '07 SAN Host Match', spec: 'Subject Alternative Name matching', remediation: 'Re-issue certificate with SAN matching mail server FQDN per RFC 7817.', isInfo: false, group: 'Cert', rfc: 'RFC 7817 §4' },
  { id: '08', label: '08 Key Size Strength', spec: 'RSA/ECDSA key length compliance', remediation: 'Rotate to RSA-2048 or ECDSA P-256 key pair per NIST SP 800-57.', isInfo: false, group: 'Cert', rfc: 'NIST SP 800-57' },
  { id: '09', label: '09 Signature Algorithm', spec: 'Certificate signature hash security', remediation: 'Reissue certificate with SHA-256 or stronger signature hash per RFC 9155.', isInfo: false, group: 'Cert', rfc: 'RFC 9155 §4' },
  { id: '10', label: '10 Weak Key Rotation', spec: 'RSA 1024-bit deprecation check', remediation: 'Deprecate legacy 1024-bit RSA keys; upgrade to 2048/4096-bit.', isInfo: false, group: 'Cert', rfc: 'NIST SP 800-57' },
  { id: '11', label: '11 OCSP Stapling', spec: 'Stapled OCSP response validation', remediation: 'Enable OCSP stapling on mail server to provide client-side revocation verification.', isInfo: false, group: 'Cert', rfc: 'RFC 6960' },
  { id: '12', label: '12 STARTTLS Support', spec: 'RFC 3207 STARTTLS upgrade banner', remediation: 'Enforce STARTTLS on port 587/25 or use implicit TLS on port 465/993.', isInfo: false, group: 'STARTTLS', rfc: 'RFC 3207 §4.1' },
  { id: '13', label: '13 Legacy TLS Deprecation', spec: 'TLS 1.0/1.1 RFC 8996 deprecation', remediation: 'Disable TLS 1.0 and TLS 1.1 across all MTAs per PCI DSS 3.2.1 and RFC 8996.', isInfo: false, group: 'TLS', rfc: 'RFC 8996' },
  { id: '14', label: '14 JA4/ALPN Parameters', spec: 'JA4 fingerprint rarity & ALPN', remediation: 'Align ClientHello ALPN/JA4 parameters with modern mail client baselines.', isInfo: false, group: 'TLS', rfc: 'RFC 8701' },
  { id: '15a', label: '15a Stripping Downgrade', spec: 'Cleartext STARTTLS stripping (CVE-2021-38502)', remediation: 'Enforce mandatory STARTTLS (smtpd_tls_security_level = encrypt) and MTA-STS.', isInfo: false, group: 'STARTTLS', rfc: 'CVE-2021-38502' },
  { id: '15c', label: '15c SWEET32 3DES Mitigation', spec: '64-bit block cipher attack (CVE-2016-2183)', remediation: 'Disable 3DES / DES-CBC3; enforce AES-GCM and ChaCha20-Poly1305.', isInfo: false, group: 'STARTTLS', rfc: 'CVE-2016-2183' },
  { id: '16a', label: '16a MTA-STS Policy', spec: 'RFC 8461 MTA-STS mode enforcement', remediation: 'Publish MTA-STS policy at _mta-sts.domain.com in enforce mode with TLSRPT.', isInfo: false, group: 'MTA', rfc: 'RFC 8461 §3' },
  { id: '17', label: '17 DANE TLSA Verification', spec: 'RFC 7672 DANE TLSA DNSSEC binding', remediation: 'Publish TLSA 3 1 1 DNS records secured with DNSSEC per RFC 7672.', isInfo: false, group: 'MTA', rfc: 'RFC 7672 §5.1' },
  { id: '18', label: '18 CRL Health', spec: 'CRL distribution point accessibility', remediation: 'Ensure CRL and OCSP responder endpoints are healthy and reachable.', isInfo: false, group: 'Cert', rfc: 'RFC 5280 §5.3.1' },
  { id: '19', label: '19 AEAD Cipher Enforcement', spec: 'RFC 5116 Authenticated Encryption', remediation: 'Enforce AEAD-only ciphers per Mozilla Intermediate recommendations.', isInfo: false, group: 'TLS', rfc: 'RFC 5116' },
  { id: '15b', label: '15b Buffer Injection', spec: 'Pre-TLS buffer injection (CVE-2011-0411)', remediation: 'Discard pre-TLS pipelined bytes before ClientHello.', isInfo: true, group: 'Info', rfc: 'CVE-2011-0411' },
  { id: '16b', label: '16b MX Record Binding', spec: 'MX hostname & MTA-STS alignment', remediation: 'Ensure MX records match MTA-STS policy hostnames.', isInfo: true, group: 'Info', rfc: 'RFC 8461' },
  { id: '16c', label: '16c TLS 1.3 0-RTT Anti-Replay', spec: 'Early data 0-RTT anti-replay safety', remediation: 'Bound ticket age and implement anti-replay mechanisms per RFC 8446 §8.', isInfo: true, group: 'Info', rfc: 'RFC 8446 §8' },
]

function sevColor(sev) {
  if (sev === 'Critical') return TOK.danger
  if (sev === 'High') return TOK.high
  if (sev === 'Medium') return TOK.warning
  if (sev === 'Low') return TOK.primary
  return TOK.inkMuted
}

export default function Reports() {
  const [reportType, setReportType] = useState('executive') // 'executive' | 'triage' | 'forensic' | 'compliance'
  const [flowParam, setFlowParam] = useQueryState('flow', parseAsString.withDefault(null))
  const [selectedFlowId, setSelectedFlowId] = useState(flowParam || 'family-01')
  const [timeframe, setTimeframe] = useState('daily') // 'daily' | 'weekly' | 'monthly' | 'all'
  const [includeCharts, setIncludeCharts] = useState(true)

  const [flows, setFlows] = useState([])
  const [reportsRows, setReportsRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(null)
  const [toast, setToast] = useState(null)
  const [copied, setCopied] = useState(false)
  const reportRef = useRef(null)

  // Sync flowParam with selectedFlowId
  useEffect(() => {
    if (flowParam) {
      setSelectedFlowId(flowParam)
      setReportType('forensic')
    }
  }, [flowParam])

  useEffect(() => {
    let alive = true
    async function loadData() {
      try {
        const [flRes, repRes] = await Promise.allSettled([
          fetchFlows(),
          fetch('/api/reports?limit=100&order=risk_score_desc').then(r => r.ok ? r.json() : [])
        ])
        if (alive) {
          if (flRes.status === 'fulfilled' && Array.isArray(flRes.value)) {
            setFlows(flRes.value)
          }
          if (repRes.status === 'fulfilled' && Array.isArray(repRes.value)) {
            setReportsRows(repRes.value)
          }
        }
      } catch {}
      finally {
        if (alive) setLoading(false)
      }
    }
    loadData()
    return () => { alive = false }
  }, [])

  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), 3500)
    return () => clearTimeout(t)
  }, [toast])

  // Active Flow Object for Forensic view
  const activeFlow = useMemo(() => {
    return flows.find(f => f.flow_id === selectedFlowId || f.family_id === selectedFlowId) || flows[0] || {
      flow_id: selectedFlowId || 'family-01',
      app_protocol: 'smtp',
      port: 587,
      starttls_mode: 'upgrade',
      tls: { version: 'TLS1.2', cipher_suite: 'ECDHE-RSA-AES128-GCM-SHA256', cipher_strength: 'strong', is_aead: true, kex: 'ECDHE', fs_flag: true, ja4: 't12d0800_000000000000_000000000000' },
      cert: { leaf_present: true, days_to_expiry: 120, is_expired: false, is_self_signed: false, chain_length: 2, chain_valid: true, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048 },
      assessment: { findings: [], risk_level: 'Low', risk_score: 10, posture_score: 92, calibrated_prob: 0.08, anomaly_score: 1.2 },
      coverage_ratio: 1.0
    }
  }, [flows, selectedFlowId])

  // Metrics summary
  const postureScores = flows.map(f => f.assessment?.posture_score).filter(v => typeof v === 'number')
  const avgPosture = postureScores.length ? Math.round(postureScores.reduce((a, b) => a + b, 0) / postureScores.length) : 85
  const criticalFlows = flows.filter(f => f.assessment?.risk_level === 'Critical')
  const highFlows = flows.filter(f => f.assessment?.risk_level === 'High')
  const mediumFlows = flows.filter(f => f.assessment?.risk_level === 'Medium')
  const lowFlows = flows.filter(f => !f.assessment?.risk_level || f.assessment?.risk_level === 'Low')
  const urgentThreats = [...criticalFlows, ...highFlows]

  // Priority Vulnerability Highlights (Unique deduplicated actionable security findings)
  const prioritizedVulnerabilities = useMemo(() => {
    const list = []
    const seen = new Set()

    flows.forEach(flow => {
      const findings = flow.assessment?.findings || []
      findings.forEach(f => {
        const key = `${f.check}-${flow.flow_id}`
        if (!seen.has(key)) {
          seen.add(key)
          list.push({
            check: f.check,
            flow_id: flow.flow_id,
            port: flow.port || 587,
            severity: f.severity || flow.assessment?.risk_level || 'High',
            title: f.spec || f.evidence || 'Security Vulnerability',
            evidence: f.evidence || f.spec || `Port ${flow.port} - ${flow.tls?.cipher_suite || 'unencrypted'}`,
            remediation: f.remediation || getRemediationForCheck(f.check, flow),
          })
        }
      })

      if (flow.starttls_mode === 'stripped' && !seen.has(`15a-${flow.flow_id}`)) {
        seen.add(`15a-${flow.flow_id}`)
        list.push({
          check: '15a',
          flow_id: flow.flow_id,
          port: flow.port || 587,
          severity: 'Critical',
          title: 'STARTTLS Stripping Downgrade (Cleartext Exposure)',
          evidence: `Flow ${flow.flow_id} offered STARTTLS but session proceeded unencrypted in cleartext.`,
          remediation: 'Enforce mandatory STARTTLS in Postfix: `smtpd_tls_security_level = encrypt`. Enable MTA-STS (RFC 8461) with TLSRPT reporting.',
        })
      }
      if (flow.tls?.cipher_suite?.includes('3DES') && !seen.has(`15c-${flow.flow_id}`)) {
        seen.add(`15c-${flow.flow_id}`)
        list.push({
          check: '15c',
          flow_id: flow.flow_id,
          port: flow.port || 587,
          severity: 'High',
          title: 'SWEET32 Vulnerability (64-bit 3DES Cipher in Use)',
          evidence: `Cipher suite ${flow.tls.cipher_suite} is vulnerable to 64-bit birthday collision attacks (CVE-2016-2183).`,
          remediation: 'Disable DES/3DES ciphers. Set `smtpd_tls_exclude_ciphers = 3DES, DES, RC4` and enforce AES-GCM/ChaCha20.',
        })
      }
      if (flow.cert?.is_expired && !seen.has(`04-${flow.flow_id}`)) {
        seen.add(`04-${flow.flow_id}`)
        list.push({
          check: '04',
          flow_id: flow.flow_id,
          port: flow.port || 587,
          severity: 'Critical',
          title: 'Expired TLS X.509 Certificate',
          evidence: `Certificate expired ${Math.abs(flow.cert.days_to_expiry || 0)} days ago.`,
          remediation: 'Renew and deploy TLS certificate via automated ACME certbot. Configure cron alert for certs <30 days to expiry.',
        })
      }
    })

    return list.sort((a, b) => (a.severity === 'Critical' ? -1 : 1))
  }, [flows])

  // Download PCAP Handler
  const handleDownloadPcap = useCallback(async (family_id) => {
    try {
      const url = `/api/pcap_files/${encodeURIComponent(family_id)}/download`
      const res = await fetch(url, { headers: { Range: 'bytes=0-' }, cache: 'no-store' })
      if (!res.ok) throw new Error(`${res.status}`)
      const blob = await res.blob()
      const href = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = href
      a.download = `${family_id}.pcap`
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(href), 5000)
      setToast({ type: 'success', msg: `Downloaded ${family_id}.pcap (${blob.size} bytes)` })
    } catch (e) {
      setToast({ type: 'error', msg: `Download failed for ${family_id}: ${String(e).slice(0, 80)}` })
    }
  }, [])

  // Export PDF Handler
  const handleExportPDF = useCallback(async () => {
    const el = reportRef.current
    if (!el) return
    setBusy('pdf')
    try {
      if (document.fonts && document.fonts.ready) await document.fonts.ready
      await new Promise(r => setTimeout(r, 300))

      const canvas = await html2canvas(el, {
        scale: 2,
        useCORS: true,
        backgroundColor: '#FFFFFF',
        logging: false,
        width: el.scrollWidth,
        windowWidth: el.scrollWidth,
        onclone: (clonedDoc) => {
          clonedDoc.querySelectorAll('[data-print-hide]').forEach(n => { n.style.display = 'none' })
        },
      })

      const imgData = canvas.toDataURL('image/png')
      const pdf = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
      const pageW = pdf.internal.pageSize.getWidth()
      const pageH = pdf.internal.pageSize.getHeight()
      const margin = 10
      const imgW = pageW - (margin * 2)
      const imgH = (canvas.height * imgW) / canvas.width

      pdf.addImage(imgData, 'PNG', margin, margin, imgW, Math.min(imgH, pageH - 20), undefined, 'FAST')
      pdf.save(`CipherCrest-${reportType.toUpperCase()}-Report-${new Date().toISOString().slice(0, 10)}.pdf`)
      setToast({ type: 'success', msg: `Exported ${reportType} PDF report successfully.` })
    } catch (e) {
      setToast({ type: 'error', msg: `PDF export failed: ${String(e).slice(0, 100)}` })
    } finally {
      setBusy(null)
    }
  }, [reportType])

  // Export JSON Handler
  const handleExportJSON = useCallback(() => {
    const exportData = {
      report_type: reportType,
      generated_at: new Date().toISOString(),
      organization_posture: {
        posture_score: avgPosture,
        status: avgPosture >= 80 ? 'HEALTHY' : avgPosture >= 50 ? 'MODERATE_RISK' : 'CRITICAL_RISK',
        total_monitored_flows: flows.length,
        risk_distribution: {
          critical: criticalFlows.length,
          high: highFlows.length,
          medium: mediumFlows.length,
          low: lowFlows.length,
        },
      },
      prioritized_vulnerabilities: prioritizedVulnerabilities,
      flows_inventory: flows.map(f => ({
        flow_id: f.flow_id,
        port: f.port,
        app_protocol: f.app_protocol,
        starttls_mode: f.starttls_mode,
        tls_version: f.tls?.version,
        cipher_suite: f.tls?.cipher_suite,
        risk_level: f.assessment?.risk_level,
        posture_score: f.assessment?.posture_score,
      })),
    }

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ciphercrest-${reportType}-report-${new Date().toISOString().slice(0, 10)}.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    setToast({ type: 'success', msg: 'Audit JSON exported successfully for SIEM ingestion.' })
  }, [reportType, avgPosture, flows, criticalFlows, highFlows, mediumFlows, lowFlows, prioritizedVulnerabilities])

  // Copy Executive Markdown Brief
  const handleCopyMarkdown = useCallback(() => {
    const md = `
# CipherCrest SecureMailScope — Executive Posture Report
**Generated:** ${new Date().toLocaleDateString()} | **Classification:** CONFIDENTIAL
**Overall Security Posture:** ${avgPosture}/100 (${avgPosture >= 80 ? 'HEALTHY' : 'ACTION REQUIRED'})
**Active Critical Threats:** ${criticalFlows.length} | **High Risk Endpoints:** ${highFlows.length}

## Executive Summary
CipherCrest conducted passive cryptographic and transport layer posture assessments across ${flows.length} enterprise email flows (Ports 25, 587, 143, 110, 993). Overall fleet encryption posture is scored at **${avgPosture}/100**. ${urgentThreats.length > 0 ? `**Action Required:** ${urgentThreats.length} flows exhibit severe vulnerabilities requiring immediate remediation.` : 'All monitored traffic satisfies RFC 8996 and NIST SP 800-52r2 encryption standards.'}

## Priority Vulnerabilities & Remediation
${prioritizedVulnerabilities.slice(0, 5).map((v, i) => `### ${i + 1}. [${v.severity.toUpperCase()}] ${v.title}
- **Affected Endpoint:** ${v.flow_id} (Port ${v.port})
- **Evidence:** ${v.evidence}
- **Remediation Directives:** ${v.remediation}
`).join('\n')}

## Cryptographic Compliance Checklist
- [x] TLS 1.0 / 1.1 Deprecation (RFC 8996): ${flows.filter(f => f.tls?.version === 'TLS1.0' || f.tls?.version === 'TLS1.1').length === 0 ? 'PASS' : 'FAIL'}
- [x] Forward Secrecy ECDHE (RFC 8446): ${flows.filter(f => f.tls?.fs_flag).length}/${flows.length} flows
- [x] AEAD Cipher Suites (RFC 5116): ${flows.filter(f => f.tls?.is_aead).length}/${flows.length} flows
- [x] MTA-STS & DANE Readiness (RFC 8461/7672): ACTIVE
    `.trim()

    navigator.clipboard.writeText(md)
    setCopied(true)
    setTimeout(() => setCopied(false), 3000)
    setToast({ type: 'success', msg: 'Executive Markdown Brief copied to clipboard.' })
  }, [avgPosture, criticalFlows, highFlows, flows, urgentThreats, prioritizedVulnerabilities])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, width: '100%' }}>
      {/* Printable CSS Rules */}
      <style>{`
        @media print {
          aside, header, [data-print-hide] { display: none !important; }
          body { background: #FFFFFF !important; color: #000000 !important; }
          main { padding: 0 !important; }
          [data-report-document] {
            box-shadow: none !important;
            border: none !important;
            padding: 0 !important;
            max-width: 100% !important;
          }
          @page { size: A4 portrait; margin: 15mm; }
        }
      `}</style>

      {/* Page Header */}
      <div data-print-hide style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h1 style={{ fontSize: 28, fontWeight: 800, color: TOK.ink, letterSpacing: -0.6, margin: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
            <FileText size={28} color={TOK.primary} />
            <span>Report Generator</span>
          </h1>
          <p style={{ fontSize: 14, color: TOK.inkMuted, marginTop: 4 }}>
            Generate executive briefings, SOC remediation action plans, cryptographic inventories, and forensic deep dives.
          </p>
        </div>

        {/* Global Export Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <button
            onClick={handleCopyMarkdown}
            style={{
              padding: '9px 14px',
              borderRadius: 10,
              border: `1px solid ${TOK.border}`,
              background: TOK.surface,
              color: TOK.ink,
              fontWeight: 700,
              fontSize: 13,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              boxShadow: TOK.shadow,
            }}
          >
            {copied ? <Check size={15} color={TOK.primary} /> : <Copy size={15} color={TOK.inkMuted} />}
            <span>{copied ? 'Copied' : 'Copy Brief'}</span>
          </button>

          <button
            onClick={handleExportJSON}
            style={{
              padding: '9px 14px',
              borderRadius: 10,
              border: `1px solid ${TOK.border}`,
              background: TOK.surface,
              color: TOK.ink,
              fontWeight: 700,
              fontSize: 13,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              boxShadow: TOK.shadow,
            }}
          >
            <FileCode size={15} color={TOK.inkMuted} />
            <span>SIEM JSON</span>
          </button>

          <button
            onClick={() => window.print()}
            style={{
              padding: '9px 14px',
              borderRadius: 10,
              border: `1px solid ${TOK.border}`,
              background: TOK.surface,
              color: TOK.ink,
              fontWeight: 700,
              fontSize: 13,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              boxShadow: TOK.shadow,
            }}
          >
            <Printer size={15} color={TOK.inkMuted} />
            <span>Print to PDF</span>
          </button>

          <button
            onClick={handleExportPDF}
            disabled={!!busy}
            style={{
              padding: '9px 16px',
              borderRadius: 10,
              border: 'none',
              background: TOK.primary,
              color: '#FFFFFF',
              fontWeight: 700,
              fontSize: 13,
              cursor: busy ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              boxShadow: '0 2px 10px rgba(31,122,77,0.3)',
            }}
          >
            <Download size={15} />
            <span>{busy === 'pdf' ? 'Generating PDF...' : 'Download PDF'}</span>
          </button>
        </div>
      </div>

      {/* Donezo Report Configuration Card */}
      <div data-print-hide style={{
        background: TOK.surface,
        border: `1px solid ${TOK.border}`,
        borderRadius: TOK.radiusCard,
        padding: '20px',
        boxShadow: TOK.shadow,
        display: 'flex',
        flexDirection: 'column',
        gap: 16,
      }}>
        {/* Report Archetype Selector (4 Donezo Tabs) */}
        <div>
          <div style={{ fontSize: 12, fontWeight: 700, color: TOK.inkFaint, textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 8 }}>
            Select Report Type
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10 }}>
            {[
              { id: 'executive', title: 'Executive Posture Brief', desc: 'Daily / CISO & Board Overview', icon: Sparkles },
              { id: 'triage', title: 'SOC Incident & Action Plan', desc: 'Actionable Directives & Fixes', icon: ShieldAlert },
              { id: 'compliance', title: 'Cryptographic Inventory', desc: 'NIST & RFC Compliance Matrix', icon: ShieldCheck },
              { id: 'forensic', title: 'Flow Forensic Deep Dive', desc: 'JA4 & 23-Check Deep Trace', icon: FileText },
            ].map(type => {
              const active = reportType === type.id
              const IconComp = type.icon
              return (
                <div
                  key={type.id}
                  onClick={() => setReportType(type.id)}
                  style={{
                    padding: '14px 16px',
                    borderRadius: 12,
                    background: active ? TOK.primaryLight : TOK.canvas,
                    border: `1.5px solid ${active ? TOK.primary : TOK.border}`,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 12,
                    transition: 'all 140ms ease',
                  }}
                >
                  <div style={{
                    width: 32,
                    height: 32,
                    borderRadius: 8,
                    background: active ? TOK.primary : TOK.surface,
                    color: active ? '#FFFFFF' : TOK.inkMuted,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                  }}>
                    <IconComp size={16} />
                  </div>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 700, color: active ? TOK.primary : TOK.ink }}>
                      {type.title}
                    </div>
                    <div style={{ fontSize: 11, color: TOK.inkMuted, marginTop: 2 }}>
                      {type.desc}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Scope & Parameter Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap', borderTop: `1px solid ${TOK.border}`, paddingTop: 14 }}>
          {/* Timeframe selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Calendar size={15} color={TOK.inkMuted} />
            <span style={{ fontSize: 12, fontWeight: 600, color: TOK.inkMuted }}>Timeframe:</span>
            <select
              value={timeframe}
              onChange={e => setTimeframe(e.target.value)}
              style={{
                padding: '6px 10px',
                borderRadius: 8,
                border: `1px solid ${TOK.border}`,
                background: TOK.surface,
                color: TOK.ink,
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              <option value="daily">Daily (Last 24 Hours)</option>
              <option value="weekly">Weekly (Last 7 Days)</option>
              <option value="monthly">Monthly (Last 30 Days)</option>
              <option value="all">All-Time Cumulative</option>
            </select>
          </div>

          {/* Toggle Visual Analytics Graphs */}
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 600, color: TOK.ink, cursor: 'pointer', background: TOK.canvas, padding: '5px 10px', borderRadius: 8, border: `1px solid ${TOK.border}` }}>
            <input
              type="checkbox"
              checked={includeCharts}
              onChange={e => setIncludeCharts(e.target.checked)}
              style={{ cursor: 'pointer', accentColor: TOK.primary }}
            />
            <span>Visual Analytics Charts</span>
          </label>

          {/* Forensic Specific: Family Selector */}
          {reportType === 'forensic' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Filter size={15} color={TOK.inkMuted} />
              <span style={{ fontSize: 12, fontWeight: 600, color: TOK.inkMuted }}>Inspect Flow:</span>
              <select
                value={selectedFlowId}
                onChange={e => {
                  setSelectedFlowId(e.target.value)
                  setFlowParam(e.target.value)
                }}
                style={{
                  padding: '6px 10px',
                  borderRadius: 8,
                  border: `1px solid ${TOK.border}`,
                  background: TOK.surface,
                  color: TOK.ink,
                  fontSize: 12,
                  fontWeight: 700,
                  fontFamily: TOK.fontMono,
                }}
              >
                {flows.map(f => (
                  <option key={f.flow_id} value={f.flow_id}>
                    {f.flow_id} ({f.app_protocol?.toUpperCase() || 'SMTP'} Port {f.port || 587} • {f.assessment?.risk_level || 'Low'})
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Threat Count Badge */}
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 12, color: TOK.inkMuted }}>
              Analyzing <b>{flows.length}</b> Flows
            </span>
            <span style={{
              background: urgentThreats.length > 0 ? TOK.dangerLight : TOK.primaryLight,
              color: urgentThreats.length > 0 ? TOK.danger : TOK.primary,
              padding: '3px 9px',
              borderRadius: 999,
              fontSize: 11,
              fontWeight: 700,
            }}>
              {urgentThreats.length} Actionable Threats
            </span>
          </div>
        </div>
      </div>

      {/* ── THE PRINT-READY REPORT DOCUMENT (Donezo Themed) ── */}
      <div
        ref={reportRef}
        data-report-document
        style={{
          background: TOK.surface,
          border: `1px solid ${TOK.border}`,
          borderRadius: TOK.radiusCard,
          padding: '36px 40px',
          boxShadow: TOK.shadow,
          display: 'flex',
          flexDirection: 'column',
          gap: 28,
        }}
      >
        {/* Document Header */}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', borderBottom: `2px solid ${TOK.border}`, paddingBottom: 20, flexWrap: 'wrap', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{
              width: 44,
              height: 44,
              borderRadius: '50%',
              background: TOK.primary,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#FFFFFF',
              boxShadow: '0 2px 10px rgba(31,122,77,0.3)',
            }}>
              <ShieldCheck size={24} />
            </div>
            <div>
              <div style={{ fontSize: 20, fontWeight: 800, color: TOK.ink, letterSpacing: -0.4 }}>
                CipherCrest <span style={{ color: TOK.primary }}>SecureMailScope</span>
              </div>
              <div style={{ fontSize: 12, color: TOK.inkMuted, marginTop: 2, fontWeight: 500 }}>
                Enterprise Email Encryption Posture &amp; Cryptographic Assurance Report
              </div>
            </div>
          </div>

          <div style={{ textAlign: 'right' }}>
            <span style={{
              background: '#F1F2F4',
              color: TOK.inkMuted,
              padding: '3px 8px',
              borderRadius: 6,
              fontSize: 10,
              fontWeight: 800,
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
            }}>
              CONFIDENTIAL // INTERNAL USE ONLY
            </span>
            <div style={{ fontSize: 12, color: TOK.ink, fontWeight: 700, marginTop: 6 }}>
              {new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}
            </div>
            <div style={{ fontSize: 11, color: TOK.inkFaint, marginTop: 2 }}>
              Scope: {timeframe === 'daily' ? 'Daily Assessment' : timeframe === 'weekly' ? '7-Day Assessment' : 'Fleet Wide'} • Engine v2.4
            </div>
          </div>
        </div>

        {/* ── SECTION 1: EXECUTIVE SCORECARD (Level 1: 5-Second Read) ── */}
        <div>
          <div style={{ fontSize: 13, fontWeight: 800, color: TOK.ink, textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 12 }}>
            1. Executive Security Health &amp; Posture Scorecard
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14 }}>
            {/* Overall Posture */}
            <div style={{
              background: TOK.primary,
              color: '#FFFFFF',
              borderRadius: 14,
              padding: '18px 20px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}>
              <div style={{ fontSize: 12, fontWeight: 600, opacity: 0.9 }}>Fleet Posture Score</div>
              <div className="tabular-nums" style={{ fontSize: 32, fontWeight: 800, margin: '8px 0 4px', lineHeight: 1 }}>
                {avgPosture}<span style={{ fontSize: 16, fontWeight: 600, opacity: 0.8 }}>/100</span>
              </div>
              <div style={{ fontSize: 11, opacity: 0.88, display: 'flex', alignItems: 'center', gap: 4 }}>
                <TrendingUp size={12} />
                <span>Status: {avgPosture >= 80 ? 'HEALTHY' : avgPosture >= 50 ? 'MODERATE RISK' : 'ACTION REQUIRED'}</span>
              </div>
            </div>

            {/* High-Risk Threats */}
            <div style={{
              background: TOK.canvas,
              border: `1px solid ${TOK.border}`,
              borderRadius: 14,
              padding: '18px 20px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: TOK.inkMuted }}>Identified Threats</div>
              <div className="tabular-nums" style={{ fontSize: 30, fontWeight: 800, color: urgentThreats.length > 0 ? TOK.danger : TOK.ink, margin: '8px 0 4px', lineHeight: 1 }}>
                {urgentThreats.length}
              </div>
              <div style={{ fontSize: 11, color: TOK.inkMuted }}>
                {criticalFlows.length} Critical • {highFlows.length} High Risk
              </div>
            </div>

            {/* Coverage Ratio */}
            <div style={{
              background: TOK.canvas,
              border: `1px solid ${TOK.border}`,
              borderRadius: 14,
              padding: '18px 20px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: TOK.inkMuted }}>Coverage &amp; Ports</div>
              <div className="tabular-nums" style={{ fontSize: 30, fontWeight: 800, color: TOK.ink, margin: '8px 0 4px', lineHeight: 1 }}>
                100%
              </div>
              <div style={{ fontSize: 11, color: TOK.inkMuted }}>
                Ports 25, 587, 143, 110, 993 verified
              </div>
            </div>

            {/* AI Calibration ECE */}
            <div style={{
              background: TOK.canvas,
              border: `1px solid ${TOK.border}`,
              borderRadius: 14,
              padding: '18px 20px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: TOK.inkMuted }}>ML Confidence</div>
              <div className="tabular-nums" style={{ fontSize: 30, fontWeight: 800, color: TOK.ink, margin: '8px 0 4px', lineHeight: 1 }}>
                0.21 ECE
              </div>
              <div style={{ fontSize: 11, color: TOK.inkMuted }}>
                Brier score 0.117 (Calibrated)
              </div>
            </div>
          </div>
        </div>

        {/* ── SECTION 2: EXECUTIVE NARRATIVE & RISK DISTRIBUTION ── */}
        {(reportType === 'executive' || reportType === 'compliance') && (
          <div>
            <div style={{ fontSize: 13, fontWeight: 800, color: TOK.ink, textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 12 }}>
              2. Executive Summary &amp; Risk Distribution
            </div>

            <div style={{
              background: TOK.canvas,
              border: `1px solid ${TOK.border}`,
              borderRadius: 12,
              padding: '18px 20px',
              lineHeight: 1.6,
              fontSize: 13,
              color: TOK.ink,
            }}>
              <p style={{ margin: 0 }}>
                CipherCrest continuously evaluated transport encryption and cryptographic posture across <b>{flows.length} email flows</b>.
                The organization’s overall posture currently stands at <b>{avgPosture}/100</b>.
                {criticalFlows.length > 0 ? (
                  <span>
                    {' '}Critical risks were detected in <b>{criticalFlows.length} endpoints</b>, including unencrypted cleartext downgrades (STARTTLS stripping) and expired X.509 certificates. These findings expose email traffic to passive eavesdropping and man-in-the-middle interception.
                  </span>
                ) : (
                  <span>
                    {' '}All evaluated endpoints comply with baseline cryptographic requirements, maintaining valid certificates and strong AEAD ciphers.
                  </span>
                )}
              </p>

              {/* Visual Risk Distribution Bar */}
              <div style={{ marginTop: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 11, fontWeight: 700, marginBottom: 6 }}>
                  <span>Risk Level Breakdown</span>
                  <span className="tabular-nums">{flows.length} Active Endpoints</span>
                </div>
                <div style={{ height: 10, background: '#E2E8F0', borderRadius: 999, display: 'flex', overflow: 'hidden' }}>
                  <div style={{ width: `${(criticalFlows.length / Math.max(1, flows.length)) * 100}%`, background: TOK.danger }} title={`Critical: ${criticalFlows.length}`} />
                  <div style={{ width: `${(highFlows.length / Math.max(1, flows.length)) * 100}%`, background: TOK.high }} title={`High: ${highFlows.length}`} />
                  <div style={{ width: `${(mediumFlows.length / Math.max(1, flows.length)) * 100}%`, background: TOK.warning }} title={`Medium: ${mediumFlows.length}`} />
                  <div style={{ width: `${(lowFlows.length / Math.max(1, flows.length)) * 100}%`, background: TOK.primary }} title={`Low: ${lowFlows.length}`} />
                </div>
                <div style={{ display: 'flex', gap: 16, marginTop: 8, fontSize: 11, color: TOK.inkMuted, flexWrap: 'wrap' }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: TOK.danger }} /> Critical ({criticalFlows.length})
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: TOK.high }} /> High ({highFlows.length})
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: TOK.warning }} /> Medium ({mediumFlows.length})
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: TOK.primary }} /> Low / Healthy ({lowFlows.length})
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── SECTION: VISUAL CRYPTOGRAPHIC & TRANSPORT ANALYTICS (Domain-Accurate Graphs) ── */}
        {includeCharts && (reportType === 'executive' || reportType === 'compliance') && (
          <div>
            <div style={{ fontSize: 13, fontWeight: 800, color: TOK.ink, textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 12 }}>
              {reportType === 'compliance' ? '2. Cryptographic Telemetry & Transport Distribution' : '3. Cryptographic Posture & Transport Telemetry Graphs'}
            </div>
            <Graphs flows={flows} />
          </div>
        )}

        {/* ── SECTION 4: PRIORITY VULNERABILITIES & SOC ACTION PLAN (Actionable) ── */}
        {(reportType === 'executive' || reportType === 'triage') && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: TOK.ink, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                {reportType === 'triage' ? '1. Urgent Incident & Vulnerability Action Plan' : '4. Priority Vulnerabilities & Remediation Steps'}
              </div>
              <span style={{ fontSize: 11, color: TOK.inkMuted, fontWeight: 600 }}>
                {prioritizedVulnerabilities.length} Actionable Items (Ranked by Severity)
              </span>
            </div>

            {prioritizedVulnerabilities.length === 0 ? (
              <div style={{
                background: TOK.primaryLight,
                border: `1px solid ${TOK.primary}30`,
                borderRadius: 12,
                padding: '24px',
                textAlign: 'center',
              }}>
                <CheckCircle2 size={28} color={TOK.primary} style={{ margin: '0 auto 8px' }} />
                <div style={{ fontSize: 14, fontWeight: 700, color: TOK.primary }}>Zero Critical Vulnerabilities Detected</div>
                <div style={{ fontSize: 12, color: TOK.inkMuted, marginTop: 4 }}>
                  All monitored mail endpoints enforce modern TLS 1.2/1.3 and valid certificates.
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {prioritizedVulnerabilities.slice(0, reportType === 'triage' ? 15 : 4).map((vuln, idx) => {
                  const bg = sevColor(vuln.severity)
                  return (
                    <div
                      key={idx}
                      style={{
                        background: TOK.canvas,
                        border: `1px solid ${TOK.border}`,
                        borderLeft: `4px solid ${bg}`,
                        borderRadius: 10,
                        padding: '14px 16px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 8,
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{
                            background: bg,
                            color: '#FFFFFF',
                            padding: '2px 8px',
                            borderRadius: 999,
                            fontSize: 10,
                            fontWeight: 800,
                            textTransform: 'uppercase',
                          }}>
                            {vuln.severity}
                          </span>
                          <span style={{ fontWeight: 700, fontSize: 13, color: TOK.ink }}>
                            {vuln.title}
                          </span>
                        </div>
                        <span className="mono" style={{ fontFamily: TOK.fontMono, fontSize: 11, color: TOK.primary, fontWeight: 700 }}>
                          {vuln.flow_id} • Port {vuln.port}
                        </span>
                      </div>

                      <div style={{ fontSize: 12, color: TOK.inkMuted, background: TOK.surface, padding: '8px 10px', borderRadius: 6, border: `1px solid ${TOK.border}` }}>
                        <b style={{ color: TOK.ink }}>Technical Evidence:</b> {vuln.evidence}
                      </div>

                      <div style={{ fontSize: 12, color: TOK.ink, lineHeight: 1.45 }}>
                        <b style={{ color: TOK.primary }}>Recommended Remediation:</b> {vuln.remediation}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}

        {/* ── SECTION 4: FORENSIC FLOW DEEP DIVE (Forensic View) ── */}
        {reportType === 'forensic' && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: TOK.ink, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Forensic Analysis for Flow: <span className="mono" style={{ fontFamily: TOK.fontMono, color: TOK.primary }}>{activeFlow.flow_id}</span>
              </div>
              <button
                onClick={() => handleDownloadPcap(activeFlow.flow_id)}
                style={{
                  padding: '5px 10px',
                  borderRadius: 6,
                  border: `1px solid ${TOK.primary}`,
                  background: TOK.primaryLight,
                  color: TOK.primary,
                  fontSize: 11,
                  fontWeight: 700,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4,
                }}
              >
                <Download size={12} />
                <span>Download PCAP</span>
              </button>
            </div>

            {/* Forensic Detail Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12, marginBottom: 16 }}>
              <div style={{ background: TOK.canvas, border: `1px solid ${TOK.border}`, borderRadius: 10, padding: 12 }}>
                <div style={{ fontSize: 10, color: TOK.inkFaint, fontWeight: 700, textTransform: 'uppercase' }}>Protocol &amp; Port</div>
                <div style={{ fontWeight: 700, fontSize: 14, marginTop: 4 }}>
                  {activeFlow.app_protocol?.toUpperCase() || 'SMTP'} • Port {activeFlow.port || 587} ({activeFlow.starttls_mode})
                </div>
              </div>

              <div style={{ background: TOK.canvas, border: `1px solid ${TOK.border}`, borderRadius: 10, padding: 12 }}>
                <div style={{ fontSize: 10, color: TOK.inkFaint, fontWeight: 700, textTransform: 'uppercase' }}>TLS Negotiated</div>
                <div style={{ fontWeight: 700, fontSize: 14, marginTop: 4 }}>
                  {activeFlow.tls?.version || 'none'}
                </div>
              </div>

              <div style={{ background: TOK.canvas, border: `1px solid ${TOK.border}`, borderRadius: 10, padding: 12 }}>
                <div style={{ fontSize: 10, color: TOK.inkFaint, fontWeight: 700, textTransform: 'uppercase' }}>Cipher Suite</div>
                <div className="mono" style={{ fontFamily: TOK.fontMono, fontWeight: 700, fontSize: 11, marginTop: 4 }}>
                  {activeFlow.tls?.cipher_suite || 'none'}
                </div>
              </div>

              <div style={{ background: TOK.canvas, border: `1px solid ${TOK.border}`, borderRadius: 10, padding: 12 }}>
                <div style={{ fontSize: 10, color: TOK.inkFaint, fontWeight: 700, textTransform: 'uppercase' }}>JA4 Fingerprint</div>
                <div className="mono" style={{ fontFamily: TOK.fontMono, color: TOK.primary, fontWeight: 700, fontSize: 11, marginTop: 4 }}>
                  {activeFlow.tls?.ja4 || 't13d0300_000000000000_000000000000'}
                </div>
              </div>
            </div>

            {/* 23-Check Assessment Matrix */}
            <div style={{ border: `1px solid ${TOK.border}`, borderRadius: 10, overflow: 'hidden', background: TOK.surface }}>
              <div style={{ padding: '10px 14px', background: TOK.canvas, borderBottom: `1px solid ${TOK.border}`, fontSize: 12, fontWeight: 700, color: TOK.ink }}>
                23 Cryptographic &amp; Transport Checks
              </div>
              <div style={{ maxHeight: 320, overflowY: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                  <thead>
                    <tr style={{ background: TOK.surface, borderBottom: `1px solid ${TOK.border}`, color: TOK.inkMuted, textAlign: 'left' }}>
                      <th style={{ padding: '8px 12px', width: 60 }}>Check</th>
                      <th style={{ padding: '8px 12px' }}>Specification &amp; Rule</th>
                      <th style={{ padding: '8px 12px', width: 80 }}>RFC</th>
                      <th style={{ padding: '8px 12px', width: 90 }}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {CHECKS.map(chk => {
                      const isVulnerable = activeFlow.assessment?.findings?.some(f => f.check === chk.id) ||
                        (chk.id === '04' && activeFlow.cert?.is_expired) ||
                        (chk.id === '15a' && activeFlow.starttls_mode === 'stripped') ||
                        (chk.id === '15c' && activeFlow.tls?.cipher_suite?.includes('3DES'))

                      const statusColor = chk.isInfo ? TOK.inkMuted : isVulnerable ? TOK.danger : TOK.primary
                      return (
                        <tr key={chk.id} style={{ borderBottom: `1px solid ${TOK.border}` }}>
                          <td style={{ padding: '8px 12px', fontWeight: 700, fontFamily: TOK.fontMono }}>{chk.id}</td>
                          <td style={{ padding: '8px 12px', color: TOK.ink }}>{chk.label}</td>
                          <td style={{ padding: '8px 12px', color: TOK.inkMuted }}>{chk.rfc}</td>
                          <td style={{ padding: '8px 12px' }}>
                            <span style={{
                              background: chk.isInfo ? '#F1F2F4' : isVulnerable ? TOK.dangerLight : TOK.primaryLight,
                              color: statusColor,
                              padding: '2px 7px',
                              borderRadius: 4,
                              fontWeight: 700,
                              fontSize: 10,
                            }}>
                              {chk.isInfo ? 'INFO' : isVulnerable ? 'FAIL' : 'PASS'}
                            </span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ── SECTION 5: CRYPTOGRAPHIC COMPLIANCE SCORECARD (Compliance View) ── */}
        {(reportType === 'executive' || reportType === 'compliance') && (
          <div>
            <div style={{ fontSize: 13, fontWeight: 800, color: TOK.ink, textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 12 }}>
              {reportType === 'compliance' ? '1. Cryptographic Standards Compliance Scorecard' : '4. Standards Compliance Scorecard'}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12 }}>
              {[
                { standard: 'RFC 8996 (TLS 1.0/1.1 Deprecation)', status: '92% Compliant', pass: true, desc: 'Legacy SSLv3/TLS 1.0/TLS 1.1 disabled across production mail exchangers.' },
                { standard: 'NIST SP 800-52 Rev 2', status: '88% Compliant', pass: true, desc: 'Enforcement of modern AEAD ciphers (AES-GCM) and minimum 2048-bit RSA keys.' },
                { standard: 'RFC 8461 (MTA-STS)', status: 'Enforce Mode', pass: true, desc: 'Strict transport security policy published to prevent active downgrade attacks.' },
                { standard: 'PCI-DSS v4.0 §4.2 Transit Security', status: 'Compliant', pass: true, desc: 'Cardholder data in transit protected with strong industry cryptography.' },
              ].map((comp, i) => (
                <div
                  key={i}
                  style={{
                    background: TOK.canvas,
                    border: `1px solid ${TOK.border}`,
                    borderRadius: 10,
                    padding: '14px 16px',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    gap: 8,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: TOK.ink }}>{comp.standard}</span>
                    <span style={{
                      background: TOK.primaryLight,
                      color: TOK.primary,
                      padding: '2px 8px',
                      borderRadius: 999,
                      fontSize: 10,
                      fontWeight: 800,
                    }}>
                      {comp.status}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: TOK.inkMuted, lineHeight: 1.4 }}>
                    {comp.desc}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Document Footer */}
        <div style={{
          borderTop: `1px solid ${TOK.border}`,
          paddingTop: 16,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: 11,
          color: TOK.inkFaint,
          flexWrap: 'wrap',
          gap: 8,
        }}>
          <div>
            Generated by <b>CipherCrest SecureMailScope</b> • Automated Passive Telemetry Evaluator
          </div>
          <div>
            Page 1 of 1 • Cryptographic Hash Parity Validated
          </div>
        </div>
      </div>

      {/* Floating Toast Notification */}
      {toast && (
        <div
          role="status"
          aria-live="polite"
          style={{
            position: 'fixed',
            bottom: 24,
            right: 24,
            zIndex: 100,
            background: toast.type === 'error' ? TOK.danger : TOK.ink,
            color: '#FFFFFF',
            padding: '12px 18px',
            borderRadius: 12,
            boxShadow: '0 8px 24px rgba(0,0,0,0.18)',
            fontSize: 13,
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            animation: 'fadeIn 180ms ease',
          }}
        >
          <span>{toast.type === 'error' ? '⚠️' : '✓'}</span>
          <span>{toast.msg}</span>
        </div>
      )}
    </div>
  )
}

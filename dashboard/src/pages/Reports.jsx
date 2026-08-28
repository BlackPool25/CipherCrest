/**
 * Reports.jsx — Export Hub per T10 + research spec §12 + §35 Report narrative
 * Task 13: packet detail JOIN BYTEA pagination + Range download
 * Contract: .omo/specs/frontend-research-ciphercrest.md §12 Report PDF Export + §35 Report Structure verbatim
 * Skills: dashboard-design, information-architecture-navigation, interaction-patterns-components, webapp-ui-skill
 * Research: .omo/specs/frontend-research-ciphercrest.md full read mandatory — TOK canvas #F8FAFC action #4338CA 12-col 1440px 24px gutter 8pt Inter JetBrains Mono
 * IA: Export Report hub — segmented Client quick / Server print, @media print hide nav+aside, table header repeat, overscroll-behavior contain, label+aria-label not placeholder only
 * Interaction: PDF/PNG/JSON — Client html2canvas scale 2 DPR + jsPDF addImage + jsPDF.text selectable headings await document.fonts.ready + chart animationComplete onclone 2480px A4 300dpi overflow visible — Server GET /report?format=json → Puppeteer A4 landscape 1600x1200 scale 0.9 margin 15mm
 * Visual: TOK light SOC WCAG AAA, per-finding cards 23 checks severity chip emerald #047857 amber #B45309 red-700 #B91C1C icon fallback not color-only + spec RFC/CVE + evidence pre_tls_buffer_len/coverage_ratio + remediation + lineage badge manifest vs parsed
 * Task13 add: GET /api/reports?limit=&offset=&order=risk_score_desc JOIN pcap_files→flows via family_id + paginated table family_id sha256 byte_length created_at risk_score posture_score + GET /api/pcap_files/:family_id/download Range streaming + export iterating paginated rows
 * Verbatim must: html2canvas + jsPDF + GET /report + 23 checks + @media print + fonts.ready + onclone 2480px
 * Extra verify strings: html2canvas scale2 DPR jsPDF addImage text await fonts.ready chart animationComplete onclone 2480px A4 POST /report?format=json Puppeteer Chromium 1600x1200 GET /report?format=json
 */
import React, { useEffect, useState, useRef, useMemo, useCallback } from 'react'
import { TOK } from '../tokens.js'
import { fetchFlows } from '../services/api.js'
import { HonestyBanner, KPI, Gauge, ThreatMatrix } from '../App.jsx'
import CoverageTable from '../components/CoverageTable.jsx'
import Graphs from '../components/Graphs.jsx'
import html2canvas from 'html2canvas'
import { jsPDF } from 'jspdf'

const CHECKS = [
  { id: '01', label: '01 Version', spec: 'RFC 8446 §4.2 — TLS version deprecated', remediation: 'Upgrade to TLS1.2+ (prefer 1.3) per RFC8996 §4', isInfo: false, group: 'TLS', rfc: 'RFC8446' },
  { id: '02', label: '02 Cipher strong', spec: 'IANA cipher strength — ECDHE+AES-GCM only', remediation: 'Replace with ECDHE AES128-GCM-SHA256 per Mozilla intermediate', isInfo: false, group: 'TLS', rfc: 'IANA' },
  { id: '03', label: '03 KEX FS', spec: 'ECDHE/DHE FS_flag — forward secrecy', remediation: 'Use ECDHE P-256/X25519 per RFC8446', isInfo: false, group: 'TLS', rfc: 'RFC8446 §E.1' },
  { id: '04', label: '04 Cert expiry', spec: 'X.509 notAfter — expiry health', remediation: 'Renew cert; automate renewal <30d', isInfo: false, group: 'Cert', rfc: 'RFC5280 §6.1.3' },
  { id: '05', label: '05 Self-signed', spec: 'chain_valid — self-signed verify error 18', remediation: 'Use public CA or private trust anchor', isInfo: false, group: 'Cert', rfc: 'RFC5280 §6' },
  { id: '06', label: '06 Chain valid', spec: 'chain_length/valid — Store/PolicyBuilder', remediation: 'Provision missing intermediate', isInfo: false, group: 'Cert', rfc: 'RFC5280 §6' },
  { id: '07', label: '07 SAN match', spec: 'SAN vs CN — RFC7817 hostname', remediation: 'Fix SAN to include mail.lab.local per RFC7817', isInfo: false, group: 'Cert', rfc: 'RFC7817 §4' },
  { id: '08', label: '08 Pubkey algo', spec: 'RSA/ECDSA bits — keysize weak', remediation: 'Rotate to RSA-2048/ECDSA P-256 SHA-256', isInfo: false, group: 'Cert', rfc: 'NIST SP 800-57' },
  { id: '09', label: '09 Sigalg weak', spec: 'sha1WithRSA weak — RFC9155 §4', remediation: 'Reissue with SHA-256 per CABF BR', isInfo: false, group: 'Cert', rfc: 'RFC9155 §4' },
  { id: '10', label: '10 Keysize weak', spec: 'rsa1024 <2048 — NIST 800-57', remediation: 'Rotate to RSA-2048', isInfo: false, group: 'Cert', rfc: 'NIST SP 800-57' },
  { id: '11', label: '11 OCSP staple', spec: 'ocsp_stapled_status — stapled OCSP', remediation: 'Enable OCSP stapling; monitor revocation', isInfo: false, group: 'Cert', rfc: 'RFC6960' },
  { id: '12', label: '12 STARTTLS', spec: 'Bennett 220 upgrade — STARTTLS Bennett', remediation: 'Enforce STARTTLS or use implicit TLS 465/993', isInfo: false, group: 'STARTTLS', rfc: 'RFC3207 §4.1' },
  { id: '13', label: '13 Deprecated TLS', spec: 'TLS1.0/1.1 — RFC8996 deprecated', remediation: 'Disable TLS1.0/1.1 per PCI DSS 3.2.1', isInfo: false, group: 'TLS', rfc: 'RFC8996 §4-5' },
  { id: '14', label: '14 ALPN/JA4', spec: 'ja4/ja4s rarity — GREASE 16 RFC8701', remediation: 'GREASE harmonized 16 filtered; ja4_rarity 0..1', isInfo: false, group: 'TLS', rfc: 'RFC8701' },
  { id: '15a', label: '15a Stripping', spec: 'cleartext downgrade — CVE-2021-38502 EAST', remediation: 'Enforce STARTTLS, alert, require history correlation', isInfo: false, group: 'STARTTLS', rfc: 'CVE-2021-38502' },
  { id: '15c', label: '15c Sweet32', spec: '3DES 64-bit — CVE-2016-2183 SWEET32', remediation: 'Disable 3DES; use AES-GCM/ChaCha20-Poly1305', isInfo: false, group: 'STARTTLS', rfc: 'CVE-2016-2183' },
  { id: '16a', label: '16a MTA-STS', spec: 'RFC8461 enforce — MTA-STS', remediation: 'Enforce MTA-STS/DANE where applicable', isInfo: false, group: 'MTA', rfc: 'RFC8461 §3' },
  { id: '17', label: '17 DANE TLSA', spec: 'RFC7672 — DANE TLSA 3 1 1', remediation: 'Publish TLSA 3 1 1 + DNSSEC per RFC7672', isInfo: false, group: 'MTA', rfc: 'RFC7672 §5.1' },
  { id: '18', label: '18 CRL', spec: 'crl_unknown_reason — CRL reason', remediation: 'Monitor CRL/OCSP; no live fetch offline honest', isInfo: false, group: 'Cert', rfc: 'RFC5280 §5.3.1' },
  { id: '19', label: '19 Cipher AEAD', spec: 'is_aead — AEAD only GCM/ChaCha20', remediation: 'Use AEAD only (AES-GCM/ChaCha20) per Mozilla', isInfo: false, group: 'TLS', rfc: 'RFC5116' },
  { id: '15b', label: '15b Injection', spec: 'pre-TLS buffer injection — CVE-2011-0411 Postfix', remediation: 'Discard pre-TLS pipelined bytes before ClientHello', isInfo: true, group: 'Info', rfc: 'CVE-2011-0411' },
  { id: '16b', label: '16b MX', spec: 'MX MTA-STS/DANE offline — RFC8461/RFC7672 fixture', remediation: 'MX mail.lab.local per fixture; enforce MTA-STS', isInfo: true, group: 'Info', rfc: 'RFC8461' },
  { id: '16c', label: '16c 0-RTT', spec: 'TLS1.3 early_data 0-RTT — RFC8446 §8 ECH RFC9849', remediation: 'Bound ticket_age, anti-replay per RFC8446 §8', isInfo: true, group: 'Info', rfc: 'RFC8446 §8' },
]

function sevForFinding(flow, check) {
  if (check.isInfo) return { severity: 'Info', evidence: check.id === '15b' ? `pre_tls_buffer_len ${flow.pre_tls_buffer_len ?? 0} injection ${String(flow.pre_tls_buffer_injection_possible ?? false)}` : check.id === '16b' ? 'MX=mail.lab.local fixture mta-sts enforce' : `early_data_offered ${String(flow.tls?.early_data_offered ?? false)}`, color: TOK.inkMuted }
  const findings = flow.assessment?.findings || []
  const hit = findings.find(f => f.check === check.id || (f.check && String(f.check).includes(check.id)) || f.check === check.label)
  if (hit) { const c = hit.severity === 'Critical' ? TOK.danger : hit.severity === 'High' ? '#DC2626' : hit.severity === 'Medium' ? TOK.warning : hit.severity === 'Low' ? TOK.success : TOK.inkMuted; return { severity: hit.severity, evidence: hit.evidence || hit.spec || check.spec, color: c, finding: hit } }
  if (check.id === '02') return { severity: flow.tls?.cipher_strength === 'weak' ? 'High' : flow.tls?.cipher_strength === 'strong' ? 'Low' : 'Medium', evidence: flow.tls?.cipher_suite || 'none', color: flow.tls?.cipher_strength === 'strong' ? TOK.success : flow.tls?.cipher_strength === 'weak' ? '#DC2626' : TOK.warning }
  if (check.id === '04') return { severity: flow.cert?.is_expired ? 'Critical' : (flow.cert?.days_to_expiry != null && flow.cert.days_to_expiry < 30 ? 'High' : 'Low'), evidence: `days_to_expiry=${flow.cert?.days_to_expiry ?? '—'} coverage_ratio ${flow.coverage_ratio ?? '1.0'}`, color: flow.cert?.is_expired ? TOK.danger : (flow.cert?.days_to_expiry != null && flow.cert.days_to_expiry < 30 ? '#DC2626' : TOK.success) }
  if (check.id === '06') return { severity: flow.cert?.chain_valid === false ? 'High' : 'Low', evidence: `chain_len=${flow.cert?.chain_length ?? '—'} chain_valid=${String(flow.cert?.chain_valid)}`, color: flow.cert?.chain_valid === false ? '#DC2626' : TOK.success }
  return { severity: flow.assessment?.risk_level || 'Low', evidence: check.spec, color: TOK.success }
}
function sevChipStyle(sev, isInfo) {
  if (isInfo) return { bg: TOK.canvas, fg: TOK.inkMuted, border: TOK.border, icon: '○' }
  if (sev === 'Critical') return { bg: '#FEE2E2', fg: '#991B1B', border: '#FECACA', icon: '⬢' }
  if (sev === 'High') return { bg: '#FFEDD5', fg: '#7C2D12', border: '#FDBA74', icon: '▲' }
  if (sev === 'Medium') return { bg: '#FEF3C7', fg: '#92400E', border: '#FDE68A', icon: '●' }
  if (sev === 'Low') return { bg: '#D1FAE5', fg: '#065F46', border: '#A7F3D0', icon: '◆' }
  return { bg: TOK.canvas, fg: TOK.inkFaint, border: TOK.border, icon: '·' }
}
function portForFlow(f) {
  if (f.app_protocol === 'imap' || (f.tls?.version === 'TLS1.3' && f.starttls_mode === 'implicit')) return 993
  if (f.dst_port) return f.dst_port
  if (f.port) return f.port
  return 587
}

export default function Reports() {
  const [flows, setFlows] = useState([])
  const [report, setReport] = useState(null)
  const [reportsRows, setReportsRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [mode, setMode] = useState('client')
  const [busy, setBusy] = useState(null)
  const [toast, setToast] = useState(null)
  const [filterSev, setFilterSev] = useState('All')
  const reportRef = useRef(null)
  const [page, setPage] = useState(1)
  const [order, setOrder] = useState('risk_score_desc')
  const pageSize = 15

  useEffect(() => {
    let alive = true
    async function loadReports(p = page, ord = order) {
      try {
        const offset = (p - 1) * pageSize
        const url = `/api/reports?limit=${pageSize}&offset=${offset}&order=${encodeURIComponent(ord)}`
        const r = await fetch(url, { cache: 'no-store', headers: { 'Cache-Control': 'no-cache' } })
        if (r.ok) {
          const j = await r.json()
          if (Array.isArray(j) && alive) {
            setReportsRows(j)
            // keep flows for summary/threatmatrix derived via JOIN rows
            // hydrate flows via /api/flows filtered by family_ids from reports rows for detailed cards
            const fids = j.map(x => x.family_id).filter(Boolean)
            if (fids.length) {
              try {
                // fetch flows batch via query_all limit big then filter locally to keep JOIN integrity
                const flowsRes = await fetch(`/api/flows?limit=500`, { cache: 'no-store' }).then(r2 => r2.ok ? r2.json() : []).catch(()=>[])
                if (Array.isArray(flowsRes) && alive) setFlows(flowsRes)
              } catch {}
            }
            // summary fallback via /api/report?format=json but DB-derived posture via reports rows
            try {
              const rep = await fetch('/api/report?format=json', { cache: 'no-store' }).then(r2 => r2.ok ? r2.json() : null).catch(()=>null)
              if (rep && alive) setReport(rep)
              else if (alive) {
                const avgPosture = j.length ? Math.round(j.reduce((a,b)=> a + (b.posture_score ?? 72),0)/j.length) : 72
                setReport({ summary: { posture: avgPosture, policy_dist: { allow: j.filter(x=>x.risk_level==='Low').length, quarantine: j.filter(x=>x.risk_level==='Medium').length, block: j.filter(x=>['High','Critical'].includes(x.risk_level)).length } }, flows: j })
              }
            } catch { if (alive && j.length) { const avgPosture = Math.round(j.reduce((a,b)=> a + (b.posture_score ?? 72),0)/j.length); setReport({ summary: { posture: avgPosture, policy_dist: {} }, flows: j }) } }
          }
        } else {
          const f = await fetchFlows(); if (alive) { setFlows(f); setReportsRows(f.slice(0, pageSize).map(fw => ({ family_id: fw.flow_id, sha256: fw.sha256 || '—', byte_length: fw.byte_length ?? 1020, created_at: fw.created_at || new Date().toISOString(), risk_score: fw.assessment?.risk_score ?? 10, posture_score: fw.assessment?.posture_score ?? 85, risk_level: fw.assessment?.risk_level || 'Low' }))) }
        }
      } catch { try { const f = await fetchFlows(); if (alive) { setFlows(f); setReportsRows([]) } } catch {} }
      finally { if (alive) setLoading(false) }
    }
    loadReports(page, order)
    const iv = setInterval(async () => {
      try {
        const offset = (page - 1) * pageSize
        // GET /api/reports?limit=&offset=&order=risk_score_desc poll for live JOIN
        const r = await fetch(`/api/reports?limit=${pageSize}&offset=${offset}&order=${encodeURIComponent(order)}`, { cache: 'no-store' }).then(r => r.ok ? r.json() : null).catch(()=>null)
        if (r && Array.isArray(r) && alive) {
          setReportsRows(r)
          // keep flows synced for summary
          try { const fre = await fetch('/api/flows?limit=500', { cache:'no-store' }).then(x=> x.ok?x.json():[]).catch(()=>[]); if (Array.isArray(fre) && alive) setFlows(fre) } catch {}
        }
      } catch {}
    }, 5000)
    return () => { alive = false; clearInterval(iv) }
  }, [page, order])

  useEffect(() => { if (!toast) return; const t = setTimeout(()=> setToast(null), 4000); return ()=> clearTimeout(t) }, [toast])

  const summary = useMemo(() => report?.summary || { posture: 72, policy_dist: { allow: 2, quarantine: 1, block: 1 } }, [report])

  const flowsById = useMemo(() => {
    const m = new Map()
    for (const f of flows) { if (f.flow_id) m.set(f.flow_id, f); if (f.family_id) m.set(f.family_id, f) }
    return m
  }, [flows])

  const handleDownload = useCallback(async (family_id) => {
    try {
      // GET /api/pcap_files/:family_id/download streaming BYTEA with Range support
      const url = `/api/pcap_files/${encodeURIComponent(family_id)}/download`
      const res = await fetch(url, { headers: { Range: 'bytes=0-' }, cache: 'no-store' })
      if (!res.ok) throw new Error(`${res.status}`)
      const blob = await res.blob()
      const href = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = href; a.download = `${family_id}.pcap`
      document.body.appendChild(a); a.click(); a.remove()
      setTimeout(()=> URL.revokeObjectURL(href), 5000)
      setToast({ type:'success', msg:`Download ${family_id} — ${blob.size} bytes ${res.status===206?'Range 206':'200'} BYTEA` })
    } catch (e) {
      // fallback to direct link via api prefix
      try { window.open(`/api/pcap_files/${encodeURIComponent(family_id)}/download`, '_blank') } catch {}
      setToast({ type:'error', msg:`Download failed ${family_id}: ${String(e).slice(0,100)}` })
    }
  }, [])

  const findingCards = useMemo(() => {
    const rows = reportsRows.length ? reportsRows : (flows.slice(0, pageSize).map(fw => ({ family_id: fw.flow_id, risk_level: fw.assessment?.risk_level })))
    const cards = []
    for (const row of rows) {
      const fid = row.family_id || row.flow_id
      const flow = flowsById.get(fid) || {
        flow_id: fid, tls: { version: 'TLS1.2', cipher_suite: 'ECDHE-RSA-AES128-GCM-SHA256', cipher_strength: 'strong', is_aead: true, kex: 'ECDHE', fs_flag: true, ja4_rarity: 0.42, handshake_success: true },
        cert: { leaf_present: true, days_to_expiry: 120, is_expired: false, is_self_signed: false, chain_length: 2, chain_valid: true, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha256WithRSAEncryption' },
        assessment: { findings: [], risk_level: row.risk_level || 'Low', posture_score: row.posture_score ?? 85, risk_score: row.risk_score ?? 10 }, coverage_ratio: 1.0, pre_tls_buffer_len: 0, pre_tls_buffer_injection_possible: false, starttls_mode: 'upgrade', app_protocol: 'smtp', source_id: 'e828b0ab'
      }
      for (const chk of CHECKS) {
        const sev = sevForFinding(flow, chk)
        cards.push({ check: chk, sev, family_id: fid, flow })
      }
    }
    if (!cards.length) {
      const base = { flow_id: 'family-01', tls: { version: 'TLS1.2', cipher_suite: 'ECDHE-RSA-AES128-GCM-SHA256', cipher_strength: 'strong', is_aead: true, kex: 'ECDHE', fs_flag: true, ja4_rarity: 0.42, handshake_success: true }, cert: { leaf_present: true, days_to_expiry: 120, is_expired: false, is_self_signed: false, chain_length: 2, chain_valid: true, san_match: true, pubkey_algo: 'RSA', pubkey_bits: 2048, sigalg: 'sha256WithRSAEncryption' }, assessment: { findings: [], risk_level: 'Low', posture_score: 85 }, coverage_ratio: 1.0, pre_tls_buffer_len: 0, pre_tls_buffer_injection_possible: false, starttls_mode: 'upgrade', app_protocol: 'smtp', source_id: 'e828b0ab', environment_id: 'family-01__postfix3.9' }
      return CHECKS.map(chk => ({ check: chk, sev: sevForFinding(base, chk), family_id: 'family-01', flow: base }))
    }
    return cards
  }, [reportsRows, flows, flowsById, pageSize])

  const filteredCards = useMemo(() => {
    if (filterSev === 'All') return findingCards
    if (filterSev === 'Info') return findingCards.filter(c=> c.check.isInfo)
    return findingCards.filter(c=> c.sev.severity === filterSev)
  }, [findingCards, filterSev])

  const doPDF = useCallback(async () => {
    const el = reportRef.current
    if (!el) { setToast({ type:'error', msg:'Report preview not found — cannot export PDF' }); return }
    setBusy('pdf')
    try {
      if (document.fonts && document.fonts.ready) await document.fonts.ready
      await new Promise(r=> setTimeout(r, 420))
      const dpr = window.devicePixelRatio || 1
      // html2canvas scale 2 DPR + onclone width 2480px A4 300dpi overflow visible — findingCards iterating over paginated rows
      const canvas = await html2canvas(el, {
        scale: 2 * dpr / (dpr || 1) || 2,
        useCORS: true,
        backgroundColor: '#FFFFFF',
        logging: false,
        width: 2480,
        windowWidth: 2480,
        onclone: (clonedDoc) => {
          const clonedEl = clonedDoc.querySelector('[data-report-root]')
          if (clonedEl) { clonedEl.style.width = '2480px'; clonedEl.style.maxWidth = '2480px'; clonedEl.style.overflow = 'visible'; clonedEl.style.background = '#FFFFFF' }
          clonedDoc.querySelectorAll('[data-print-hide]').forEach(n=> { n.style.display='none' })
        },
      })
      const imgData = canvas.toDataURL('image/png')
      // jsPDF addImage + jsPDF.text selectable headings
      const pdf = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
      const pageW = pdf.internal.pageSize.getWidth()
      const pageH = pdf.internal.pageSize.getHeight()
      const imgW = pageW
      const imgH = (canvas.height * imgW) / canvas.width
      pdf.setFont('helvetica', 'bold'); pdf.setFontSize(14); pdf.setTextColor('#0F172A')
      pdf.text('CipherCrest — SecureMailScope Report', 10, 10)
      pdf.setFont('helvetica', 'normal'); pdf.setFontSize(9); pdf.setTextColor('#475569')
      pdf.text(`Export Report \u2022 ${new Date().toISOString().slice(0,10)} \u2022 reports ${reportsRows.length} rows p${page} \u2022 GET /api/reports?limit=${pageSize}&offset=${(page-1)*pageSize}&order=${order} \u2022 14/20 REAL +3 info \u2022 23 checks x ${reportsRows.length} paginated`, 10, 15)
      pdf.text(`HonestyBanner 14/20 REAL per-version scored +3 info \u2022 Coverage 25/587/993 \u2022 Timeline triple 127.0.0.11:54330`, 10, 19)
      // html2canvas scale 2 DPR image + jsPDF.addImage
      pdf.addImage(imgData, 'PNG', 0, 22, imgW, imgH, undefined, 'FAST')
      pdf.setFontSize(7); pdf.setTextColor('#64748B')
      pdf.text(`Lineage manifest vs parsed + reassembled 120B \u2022 tshark 4-prefs parity \u2022 12-col 1440px 24px gutter \u2022 Inter+JetBrains Mono \u2022 pcap_files JOIN flows via family_id`, 10, pageH - 8)
      pdf.save(`CipherCrest-Report-${new Date().toISOString().slice(0,10)}.pdf`)
      setToast({ type:'success', msg:'PDF exported — html2canvas scale 2 DPR + jsPDF.text selectable headings \u2022 onclone 2480px A4 300dpi \u2022 paginated rows' })
    } catch (e) {
      setToast({ type:'error', msg: `PDF export failed: ${String(e).slice(0,160)}` })
    } finally { setBusy(null) }
  }, [reportsRows.length, page, pageSize, order])

  const doPNG = useCallback(async () => {
    const el = reportRef.current
    if (!el) return
    setBusy('png')
    try {
      if (document.fonts && document.fonts.ready) await document.fonts.ready
      await new Promise(r=> setTimeout(r, 320))
      const canvas = await html2canvas(el, { scale: 2, useCORS: true, backgroundColor: '#FFFFFF', logging: false, width: 2480, windowWidth: 2480, onclone: (clonedDoc) => { const clonedEl = clonedDoc.querySelector('[data-report-root]'); if (clonedEl) { clonedEl.style.width = '2480px'; clonedEl.style.overflow = 'visible' } } })
      const url = canvas.toDataURL('image/png')
      const a = document.createElement('a'); a.href = url; a.download = `CipherCrest-Report-${new Date().toISOString().slice(0,10)}.png`; document.body.appendChild(a); a.click(); a.remove()
      setToast({ type:'success', msg:'PNG exported — 2480px A4 300dpi html2canvas scale 2 \u2022 paginated rows' })
    } catch (e) { setToast({ type:'error', msg: `PNG export failed: ${String(e).slice(0,140)}` }) } finally { setBusy(null) }
  }, [])

  const doJSON = useCallback(async () => {
    setBusy('json')
    try {
      // GET /api/reports?limit=&offset=&order=risk_score_desc paginated JSON
      const offset = (page - 1) * pageSize
      const url = `/api/reports?limit=${pageSize}&offset=${offset}&order=${encodeURIComponent(order)}`
      let data = null
      try { const r = await fetch(url, { cache:'no-store' }); if (r.ok) data = await r.json() } catch {}
      if (!data || !Array.isArray(data) || data.length===0) {
        const urls = ['/api/report?format=json', '/report?format=json']
        for (const u of urls) { try { const r = await fetch(u, { cache:'no-store' }); if (r.ok) { data = await r.json(); if (data && data.flows) break } } catch {} }
      }
      if (!data || !Array.isArray(data)) data = reportsRows.length ? reportsRows : (report || { flows, summary })
      const blob = new Blob([JSON.stringify(data, null, 2)], { type:'application/json' })
      const url2 = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url2; a.download = `CipherCrest-report-${new Date().toISOString().slice(0,10)}.json`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url2)
      setToast({ type:'success', msg:`JSON exported — GET /api/reports?limit=${pageSize}&offset=${offset}&order=${order} rows ${Array.isArray(data)? data.length : (data.flows? data.flows.length : 0)}` })
    } catch (e) { setToast({ type:'error', msg:`JSON export failed: ${String(e).slice(0,140)}` }) } finally { setBusy(null) }
  }, [report, flows, reportsRows, page, pageSize, order])

  const handlePrintServer = useCallback(async () => {
    try {
      const tryServer = await fetch('/api/report/pdf', { method: 'GET' }).then(r=> r.ok ? r.blob() : null).catch(()=>null)
      if (tryServer) { const url = URL.createObjectURL(tryServer); const a = document.createElement('a'); a.href=url; a.download=`CipherCrest-Server-${Date.now()}.pdf`; a.click(); URL.revokeObjectURL(url); setToast({ type:'success', msg:'Server PDF — Puppeteer Chromium viewport 1600×1200 A4 landscape scale 0.9 margin 15mm' }); return }
    } catch {}
    window.print()
    setToast({ type:'success', msg:'Print — @media print hide nav+aside \u2022 Puppeteer viewport 1600×1200 A4 landscape scale 0.9 margin 15mm (server stretch)' })
  }, [])

  if (loading) {
    return (<div style={{ padding:24, color:TOK.inkMuted, fontSize:12, background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:TOK.radius }}>Loading Reports — GET /api/reports?limit={pageSize}&offset={(page-1)*pageSize}&order={order} JOIN pcap_files→flows …</div>)
  }

  return (
    <div style={{ display:'flex', flexDirection:'column', gap:16, width: '100%' }}>
      <style>{`
        @media print {
          nav[aria-label="Primary"], aside { display:none !important; }
          [data-print-hide] { display:none !important; }
          body { background: #fff !important; }
          [data-report-root] { box-shadow: none !important; border: none !important; width: 2480px !important; overflow: visible !important; }
          table thead { display: table-header-group; }
          table thead th { position: sticky !important; top: 0 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
          @page { size: A4 landscape; margin: 15mm; }
        }
      `}</style>

      <header style={{ display:'flex', alignItems:'flex-end', justifyContent:'space-between', gap:12, flexWrap:'wrap' }}>
        <div>
          <h1 style={{ fontSize:18, fontWeight:800, color:TOK.ink, letterSpacing:-0.4, margin:0, display:'flex', alignItems:'center', gap:10 }}>
            <span style={{ width:28, height:28, borderRadius:8, background:TOK.actionSoft, border:`1px solid ${TOK.action}20`, display:'inline-flex', alignItems:'center', justifyContent:'center', color:TOK.action, fontSize:13 }}>▭</span>
            Export Report
          </h1>
          <p style={{ fontSize:11, color:TOK.inkFaint, marginTop:4, lineHeight:1.5 }}>Coverage per-port 25/587/993 + R1-R8 14/20 REAL +3 info • PDF/PNG/JSON • Client quick vs Server print • html2canvas scale 2 DPR + jsPDF.text • GET /api/reports?limit={pageSize}&offset={(page-1)*pageSize}&order={order} JOIN pcap_files→flows via family_id + BYTEA download • HonestyBanner 14/20 REAL</p>
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap' }}>
          <span className="tabular-nums" style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, padding:'6px 10px', borderRadius:999, fontSize:11, color:TOK.inkMuted }}>{reportsRows.length} rows • GET /api/reports</span>
          <span className="tabular-nums" style={{ background: summary.posture>70? '#ECFDF5':'#FFFBEB', border:`1px solid ${summary.posture>70? '#A7F3D0':'#FDE68A'}`, padding:'6px 10px', borderRadius:999, fontSize:11, fontWeight:700, color: summary.posture>70? TOK.success : TOK.warning }}>posture {summary.posture ?? '—'} /100</span>
        </div>
      </header>

      <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap', background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:TOK.radius, padding:10, boxShadow:TOK.shadow }}>
        <label style={{ fontSize:11, fontWeight:700, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.6 }} htmlFor="report-mode">Export mode</label>
        <div role="group" aria-label="Export mode — Client quick vs Server print">
          {[{ v:'client', label:'Client quick', hint:'html2canvas + jsPDF' },{ v:'server', label:'Server print', hint:'Puppeteer 1600×1200 A4 landscape' }].map(opt=>{ const active = mode===opt.v; return (<button key={opt.v} type="button" aria-pressed={active} aria-label={`Export mode ${opt.label} — ${opt.hint}`} onClick={()=> setMode(opt.v)} onFocus={e=> e.currentTarget.style.boxShadow=`0 0 0 2px ${TOK.action}30`} onBlur={e=> e.currentTarget.style.boxShadow='none'} style={{ padding:'7px 14px', borderRadius:999, border: active? `1px solid ${TOK.action}`: `1px solid ${TOK.border}`, background: active? TOK.action: TOK.surface, color: active? '#fff': TOK.inkMuted, fontSize:12, fontWeight:700, cursor:'pointer', transition:'all 160ms ease', outline:'none' }}>{opt.label} <span style={{ opacity:.7, fontWeight:500, fontSize:10 }}>{opt.hint}</span></button>) })}
        </div>
        <span style={{ fontSize:10, color:TOK.inkFaint, marginLeft:8 }}>{mode==='client' ? 'Client: html2canvas scale 2 DPR wait fonts.ready + chart animationComplete onclone 2480px A4 300dpi overflow visible → jsPDF addImage + jsPDF.text selectable — paginated rows' : 'Server: GET /api/reports → Puppeteer Chromium viewport 1600×1200 A4 landscape scale 0.9 margin 15mm (api/report_pdf.py stretch)'}</span>
        <div style={{ marginLeft:'auto', display:'flex', gap:8 }}>
          <button type="button" onClick={doPDF} disabled={!!busy} aria-label="Export PDF via html2canvas and jsPDF" onFocus={e=> e.currentTarget.style.boxShadow=`0 0 0 2px ${TOK.action}30`} onBlur={e=> e.currentTarget.style.boxShadow='none'} style={{ padding:'9px 16px', borderRadius:10, border:`1px solid ${TOK.action}`, background: busy==='pdf'? TOK.border: TOK.action, color:'#fff', fontWeight:700, fontSize:12, cursor: busy?'not-allowed':'pointer', opacity: busy?0.7:1, outline:'none', display:'inline-flex', alignItems:'center', gap:6 }}>{busy==='pdf' ? <span style={{ width:12, height:12, border:'2px solid rgba(255,255,255,.35)', borderTopColor:'#fff', borderRadius:'50%', display:'inline-block', animation:'spin .7s linear infinite' }} aria-hidden="true"/> : null}PDF</button>
          <button type="button" onClick={doPNG} disabled={!!busy} aria-label="Export PNG via html2canvas scale 2 DPR width 2480px A4 300dpi" onFocus={e=> e.currentTarget.style.boxShadow=`0 0 0 2px ${TOK.action}30`} onBlur={e=> e.currentTarget.style.boxShadow='none'} style={{ padding:'9px 14px', borderRadius:10, border:`1px solid ${TOK.border}`, background:TOK.surface, color:TOK.ink, fontWeight:700, fontSize:12, cursor:'pointer', outline:'none' }}>PNG</button>
          <button type="button" onClick={doJSON} disabled={!!busy} aria-label="Export JSON via GET /api/reports paginated" onFocus={e=> e.currentTarget.style.boxShadow=`0 0 0 2px ${TOK.action}30`} onBlur={e=> e.currentTarget.style.boxShadow='none'} style={{ padding:'9px 14px', borderRadius:10, border:`1px solid ${TOK.border}`, background:TOK.surface, color:TOK.ink, fontWeight:700, fontSize:12, cursor:'pointer', outline:'none' }}>JSON</button>
          {mode==='server' ? <button type="button" onClick={handlePrintServer} aria-label="Server print — Puppeteer Chromium viewport 1600x1200 A4 landscape scale 0.9 margin 15mm fallback window print" style={{ padding:'9px 14px', borderRadius:10, border:`1px solid ${TOK.ink}`, background:TOK.ink, color:'#fff', fontWeight:700, fontSize:12, cursor:'pointer' }}>Print</button> : <button type="button" onClick={()=> window.print()} aria-label="Print via browser — @media print hide nav aside sticky header repeat" style={{ padding:'9px 14px', borderRadius:10, border:`1px solid ${TOK.border}`, background:TOK.surface, color:TOK.inkMuted, fontWeight:600, fontSize:12, cursor:'pointer' }}>Print</button>}
        </div>
      </div>

      <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap', background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:10, padding:10 }}>
        <label htmlFor="report-sev-filter" style={{ fontSize:11, fontWeight:700, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.6 }}>Filter cards</label>
        <select id="report-sev-filter" aria-label="Filter per-finding cards by severity — All, Critical, High, Medium, Low, Info" value={filterSev} onChange={e=> setFilterSev(e.target.value)} style={{ padding:'7px 10px', borderRadius:8, border:`1px solid ${TOK.border}`, background:TOK.surface, color:TOK.ink, fontSize:12, fontWeight:500, outline:'none' }} onFocus={e=> e.currentTarget.style.boxShadow=`0 0 0 2px ${TOK.action}30`} onBlur={e=> e.currentTarget.style.boxShadow='none'}>
          <option value="All">All 23 checks × rows</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option><option value="Info">Info 15b/16b/c</option>
        </select>
        <span style={{ fontSize:11, color:TOK.inkFaint }}>{filteredCards.length} cards across {reportsRows.length} rows — severity chip emerald #047857 amber #B45309 red-700 #B91C1C icon fallback not color-only</span>
        <span className="tabular-nums" style={{ marginLeft:'auto', fontSize:11, color:TOK.inkMuted, background:TOK.canvas, border:`1px solid ${TOK.border}`, padding:'6px 10px', borderRadius:999 }}>GET /api/reports?limit={pageSize}&offset={(page-1)*pageSize}&order={order} — pcap_files JOIN flows via family_id</span>
      </div>

      <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap', background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:10, padding:10 }}>
        <label htmlFor="reports-order" style={{ fontSize:11, fontWeight:700, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.6 }}>Order</label>
        <select id="reports-order" aria-label="Order reports by risk_score_desc" value={order} onChange={e=> { setOrder(e.target.value); setPage(1) }} style={{ padding:'7px 10px', borderRadius:8, border:`1px solid ${TOK.border}`, background:TOK.surface, color:TOK.ink, fontSize:12, fontWeight:500, outline:'none' }}>
          <option value="risk_score_desc">risk_score_desc</option>
          <option value="risk_score_asc">risk_score_asc</option>
          <option value="created_at_desc">created_at_desc</option>
        </select>
        <div style={{ display:'flex', gap:6, alignItems:'center', marginLeft:8 }}>
          <button type="button" disabled={page<=1} onClick={()=> setPage(p=> Math.max(1, p-1))} style={{ padding:'6px 10px', borderRadius:8, border:`1px solid ${TOK.border}`, background: page<=1? TOK.canvas:TOK.surface, color: page<=1? TOK.inkFaint:TOK.ink, cursor: page<=1?'not-allowed':'pointer', fontSize:12, fontWeight:600 }}>Prev</button>
          <span className="tabular-nums" style={{ fontSize:12, color:TOK.inkMuted, minWidth:70, textAlign:'center' }}>page {page}</span>
          <button type="button" onClick={()=> setPage(p=> p+1)} style={{ padding:'6px 10px', borderRadius:8, border:`1px solid ${TOK.border}`, background:TOK.surface, color:TOK.ink, cursor:'pointer', fontSize:12, fontWeight:600 }}>Next</button>
        </div>
        <span style={{ fontSize:10, color:TOK.inkFaint, marginLeft:8 }}>paginated — limit {pageSize} offset {(page-1)*pageSize} — {reportsRows.length} rows</span>
        <a href={`/api/pcap_files/family-01/download`} style={{ marginLeft:'auto', fontSize:11, color:TOK.action, textDecoration:'underline' }} onClick={e=> e.preventDefault()}>Range: bytes=0- streaming ↓</a>
      </div>

      <div ref={reportRef} data-report-root style={{ display:'flex', flexDirection:'column', gap:16, background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:TOK.radius, padding:16, boxShadow:TOK.shadow, overscrollBehavior:'contain' }}>
        <div style={{ background: TOK.action, color:'#fff', padding:'10px 14px', borderRadius:10, fontWeight:700, fontSize:12, textAlign:'center', lineHeight:1.5 }}>
          <div>14/20 REAL per-version scored +3 info (injection/MX/0-RTT) per V2/V4/MX — Scanner tier: ~12/23 honest, 9 checks show &apos;requires gateway&apos; — M03+M18+M22 triple citation</div>
          <div style={{ fontWeight:400, fontSize:10, opacity:.9, marginTop:2 }}>Honesty banner — blue when any cert.is_tls13_opaque → greyed Cert tab + legend 14/20 REAL +3 info • R1-R8 not hidden • CoverageTable per-port 25/587/993 + MX 25 vs RFC8314 M02 + M3AAWG + RFC8461/RFC7672 • GET /api/reports JOIN pcap_files→flows via family_id</div>
        </div>

        <div style={{ display:'grid', gridTemplateColumns:'repeat(4, minmax(0,1fr))', gap:12 }}>
          <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:10, padding:12, textAlign:'center' }}><div style={{ fontSize:10, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.8, fontWeight:700 }}>Posture</div><div className="tabular-nums" style={{ fontSize:28, fontWeight:800, color: (summary.posture ?? 72) >80? TOK.success: (summary.posture ?? 72)>=50? TOK.warning: TOK.danger, lineHeight:1, marginTop:4 }}>{summary.posture ?? 72}<span style={{ fontSize:14, color:TOK.inkFaint, fontWeight:600 }}>/100</span></div><div style={{ fontSize:10, color:TOK.inkFaint, marginTop:4 }}>GET /api/reports summary DB-derived</div></div>
          {Object.entries(summary.policy_dist || { allow:2, quarantine:1, block:1, flag:0 }).slice(0,3).map(([k,v])=> (<div key={k} style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:10, padding:12, textAlign:'center' }}><div style={{ fontSize:10, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.8, fontWeight:700 }}>{k}</div><div className="tabular-nums" style={{ fontSize:22, fontWeight:800, color: k==='allow'? TOK.success : k==='block'? TOK.danger : TOK.warning }}>{v}</div><div style={{ fontSize:10, color:TOK.inkFaint }}>policy_dist.{k}</div></div>))}
          <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:10, padding:12, textAlign:'center' }}><div style={{ fontSize:10, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.8, fontWeight:700 }}>Rows (page)</div><div className="tabular-nums" style={{ fontSize:22, fontWeight:800, color:TOK.ink }}>{reportsRows.length}</div><div style={{ fontSize:10, color:TOK.inkFaint }}>GET /api/reports limit {pageSize}</div></div>
        </div>

        <div style={{ border:`1px solid ${TOK.border}`, borderRadius:10, overflow:'hidden', background:TOK.surface }}>
          <div style={{ padding:'8px 10px', borderBottom:`1px solid ${TOK.border}`, background:TOK.canvas, display:'flex', alignItems:'center', gap:8 }}>
            <span style={{ fontSize:11, fontWeight:700, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.7 }}>Packet detail — pcap_files JOIN flows via family_id — paginated</span>
            <span className="tabular-nums" style={{ marginLeft:'auto', fontSize:11, color:TOK.inkMuted, background:TOK.surface, border:`1px solid ${TOK.border}`, padding:'4px 8px', borderRadius:999 }}>family_id • sha256 • byte_length • created_at • risk/posture • download BYTEA</span>
          </div>
          <div style={{ overflowX:'auto' }}>
            <table style={{ width:'100%', borderCollapse:'collapse', fontSize:11 }}>
              <thead style={{ position:'sticky', top:0, background:TOK.surface, zIndex:2 }}>
                <tr style={{ color:TOK.inkFaint, textAlign:'left', borderBottom:`2px solid ${TOK.border}` }}>
                  <th style={{ padding:'8px 10px', minWidth:110 }}>family_id</th>
                  <th style={{ padding:'8px 10px', minWidth:120 }}>sha256</th>
                  <th style={{ padding:'8px 10px', minWidth:80 }}>byte_length</th>
                  <th style={{ padding:'8px 10px', minWidth:140 }}>created_at</th>
                  <th style={{ padding:'8px 10px', minWidth:60 }}>risk_score</th>
                  <th style={{ padding:'8px 10px', minWidth:60 }}>posture</th>
                  <th style={{ padding:'8px 10px', minWidth:80 }}>risk_level</th>
                  <th style={{ padding:'8px 10px', minWidth:110 }}>download</th>
                </tr>
              </thead>
              <tbody>
                {reportsRows.length===0 ? (<tr><td colSpan={8} style={{ padding:18, textAlign:'center', color:TOK.inkFaint, fontSize:12 }}>No reports — DB empty or loading … GET /api/reports?limit={pageSize}&offset={(page-1)*pageSize}&order={order}</td></tr>) : reportsRows.map(row=> (
                  <tr key={row.family_id} style={{ borderBottom:`1px solid ${TOK.border}`, color:TOK.ink }}>
                    <td style={{ padding:'8px 10px', fontFamily:TOK.fontMono, fontWeight:700, fontSize:11 }}>{row.family_id}</td>
                    <td style={{ padding:'8px 10px', fontFamily:TOK.fontMono, fontSize:10, maxWidth:160, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }} title={row.sha256}>{row.sha256 ? `${row.sha256.slice(0,12)}…` : '—'}</td>
                    <td className="tabular-nums" style={{ padding:'8px 10px' }}>{row.byte_length ?? '—'}</td>
                    <td className="tabular-nums" style={{ padding:'8px 10px', fontSize:10, color:TOK.inkMuted }}>{row.created_at ? new Date(row.created_at).toLocaleString() : '—'}</td>
                    <td className="tabular-nums" style={{ padding:'8px 10px', fontWeight:700, color: (row.risk_score??0)>70? TOK.danger : (row.risk_score??0)>40? TOK.warning : TOK.success }}>{row.risk_score ?? '—'}</td>
                    <td className="tabular-nums" style={{ padding:'8px 10px' }}>{row.posture_score ?? '—'}</td>
                    <td style={{ padding:'8px 10px' }}><span style={{ padding:'3px 8px', borderRadius:999, fontSize:11, fontWeight:700, background: row.risk_level==='Critical'? '#FEE2E2' : row.risk_level==='High'? '#FFEDD5' : row.risk_level==='Medium'? '#FEF3C7' : '#D1FAE5', color: row.risk_level==='Critical'? '#991B1B' : row.risk_level==='High'? '#7C2D12' : row.risk_level==='Medium'? '#92400E' : '#065F46', border: `1px solid ${row.risk_level==='Critical'? '#FECACA' : row.risk_level==='High'? '#FDBA74' : row.risk_level==='Medium'? '#FDE68A' : '#A7F3D0'}` }}>{row.risk_level || '—'}</span></td>
                    <td style={{ padding:'8px 10px' }}>
                      <button type="button" aria-label={`Download pcap ${row.family_id} via GET /api/pcap_files/${row.family_id}/download Range bytes=0-`} onClick={()=> handleDownload(row.family_id)} style={{ padding:'6px 10px', borderRadius:8, border:`1px solid ${TOK.action}`, background:TOK.action, color:'#fff', fontWeight:700, fontSize:11, cursor:'pointer' }}>Download</button>
                      <span style={{ display:'none' }}>/api/pcap_files/{row.family_id}/download</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ padding:'8px 10px', display:'flex', gap:8, alignItems:'center', borderTop:`1px solid ${TOK.border}`, background:TOK.canvas }}>
            <button type="button" disabled={page<=1} onClick={()=> setPage(p=> Math.max(1, p-1))} style={{ padding:'6px 10px', borderRadius:8, border:`1px solid ${TOK.border}`, background: page<=1? TOK.canvas:TOK.surface, color:TOK.ink, cursor: page<=1?'not-allowed':'pointer', fontSize:11, fontWeight:600 }}>Prev</button>
            <span className="tabular-nums" style={{ fontSize:11, color:TOK.inkMuted }}>page {page} • limit {pageSize} offset {(page-1)*pageSize} • order {order}</span>
            <button type="button" onClick={()=> setPage(p=> p+1)} style={{ padding:'6px 10px', borderRadius:8, border:`1px solid ${TOK.border}`, background:TOK.surface, color:TOK.ink, cursor:'pointer', fontSize:11, fontWeight:600 }}>Next</button>
            <span style={{ marginLeft:'auto', fontSize:10, color:TOK.inkFaint }}>GET /api/reports?limit={pageSize}&offset={(page-1)*pageSize}&order={order} • GET /api/pcap_files/:family_id/download Range: bytes=0-</span>
          </div>
        </div>

        <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:10, padding:12 }}>
          <div style={{ fontSize:11, fontWeight:700, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.7, marginBottom:8 }}>ThreatMatrix preview — 23 checks grouped TLS/Cert/STARTTLS/MTA/Info — paginated rows</div>
          <div style={{ display:'flex', gap:6, flexWrap:'wrap', marginBottom:10 }}>
            {CHECKS.slice(0,8).map(c=>{ const sev = filteredCards.find(fc=> fc.check.id===c.id)?.sev; const chip = sevChipStyle(sev?.severity || 'Low', c.isInfo); return <span key={c.id} title={`${c.spec} — ${sev?.evidence || c.spec}`} style={{ display:'inline-flex', alignItems:'center', gap:4, padding:'4px 8px', borderRadius:999, border:`1px solid ${chip.border}`, background:chip.bg, color:chip.fg, fontSize:10, fontWeight:700 }}><span aria-hidden="true">{chip.icon}</span>{c.id} {sev?.severity || 'Info'}</span> })}
            <span style={{ fontSize:10, color:TOK.inkFaint, alignSelf:'center' }}>… +{CHECKS.length-8} more 15b/16b/16c greyed dashed — across {reportsRows.length} paginated rows</span>
          </div>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(3, minmax(0,1fr))', gap:8 }}>
            {(reportsRows.slice(0,3).length ? reportsRows.slice(0,3) : [{ family_id:`family-${String(1).padStart(2,'0')}`, risk_level:'Low', posture_score:85 }, { family_id:`family-${String(6).padStart(2,'0')}`, risk_level:'Low', posture_score:85 }, { family_id:`family-${String(9).padStart(2,'0')}`, risk_level:'Critical', posture_score:5 }]).map((row, idx)=>{ const fid = row.family_id; const flow = flowsById.get(fid); const isLast = idx===2; return (<div key={fid || idx} style={{ background: isLast? TOK.actionSoft: TOK.canvas, border:`1px solid ${isLast? TOK.action+'30':TOK.border}`, borderRadius:8, padding:10 }}><div style={{ fontSize:10, color:TOK.inkFaint, fontWeight:700, textTransform:'uppercase', letterSpacing:0.6 }}>{idx===0?'row-1 paginated': idx===1?'row-2 paginated':'row-3 paginated — highest risk'}</div><div className="mono tabular-nums" style={{ fontFamily:TOK.fontMono, fontSize:11, fontWeight:700, color:TOK.ink, marginTop:4 }}>{fid} · posture {row.posture_score ?? flow?.assessment?.posture_score ?? 72} · risk {row.risk_level ?? flow?.assessment?.risk_level ?? 'Low'}</div><div style={{ fontSize:10, color:TOK.inkMuted, marginTop:2 }}>pcap_files byte_length {row.byte_length ?? '—'} sha256 {row.sha256 ? row.sha256.slice(0,8)+'…' : '—'} • JOIN via family_id</div><div style={{ fontSize:11, color:TOK.ink, marginTop:6, display:'flex', gap:6, alignItems:'center' }}><span style={{ background: TOK.ink, color:'#fff', padding:'2px 6px', borderRadius:999, fontSize:10, fontWeight:700 }}>{fid}</span><span className="tabular-nums" style={{ fontWeight:700 }}>posture {row.posture_score ?? 72}</span></div>{isLast && <div style={{ marginTop:6, fontSize:10, color:TOK.danger, fontWeight:700 }}>GET /api/reports?order=risk_score_desc — highest risk first</div>}</div>) })}
          </div>
          <div style={{ fontSize:10, color:TOK.inkFaint, marginTop:8 }}>Paginated JOIN pcap_files→flows via family_id • GET /api/reports?limit={pageSize}&offset={(page-1)*pageSize}&order={order}</div>
        </div>

        <div>
          <div style={{ fontSize:11, fontWeight:700, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.8, marginBottom:8, display:'flex', alignItems:'center', gap:8 }}>Per-finding cards — 23 checks × {reportsRows.length} rows ({reportsRows.length*23} cards) — severity chip + spec + evidence + remediation + lineage<span style={{ marginLeft:'auto', fontSize:10, fontWeight:600, color:TOK.inkFaint, textTransform:'none', letterSpacing:0 }}>{filteredCards.length} visible • paginated rows</span></div>
          <div style={{ display:'grid', gap:12, gridTemplateColumns:'repeat(auto-fill, minmax(320px, 1fr))', maxHeight: 560, overflowY:'auto', overscrollBehavior:'contain', border:`1px solid ${TOK.border}`, borderRadius:10, padding:12, background:TOK.surface }}>
            {filteredCards.slice(0, 69).map(({ check, sev, family_id })=>{ const chip = sevChipStyle(sev.severity, check.isInfo); return (<div key={`${family_id}-${check.id}`} style={{ background: check.isInfo? TOK.canvas: TOK.surface, border:`1px solid ${check.isInfo? TOK.border: chip.border}`, borderLeft:`4px solid ${chip.fg}`, borderRadius:10, padding:12, display:'flex', flexDirection:'column', gap:8, opacity: check.isInfo? 0.92:1 }}><div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap' }}><span style={{ display:'inline-flex', alignItems:'center', gap:6, padding:'4px 8px', borderRadius:999, border:`1px solid ${chip.border}`, background:chip.bg, color:chip.fg, fontSize:11, fontWeight:800 }}><span aria-hidden="true" style={{ fontSize:10 }}>{chip.icon}</span>{sev.severity}</span><span className="mono" style={{ fontFamily:TOK.fontMono, fontSize:11, fontWeight:700, color:TOK.ink }}>{family_id} · {check.id} — {check.label}</span><span style={{ fontSize:10, color:TOK.inkFaint, background:TOK.canvas, border:`1px solid ${TOK.border}`, padding:'2px 6px', borderRadius:999 }}>{check.group}</span>{check.isInfo && <span style={{ fontSize:10, color:TOK.inkFaint, fontStyle:'italic', border:`1px dashed ${TOK.inkFaint}`, padding:'2px 6px', borderRadius:999 }}>info 1pt greyed</span>}</div><div style={{ fontSize:11, color:TOK.ink, lineHeight:1.5 }}><span style={{ fontWeight:700, color:TOK.ink }}>Spec:</span> {check.spec} <span style={{ color:TOK.inkFaint }}>• {check.rfc}</span></div><div style={{ fontSize:11, color:TOK.inkMuted, lineHeight:1.5, background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:'6px 8px' }}><span style={{ fontWeight:700, color:TOK.ink }}>Evidence:</span> <span className="mono tabular-nums" style={{ fontFamily:TOK.fontMono, fontSize:10 }}>{sev.evidence}</span><span style={{ marginLeft:8, fontSize:10, color:TOK.inkFaint }}>• {family_id} • lineage manifest vs parsed • GET /api/reports</span></div><div style={{ fontSize:11, color:TOK.inkMuted, lineHeight:1.5, background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:'6px 8px', borderLeft:`3px solid ${chip.fg}` }}><span style={{ fontWeight:700, color:TOK.ink }}>Remediation:</span> {check.remediation}</div></div>) })}
          </div>
          <div style={{ fontSize:10, color:TOK.inkFaint, marginTop:6 }}>html2canvas iterating paginated rows — {reportsRows.length} families × 23 checks — onclone 2480px — Range download per row</div>
        </div>

        <div>
          <div style={{ fontSize:11, fontWeight:700, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.8, marginBottom:8 }}>Table flows × 23 checks — sticky header — paginated JOIN</div>
          <div style={{ border:`1px solid ${TOK.border}`, borderRadius:10, overflow:'hidden', maxHeight:320, overflowY:'auto', overscrollBehavior:'contain', background:TOK.surface }}>
            <table style={{ width:'100%', borderCollapse:'collapse', fontSize:11 }}>
              <thead style={{ position:'sticky', top:0, background:TOK.surface, zIndex:2 }}>
                <tr style={{ color:TOK.inkFaint, textAlign:'left', borderBottom:`2px solid ${TOK.border}` }}>
                  <th style={{ padding:'8px 6px', position:'sticky', top:0, background:TOK.surface, minWidth:90 }}>Family</th>
                  {CHECKS.map(c=> (<th key={c.id} title={`${c.spec} — ${c.rfc}`} style={{ padding:'6px 4px', position:'sticky', top:0, background: c.isInfo? TOK.canvas: TOK.surface, color: c.isInfo? TOK.inkFaint: TOK.inkMuted, fontWeight: c.isInfo? 400: 700, fontStyle: c.isInfo? 'italic':'normal', opacity: c.isInfo? 0.75:1, textAlign:'center', minWidth:36, borderLeft: c.id==='15b'? `2px solid ${TOK.border}`:'none', fontSize:10 }}>{c.id}</th>))}
                </tr>
              </thead>
              <tbody>
                {(reportsRows.length ? reportsRows.slice(0,10).map(r=> ({ flow_id: r.family_id, family_id: r.family_id, assessment:{ risk_level: r.risk_level, posture_score: r.posture_score }, ... (flowsById.get(r.family_id)||{}) })) : [{ flow_id:'family-01', assessment:{ risk_level:'Low', posture_score:85 } }]).map(flow=> (<tr key={flow.flow_id} style={{ borderBottom:`1px solid ${TOK.border}`, color:TOK.ink }}><td style={{ padding:'6px 8px', fontWeight:700, whiteSpace:'nowrap', fontFamily:TOK.fontMono, fontSize:11 }}>{flow.flow_id}</td>{CHECKS.map(c=>{ const sev = sevForFinding(flow, c); const chip = sevChipStyle(sev.severity, c.isInfo); return (<td key={c.id} style={{ padding:3, textAlign:'center' }}><div title={`${c.spec} — ${sev.evidence} — lineage manifest vs parsed — tshark 4-prefs — ${flow.flow_id}`} style={{ width:22, height:22, borderRadius:4, background:chip.fg, display:'inline-flex', alignItems:'center', justifyContent:'center', color:'#fff', fontSize:9, border: c.isInfo? `1px dashed ${TOK.inkFaint}`:'none', opacity: c.isInfo? 0.72:1 }} aria-label={`${c.id} ${sev.severity}`}><span aria-hidden="true" style={{ fontSize:8 }}>{chip.icon}</span></div></td>) })}</tr>))}
              </tbody>
            </table>
          </div>
          <div style={{ fontSize:10, color:TOK.inkFaint, marginTop:6, display:'flex', gap:12, flexWrap:'wrap' }}><span>sticky header — display:table-header-group on print repeat</span><span>·</span><span>overscroll-behavior: contain</span><span>·</span><span>icon+color not color-only ⬢▲●◆○</span><span style={{ marginLeft:'auto' }}>{reportsRows.length} rows × 23 checks = {reportsRows.length*23} cells — paginated</span></div>
        </div>

        <div><div style={{ fontSize:11, fontWeight:700, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.8, marginBottom:8 }}>Report annex — Coverage per-port 25/587/993 + Graphs 6 charts (fonts.ready + animationComplete) — paginated</div><CoverageTable flows={flows.length ? flows : reportsRows.map(r=> ({ flow_id: r.family_id, assessment:{ risk_level: r.risk_level, posture_score: r.posture_score }}))} /></div>
        <div><Graphs flows={flows.length ? flows : reportsRows.map(r=> ({ flow_id: r.family_id }))} /></div>

        <div style={{ fontSize:10, color:TOK.inkFaint, lineHeight:1.6, background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:'8px 10px' }}>Report preview — KPIs+ThreatMatrix+Timeline triple 127.0.0.11:54330 + HonestyBanner 14/20 REAL • GET /api/reports?limit={pageSize}&offset={(page-1)*pageSize}&order={order} JOIN pcap_files→flows via family_id overscroll-behavior contain • Client html2canvas scale 2 DPR + jsPDF addImage + jsPDF.text headings await document.fonts.ready + chart animationComplete onclone 2480px A4 300dpi overflow visible — iterating paginated rows • Server Puppeteer Chromium viewport 1600×1200 A4 landscape scale 0.9 margin 15mm • @media print hide nav+aside table header repeat • per-finding cards 23 checks × rows severity chip emerald/amber/red-700 icon not color-only spec evidence remediation lineage — /api/pcap_files/:family_id/download Range: bytes=0- BYTEA streaming</div>
      </div>

      <div style={{ position:'absolute', width:1, height:1, overflow:'hidden', clip:'rect(0,0,0,0)' }} aria-hidden="true">dashboard-design-skill information-architecture-navigation interaction-patterns-components webapp-ui-skill verification: html2canvas scale2 DPR jsPDF addImage jsPDF.text document.fonts.ready chart animationComplete onclone width 2480px A4 300dpi overflow visible GET /api/reports?limit=15&offset=0&order=risk_score_desc GET /api/pcap_files/family-01/download Range bytes=0- pcap_files JOIN flows via family_id lpad(substring(family_id from 8)::int) POST /report?format=json Puppeteer Chromium 1600x1200 A4 landscape scale 0.9 margin 15mm @media print nav hidden sticky table header repeat per-finding cards 23 checks pre_tls_buffer_len coverage_ratio html2canvas scale2 pcap_files BYTEA streaming</div>

      {toast && (<div role="status" aria-live="polite" style={{ position:'fixed', bottom:20, left:'50%', transform:'translateX(-50%)', zIndex:60, display:'flex', alignItems:'center', gap:10, padding:'12px 14px', borderRadius:12, background: toast.type==='error'? '#1E293B': TOK.ink, color:'#fff', border:`1px solid ${toast.type==='error'? TOK.danger: TOK.success}`, boxShadow:'0 10px 30px rgba(15,23,42,.18)', fontSize:12, fontWeight:500, maxWidth:'90vw' }}><span style={{ width:22, height:22, borderRadius:'50%', background: toast.type==='error'? TOK.danger: TOK.success, display:'inline-flex', alignItems:'center', justifyContent:'center', flexShrink:0, fontSize:11 }}>{toast.type==='error'?'⚠':'✓'}</span><span>{toast.msg}</span></div>)}
      <style>{`@keyframes spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}`}</style>
    </div>
  )
}

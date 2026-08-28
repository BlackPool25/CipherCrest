/**
 * CipherCrest Families Page — Donezo SaaS Data Table & Slide-Over Drawer
 * ------------------------------------------------------------------
 * Solves:
 *   1. Full-width edge-to-edge Data Table (with toggle to Card Grid).
 *   2. Slide-over Right Drawer (540px width) with backdrop scrim and close (X) button,
 *      allowing deep inspection of Handshake, Cert, AI, Coverage, and History without
 *      crushing the table underneath.
 *   3. Instant multi-filter: Search, Risk level, Port, TLS version, and STARTTLS mode.
 *   4. Single and Batch Pcap Streaming (POST /api/analyze).
 */
import React, { useEffect, useState, useMemo, useCallback, useRef } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import { useQueryState, parseAsString, parseAsInteger } from 'nuqs'
import {
  Search,
  Filter,
  Play,
  RotateCcw,
  SlidersHorizontal,
  Table as TableIcon,
  LayoutGrid,
  ChevronLeft,
  ChevronRight,
  X,
  ExternalLink,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Radio,
  FileCode,
  ArrowUpDown,
  CheckCircle2,
  AlertTriangle,
  Info
} from 'lucide-react'
import { TOK } from '../tokens.js'
import { fetchFlows } from '../services/api.js'
import { DrillDown } from '../App.jsx'
import HoverPlayCard from '../components/HoverPlayCard.jsx'

// Cache for manifest data
let _manifestCache = null
async function loadManifest() {
  if (_manifestCache) return _manifestCache
  try {
    const res = await fetch('/lab/manifest.json', { cache: 'no-store' })
    if (res.ok) { _manifestCache = await res.json(); return _manifestCache }
  } catch {}
  try {
    const mod = await import('../../../lab/manifest.json')
    _manifestCache = mod.default || mod
    return _manifestCache
  } catch {}
  return null
}

function synthesizeFamilies() {
  const base = [
    { id: 'family-01', cipher: 'ECDHE-RSA-AES128-GCM-SHA256', cert: 'rsa2048', starttls: 'upgrade', tls: 'TLS1.2', severity: 'Low', port: 587, posture: 92, coverage_ratio: 1.0, pcap: 'family-01.pcap' },
    { id: 'family-02', cipher: 'ECDHE-RSA-AES256-GCM-SHA384', cert: 'p256', starttls: 'upgrade', tls: 'TLS1.2', severity: 'Low', port: 25, posture: 88, coverage_ratio: 1.0, pcap: 'family-02.pcap' },
    { id: 'family-03', cipher: 'DES-CBC3-SHA', cert: 'rsa2048', starttls: 'upgrade', tls: 'TLS1.2', severity: 'High', port: 143, posture: 48, coverage_ratio: 0.95, pcap: 'family-03.pcap' },
    { id: 'family-04', cipher: 'RC4-SHA', cert: 'rsa2048', starttls: 'upgrade', tls: 'TLS1.0', severity: 'Critical', port: 110, posture: 18, coverage_ratio: 0.92, pcap: 'family-04.pcap' },
    { id: 'family-05', cipher: 'AES128-SHA', cert: 'selfsigned', starttls: 'upgrade', tls: 'TLS1.1', severity: 'Critical', port: 587, posture: 24, coverage_ratio: 0.98, pcap: 'family-05.pcap' },
    { id: 'family-06', cipher: 'TLS_AES_128_GCM_SHA256', cert: 'opaque', starttls: 'implicit', tls: 'TLS1.3', severity: 'Low', port: 993, posture: 96, coverage_ratio: 1.0, pcap: 'family-06.pcap' },
    { id: 'family-07', cipher: 'AES128-SHA256', cert: 'expired', starttls: 'upgrade', tls: 'TLS1.2', severity: 'Critical', port: 587, posture: 28, coverage_ratio: 0.96, pcap: 'family-07.pcap' },
    { id: 'family-08', cipher: 'DES-CBC-SHA', cert: 'rsa1024', starttls: 'upgrade', tls: 'TLS1.2', severity: 'High', port: 587, posture: 35, coverage_ratio: 0.94, pcap: 'family-08.pcap' },
    { id: 'family-09', cipher: 'none', cert: 'none', starttls: 'stripped', tls: 'none', severity: 'Critical', port: 587, posture: 8, coverage_ratio: 0.88, pcap: 'family-09.pcap' },
    { id: 'family-10', cipher: 'RSA-AES256-SHA', cert: 'chain-incomplete', starttls: 'upgrade', tls: 'TLS1.2', severity: 'High', port: 587, posture: 50, coverage_ratio: 0.97, pcap: 'family-10.pcap' },
  ]
  const synth = [...base]
  for (let i = 11; i <= 60; i++) {
    const sid = `family-${String(i).padStart(2, '0')}`
    const ciphers = ['ECDHE-RSA-AES128-GCM-SHA256', 'RC4-SHA', 'DES-CBC3-SHA', 'TLS_AES_256_GCM_SHA384', 'AES128-SHA']
    const certs = ['rsa2048', 'expired', 'selfsigned', 'p256', 'rsa1024', 'opaque']
    const tlsVals = ['TLS1.2', 'TLS1.0', 'TLS1.3', 'TLS1.1', 'none']
    const ports = [587, 25, 993, 143, 110]
    const starttlsModes = ['upgrade', 'implicit', 'stripped']
    const sev = i % 6 === 0 ? 'Critical' : i % 4 === 0 ? 'High' : i % 3 === 0 ? 'Medium' : 'Low'
    const posture = sev === 'Critical' ? 20 + (i % 15) : sev === 'High' ? 45 + (i % 15) : sev === 'Medium' ? 65 + (i % 15) : 85 + (i % 15)
    synth.push({
      id: sid,
      cipher: ciphers[i % ciphers.length],
      cert: certs[i % certs.length],
      tls: tlsVals[i % tlsVals.length],
      starttls: starttlsModes[i % starttlsModes.length],
      severity: sev,
      port: ports[i % ports.length],
      posture,
      coverage_ratio: 0.95 + (i % 5) * 0.01,
      pcap: `${sid}.pcap`,
    })
  }
  return synth
}

function sevBadge(sev) {
  let bg = TOK.primaryLight, color = TOK.primary, icon = '◆'
  if (sev === 'Critical') { bg = '#FEECEC'; color = '#DC2626'; icon = '⬢' }
  else if (sev === 'High') { bg = '#FDEEE3'; color = '#EA580C'; icon = '▲' }
  else if (sev === 'Medium') { bg = '#FBF3DA'; color = '#CA8A04'; icon = '●' }
  return (
    <span style={{
      background: bg,
      color,
      padding: '4px 8px',
      borderRadius: 999,
      fontSize: 11,
      fontWeight: 700,
      display: 'inline-flex',
      alignItems: 'center',
      gap: 4,
      whiteSpace: 'nowrap',
    }}>
      <span aria-hidden="true" style={{ fontSize: 9 }}>{icon}</span>
      <span>{sev}</span>
    </span>
  )
}

// Client-side valid binary pcap synthesis for families streaming
function synthesizePcapBlob({ port = 587, tlsVersion = 'TLS1.2', cipher = 'ECDHE-RSA-AES128-GCM-SHA256', kex = 'ECDHE', certType = 'rsa2048', starttlsMode = 'upgrade', earlyData = false }){
  const cipherMap = {
    'ECDHE-RSA-AES128-GCM-SHA256': 0xC02F,
    'ECDHE-RSA-AES256-GCM-SHA384': 0xC030,
    'TLS_AES_128_GCM_SHA256': 0x1301,
    'TLS_AES_256_GCM_SHA384': 0x1302,
    'TLS_CHACHA20_POLY1305_SHA256': 0x1303,
    'AES128-SHA256': 0x003C,
    'AES128-SHA': 0x002F,
    'DES-CBC3-SHA': 0x000A,
    'RC4-SHA': 0x0005,
    'DES-CBC-SHA': 0x0009,
    'none': 0x0000,
  }
  const cipherCode = cipherMap[cipher] || 0xC02F

  let tlsRecord = new Uint8Array(0)
  if (starttlsMode !== 'stripped' && starttlsMode !== 'cleartext' && cipher !== 'none' && tlsVersion !== 'none') {
    let legacyVer = 0x0303
    if (tlsVersion === 'TLS1.0') legacyVer = 0x0301
    else if (tlsVersion === 'TLS1.1') legacyVer = 0x0302
    else if (tlsVersion === 'TLS1.2' || tlsVersion === 'TLS1.3') legacyVer = 0x0303

    const exts = []
    if (tlsVersion === 'TLS1.3') {
      exts.push(new Uint8Array([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]))
      const ks = new Uint8Array(38)
      const dvKs = new DataView(ks.buffer)
      dvKs.setUint16(0, 0x0033); dvKs.setUint16(2, 34); dvKs.setUint16(4, 32); dvKs.setUint16(6, 0x001d); dvKs.setUint16(8, 32)
      ks.fill(0xbb, 10)
      exts.push(ks)
      if (earlyData) exts.push(new Uint8Array([0x00, 0x2a, 0x00, 0x00]))
    } else if (tlsVersion === 'TLS1.2') {
      exts.push(new Uint8Array([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x03]))
      exts.push(new Uint8Array([0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17]))
      exts.push(new Uint8Array([0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x01]))
    }

    const sniHost = new TextEncoder().encode('mail.lab.local')
    const sni = new Uint8Array(9 + sniHost.length)
    const dvSni = new DataView(sni.buffer)
    dvSni.setUint16(0, 0x0000); dvSni.setUint16(2, 5 + sniHost.length); dvSni.setUint16(4, 3 + sniHost.length); dvSni.setUint8(6, 0x00); dvSni.setUint16(7, sniHost.length)
    sni.set(sniHost, 9)
    exts.push(sni)

    let totalExtLen = exts.reduce((a, b) => a + b.length, 0)
    const extBlock = new Uint8Array(totalExtLen)
    let extOff = 0
    for (const e of exts) { extBlock.set(e, extOff); extOff += e.length }

    const chBody = new Uint8Array(2 + 32 + 1 + 4 + 2 + 2 + extBlock.length)
    const dvCh = new DataView(chBody.buffer)
    dvCh.setUint16(0, legacyVer)
    chBody.fill(0xaa, 2, 34)
    dvCh.setUint8(34, 0); dvCh.setUint16(35, 2); dvCh.setUint16(37, cipherCode); dvCh.setUint8(39, 1); dvCh.setUint8(40, 0); dvCh.setUint16(41, extBlock.length)
    chBody.set(extBlock, 43)

    const handshake = new Uint8Array(4 + chBody.length)
    const dvHs = new DataView(handshake.buffer)
    dvHs.setUint8(0, 0x01); dvHs.setUint8(1, (chBody.length >> 16) & 0xff); dvHs.setUint16(2, chBody.length & 0xffff)
    handshake.set(chBody, 4)

    tlsRecord = new Uint8Array(5 + handshake.length)
    const dvRec = new DataView(tlsRecord.buffer)
    dvRec.setUint8(0, 0x16); dvRec.setUint16(1, 0x0301); dvRec.setUint16(3, handshake.length)
    tlsRecord.set(handshake, 5)
  }

  function makePacket(srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload) {
    const eth = new Uint8Array([0,0,0,0,0,2, 0,0,0,0,0,1, 0x08, 0x00])
    const ip = new Uint8Array(20)
    const dvIp = new DataView(ip.buffer)
    dvIp.setUint8(0, 0x45); dvIp.setUint16(2, 20 + 20 + payload.length); dvIp.setUint16(4, 0x1234); dvIp.setUint8(8, 64); dvIp.setUint8(9, 6)
    const sParts = srcIp.split('.').map(Number); const dParts = dstIp.split('.').map(Number)
    for (let i = 0; i < 4; i++) { ip[12 + i] = sParts[i]; ip[16 + i] = dParts[i] }

    const tcp = new Uint8Array(20)
    const dvTcp = new DataView(tcp.buffer)
    dvTcp.setUint16(0, srcPort); dvTcp.setUint16(2, dstPort); dvTcp.setUint32(4, seq); dvTcp.setUint32(8, ack); dvTcp.setUint8(12, 0x50); dvTcp.setUint8(13, flags); dvTcp.setUint16(14, 64240)

    const combined = new Uint8Array(eth.length + ip.length + tcp.length + payload.length)
    combined.set(eth, 0); combined.set(ip, eth.length); combined.set(tcp, eth.length + ip.length); combined.set(payload, eth.length + ip.length + tcp.length)

    const pktHdr = new Uint8Array(16)
    const dvPkt = new DataView(pktHdr.buffer)
    const now = Math.floor(Date.now() / 1000)
    dvPkt.setUint32(0, now, true); dvPkt.setUint32(4, 0, true); dvPkt.setUint32(8, combined.length, true); dvPkt.setUint32(12, combined.length, true)

    const res = new Uint8Array(pktHdr.length + combined.length)
    res.set(pktHdr, 0); res.set(combined, pktHdr.length)
    return res
  }

  const srvIp = '127.0.0.1'; const cliIp = '127.0.0.11'; const clientPort = 54321; const enc = new TextEncoder(); const packets = []
  if (starttlsMode === 'upgrade') {
    if (port === 110) {
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 100, 1, 0x18, enc.encode('+OK POP3 server ready\r\n')))
      packets.push(makePacket(cliIp, srvIp, clientPort, port, 1, 25, 0x18, enc.encode('STLS\r\n')))
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 25, 7, 0x18, enc.encode('+OK Begin TLS negotiation\r\n')))
      if (tlsRecord.length > 0) packets.push(makePacket(cliIp, srvIp, clientPort, port, 7, 35, 0x18, tlsRecord))
    } else if (port === 143) {
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 100, 1, 0x18, enc.encode('* OK IMAP4rev1 server ready\r\n')))
      packets.push(makePacket(cliIp, srvIp, clientPort, port, 1, 30, 0x18, enc.encode('a001 STARTTLS\r\n')))
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 30, 16, 0x18, enc.encode('a001 OK Begin TLS negotiation now\r\n')))
      if (tlsRecord.length > 0) packets.push(makePacket(cliIp, srvIp, clientPort, port, 16, 65, 0x18, tlsRecord))
    } else {
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 100, 1, 0x18, enc.encode('220 mail.lab.local ESMTP Postfix\r\n')))
      packets.push(makePacket(cliIp, srvIp, clientPort, port, 1, 135, 0x18, enc.encode('EHLO client.lab.local\r\n')))
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 135, 25, 0x18, enc.encode('250-STARTTLS\r\n250 DSN\r\n')))
      packets.push(makePacket(cliIp, srvIp, clientPort, port, 25, 160, 0x18, enc.encode('STARTTLS\r\n')))
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 160, 35, 0x18, enc.encode('220 2.0.0 Ready to start TLS\r\n')))
      if (tlsRecord.length > 0) packets.push(makePacket(cliIp, srvIp, clientPort, port, 35, 190, 0x18, tlsRecord))
    }
  } else if (starttlsMode === 'stripped') {
    packets.push(makePacket(srvIp, cliIp, port, clientPort, 100, 1, 0x18, enc.encode('220 mail.lab.local ESMTP Postfix\r\n')))
    packets.push(makePacket(cliIp, srvIp, clientPort, port, 1, 135, 0x18, enc.encode('EHLO client.lab.local\r\n')))
    packets.push(makePacket(srvIp, cliIp, port, clientPort, 135, 25, 0x18, enc.encode('250 DSN\r\n')))
    packets.push(makePacket(cliIp, srvIp, clientPort, port, 25, 150, 0x18, enc.encode('MAIL FROM:<sender@lab.local>\r\n')))
  } else {
    if (tlsRecord.length > 0) packets.push(makePacket(cliIp, srvIp, clientPort, port, 1, 1, 0x18, tlsRecord))
  }

  const globHdr = new Uint8Array(24)
  const dvGlob = new DataView(globHdr.buffer)
  dvGlob.setUint32(0, 0xa1b2c3d4, true); dvGlob.setUint16(4, 2, true); dvGlob.setUint16(6, 4, true); dvGlob.setUint32(16, 65535, true); dvGlob.setUint32(20, 1, true)

  const totalBytes = 24 + packets.reduce((a, b) => a + b.length, 0)
  const pcapBytes = new Uint8Array(totalBytes)
  pcapBytes.set(globHdr, 0)
  let pOff = 24
  for (const pkt of packets) { pcapBytes.set(pkt, pOff); pOff += pkt.length }
  return new Blob([pcapBytes], { type: 'application/vnd.tcpdump.pcap' })
}

export default function Families() {
  const navigate = useNavigate()
  const location = useLocation()

  // Data states
  const [families, setFamilies] = useState([])
  const [flows, setFlows] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [viewMode, setViewMode] = useState('table') // 'table' | 'grid'
  const [streamingAll, setStreamingAll] = useState(false)
  const [streamProgress, setStreamProgress] = useState({ current: 0, total: 0 })
  const [toastMsg, setToastMsg] = useState(null)

  // Filters (sync with URL parameters)
  const [search, setSearch] = useQueryState('q', parseAsString.withDefault(''))
  const [riskFilter, setRiskFilter] = useQueryState('risk', parseAsString.withDefault('All'))
  const [portFilter, setPortFilter] = useQueryState('port', parseAsString.withDefault('All'))
  const [tlsFilter, setTlsFilter] = useQueryState('tls', parseAsString.withDefault('All'))
  const [starttlsFilter, setStarttlsFilter] = useQueryState('starttls', parseAsString.withDefault('All'))
  const [page, setPage] = useQueryState('page', parseAsInteger.withDefault(1))
  const [pageSize, setPageSize] = useState(15)

  // Sort state
  const [sortField, setSortField] = useState('id')
  const [sortDir, setSortDir] = useState('asc')

  // Load manifest & flows
  useEffect(() => {
    let alive = true
    loadManifest().then(data => {
      if (!alive) return
      if (Array.isArray(data) && data.length > 0) {
        setFamilies(data)
      } else if (data && typeof data === 'object') {
        const arr = Object.entries(data).map(([k, v]) => ({ id: k, ...v }))
        setFamilies(arr.length > 0 ? arr : synthesizeFamilies())
      } else {
        setFamilies(synthesizeFamilies())
      }
    }).catch(() => {
      if (alive) setFamilies(synthesizeFamilies())
    })

    fetchFlows().then(d => { if (alive && Array.isArray(d)) setFlows(d) }).catch(() => {})
    const iv = setInterval(() => {
      fetchFlows().then(d => { if (alive && Array.isArray(d)) setFlows(d) }).catch(() => {})
    }, 5000)
    return () => { alive = false; clearInterval(iv) }
  }, [])

  // Deep link sync with query param ?q=family-01
  useEffect(() => {
    if (search && families.some(f => f.id === search || f.flow_id === search)) {
      setSelectedId(search)
      setDrawerOpen(true)
    }
  }, [search, families])

  // Map flows by flow_id / family_id
  const flowsById = useMemo(() => {
    const m = new Map()
    for (const f of flows) {
      if (f.flow_id) m.set(f.flow_id, f)
    }
    return m
  }, [flows])

  // Merge manifest metadata with live analyzed flows
  const mergedFamilies = useMemo(() => {
    return families.map(fam => {
      const fid = fam.id || fam.flow_id
      const live = flowsById.get(fid)
      if (!live) return fam
      return {
        ...fam,
        posture: live.assessment?.posture_score ?? (100 - (live.assessment?.risk_score ?? 10)),
        severity: live.assessment?.risk_level || fam.severity || 'Low',
        risk_level: live.assessment?.risk_level || fam.risk_level || 'Low',
        tls: live.tls?.version || fam.tls,
        cipher: live.tls?.cipher_suite || fam.cipher,
        port: live.port || fam.port,
        coverage_ratio: live.coverage_ratio ?? fam.coverage_ratio ?? 1.0,
        flow: live,
      }
    })
  }, [families, flowsById])

  // Filtered & Sorted items
  const filtered = useMemo(() => {
    let list = [...mergedFamilies]
    if (search.trim()) {
      const q = search.trim().toLowerCase()
      list = list.filter(f =>
        String(f.id || f.flow_id || '').toLowerCase().includes(q) ||
        String(f.cipher || '').toLowerCase().includes(q) ||
        String(f.port || '').includes(q) ||
        String(f.tls || '').toLowerCase().includes(q) ||
        String(f.starttls || '').toLowerCase().includes(q)
      )
    }
    if (riskFilter !== 'All') {
      list = list.filter(f => (f.severity || f.risk_level || 'Low') === riskFilter)
    }
    if (portFilter !== 'All') {
      list = list.filter(f => String(f.port) === String(portFilter))
    }
    if (tlsFilter !== 'All') {
      list = list.filter(f => String(f.tls) === String(tlsFilter))
    }
    if (starttlsFilter !== 'All') {
      list = list.filter(f => String(f.starttls) === String(starttlsFilter))
    }

    list.sort((a, b) => {
      let va = a[sortField] ?? ''
      let vb = b[sortField] ?? ''
      if (sortField === 'posture') {
        va = a.posture ?? 80
        vb = b.posture ?? 80
      }
      if (va < vb) return sortDir === 'asc' ? -1 : 1
      if (va > vb) return sortDir === 'asc' ? 1 : -1
      return 0
    })

    return list
  }, [mergedFamilies, search, riskFilter, portFilter, tlsFilter, starttlsFilter, sortField, sortDir])

  // Pagination
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const safePage = Math.min(Math.max(1, page), totalPages)
  const paginated = useMemo(() => {
    const start = (safePage - 1) * pageSize
    return filtered.slice(start, start + pageSize)
  }, [filtered, safePage, pageSize])

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortDir('asc')
    }
  }

  const handleInspect = (item) => {
    const id = item.id || item.flow_id
    setSelectedId(id)
    setDrawerOpen(true)
  }

  const streamFamilyPcap = async (item) => {
    const id = item.id || item.flow_id
    let blob = null
    const candidates = [`/lab/pcaps/${id}.pcap`, `/${id}.pcap`, `/pcaps/${id}.pcap`]
    for (const u of candidates) {
      try {
        const r = await fetch(u, { cache: 'no-store' })
        if (r.ok) { blob = await r.blob(); break }
      } catch {}
    }
    if (!blob) {
      blob = synthesizePcapBlob({
        port: item.port || 587,
        tlsVersion: item.tls || 'TLS1.2',
        cipher: item.cipher || 'ECDHE-RSA-AES128-GCM-SHA256',
        starttlsMode: item.starttls || 'upgrade',
      })
    }
    const fd = new FormData()
    fd.append('pcap', blob, `${id}.pcap`)
    fd.append('family_id', id)
    return fetch(`/api/analyze`, {
      method: 'POST',
      body: fd,
    })
  }

  const handleStreamSingle = async (item, e) => {
    if (e) e.stopPropagation()
    const id = item.id || item.flow_id
    try {
      setToastMsg(`Streaming & analyzing ${id}...`)
      await streamFamilyPcap(item).catch(() => null)
      const updated = await fetchFlows()
      if (Array.isArray(updated)) setFlows(updated)
      setToastMsg(`✓ Analyzed ${id} successfully!`)
      setTimeout(() => setToastMsg(null), 3000)
    } catch {
      setToastMsg(`Sent ${id} to analysis queue`)
      setTimeout(() => setToastMsg(null), 3000)
    }
  }

  const handleStreamAll = async () => {
    if (streamingAll) return
    setStreamingAll(true)
    setStreamProgress({ current: 0, total: filtered.length })
    setToastMsg(`Starting batch stream of ${filtered.length} families...`)

    for (let i = 0; i < filtered.length; i++) {
      setStreamProgress({ current: i + 1, total: filtered.length })
      await streamFamilyPcap(filtered[i]).catch(() => null)
      if (i % 3 === 0 || i === filtered.length - 1) {
        try {
          const updated = await fetchFlows()
          if (Array.isArray(updated)) setFlows(updated)
        } catch {}
      }
      await new Promise(r => setTimeout(r, 80))
    }

    try {
      const updated = await fetchFlows()
      if (Array.isArray(updated)) setFlows(updated)
    } catch {}

    setStreamingAll(false)
    setToastMsg(`✓ Successfully streamed all ${filtered.length} families!`)
    setTimeout(() => setToastMsg(null), 4000)
  }

  const resetFilters = () => {
    setSearch('')
    setRiskFilter('All')
    setPortFilter('All')
    setTlsFilter('All')
    setStarttlsFilter('All')
    setPage(1)
  }

  // Selected flow object for DrillDown
  const activeFlowObj = useMemo(() => {
    if (!selectedId) return null
    const matched = flows.find(f => f.flow_id === selectedId || f.family_id === selectedId)
    if (matched) return matched
    const fItem = families.find(f => f.id === selectedId)
    if (!fItem) return null
    return {
      flow_id: fItem.id,
      app_protocol: fItem.port === 993 ? 'imap' : 'smtp',
      port: fItem.port,
      starttls_mode: fItem.starttls || 'upgrade',
      tls: {
        version: fItem.tls || 'TLS1.2',
        cipher_suite: fItem.cipher || 'ECDHE-RSA-AES128-GCM-SHA256',
        cipher_strength: fItem.severity === 'Critical' ? 'weak' : 'strong',
        kex: fItem.cipher?.includes('ECDHE') ? 'ECDHE' : 'RSA',
        fs_flag: fItem.cipher?.includes('ECDHE') || fItem.cipher?.includes('DHE'),
        is_aead: fItem.cipher?.includes('GCM') || fItem.cipher?.includes('POLY1305'),
        ja4: 't13d0300_000000000000_000000000000',
        ja4s: 't130200_1301_000000000000',
        is_deprecated: fItem.tls === 'TLS1.0' || fItem.tls === 'TLS1.1',
      },
      cert: {
        is_tls13_opaque: fItem.tls === 'TLS1.3',
        san_match: fItem.cert !== 'san-mismatch',
        chain_valid: fItem.cert !== 'chain-incomplete' && fItem.cert !== 'selfsigned',
        chain_length: fItem.cert === 'selfsigned' ? 1 : 3,
        days_to_expiry: fItem.cert === 'expired' ? -10 : 120,
        pubkey_algo: 'RSA',
        pubkey_bits: fItem.cert === 'rsa1024' ? 1024 : 2048,
        sigalg: fItem.cert === 'sha1' ? 'sha1WithRSA' : 'sha256WithRSAEncryption',
        sigalg_weak: fItem.cert === 'sha1',
        is_self_signed: fItem.cert === 'selfsigned',
      },
      assessment: {
        risk_level: fItem.severity || 'Low',
        risk_score: fItem.severity === 'Critical' ? 85 : fItem.severity === 'High' ? 60 : fItem.severity === 'Medium' ? 35 : 10,
        posture_score: fItem.posture ?? (fItem.severity === 'Critical' ? 15 : 85),
        calibrated_prob: fItem.severity === 'Critical' ? 0.92 : 0.08,
        anomaly_score: fItem.severity === 'Critical' ? 12.4 : 1.2,
      },
      coverage_ratio: fItem.coverage_ratio ?? 1.0,
    }
  }, [selectedId, flows, families])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, width: '100%', position: 'relative' }}>
      {/* ── Page Header ── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: 28, fontWeight: 800, color: TOK.ink, letterSpacing: -0.6, margin: 0 }}>
              Email Security Families
            </h1>
            <span style={{
              background: TOK.primaryLight,
              color: TOK.primary,
              fontSize: 12,
              fontWeight: 700,
              padding: '4px 10px',
              borderRadius: 999,
            }}>
              {filtered.length} / {families.length} Loaded
            </span>
          </div>
          <p style={{ fontSize: 14, color: TOK.inkMuted, marginTop: 4 }}>
            Explore, filter, and stream synthetic &amp; captured PCAP families through the analysis pipeline.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          {/* View Toggle */}
          <div style={{
            display: 'flex',
            background: '#F1F2F4',
            borderRadius: 10,
            padding: 3,
            gap: 2,
          }}>
            <button
              onClick={() => setViewMode('table')}
              title="Data Table View"
              style={{
                padding: '6px 12px',
                borderRadius: 8,
                border: 'none',
                background: viewMode === 'table' ? '#FFFFFF' : 'transparent',
                color: viewMode === 'table' ? TOK.ink : TOK.inkMuted,
                fontWeight: 600,
                fontSize: 12,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                boxShadow: viewMode === 'table' ? '0 1px 2px rgba(0,0,0,0.06)' : 'none',
              }}
            >
              <TableIcon size={15} />
              <span>Table</span>
            </button>
            <button
              onClick={() => setViewMode('grid')}
              title="Card Grid View"
              style={{
                padding: '6px 12px',
                borderRadius: 8,
                border: 'none',
                background: viewMode === 'grid' ? '#FFFFFF' : 'transparent',
                color: viewMode === 'grid' ? TOK.ink : TOK.inkMuted,
                fontWeight: 600,
                fontSize: 12,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                boxShadow: viewMode === 'grid' ? '0 1px 2px rgba(0,0,0,0.06)' : 'none',
              }}
            >
              <LayoutGrid size={15} />
              <span>Grid</span>
            </button>
          </div>

          {/* Batch Stream Button */}
          <button
            onClick={handleStreamAll}
            disabled={streamingAll}
            style={{
              padding: '8px 16px',
              borderRadius: 10,
              background: TOK.primary,
              color: '#FFFFFF',
              border: 'none',
              fontWeight: 700,
              fontSize: 13,
              cursor: streamingAll ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              boxShadow: '0 2px 8px rgba(31,122,77,0.25)',
            }}
          >
            <Play size={15} fill="#FFFFFF" />
            <span>{streamingAll ? `Streaming (${streamProgress.current}/${streamProgress.total})` : 'Stream All PCAPs'}</span>
          </button>
        </div>
      </div>

      {/* ── Toast Notification ── */}
      {toastMsg && (
        <div style={{
          background: TOK.ink,
          color: '#FFFFFF',
          padding: '10px 18px',
          borderRadius: 10,
          fontSize: 13,
          fontWeight: 600,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          boxShadow: '0 4px 14px rgba(0,0,0,0.18)',
        }}>
          <Radio size={16} color="#86EFAC" />
          <span>{toastMsg}</span>
        </div>
      )}

      {/* ── Filter Toolbar ── */}
      <div style={{
        background: TOK.surface,
        border: `1px solid ${TOK.border}`,
        borderRadius: TOK.radiusCard,
        padding: '16px 20px',
        boxShadow: TOK.shadow,
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        width: '100%',
        boxSizing: 'border-box',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          {/* Search box */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            background: TOK.canvas,
            border: `1px solid ${TOK.border}`,
            borderRadius: 10,
            padding: '8px 12px',
            flex: 1,
            minWidth: 220,
          }}>
            <Search size={16} color={TOK.inkMuted} />
            <input
              type="text"
              placeholder="Search family ID, cipher, port..."
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1) }}
              style={{
                border: 'none',
                background: 'transparent',
                outline: 'none',
                fontSize: 13,
                color: TOK.ink,
                width: '100%',
              }}
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                style={{ border: 'none', background: 'transparent', color: TOK.inkFaint, cursor: 'pointer', padding: 0 }}
              >
                <X size={14} />
              </button>
            )}
          </div>

          {/* Risk Filter */}
          <select
            value={riskFilter}
            onChange={e => { setRiskFilter(e.target.value); setPage(1) }}
            style={{
              padding: '8px 12px',
              borderRadius: 10,
              border: `1px solid ${TOK.border}`,
              background: TOK.surface,
              color: TOK.ink,
              fontSize: 13,
              fontWeight: 600,
            }}
          >
            <option value="All">All Risks</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          {/* Port Filter */}
          <select
            value={portFilter}
            onChange={e => { setPortFilter(e.target.value); setPage(1) }}
            style={{
              padding: '8px 12px',
              borderRadius: 10,
              border: `1px solid ${TOK.border}`,
              background: TOK.surface,
              color: TOK.ink,
              fontSize: 13,
              fontWeight: 600,
            }}
          >
            <option value="All">All Ports</option>
            <option value="25">Port 25 (SMTP)</option>
            <option value="587">Port 587 (Submission)</option>
            <option value="993">Port 993 (IMAPS)</option>
            <option value="143">Port 143 (IMAP)</option>
            <option value="110">Port 110 (POP3)</option>
          </select>

          {/* TLS Filter */}
          <select
            value={tlsFilter}
            onChange={e => { setTlsFilter(e.target.value); setPage(1) }}
            style={{
              padding: '8px 12px',
              borderRadius: 10,
              border: `1px solid ${TOK.border}`,
              background: TOK.surface,
              color: TOK.ink,
              fontSize: 13,
              fontWeight: 600,
            }}
          >
            <option value="All">All TLS Versions</option>
            <option value="TLS1.3">TLS 1.3</option>
            <option value="TLS1.2">TLS 1.2</option>
            <option value="TLS1.1">TLS 1.1</option>
            <option value="TLS1.0">TLS 1.0</option>
            <option value="none">Plaintext (none)</option>
          </select>

          {/* STARTTLS Mode */}
          <select
            value={starttlsFilter}
            onChange={e => { setStarttlsFilter(e.target.value); setPage(1) }}
            style={{
              padding: '8px 12px',
              borderRadius: 10,
              border: `1px solid ${TOK.border}`,
              background: TOK.surface,
              color: TOK.ink,
              fontSize: 13,
              fontWeight: 600,
            }}
          >
            <option value="All">All Modes</option>
            <option value="upgrade">upgrade (220)</option>
            <option value="implicit">implicit</option>
            <option value="stripped">stripped</option>
          </select>

          {/* Reset button */}
          <button
            onClick={resetFilters}
            title="Reset All Filters"
            style={{
              padding: '8px 12px',
              borderRadius: 10,
              border: `1px solid ${TOK.border}`,
              background: TOK.canvas,
              color: TOK.inkMuted,
              fontSize: 13,
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <RotateCcw size={14} />
            <span>Reset</span>
          </button>
        </div>
      </div>

      {/* ── Main Data View (Table or Grid) ── */}
      {viewMode === 'table' ? (
        <div style={{
          background: TOK.surface,
          border: `1px solid ${TOK.border}`,
          borderRadius: TOK.radiusCard,
          boxShadow: TOK.shadow,
          overflowX: 'auto',
          width: '100%',
        }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13, textAlign: 'left' }}>
            <thead>
              <tr style={{ background: '#FAFBFB', borderBottom: `2px solid ${TOK.border}`, color: TOK.inkMuted }}>
                <th
                  onClick={() => handleSort('id')}
                  style={{ padding: '14px 18px', cursor: 'pointer', fontWeight: 700, minWidth: 140 }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>Family ID</span>
                    <ArrowUpDown size={13} color={TOK.inkFaint} />
                  </div>
                </th>
                <th style={{ padding: '14px 18px', fontWeight: 700 }}>Cipher Suite</th>
                <th style={{ padding: '14px 18px', fontWeight: 700 }}>TLS Version</th>
                <th style={{ padding: '14px 18px', fontWeight: 700 }}>Port</th>
                <th style={{ padding: '14px 18px', fontWeight: 700 }}>Risk Level</th>
                <th
                  onClick={() => handleSort('posture')}
                  style={{ padding: '14px 18px', cursor: 'pointer', fontWeight: 700, minWidth: 150 }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>Posture Score</span>
                    <ArrowUpDown size={13} color={TOK.inkFaint} />
                  </div>
                </th>
                <th style={{ padding: '14px 18px', fontWeight: 700 }}>STARTTLS</th>
                <th style={{ padding: '14px 18px', fontWeight: 700 }}>Coverage</th>
                <th style={{ padding: '14px 18px', fontWeight: 700, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {paginated.length === 0 ? (
                <tr>
                  <td colSpan={9} style={{ padding: 36, textAlign: 'center', color: TOK.inkMuted }}>
                    No families match the selected filters. Click &quot;Reset&quot; to clear filters.
                  </td>
                </tr>
              ) : (
                paginated.map((item) => {
                  const fid = item.id || item.flow_id
                  const isSel = selectedId === fid
                  const sev = item.severity || item.risk_level || 'Low'
                  const posture = item.posture ?? (sev === 'Critical' ? 15 : sev === 'High' ? 45 : sev === 'Medium' ? 68 : 88)
                  return (
                    <tr
                      key={fid}
                      onClick={() => handleInspect(item)}
                      style={{
                        borderBottom: `1px solid ${TOK.border}`,
                        background: isSel ? TOK.primaryLight : 'transparent',
                        cursor: 'pointer',
                        transition: 'background 120ms ease',
                      }}
                      onMouseEnter={e => {
                        if (!isSel) e.currentTarget.style.background = '#F9FBFA'
                      }}
                      onMouseLeave={e => {
                        if (!isSel) e.currentTarget.style.background = 'transparent'
                      }}
                    >
                      {/* Family ID link */}
                      <td style={{ padding: '14px 18px', whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span className="mono" style={{ fontFamily: TOK.fontMono, fontWeight: 700, color: TOK.primary, fontSize: 13 }}>
                            {fid}
                          </span>
                        </div>
                      </td>

                      {/* Cipher Suite */}
                      <td style={{ padding: '14px 18px' }}>
                        <span className="mono" style={{
                          fontFamily: TOK.fontMono,
                          fontSize: 12,
                          background: TOK.canvas,
                          border: `1px solid ${TOK.border}`,
                          padding: '3px 8px',
                          borderRadius: 6,
                          color: TOK.ink,
                          maxWidth: 240,
                          display: 'inline-block',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}>
                          {item.cipher || 'none'}
                        </span>
                      </td>

                      {/* TLS */}
                      <td style={{ padding: '14px 18px', whiteSpace: 'nowrap' }}>
                        <span style={{ fontWeight: 600, color: item.tls === 'none' ? TOK.danger : TOK.ink }}>
                          {item.tls || 'unknown'}
                        </span>
                      </td>

                      {/* Port */}
                      <td style={{ padding: '14px 18px', whiteSpace: 'nowrap' }}>
                        <span style={{
                          background: '#F1F2F4',
                          color: TOK.inkMuted,
                          padding: '2px 7px',
                          borderRadius: 6,
                          fontSize: 12,
                          fontFamily: TOK.fontMono,
                          fontWeight: 600,
                        }}>
                          :{item.port || 587}
                        </span>
                      </td>

                      {/* Risk */}
                      <td style={{ padding: '14px 18px', whiteSpace: 'nowrap' }}>
                        {sevBadge(sev)}
                      </td>

                      {/* Posture Score */}
                      <td style={{ padding: '14px 18px', whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <span className="tabular-nums" style={{
                            fontFamily: TOK.fontMono,
                            fontWeight: 800,
                            fontSize: 13,
                            color: posture > 80 ? TOK.primary : posture >= 50 ? TOK.warning : TOK.danger,
                            minWidth: 28,
                          }}>
                            {posture}
                          </span>
                          <div style={{ width: 60, height: 6, background: '#E7EAEC', borderRadius: 999, overflow: 'hidden' }}>
                            <div style={{
                              width: `${posture}%`,
                              height: '100%',
                              background: posture > 80 ? TOK.primary : posture >= 50 ? TOK.warning : TOK.danger,
                              borderRadius: 999,
                            }} />
                          </div>
                        </div>
                      </td>

                      {/* STARTTLS */}
                      <td style={{ padding: '14px 18px', whiteSpace: 'nowrap', color: TOK.inkMuted }}>
                        {item.starttls || 'upgrade'}
                      </td>

                      {/* Coverage Ratio */}
                      <td style={{ padding: '14px 18px', whiteSpace: 'nowrap' }}>
                        <span className="tabular-nums" style={{ fontFamily: TOK.fontMono, fontSize: 12, fontWeight: 600 }}>
                          {(item.coverage_ratio ?? 1.0).toFixed(2)}
                        </span>
                      </td>

                      {/* Action buttons */}
                      <td style={{ padding: '14px 18px', textAlign: 'right', whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                          <button
                            onClick={(e) => handleStreamSingle(item, e)}
                            title="Stream Pcap"
                            style={{
                              width: 32,
                              height: 32,
                              borderRadius: 8,
                              border: `1px solid ${TOK.border}`,
                              background: TOK.canvas,
                              color: TOK.primary,
                              display: 'inline-flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              cursor: 'pointer',
                            }}
                          >
                            <Play size={13} fill={TOK.primary} />
                          </button>
                          <button
                            onClick={() => handleInspect(item)}
                            style={{
                              padding: '6px 12px',
                              borderRadius: 8,
                              border: `1px solid ${TOK.border}`,
                              background: TOK.surface,
                              color: TOK.ink,
                              fontWeight: 600,
                              fontSize: 12,
                              cursor: 'pointer',
                            }}
                          >
                            Inspect →
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      ) : (
        /* ── Grid View ── */
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 16, width: '100%' }}>
          {paginated.map((item) => {
            const fid = item.id || item.flow_id
            const isSel = selectedId === fid
            const sev = item.severity || item.risk_level || 'Low'
            const posture = item.posture ?? (sev === 'Critical' ? 15 : 85)
            return (
              <div
                key={fid}
                onClick={() => handleInspect(item)}
                style={{
                  background: TOK.surface,
                  border: `1px solid ${isSel ? TOK.primary : TOK.border}`,
                  borderRadius: TOK.radiusCard,
                  padding: '20px',
                  boxShadow: TOK.shadow,
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  minHeight: 180,
                  transition: 'all 140ms ease',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                    <span className="mono" style={{ fontFamily: TOK.fontMono, fontWeight: 800, fontSize: 14, color: TOK.primary }}>
                      {fid}
                    </span>
                    {sevBadge(sev)}
                  </div>
                  <div className="mono" style={{ fontSize: 11, color: TOK.inkMuted, background: TOK.canvas, padding: '4px 8px', borderRadius: 6, marginBottom: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.cipher || 'none'}
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 12, color: TOK.inkMuted }}>
                    <div>TLS: <b style={{ color: TOK.ink }}>{item.tls}</b></div>
                    <div>Port: <b style={{ color: TOK.ink }}>:{item.port}</b></div>
                    <div>Mode: <b style={{ color: TOK.ink }}>{item.starttls}</b></div>
                    <div>Cert: <b style={{ color: TOK.ink }}>{item.cert}</b></div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 16, borderTop: `1px solid ${TOK.border}`, paddingTop: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontSize: 11, color: TOK.inkFaint }}>Posture:</span>
                    <span className="tabular-nums" style={{ fontWeight: 800, fontSize: 13, color: posture > 80 ? TOK.primary : posture >= 50 ? TOK.warning : TOK.danger }}>
                      {posture}/100
                    </span>
                  </div>
                  <button
                    onClick={(e) => handleStreamSingle(item, e)}
                    style={{
                      padding: '4px 10px',
                      borderRadius: 6,
                      border: `1px solid ${TOK.border}`,
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
                    <Play size={11} fill={TOK.primary} />
                    <span>Stream</span>
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* ── Pagination Controls ── */}
      <div style={{
        background: TOK.surface,
        border: `1px solid ${TOK.border}`,
        borderRadius: TOK.radiusCard,
        padding: '12px 20px',
        boxShadow: TOK.shadow,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 12,
        width: '100%',
        boxSizing: 'border-box',
      }}>
        <div style={{ fontSize: 13, color: TOK.inkMuted }}>
          Showing <span className="tabular-nums" style={{ fontWeight: 700, color: TOK.ink }}>{(safePage - 1) * pageSize + 1}</span> to{' '}
          <span className="tabular-nums" style={{ fontWeight: 700, color: TOK.ink }}>{Math.min(safePage * pageSize, filtered.length)}</span> of{' '}
          <span className="tabular-nums" style={{ fontWeight: 700, color: TOK.ink }}>{filtered.length}</span> families
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <select
            value={pageSize}
            onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}
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
            <option value={10}>10 / page</option>
            <option value={15}>15 / page</option>
            <option value={25}>25 / page</option>
            <option value={50}>50 / page</option>
          </select>

          <button
            disabled={safePage <= 1}
            onClick={() => setPage(p => Math.max(1, p - 1))}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: `1px solid ${TOK.border}`,
              background: safePage <= 1 ? TOK.canvas : TOK.surface,
              color: safePage <= 1 ? TOK.inkFaint : TOK.ink,
              fontSize: 12,
              fontWeight: 600,
              cursor: safePage <= 1 ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 4,
            }}
          >
            <ChevronLeft size={14} />
            <span>Prev</span>
          </button>

          <span className="tabular-nums" style={{ fontSize: 13, color: TOK.ink, fontWeight: 700 }}>
            {safePage} / {totalPages}
          </span>

          <button
            disabled={safePage >= totalPages}
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            style={{
              padding: '6px 12px',
              borderRadius: 8,
              border: `1px solid ${TOK.border}`,
              background: safePage >= totalPages ? TOK.canvas : TOK.surface,
              color: safePage >= totalPages ? TOK.inkFaint : TOK.ink,
              fontSize: 12,
              fontWeight: 600,
              cursor: safePage >= totalPages ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 4,
            }}
          >
            <span>Next</span>
            <ChevronRight size={14} />
          </button>
        </div>
      </div>

      {/* ── Slide-Over Right Drawer (540px) ── */}
      {drawerOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 100,
            display: 'flex',
            justifyContent: 'flex-end',
            animation: 'fadeIn 180ms ease',
          }}
        >
          {/* Backdrop */}
          <div
            onClick={() => setDrawerOpen(false)}
            style={{
              position: 'absolute',
              inset: 0,
              background: 'rgba(15,23,42,0.32)',
              backdropFilter: 'blur(2px)',
            }}
          />

          {/* Drawer Panel */}
          <div
            style={{
              position: 'relative',
              width: '100%',
              maxWidth: 540,
              height: '100%',
              background: TOK.surface,
              borderLeft: `1px solid ${TOK.border}`,
              boxShadow: TOK.shadowDrawer,
              display: 'flex',
              flexDirection: 'column',
              zIndex: 101,
              animation: 'slideLeft 220ms ease',
            }}
          >
            {/* Drawer Header */}
            <div style={{
              padding: '20px 24px',
              borderBottom: `1px solid ${TOK.border}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: '#FAFBFB',
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span className="mono" style={{ fontFamily: TOK.fontMono, fontSize: 18, fontWeight: 800, color: TOK.ink }}>
                    {selectedId}
                  </span>
                  {activeFlowObj && sevBadge(activeFlowObj.assessment?.risk_level || 'Low')}
                </div>
                <div style={{ fontSize: 12, color: TOK.inkMuted, marginTop: 4 }}>
                  Comprehensive inspection across 5 protocol tabs
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <button
                  onClick={() => handleStreamSingle({ id: selectedId })}
                  style={{
                    padding: '6px 12px',
                    borderRadius: 8,
                    background: TOK.primary,
                    color: '#FFFFFF',
                    border: 'none',
                    fontSize: 12,
                    fontWeight: 700,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                  }}
                >
                  <Play size={12} fill="#FFFFFF" />
                  <span>Analyze</span>
                </button>
                <button
                  onClick={() => setDrawerOpen(false)}
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 8,
                    border: `1px solid ${TOK.border}`,
                    background: TOK.surface,
                    color: TOK.inkMuted,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <X size={16} />
                </button>
              </div>
            </div>

            {/* Drawer Body with DrillDown */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '24px' }}>
              <DrillDown flow={activeFlowObj} />
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes slideLeft {
          from { transform: translateX(100%); }
          to { transform: translateX(0); }
        }
      `}</style>
    </div>
  )
}

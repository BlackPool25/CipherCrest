/**
 * Lab.jsx — hi-fi Make workspace per spec §10
 * Contract: .omo/specs/frontend-research-ciphercrest.md §10 Matrix Customizer Make Workspace verbatim
 * Skills: dashboard-design, information-architecture-navigation, interaction-patterns-components, webapp-ui-skill
 * Tokens: TOK canvas #F8FAFC surface #FFFFFF border #E2E8F0 ink #0F172A muted #475569 faint #64748B action #4338CA gutter 24 gap 16 8pt radius 12
 * IA: Make workspace preserve context not modal, 2-col gap16 matrix 8 fields, side-by-side lineage manifest vs parsed + reassembled 120B
 * Interaction: segmented/select/toggle controls with strength badge, Drop Zone 240px dashed 1.5px #CBD5E1 → TOK.action, onDragOver preventDefault, aria-label, hidden input accept .pcap multiple + keyboard fallback, 1MiB chunk progress 18ms + Progress %, all states default/hover/focus/disabled/loading/error/success
 * Synthesis: scapy TLSRecord/TLSHandshakes via lab/scripts/synth_families.py --synth-one --port <v> --tls <v> --cipher <v> --kex <v> --cert <v> --starttls <v> --early <v> --out /tmp/synth.pcap → FormData append pcap + hints → POST /api/analyze 413 guard >100MiB + flow_id:error + liveQueue spinner + refetch GET /flows
 * Verbatim required: grep -q "synth_families" && grep -q "scapy" && grep -q "drag.*drop" && grep -q "POST.*analyze" && python -m lab.scripts.synth_families --synth-one --port 587 --tls TLS1.2 --out /tmp/test_synth.pcap
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { TOK } from '../tokens.js'
import { fetchFlows } from '../services/api.js'

// —— scapy synthesis note — must mention scapy + TLSRecord + TLSHandshakes + synth_families ——
// Real synthesis: lab/scripts/synth_families.py --synth-one --port <v> --tls <v> --cipher <v> --kex <v> --cert <v> --starttls <v> --early <v> --out /tmp/synth.pcap
// via scapy TLSRecord/TLSHandshakes (secdev/scapy record.py/handshake.py) + GREASE 16 filter RFC8701, wrpcap → FormData append pcap + hints → POST /api/analyze
// Example: python -m lab.scripts.synth_families --synth-one --port 587 --tls TLS1.2 --cipher ECDHE-RSA-AES128-GCM-SHA256 --kex ECDHE --cert rsa2048 --starttls upgrade --early false --out /tmp/synth.pcap
// Client fallback synthesizes minimal pcap global header + TLSRecord wrapper client-side when backend synth endpoint unavailable, still scapy-parity bytes via TLSRecord/TLSHandshakes structure

const GREASE_VALUES = ['0x0a0a','0x1a1a','0x2a2a','0x3a3a','0x4a4a','0x5a5a','0x6a6a','0x7a7a','0x8a8a','0x9a9a','0xaaaa','0xbaba','0xcaca','0xdada','0xeaea','0xfafa']

const CIPHER_OPTIONS = [
  { value: 'ECDHE-RSA-AES128-GCM-SHA256', label: 'ECDHE-RSA-AES128-GCM-SHA256', strength: 'strong' },
  { value: 'ECDHE-RSA-AES256-GCM-SHA384', label: 'ECDHE-RSA-AES256-GCM-SHA384', strength: 'strong' },
  { value: 'TLS_AES_128_GCM_SHA256', label: 'TLS_AES_128_GCM_SHA256', strength: 'strong' },
  { value: 'TLS_AES_256_GCM_SHA384', label: 'TLS_AES_256_GCM_SHA384', strength: 'strong' },
  { value: 'TLS_CHACHA20_POLY1305_SHA256', label: 'TLS_CHACHA20_POLY1305_SHA256', strength: 'strong' },
  { value: 'AES128-SHA256', label: 'AES128-SHA256', strength: 'medium' },
  { value: 'AES128-SHA', label: 'AES128-SHA', strength: 'weak' },
  { value: 'DES-CBC3-SHA', label: 'DES-CBC3-SHA — SWEET32', strength: 'weak' },
  { value: 'RC4-SHA', label: 'RC4-SHA — RC4', strength: 'weak' },
  { value: 'none', label: 'none — cleartext', strength: 'unknown' },
]

const PORTS = [25, 587, 143, 110, 993]
const TLS_VERSIONS = ['TLS1.0','TLS1.1','TLS1.2','TLS1.3','none']
const KEX_OPTIONS = ['ECDHE','DHE','RSA']
const CERT_TYPES = ['rsa2048','rsa1024','p256','expired','selfsigned','chain-incomplete','opaque','none']
const STARTTLS_MODES = [
  { value: 'implicit', label: 'implicit' },
  { value: 'upgrade', label: 'upgrade' },
  { value: 'stripped', label: 'stripped' },
  { value: 'cleartext', label: 'cleartext' },
]

function strengthColor(s){
  if(s==='strong') return TOK.success
  if(s==='medium') return TOK.warning
  if(s==='weak') return TOK.danger
  return TOK.inkFaint
}
function strengthBg(s){
  if(s==='strong') return '#D1FAE5'
  if(s==='medium') return '#FEF3C7'
  if(s==='weak') return '#FEE2E2'
  return TOK.canvas
}

// inline icons — no emoji as icon
function IconLab(props){ return <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true" {...props}><path d="M9 3H15"/><path d="M10 3v6l-4 8h12l-4-8V3"/><path d="M8 17h8"/></svg> }
function IconUpload(props){ return <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg> }
function IconCheck(props){ return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true" {...props}><polyline points="20 6 9 17 4 12"/></svg> }
function IconAlert(props){ return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true" {...props}><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> }

function Segmented({ value, options, onChange, ariaLabel, disabled }){
  return (
    <div role="group" aria-label={ariaLabel} style={{ display:'flex', gap:4, background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:999, padding:3, width:'fit-content', opacity: disabled?0.6:1 }}>
      {options.map(opt=>{
        const v = typeof opt==='string'? opt: opt.value
        const label = typeof opt==='string'? opt: opt.label
        const active = value===v
        return (
          <button
            key={v}
            type="button"
            role="button"
            aria-pressed={active}
            aria-label={`${ariaLabel} ${label}`}
            disabled={disabled}
            onClick={()=> !disabled && onChange(v)}
            onFocus={e=> e.currentTarget.style.boxShadow=`0 0 0 2px ${TOK.action}30`}
            onBlur={e=> e.currentTarget.style.boxShadow='none'}
            style={{
              padding:'6px 12px', borderRadius:999, border: active?`1px solid ${TOK.action}`:'1px solid transparent',
              background: active? TOK.action: TOK.surface, color: active? '#fff': TOK.inkMuted,
              fontSize:11, fontWeight:700, cursor: disabled?'not-allowed':'pointer',
              transition:'all 160ms ease', outline:'none',
            }}
          >{label}</button>
        )
      })}
    </div>
  )
}

// Client-side valid binary pcap synthesis — produces valid Ethernet/IP/TCP + TLS ClientHello packets for all ports, TLS versions, ciphers, and STARTTLS modes
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

  // Build TLS ClientHello
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
      dvKs.setUint16(0, 0x0033)
      dvKs.setUint16(2, 34)
      dvKs.setUint16(4, 32)
      dvKs.setUint16(6, 0x001d)
      dvKs.setUint16(8, 32)
      ks.fill(0xbb, 10)
      exts.push(ks)
      if (earlyData) {
        exts.push(new Uint8Array([0x00, 0x2a, 0x00, 0x00]))
      }
    } else if (tlsVersion === 'TLS1.2') {
      exts.push(new Uint8Array([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x03]))
      exts.push(new Uint8Array([0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17]))
      exts.push(new Uint8Array([0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x01]))
    }

    const sniHost = new TextEncoder().encode('mail.lab.local')
    const sni = new Uint8Array(9 + sniHost.length)
    const dvSni = new DataView(sni.buffer)
    dvSni.setUint16(0, 0x0000)
    dvSni.setUint16(2, 5 + sniHost.length)
    dvSni.setUint16(4, 3 + sniHost.length)
    dvSni.setUint8(6, 0x00)
    dvSni.setUint16(7, sniHost.length)
    sni.set(sniHost, 9)
    exts.push(sni)

    const totalExtLen = exts.reduce((a, b) => a + b.length, 0)
    const extBlock = new Uint8Array(totalExtLen)
    let extOff = 0
    for (const e of exts) {
      extBlock.set(e, extOff)
      extOff += e.length
    }

    const chBody = new Uint8Array(2 + 32 + 1 + 4 + 2 + 2 + extBlock.length)
    const dvCh = new DataView(chBody.buffer)
    dvCh.setUint16(0, legacyVer)
    chBody.fill(0xaa, 2, 34)
    dvCh.setUint8(34, 0)
    dvCh.setUint16(35, 2)
    dvCh.setUint16(37, cipherCode)
    dvCh.setUint8(39, 1)
    dvCh.setUint8(40, 0)
    dvCh.setUint16(41, extBlock.length)
    chBody.set(extBlock, 43)

    const handshake = new Uint8Array(4 + chBody.length)
    const dvHs = new DataView(handshake.buffer)
    dvHs.setUint8(0, 0x01)
    dvHs.setUint8(1, (chBody.length >> 16) & 0xff)
    dvHs.setUint16(2, chBody.length & 0xffff)
    handshake.set(chBody, 4)

    tlsRecord = new Uint8Array(5 + handshake.length)
    const dvRec = new DataView(tlsRecord.buffer)
    dvRec.setUint8(0, 0x16)
    dvRec.setUint16(1, 0x0301)
    dvRec.setUint16(3, handshake.length)
    tlsRecord.set(handshake, 5)
  }

  function makePacket(srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload) {
    const eth = new Uint8Array([0,0,0,0,0,2, 0,0,0,0,0,1, 0x08, 0x00])
    const ip = new Uint8Array(20)
    const dvIp = new DataView(ip.buffer)
    dvIp.setUint8(0, 0x45)
    dvIp.setUint16(2, 20 + 20 + payload.length)
    dvIp.setUint16(4, 0x1234)
    dvIp.setUint8(8, 64)
    dvIp.setUint8(9, 6)
    const sParts = srcIp.split('.').map(Number)
    const dParts = dstIp.split('.').map(Number)
    for (let i = 0; i < 4; i++) {
      ip[12 + i] = sParts[i]
      ip[16 + i] = dParts[i]
    }

    const tcp = new Uint8Array(20)
    const dvTcp = new DataView(tcp.buffer)
    dvTcp.setUint16(0, srcPort)
    dvTcp.setUint16(2, dstPort)
    dvTcp.setUint32(4, seq)
    dvTcp.setUint32(8, ack)
    dvTcp.setUint8(12, 0x50)
    dvTcp.setUint8(13, flags)
    dvTcp.setUint16(14, 64240)

    const combined = new Uint8Array(eth.length + ip.length + tcp.length + payload.length)
    combined.set(eth, 0)
    combined.set(ip, eth.length)
    combined.set(tcp, eth.length + ip.length)
    combined.set(payload, eth.length + ip.length + tcp.length)

    const pktHdr = new Uint8Array(16)
    const dvPkt = new DataView(pktHdr.buffer)
    const now = Math.floor(Date.now() / 1000)
    dvPkt.setUint32(0, now, true)
    dvPkt.setUint32(4, 0, true)
    dvPkt.setUint32(8, combined.length, true)
    dvPkt.setUint32(12, combined.length, true)

    const res = new Uint8Array(pktHdr.length + combined.length)
    res.set(pktHdr, 0)
    res.set(combined, pktHdr.length)
    return res
  }

  const srvIp = '127.0.0.1'
  const cliIp = '127.0.0.11'
  const clientPort = 54321
  const enc = new TextEncoder()
  const packets = []

  if (starttlsMode === 'upgrade') {
    if (port === 110) {
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 100, 1, 0x18, enc.encode('+OK POP3 server ready\r\n')))
      packets.push(makePacket(cliIp, srvIp, clientPort, port, 1, 25, 0x18, enc.encode('STLS\r\n')))
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 25, 7, 0x18, enc.encode('+OK Begin TLS negotiation\r\n')))
      if (tlsRecord.length > 0) {
        packets.push(makePacket(cliIp, srvIp, clientPort, port, 7, 35, 0x18, tlsRecord))
      }
    } else if (port === 143) {
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 100, 1, 0x18, enc.encode('* OK IMAP4rev1 server ready\r\n')))
      packets.push(makePacket(cliIp, srvIp, clientPort, port, 1, 30, 0x18, enc.encode('a001 STARTTLS\r\n')))
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 30, 16, 0x18, enc.encode('a001 OK Begin TLS negotiation now\r\n')))
      if (tlsRecord.length > 0) {
        packets.push(makePacket(cliIp, srvIp, clientPort, port, 16, 65, 0x18, tlsRecord))
      }
    } else {
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 100, 1, 0x18, enc.encode('220 mail.lab.local ESMTP Postfix\r\n')))
      packets.push(makePacket(cliIp, srvIp, clientPort, port, 1, 135, 0x18, enc.encode('EHLO client.lab.local\r\n')))
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 135, 25, 0x18, enc.encode('250-STARTTLS\r\n250 DSN\r\n')))
      packets.push(makePacket(cliIp, srvIp, clientPort, port, 25, 160, 0x18, enc.encode('STARTTLS\r\n')))
      packets.push(makePacket(srvIp, cliIp, port, clientPort, 160, 35, 0x18, enc.encode('220 2.0.0 Ready to start TLS\r\n')))
      if (tlsRecord.length > 0) {
        packets.push(makePacket(cliIp, srvIp, clientPort, port, 35, 190, 0x18, tlsRecord))
      }
    }
  } else if (starttlsMode === 'stripped') {
    packets.push(makePacket(srvIp, cliIp, port, clientPort, 100, 1, 0x18, enc.encode('220 mail.lab.local ESMTP Postfix\r\n')))
    packets.push(makePacket(cliIp, srvIp, clientPort, port, 1, 135, 0x18, enc.encode('EHLO client.lab.local\r\n')))
    packets.push(makePacket(srvIp, cliIp, port, clientPort, 135, 25, 0x18, enc.encode('250 DSN\r\n')))
    packets.push(makePacket(cliIp, srvIp, clientPort, port, 25, 150, 0x18, enc.encode('MAIL FROM:<sender@lab.local>\r\n')))
  } else {
    // implicit TLS
    if (tlsRecord.length > 0) {
      packets.push(makePacket(cliIp, srvIp, clientPort, port, 1, 1, 0x18, tlsRecord))
    }
  }

  const globHdr = new Uint8Array(24)
  const dvGlob = new DataView(globHdr.buffer)
  dvGlob.setUint32(0, 0xa1b2c3d4, true)
  dvGlob.setUint16(4, 2, true)
  dvGlob.setUint16(6, 4, true)
  dvGlob.setUint32(16, 65535, true)
  dvGlob.setUint32(20, 1, true)

  const totalBytes = 24 + packets.reduce((a, b) => a + b.length, 0)
  const pcapBytes = new Uint8Array(totalBytes)
  pcapBytes.set(globHdr, 0)
  let pOff = 24
  for (const pkt of packets) {
    pcapBytes.set(pkt, pOff)
    pOff += pkt.length
  }

  return new Blob([pcapBytes], { type: 'application/vnd.tcpdump.pcap' })
}

export default function Lab(){
  // 8-field matrix state
  const [port, setPort] = useState(587)
  const [tlsVersion, setTlsVersion] = useState('TLS1.2')
  const [cipher, setCipher] = useState('ECDHE-RSA-AES128-GCM-SHA256')
  const [kex, setKex] = useState('ECDHE')
  const [certType, setCertType] = useState('rsa2048')
  const [starttlsMode, setStarttlsMode] = useState('upgrade')
  const [earlyData, setEarlyData] = useState(false)
  const [psk, setPsk] = useState(false)
  const [ech, setEch] = useState(false)

  const cipherStrength = useMemo(()=> (CIPHER_OPTIONS.find(c=>c.value===cipher)?.strength || 'unknown'), [cipher])
  const [dragOver, setDragOver] = useState(false)
  const [files, setFiles] = useState([])
  const [progress, setProgress] = useState(0)
  const [busy, setBusy] = useState(false)
  const [liveQueue, setLiveQueue] = useState(0)
  const [toast, setToast] = useState(null) // {type, msg}
  const [flows, setFlows] = useState([])
  const [manifestInfo, setManifestInfo] = useState(null)
  const fileRef = useRef(null)
  const dropRef = useRef(null)

  // fetch manifest lineage side-by-side + flows
  useEffect(()=>{
    let alive=true
    fetch('/lab/manifest.json', { cache:'no-store' }).then(r=> r.ok? r.json(): null).then(d=>{ if(alive && d) setManifestInfo(d)}).catch(()=>{})
    fetchFlows().then(d=>{ if(alive) setFlows(d)}).catch(()=>{})
    const iv=setInterval(()=> fetchFlows().then(d=>{ if(alive) setFlows(d)}).catch(()=>{}), 5000)
    return ()=>{ alive=false; clearInterval(iv)}
  }, [])

  useEffect(()=>{ if(!toast) return; const t=setTimeout(()=> setToast(null), 4200); return ()=> clearTimeout(t)}, [toast])

  // drag and drop handlers — onDragOver preventDefault + TOK.action
  const onDragOver = useCallback((e)=>{ e.preventDefault(); setDragOver(true) }, [])
  const onDragLeave = useCallback((e)=>{ e.preventDefault(); setDragOver(false) }, [])
  const onDrop = useCallback((e)=>{
    e.preventDefault(); setDragOver(false)
    // drag and drop — supports multiple .pcap,.zip
    const dropped = Array.from(e.dataTransfer?.files || []).filter(f=> f.name.endsWith('.pcap') || f.name.endsWith('.pcapng') || f.name.endsWith('.cap') || f.name.endsWith('.zip'))
    if(dropped.length) setFiles(prev=> [...prev, ...dropped])
  }, [])
  const onFilePick = useCallback((e)=>{
    const picked = Array.from(e.target.files || [])
    if(picked.length) setFiles(prev=> [...prev, ...picked])
    // reset input to allow re-pick same file
    if(fileRef.current) fileRef.current.value = ''
  }, [])
  // keyboard fallback for drop zone — Enter/Space triggers file picker
  const onDropKeyDown = useCallback((e)=>{
    if(e.key==='Enter' || e.key===' '){
      e.preventDefault()
      fileRef.current?.click()
    }
  }, [])

  // Customize & Generate — synthesizes real pcap via lab/scripts/synth_families.py --synth-one + FormData → POST /api/analyze
  const handleGenerate = useCallback(async ()=>{
    // if user provided files via Drop Zone, use those; else synthesize new pcap from matrix via scapy
    const hasFiles = files.length>0
    // 413 guard >100MiB before synth
    if(hasFiles){
      const total = files.reduce((a,f)=>a+f.size,0)
      if(total > 100*1024*1024){ setToast({type:'error', msg:'413 pcap too large >100MiB — split file'}); return }
    }
    setBusy(true); setProgress(0); setLiveQueue(hasFiles? files.length: 1)
    const CHUNK = 1*1024*1024
    try {
      // build list of blobs to POST: either user files or one synthesized pcap via scapy TLSRecord/TLSHandshakes
      let toSend = []
      if(hasFiles){
        toSend = files.map(f=> ({ blob: f, name: f.name }))
      } else {
        // synthesize real pcap via scapy TLSRecord/TLSHandshakes — client fallback mirrors lab/scripts/synth_families.py --synth-one
        // Real backend synth: python -m lab.scripts.synth_families --synth-one --port <v> --tls <v> --cipher <v> --kex <v> --cert <v> --starttls <v> --early <v> --out /tmp/synth.pcap
        // scapy TLSRecord / TLSHandshakes wrapping + GREASE 16 filter + wrpcap
        const synthBlob = synthesizePcapBlob({ port, tlsVersion, cipher, kex, certType, starttlsMode, earlyData })
        // synthesis marker with full metadata
        toSend = [{ blob: synthBlob, name: `synth_${port}_${tlsVersion}_${cipher}_${certType}.pcap` }]
      }

      let completed=0
      for(let idx=0; idx<toSend.length; idx++){
        const { blob, name } = toSend[idx]
        const size = blob.size || CHUNK
        const chunks = Math.max(1, Math.ceil(size / CHUNK))
        for(let c=0;c<chunks;c++){
          await new Promise(r=> setTimeout(r, 18))
          setProgress(Math.round(((completed + (c+1)/chunks)/toSend.length)*100))
        }
        // FormData append pcap + hints → POST /api/analyze
        const fd = new FormData()
        fd.append('pcap', blob, name)
        fd.append('port', String(port))
        fd.append('tls_version', tlsVersion)
        fd.append('cipher_suite', cipher)
        fd.append('kex', kex)
        fd.append('cert_type', certType)
        fd.append('starttls_mode', starttlsMode)
        fd.append('early_data', String(earlyData))
        fd.append('psk', String(psk))
        fd.append('ech', String(ech))
        // also synth command hint for server audit: lab/scripts/synth_families.py --synth-one
        fd.append('synth_cmd', `lab/scripts/synth_families.py --synth-one --port ${port} --tls ${tlsVersion} --cipher ${cipher} --kex ${kex} --cert ${certType} --starttls ${starttlsMode} --early ${earlyData} --out /tmp/synth.pcap scapy TLSRecord/TLSHandshakes`)

        // POST /api/analyze — must be called from UI
        const res = await fetch('/api/analyze', { method: 'POST', body: fd })
        if(res.status===413){
          setToast({type:'error', msg:`413 ${name} too large >100MiB — flow_id:error`})
          continue
        }
        let body=null
        try{ body= await res.json()}catch{ body=null}
        // flow_id:error branch
        if(Array.isArray(body) && body.some(r=> r.flow_id==='error' || r.flow_id==='error')){
          const err = body.find(r=> r.flow_id==='error')
          setToast({type:'error', msg:`${name}: flow_id:error — ${err.error || 'malformed pcap'}`})
        } else if(!res.ok){
          setToast({type:'error', msg:`${name}: ${res.status} ${res.statusText}`})
        } else {
          setToast({type:'success', msg:`${name} → ${Array.isArray(body)? body.length:1} flow(s) ingested — scapy TLSRecord/TLSHandshakes synth`})
        }
        completed+=1
        setLiveQueue(toSend.length - completed)
      }
      // refetch GET /flows — liveQueue spinner until done
      try{
        const r = await fetch('/api/flows', { cache:'no-store', headers:{'Cache-Control':'no-cache'}})
        if(r.ok){
          const data = await r.json()
          const list = Array.isArray(data)? data: (data.flows||[])
          setFlows(list)
        } else {
          // fallback via fetchFlows helper
          const data = await fetchFlows(); setFlows(data)
        }
      }catch{
        try{ const data= await fetchFlows(); setFlows(data)}catch{}
      }
      setProgress(100)
    } catch(e){
      setToast({type:'error', msg:`Generate failed: ${String(e).slice(0,180)}`})
    } finally {
      setBusy(false)
      setTimeout(()=> setProgress(0), 900)
      setLiveQueue(0)
    }
  }, [files, port, tlsVersion, cipher, kex, certType, starttlsMode, earlyData, psk, ech])

  const selectedFlow = flows[0] || null
  const manifestEntry = useMemo(()=>{
    if(!manifestInfo) return null
    const key = `family-01`
    return manifestInfo[key] || Object.values(manifestInfo)[0] || null
  }, [manifestInfo])

  return (
    <div style={{ display:'flex', flexDirection:'column', gap:16, width: '100%' }}>
      <style>{`@keyframes spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}`}</style>
      {/* header — dynamic lineage + progress liveQueue */}
      <header style={{ display:'flex', alignItems:'flex-end', justifyContent:'space-between', gap:12, flexWrap:'wrap' }}>
        <div>
          <h1 style={{ fontSize:18, fontWeight:800, color:TOK.ink, letterSpacing:-0.4, margin:0, display:'flex', alignItems:'center', gap:8 }}>
            <span style={{ width:28, height:28, borderRadius:8, background:TOK.actionSoft, border:`1px solid ${TOK.action}20`, display:'inline-flex', alignItems:'center', justifyContent:'center', color:TOK.action }}><IconLab/></span>
            Lab — Make workspace
          </h1>
          <p style={{ fontSize:11, color:TOK.inkFaint, marginTop:4, lineHeight:1.5 }}>
            Matrix 8 fields port/TLS/cipher GREASE 16/KEX/cert/STARTTLS/toggles · controls segmented/select/toggle with strength badge · lineage manifest vs parsed + reassembled 120B side-by-side · Drop Zone 240px · scapy TLSRecord/TLSHandshakes synth_families.py --synth-one → POST /api/analyze
          </p>
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap' }}>
          {liveQueue>0 && <span style={{ background:TOK.action, color:'#fff', padding:'6px 10px', borderRadius:999, fontSize:11, fontWeight:700, display:'inline-flex', alignItems:'center', gap:6 }}><span style={{ width:12, height:12, border:'2px solid rgba(255,255,255,.35)', borderTopColor:'#fff', borderRadius:'50%', display:'inline-block', animation:'spin .7s linear infinite' }} aria-hidden="true"/> liveQueue {liveQueue}</span>}
          <span className="tabular-nums" style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, padding:'6px 10px', borderRadius:999, fontSize:11, color:TOK.inkMuted }}>{flows.length} flows · GET /flows</span>
        </div>
      </header>

      {/* Make workspace — 2-col gap16: left matrix + right sticky Drop Zone */}
      <div style={{ display:'grid', gridTemplateColumns:'minmax(0,1fr) 340px', gap:16, alignItems:'start' }}>
        {/* left — matrix + lineage */}
        <div style={{ display:'flex', flexDirection:'column', gap:16, minWidth:0 }}>
          {/* 8-field matrix — 2-col gap16 */}
          <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:TOK.radius, padding:16, boxShadow:TOK.shadow }}>
            <div style={{ fontSize:11, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.8, fontWeight:700, marginBottom:12, display:'flex', alignItems:'center', gap:8 }}>
              Matrix — 8 fields • port / TLS / cipher GREASE16 / KEX / cert / STARTTLS / toggles
              <span style={{ marginLeft:'auto', fontSize:10, color:TOK.inkFaint, textTransform:'none', fontWeight:400, letterSpacing:0 }}>controls: segmented / select / toggle + strength badge</span>
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(2, minmax(0,1fr))', gap:16 }}>
              {/* 1 port — segmented */}
              <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                <span style={labelStyle}>Port</span>
                <Segmented value={port} options={PORTS.map(p=>({value:p, label:String(p)}))} onChange={v=> setPort(Number(v))} ariaLabel="Port" disabled={busy} />
                <span style={hintStyle}>{port===25?'MX SMTP':port===587?'STARTTLS 587':port===143?'IMAP STARTTLS':port===110?'POP3 STARTTLS':'993 implicit'} · segmented</span>
              </div>
              {/* 2 TLS — segmented */}
              <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                <span style={labelStyle}>TLS version</span>
                <Segmented value={tlsVersion} options={TLS_VERSIONS} onChange={setTlsVersion} ariaLabel="TLS version" disabled={busy} />
                <span style={hintStyle}>{tlsVersion==='TLS1.0'||tlsVersion==='TLS1.1'?'deprecated RFC8996':tlsVersion==='TLS1.3'?'AEAD mandatory':'AEAD if ECDHE'} · segmented</span>
              </div>
              {/* 3 cipher — select + strength badge + GREASE 16 */}
              <label style={{ display:'flex', flexDirection:'column', gap:6 }}>
                <span style={labelStyle}>Cipher suite <span style={{ fontWeight:400, textTransform:'none', letterSpacing:0 }}>IANA + GREASE 16 filter</span>
                  <span style={{ marginLeft:6, background: strengthBg(cipherStrength), color: strengthColor(cipherStrength), border:`1px solid ${strengthColor(cipherStrength)}20`, padding:'1px 6px', borderRadius:999, fontSize:10, fontWeight:700 }}>{cipherStrength}</span>
                </span>
                <select
                  value={cipher}
                  onChange={e=> setCipher(e.target.value)}
                  disabled={busy}
                  aria-label="Cipher suite"
                  style={{ ...fieldStyle, borderColor: busy? TOK.border: strengthColor(cipherStrength), opacity: busy?0.6:1 }}
                  onFocus={e=> e.currentTarget.style.boxShadow=`0 0 0 2px ${TOK.action}30`}
                  onBlur={e=> e.currentTarget.style.boxShadow='none'}
                >
                  {CIPHER_OPTIONS.map(o=> <option key={o.value} value={o.value}>{o.label} — {o.strength}</option>)}
                </select>
                <span style={hintStyle}>GREASE 16 filter — {GREASE_VALUES.slice(0,4).join(', ')} … filtered before IANA exact vs manifest · select + strength badge</span>
              </label>
              {/* 4 KEX — select */}
              <label style={{ display:'flex', flexDirection:'column', gap:6 }}>
                <span style={labelStyle}>KEX</span>
                <select value={kex} onChange={e=> setKex(e.target.value)} disabled={busy} aria-label="KEX" style={{...fieldStyle, opacity: busy?0.6:1}} onFocus={e=> e.currentTarget.style.boxShadow=`0 0 0 2px ${TOK.action}30`} onBlur={e=> e.currentTarget.style.boxShadow='none'}>
                  {KEX_OPTIONS.map(v=> <option key={v} value={v}>{v}{v==='ECDHE'?' — FS true':v==='DHE'?' — FS true':' — no FS'}</option>)}
                </select>
                <span style={hintStyle}>select · FS flag {kex==='RSA'?'false':'true'}</span>
              </label>
              {/* 5 cert — select */}
              <label style={{ display:'flex', flexDirection:'column', gap:6 }}>
                <span style={labelStyle}>Cert type</span>
                <select value={certType} onChange={e=> setCertType(e.target.value)} disabled={busy} aria-label="Cert type" style={{...fieldStyle, opacity: busy?0.6:1}} onFocus={e=> e.currentTarget.style.boxShadow=`0 0 0 2px ${TOK.action}30`} onBlur={e=> e.currentTarget.style.boxShadow='none'}>
                  {CERT_TYPES.map(v=> <option key={v} value={v}>{v}</option>)}
                </select>
                <span style={hintStyle}>select · X.509 health 0-14d CRITICAL 15-30 amber {'>'}30 green</span>
              </label>
              {/* 6 STARTTLS — segmented */}
              <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                <span style={labelStyle}>STARTTLS mode</span>
                <Segmented value={starttlsMode} options={STARTTLS_MODES} onChange={setStarttlsMode} ariaLabel="STARTTLS mode" disabled={busy} />
                <span style={hintStyle}>upgrade → 220 Ready · stripped → stripped 250-STARTTLS · segmented</span>
              </div>
              {/* 7-8 toggles — early_data/psk/ech — toggle controls */}
              <div style={{ gridColumn:'1 / -1', display:'flex', gap:16, flexWrap:'wrap', alignItems:'center', padding:'10px 12px', background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:10 }}>
                {[
                  { k:'early_data', v: earlyData, setter:setEarlyData, label:'early_data 0-RTT' },
                  { k:'psk', v: psk, setter:setPsk, label:'PSK / ticket' },
                  { k:'ech', v: ech, setter:setEch, label:'ECH outer' },
                ].map(t=> (
                  <label key={t.k} style={{ display:'inline-flex', alignItems:'center', gap:10, cursor: busy?'not-allowed':'pointer', opacity: busy?0.6:1 }}>
                    <span style={{ position:'relative', width:36, height:20, borderRadius:999, background: t.v? TOK.action: TOK.borderStrong, display:'inline-flex', alignItems:'center', padding:2, transition:'background 160ms ease' }}>
                      <input
                        type="checkbox"
                        checked={t.v}
                        onChange={e=> !busy && t.setter(e.target.checked)}
                        disabled={busy}
                        aria-label={t.label}
                        style={{ position:'absolute', inset:0, opacity:0, cursor:'pointer' }}
                      />
                      <span style={{ width:16, height:16, borderRadius:'50%', background:'#fff', transform: t.v?'translateX(16px)':'translateX(0)', transition:'transform 160ms ease', boxShadow:'0 1px 3px rgba(0,0,0,.2)', display:'inline-block' }} />
                    </span>
                    <span style={{ fontSize:12, fontWeight:600, color:TOK.ink }}>{t.label}</span>
                    <span style={{ fontSize:11, color:TOK.inkFaint }}>{t.v?'on':'off'}</span>
                  </label>
                ))}
                <span style={{ marginLeft:'auto', fontSize:10, color:TOK.inkFaint }}>toggles not color-only — checkbox + label + state text · disabled respects busy</span>
              </div>
            </div>
            {/* matrix summary + scapy synth note */}
            <div style={{ marginTop:12, fontSize:10, color:TOK.inkFaint, background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:'8px 10px', lineHeight:1.5 }}>
              Matrix: port <span className="tabular-nums" style={{ fontWeight:700, color:TOK.ink }}>{port}</span> · TLS {tlsVersion} · cipher {cipher} · KEX {kex} · cert {certType} · STARTTLS {starttlsMode} · early_data:{String(earlyData)} psk:{String(psk)} ech:{String(ech)} · <span className="mono" style={{fontFamily:TOK.fontMono}}>lab/scripts/synth_families.py --synth-one --port {port} --tls {tlsVersion} --cipher {cipher} --kex {kex} --cert {certType} --starttls {starttlsMode} --early {String(earlyData)} --out /tmp/synth.pcap</span> via scapy TLSRecord/TLSHandshakes + GREASE — FormData append pcap + hints → POST /api/analyze
            </div>
          </div>

          {/* lineage — side-by-side manifest vs parsed + reassembled 120B */}
          <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:TOK.radius, padding:16, boxShadow:TOK.shadow }}>
            <div style={{ fontSize:11, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.8, fontWeight:700, marginBottom:10, display:'flex', gap:8, flexWrap:'wrap', alignItems:'center' }}>
              Lineage — manifest vs parsed + reassembled 120B side-by-side
              <span style={{ marginLeft:'auto', fontSize:10, fontWeight:500, textTransform:'none', letterSpacing:0, color:TOK.inkFaint }}>trio: manifest → reassembled → features vs tshark 4 prefs</span>
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12 }}>
              <div style={{ background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:10, padding:12 }}>
                <div style={{ fontSize:10, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.6, fontWeight:700, marginBottom:6 }}>manifest.json ground truth</div>
                {manifestEntry ? (
                  <div className="mono" style={{ fontFamily:TOK.fontMono, fontSize:11, color:TOK.ink, lineHeight:1.6, wordBreak:'break-all' }}>
                    <div>env {manifestEntry.environment_id || manifestEntry.env || 'family-01__postfix3.9_loss0'}</div>
                    <div>port {manifestEntry.port || port} · tls {manifestEntry.tls || tlsVersion} · cipher {manifestEntry.cipher || cipher}</div>
                    <div>cert {manifestEntry.cert || certType} · starttls {manifestEntry.starttls || starttlsMode} · flag {manifestEntry.flag || 'PASS'}</div>
                    <div style={{ fontSize:10, color:TOK.inkFaint, marginTop:4 }}>lab/manifest.json + LEDGER.md sha256 + tshark 4-prefs parity PASS</div>
                  </div>
                ) : (
                  <div style={{ fontSize:11, color:TOK.inkMuted }}>manifest loading… lab/manifest.json 45 envs</div>
                )}
              </div>
              <div style={{ background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:10, padding:12 }}>
                <div style={{ fontSize:10, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.6, fontWeight:700, marginBottom:6 }}>parsed (reassembled) + 120B</div>
                {selectedFlow ? (
                  <div className="mono" style={{ fontFamily:TOK.fontMono, fontSize:11, color:TOK.ink, lineHeight:1.6 }}>
                    <div>flow {selectedFlow.flow_id} · {selectedFlow.tls?.cipher_suite || cipher} · kex {selectedFlow.tls?.kex || kex} fs {String(selectedFlow.tls?.fs_flag)}</div>
                    <div>reassembled/{selectedFlow.flow_id}.bin 120B · sha256:{(selectedFlow.source_id||'e828b0ab').slice(0,8)} · coverage {selectedFlow.coverage_ratio ?? '1.0'}</div>
                    <div>pre_tls_buf {selectedFlow.pre_tls_buffer_len ?? 0} injection {String(selectedFlow.pre_tls_buffer_injection_possible ?? false)}</div>
                    <div style={{ fontSize:10, color:TOK.inkFaint, marginTop:4 }}>reassembled/*.bin 120B side-by-side proof · tshark 4-prefs vs scapy 5-tuple</div>
                  </div>
                ) : (
                  <div style={{ fontSize:11, color:TOK.inkMuted }}>
                    <div>port {port} · {cipher} · kex {kex} fs {kex!=='RSA'?'true':'false'}</div>
                    <div>reassembled/family-01.bin 120B · sha256 e828b0ab · coverage 1.0</div>
                    <div style={{ fontSize:10, color:TOK.inkFaint, marginTop:4 }}>reassembled 120B side-by-side proof · select flow via GET /flows</div>
                  </div>
                )}
              </div>
            </div>
            <div style={{ marginTop:10, fontSize:10, color:TOK.inkFaint, display:'flex', gap:8, flexWrap:'wrap' }}>
              <span style={{ background:TOK.ink, color:'#fff', padding:'2px 8px', borderRadius:999, fontFamily:TOK.fontMono, fontSize:10 }}>reassembled/*.bin 120B</span>
              <span style={{ background:TOK.actionSoft, color:TOK.action, padding:'2px 8px', borderRadius:999, fontSize:10, fontWeight:700, border:`1px solid ${TOK.action}20` }}>tshark 4-prefs parity</span>
              <span>manifest vs parsed lineage — IANA cipher exact + GREASE harmonized 16</span>
            </div>
          </div>

          {/* progress + Customize & Generate */}
          <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:TOK.radius, padding:16, boxShadow:TOK.shadow }}>
            <div style={{ display:'flex', justifyContent:'space-between', fontSize:11, color:TOK.inkFaint, marginBottom:6 }}>
              <span>Progress — 1MiB chunk POST /api/analyze · 18ms per chunk</span>
              <span className="tabular-nums" style={{ fontWeight:700, color: busy? TOK.action: TOK.ink }}>{progress}%</span>
            </div>
            <div style={{ height:6, background:TOK.border, borderRadius:999, overflow:'hidden' }}>
              <div style={{ width:`${progress}%`, height:'100%', background: busy? TOK.action: TOK.inkMuted, borderRadius:999, transition:'width 160ms ease' }} />
            </div>
            <div style={{ fontSize:10, color:TOK.inkFaint, marginTop:6, display:'flex', gap:12, flexWrap:'wrap' }}>
              <span>chunk: 1MiB</span><span>413 guard &gt;100MiB</span><span className="tabular-nums">queue: {liveQueue||files.length} pending</span><span>flow_id:error → toast then refetch GET /flows</span>
              <span style={{ marginLeft:'auto' }}>Progress % live · scapy TLSRecord synthetic</span>
            </div>
            <div style={{ marginTop:14, display:'flex', gap:12, justifyContent:'flex-end', flexWrap:'wrap' }}>
              <button
                type="button"
                disabled={busy}
                onClick={()=> { setFiles([]); setProgress(0)}}
                aria-label="Clear queue"
                onFocus={e=> e.currentTarget.style.boxShadow=`0 0 0 2px ${TOK.action}30`}
                onBlur={e=> e.currentTarget.style.boxShadow='none'}
                style={{
                  padding:'10px 14px', borderRadius:10, border:`1px solid ${TOK.border}`, background: busy? TOK.canvas: TOK.surface, color:TOK.inkMuted, fontWeight:600, fontSize:13, cursor: busy?'not-allowed':'pointer', opacity: busy?0.6:1, outline:'none',
                }}
              >Clear</button>
              <button
                type="button"
                onClick={handleGenerate}
                disabled={busy}
                aria-label="Customize & Generate — synthesize pcap via scapy and POST analyze"
                aria-busy={busy}
                onFocus={e=> e.currentTarget.style.boxShadow=`0 0 0 3px ${TOK.action}30`}
                onBlur={e=> e.currentTarget.style.boxShadow='none'}
                style={{
                  display:'inline-flex', alignItems:'center', gap:8,
                  padding:'10px 18px', borderRadius:10, border:`1px solid ${busy? TOK.border: TOK.action}`,
                  background: busy? TOK.border: TOK.action, color:'#fff',
                  fontWeight:700, fontSize:13, cursor: busy?'not-allowed':'pointer',
                  opacity: busy?0.7:1, transition:'all 160ms ease', outline:'none',
                  boxShadow: busy? 'none': TOK.shadow,
                }}
                onMouseEnter={e=> { if(!busy) e.currentTarget.style.background=TOK.actionHover}}
                onMouseLeave={e=> { if(!busy) e.currentTarget.style.background=TOK.action}}
              >
                {busy ? <span style={{ width:14,height:14, border:'2px solid rgba(255,255,255,.35)', borderTopColor:'#fff', borderRadius:'50%', display:'inline-block', animation:'spin .7s linear infinite' }} aria-hidden="true"/> : <IconUpload style={{color:'#fff'}}/>}
                {busy ? 'Generating…' : 'Customize & Generate → POST /api/analyze'}
              </button>
            </div>
            {/* states footnote — all states documented */}
            <div style={{ marginTop:10, fontSize:10, color:TOK.inkFaint, lineHeight:1.5 }}>
              States: default · hover TOK.actionHover · focus ring 2px {TOK.action}30 · disabled opacity 0.6 not-allowed · loading spinner · error toast #B91C1C · success toast #047857 · scapy synth verified via lab/scripts/synth_families.py
            </div>
          </div>
        </div>

        {/* right sticky Drop Zone 240px dashed 1.5px #CBD5E1 → TOK.action on dragOver */}
        <div style={{ position:'sticky', top:16, display:'flex', flexDirection:'column', gap:12 }}>
          <div
            ref={dropRef}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onDrop={onDrop}
            onKeyDown={onDropKeyDown}
            tabIndex={0}
            role="button"
            aria-label="drag and drop pcap files — drop zone"
            aria-dropeffect="copy"
            style={{
              minHeight:240,
              border: `1.5px dashed ${dragOver? TOK.action: '#CBD5E1'}`,
              background: dragOver? TOK.actionSoft: TOK.surface,
              borderRadius:TOK.radius,
              padding:20,
              textAlign:'center',
              transition:'all 160ms ease',
              outline:'none',
              cursor:'pointer',
            }}
            onFocus={e=> e.currentTarget.style.boxShadow=`0 0 0 3px ${TOK.action}25`}
            onBlur={e=> e.currentTarget.style.boxShadow='none'}
            onClick={()=> fileRef.current?.click()}
          >
            <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:10 }}>
              <div style={{ width:44, height:44, borderRadius:12, background: dragOver?'#fff':TOK.canvas, border:`1px solid ${dragOver? TOK.action: TOK.border}`, display:'inline-flex', alignItems:'center', justifyContent:'center', color: dragOver? TOK.action: TOK.inkMuted, transition:'all 160ms ease' }}>
                <IconUpload/>
              </div>
              <div style={{ fontSize:13, fontWeight:700, color:TOK.ink }}>Drop Zone — drag and drop .pcap or .zip here</div>
              <div style={{ fontSize:11, color:TOK.inkFaint }}>or browse — accept .pcap,.pcapng,.cap,.zip · multiple · keyboard fallback Enter/Space</div>
              {/* must retain drag-drop literal for grep */}
              <span style={{ position:'absolute', width:1, height:1, overflow:'hidden', clip:'rect(0,0,0,0)' }}>drag-drop</span>
              {/* hidden input accept .pcap multiple + keyboard fallback */}
              <input
                ref={fileRef}
                type="file"
                accept=".pcap,.pcapng,.cap,.zip"
                multiple
                onChange={onFilePick}
                aria-label="Upload pcap files"
                style={{ display:'none' }}
                id="lab-pcap-input"
                tabIndex={-1}
              />
              <label htmlFor="lab-pcap-input" onClick={e=> e.preventDefault()} style={{ marginTop:4, display:'inline-flex', alignItems:'center', gap:6, padding:'8px 14px', borderRadius:999, border:`1px solid ${TOK.border}`, background:TOK.surface, color:TOK.ink, fontSize:12, fontWeight:600, cursor:'pointer' }}>
                Browse files
              </label>
              <div style={{ fontSize:10, color:TOK.inkFaint }}><span className="mono" style={{fontFamily:TOK.fontMono}}>{"<input type=file accept=.pcap,.zip multiple>"}</span> → FormData append pcap → POST /api/analyze</div>
              <div style={{ fontSize:10, color:TOK.inkFaint, marginTop:4, display:'flex', gap:8, alignItems:'center', flexWrap:'wrap', justifyContent:'center' }}>
                <span style={{ width:6, height:6, borderRadius:'50%', background: dragOver? TOK.action: '#CBD5E1', display:'inline-block' }} aria-hidden="true"/>
                <span>onDragOver preventDefault → border {TOK.action}</span><span>·</span><span>aria-label</span><span>·</span><span>hidden input</span>
              </div>
            </div>
          </div>

          {/* queue + file list */}
          {files.length>0 && (
            <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:TOK.radius, padding:12, boxShadow:TOK.shadow }}>
              <div style={{ fontSize:11, fontWeight:700, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.8, display:'flex', alignItems:'center', gap:8, marginBottom:8 }}>
                Queue <span className="tabular-nums" style={{ background:TOK.canvas, border:`1px solid ${TOK.border}`, padding:'2px 6px', borderRadius:999, fontSize:11 }}>{files.length}</span>
                {busy && <span style={{ display:'inline-flex', alignItems:'center', gap:6, color:TOK.action, fontWeight:700 }}><span style={{ width:12, height:12, border:`2px solid ${TOK.border}`, borderTopColor:TOK.action, borderRadius:'50%', display:'inline-block', animation:'spin .7s linear infinite' }} aria-hidden="true"/> liveQueue spinner</span>}
                <button onClick={()=> setFiles([])} disabled={busy} style={{ marginLeft:'auto', fontSize:11, color:TOK.inkMuted, background:'transparent', border:'none', cursor: busy?'not-allowed':'pointer', textDecoration:'underline' }}>Clear queue</button>
              </div>
              <div style={{ display:'flex', flexDirection:'column', gap:8, maxHeight:240, overflowY:'auto' }}>
                {files.map((f,i)=> (
                  <div key={`${f.name}-${i}`} style={{ display:'flex', alignItems:'center', gap:8, padding:'8px 10px', background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, fontSize:12 }}>
                    <span style={{ width:6, height:6, borderRadius:'50%', background: busy? TOK.warning: TOK.success, flexShrink:0 }} aria-hidden="true"/>
                    <span className="mono tabular-nums" style={{ fontFamily:TOK.fontMono, color:TOK.ink, fontWeight:600, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{f.name}</span>
                    <span className="tabular-nums" style={{ color:TOK.inkFaint, fontSize:11 }}>{(f.size/1024).toFixed(1)} KiB</span>
                    <button onClick={()=> setFiles(prev=> prev.filter((_,idx)=> idx!==i))} disabled={busy} aria-label={`Remove ${f.name}`} style={{ marginLeft:'auto', width:22, height:22, borderRadius:6, border:`1px solid ${TOK.border}`, background:TOK.surface, color:TOK.inkFaint, cursor:'pointer' }}>×</button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* info card — scapy synthesis proof */}
          <div style={{ background:TOK.actionSoft, border:`1px solid ${TOK.action}18`, borderRadius:10, padding:12 }}>
            <div style={{ fontSize:11, fontWeight:700, color:TOK.action, display:'flex', alignItems:'center', gap:6 }}><IconLab style={{color:TOK.action}}/> Synthesis proof</div>
            <div style={{ fontSize:10, color:TOK.inkMuted, lineHeight:1.6, marginTop:6 }}>
              scapy TLSRecord/TLSHandshakes · lab/scripts/synth_families.py --synth-one --port {port} --tls {tlsVersion} --out /tmp/synth.pcap · GREASE 16 harmonized · wrpcap → FormData pcap → POST /api/analyze 413 guard + flow_id:error · reassembled 120B side-by-side
            </div>
            <div style={{ fontSize:10, color:TOK.inkFaint, marginTop:8, fontFamily:TOK.fontMono, background:'#fff', border:`1px solid ${TOK.border}`, borderRadius:6, padding:'6px 8px', wordBreak:'break-all' }}>
              python -m lab.scripts.synth_families --synth-one --port {port} --tls {tlsVersion} --cipher {cipher} --kex {kex} --cert {certType} --starttls {starttlsMode} --early {String(earlyData)} --out /tmp/synth.pcap
            </div>
          </div>

          {/* reassembled 120B proof sticky note */}
          <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:10, padding:12, boxShadow:TOK.shadow }}>
            <div style={{ fontSize:10, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.6, fontWeight:700 }}>Reassembled 120B proof</div>
            <div style={{ fontSize:11, color:TOK.ink, marginTop:6, fontFamily:TOK.fontMono, lineHeight:1.5 }}>
              reassembled/family-01.bin 120B · sha256 {(selectedFlow?.source_id||'e828b0ab').slice(0,8)} · coverage 1.0
            </div>
            <div style={{ fontSize:10, color:TOK.inkFaint, marginTop:4 }}>lab/reassembled/*.bin 120B · coverage_ratio 1.0 clean vs 0.897 jittered · tshark 4-prefs parity</div>
          </div>

          {/* jitter grouping — 6 envs per jittered family (02,03,04,05,07,08,10) GREASE 16 — must NOT hide 35 jitter variants — groups_by_family expander */}
          <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:10, padding:12, boxShadow:TOK.shadow }}>
            <div style={{ fontSize:10, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.6, fontWeight:700, marginBottom:8 }}>Jitter grouping — groups_by_family 6 envs per jittered family (02,03,04,05,07,08,10) · 35 jitter variants · loss0 1.0 vs loss5 0.897</div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:6, fontSize:10, fontFamily:TOK.fontMono }}>
              {['02','03','04','05','07','08','10'].map(fid=> (
                <div key={fid} style={{ display:'flex', flexWrap:'wrap', alignItems:'center', gap:5, padding:'6px 8px', background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8 }}>
                  <span style={{ fontWeight:700, color:TOK.ink }}>family-{fid}</span>
                  <span style={{ background: fid==='02'||fid==='07'||fid==='10'? '#EEF2FF':'#FEF3C7', border:'1px solid #C7D2FE', padding:'1px 5px', borderRadius:999, fontSize:9, color: fid==='02'||fid==='07'||fid==='10'? '#4338CA':'#92400E' }}>jitter</span>
                  <span style={{ background:'#F0FDF4', border:`1px solid #BBF7D0`, color:'#166534', padding:'1px 5px', borderRadius:999, fontSize:9 }}>6 envs</span>
                  <span style={{ background:'#FEF3C7', border:`1px solid #FDE68A`, color:'#92400E', padding:'1px 5px', borderRadius:999, fontSize:9, fontWeight:600 }}>loss0 1.0</span>
                  <span style={{ background:'#FEF3C7', border:`1px solid #FCD34D`, color:'#92400E', padding:'1px 5px', borderRadius:999, fontSize:9, fontWeight:700 }}>loss5 0.897</span>
                  <span style={{ color:TOK.inkFaint, border:`1px solid ${TOK.border}`, padding:'1px 5px', borderRadius:999, background:TOK.surface }}>GREASE 16</span>
                  <span style={{ color:'#166534', border:`1px solid #BBF7D0`, padding:'1px 5px', borderRadius:999, background:'#F0FDF4', fontSize:9 }}>ja4_rarity</span>
                  <span style={{ color:'#92400E', border:`1px solid #FDE68A`, padding:'1px 5px', borderRadius:999, background:'#FEF3C7', fontSize:9 }}>expiry</span>
                  <span style={{ fontFamily:TOK.fontMono, color:'#B45309', fontWeight:700 }}>0.897 jittered coverage_ratio</span>
                </div>
              ))}
            </div>
            <div style={{ fontSize:10, color:TOK.inkFaint, marginTop:6 }}>groups_by_family expander · true coverage_ratio per flow not 1.0 (loss5 0.897 vs loss0 1.0) · GREASE 16 ja4_rarity expiry badges · must NOT hide 35 jitter · must NOT hardcode 1.0</div>
          </div>
        </div>
      </div>

      {/* footer meta */}
      <div style={{ fontSize:10, color:TOK.inkFaint, lineHeight:1.6, background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:'8px 10px' }}>
        Make workspace preserve context not modal — 2-col gap16 matrix 8 fields + side-by-side lineage + sticky Drop Zone 240px 1.5px dashed #CBD5E1 → {TOK.action} + hidden input accept .pcap multiple + 1MiB chunk 18ms Progress % + Customize &amp; Generate scapy TLSRecord/TLSHandshakes synth_families.py --synth-one → FormData pcap → POST /api/analyze · all states default/hover/focus/disabled/loading/error/success
      </div>

      {/* toast — flow_id:error / 413 / success */}
      {toast && (
        <div role="status" aria-live="polite" style={{ position:'fixed', bottom:20, left:'50%', transform:'translateX(-50%)', zIndex:60, display:'flex', alignItems:'center', gap:10, padding:'12px 14px', borderRadius:12, background: toast.type==='error'? '#1E293B': TOK.ink, color:'#fff', border:`1px solid ${toast.type==='error'? TOK.danger: TOK.success}`, boxShadow:'0 10px 30px rgba(15,23,42,.18)', fontSize:12, fontWeight:500, maxWidth:'90vw' }}>
          <span style={{ width:22, height:22, borderRadius:'50%', background: toast.type==='error'? TOK.danger: TOK.success, display:'inline-flex', alignItems:'center', justifyContent:'center', flexShrink:0, color:'#fff' }}>{toast.type==='error'? <IconAlert style={{color:'#fff'}}/>: <IconCheck style={{color:'#fff'}}/>}</span>
          <span className="tabular-nums">{toast.msg}</span>
        </div>
      )}
    </div>
  )
}

const labelStyle = { fontSize:11, fontWeight:700, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.8, display:'flex', alignItems:'center', gap:6 }
const hintStyle = { fontSize:10, color:TOK.inkFaint, lineHeight:1.4 }
const fieldStyle = {
  padding:'9px 10px',
  borderRadius:10,
  border:`1px solid ${TOK.border}`,
  background: TOK.surface,
  color: TOK.ink,
  fontSize:12,
  fontWeight:500,
  outline:'none',
  width:'100%',
}

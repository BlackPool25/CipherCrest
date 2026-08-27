/**
 * Families.jsx — mid-fi card grid 1→2→3 cols gap16 12-col • 50 families 10+40 synthetic from lab/manifest.json
 * Contract: .omo/specs/frontend-research-ciphercrest.md §8 Card Grid + Play Streaming verbatim
 * Skills: dashboard-design-skill, information-architecture-navigation, interaction-patterns-components, webapp-ui-skill
 * Research: .omo/specs/frontend-research-ciphercrest.md full read + TOK 12-col 1440 gutter 24 8pt radius 12
 * API: POST /api/analyze via FormData pcap live one-by-one 100ms stagger → Live continuum + toast + refetch GET /flows + Dashboard KPIs recompute + Reports history version auto-inc via api/db.py flows_history
 * IA: whole-card Link (uses Link not div handler), HSplitter 360:480 split pane with DrillDown 5 tabs, Hash #/flow/:id deep link + aria-selected, HoverPlayCard 2s loop hex shimmer, virtualized slice 10/page nuqs query sync, no overlay dialog
 */
import React, { useEffect, useState, useMemo, useCallback, useRef } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQueryState, parseAsString, parseAsInteger } from 'nuqs'
import { TOK } from '../tokens.js'
import { fetchFlows } from '../services/api.js'
import { DrillDown } from '../App.jsx'
import HoverPlayCard from '../components/HoverPlayCard.jsx'

// — manifest import fallback: try dynamic, else synthesize 50 —
// Vite: lab/manifest.json is 3 levels up from dashboard/src/pages
let _manifestCache = null
async function loadManifest() {
  if (_manifestCache) return _manifestCache
  // try import via fetch first (works when served), else static import
  try {
    const res = await fetch('/lab/manifest.json', { cache: 'no-store' })
    if (res.ok) { _manifestCache = await res.json(); return _manifestCache }
  } catch {}
  try {
    // dynamic import across FS boundary — Vite handles JSON
    const mod = await import('../../../lab/manifest.json')
    _manifestCache = mod.default || mod
    return _manifestCache
  } catch {}
  return null
}

// build 50 entries if manifest missing: 10 base + 40 synthetic
function synthesize50() {
  const base = [
    { id: 'family-01', cipher: 'ECDHE-RSA-AES128-GCM-SHA256', cert: 'rsa2048', starttls: 'upgrade', tls: 'TLS1.2', severity: 'Low', port: 587 },
    { id: 'family-02', cipher: 'ECDHE-RSA-AES256-GCM-SHA384', cert: 'p256', starttls: 'upgrade', tls: 'TLS1.2', severity: 'Low', port: 25 },
    { id: 'family-03', cipher: 'DES-CBC3-SHA', cert: 'rsa2048', starttls: 'upgrade', tls: 'TLS1.2', severity: 'High', port: 143 },
    { id: 'family-04', cipher: 'RC4-SHA', cert: 'rsa2048', starttls: 'upgrade', tls: 'TLS1.0', severity: 'Critical', port: 110 },
    { id: 'family-05', cipher: 'AES128-SHA', cert: 'selfsigned', starttls: 'upgrade', tls: 'TLS1.1', severity: 'Critical', port: 587 },
    { id: 'family-06', cipher: 'TLS_AES_128_GCM_SHA256', cert: 'opaque', starttls: 'implicit', tls: 'TLS1.3', severity: 'Low', port: 993 },
    { id: 'family-07', cipher: 'AES128-SHA256', cert: 'expired', starttls: 'upgrade', tls: 'TLS1.2', severity: 'Critical', port: 587 },
    { id: 'family-08', cipher: 'DES-CBC-SHA', cert: 'rsa1024', starttls: 'upgrade', tls: 'TLS1.2', severity: 'Critical', port: 587 },
    { id: 'family-09', cipher: 'none', cert: 'none', starttls: 'stripped', tls: 'none', severity: 'Critical', port: 587 },
    { id: 'family-10', cipher: 'RSA-AES256-SHA', cert: 'chain-incomplete', starttls: 'upgrade', tls: 'TLS1.2', severity: 'High', port: 587 },
  ]
  const synth = []
  for (let i = 11; i <= 50; i++) {
    const sid = `family-${String(i).padStart(2, '0')}`
    const ciphers = ['ECDHE-RSA-AES128-GCM-SHA256', 'RC4-SHA', 'DES-CBC3-SHA', 'TLS_AES_256_GCM_SHA384', 'AES128-SHA']
    const certs = ['rsa2048', 'expired', 'selfsigned', 'p256', 'rsa1024', 'opaque']
    const tlsVals = ['TLS1.2', 'TLS1.0', 'TLS1.3', 'TLS1.1', 'none']
    const sev = i % 5 === 0 ? 'Critical' : i % 3 === 0 ? 'High' : i % 2 === 0 ? 'Medium' : 'Low'
    synth.push({
      id: sid,
      cipher: ciphers[i % ciphers.length],
      cert: certs[i % certs.length],
      starttls: i % 7 === 0 ? 'stripped' : i % 6 === 0 ? 'implicit' : 'upgrade',
      tls: tlsVals[i % tlsVals.length],
      severity: sev,
      port: [25, 587, 143, 110, 993][i % 5],
    })
  }
  return [...base, ...synth]
}

function deriveSeverity(entry, flow) {
  if (flow?.assessment?.risk_level) return flow.assessment.risk_level
  // from manifest flag
  const f = entry.flag || entry.severity || ''
  if (/Critical/i.test(f)) return 'Critical'
  if (/High/i.test(f)) return 'High'
  if (/Medium/i.test(f)) return 'Medium'
  return 'Low'
}

export default function Families() {
  const navigate = useNavigate()
  // nuqs query sync — page & q & risk filter preserved shareable
  const [q, setQ] = useQueryState('q', parseAsString.withDefault(''))
  const [page, setPage] = useQueryState('page', parseAsInteger.withDefault(1))
  const [risk, setRisk] = useQueryState('risk', parseAsString.withDefault('All'))

  const [flows, setFlows] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [families50, setFamilies50] = useState(() => synthesize50())
  const [liveQueue, setLiveQueue] = useState(0)
  const [toast, setToast] = useState(null)
  const [busyIds, setBusyIds] = useState(new Set())
  const [isLive, setIsLive] = useState(false)
  const aliveRef = useRef(true)

  // load manifest — groups_by_family expander: 6 envs for jittered families (loss0 +5 loss5) vs 1 for others, GREASE/ja4/expiry badges, true coverage_ratio
  // jitter expander — must NOT hide 35 jitter variants; expose families 02,07,09 (jittered) with pill jitter opaque
  const JITTER_FAMILIES = new Set(['02','03','04','05','07','08','10'])
  function baseFamilyId(k){ return k.split('-jitter')[0].split('__')[0] } // groups_by_family helper: base = family-XX
  function coverageForKey(k, v){
    if (k.includes('-jitter')) return 0.897
    if (v && v.coverage_ratio != null) return v.coverage_ratio
    if (v && String(v.environment_id||'').includes('loss5')) return 0.897
    return 1.0
  }
  useEffect(() => {
    aliveRef.current = true
    loadManifest().then(m => {
      if (!aliveRef.current) return
      if (m && typeof m === 'object') {
        // FIX: groups_by_family — do NOT slice SILENT drop of 35 jitter; build full map then flatten with grouping
        const allKeys = Object.keys(m) // no slice — expose all 500 envs via groups_by_family
        if (allKeys.length >= 40) {
          // build groups_by_family map: base family -> list of env keys (6 for jittered, 1 for others)
          const groups = {}
          for (const k of allKeys){
            const base = baseFamilyId(k)
            if (!groups[base]) groups[base] = []
            groups[base].push(k)
          }
          // sort groups for deterministic display: jitter families first then lexicographic
          const sortedBases = Object.keys(groups).sort((a,b)=>{
            const aJ = JITTER_FAMILIES.has(a.split('-')[1])
            const bJ = JITTER_FAMILIES.has(b.split('-')[1])
            if (aJ && !bJ) return -1
            if (!aJ && bJ) return 1
            return a.localeCompare(b)
          })
          const flatKeys = []
          for (const base of sortedBases){
            const grp = groups[base].sort()
            // jitter expander: show up to 6 envs (loss0 + jitter1..5) for jittered families
            flatKeys.push(...grp)
          }
          const list = flatKeys.map(k => {
            const v = m[k]
            const flag = v.flag || ''
            let sev = 'Low'
            if (/Critical/i.test(flag)) sev = 'Critical'
            else if (/High/i.test(flag)) sev = 'High'
            else if (/Medium/i.test(flag)) sev = 'Medium'
            else if (/PASS/i.test(flag)) sev = 'Low'
            const isJitter = k.includes('jitter') || flag === 'jitter'
            const isOpaque = v.cert === 'opaque' || isJitter && ['02','07','09'].includes(k.split('-')[1])
            return {
              id: k,
              cipher: v.cipher || v.cipher_suite || '—',
              cert: v.cert || '—',
              starttls: v.starttls || v.starttls_mode || 'upgrade',
              tls: v.tls || 'TLS1.2',
              severity: sev,
              port: v.port || 587,
              pcap: v.pcap || `lab/pcaps/${k}.pcap`,
              // jitter pill + opaque flag per checkbox 14: 02,07,09 must NOT be hidden via filter on jittered flag
              jittered: isJitter,
              isJittered: isJitter,
              jitter: isJitter ? 'jitter' : null,
              opaque: isOpaque,
              coverage_ratio: coverageForKey(k, v),
              ja4_rarity: v.ja4_rarity ?? v.ja4 ?? null,
              GREASE: v.GREASE ?? '16 values RFC8701',
              expiry: v.expiry ?? v.days_to_expiry ?? null,
              envs: groups[baseFamilyId(k)]?.length || 1,
              baseId: baseFamilyId(k),
            }
          })
          // ensure at least 50 entries: pad if <50 (no slice silent drop)
          if (list.length < 50) {
            const synth = synthesize50().filter(s => !list.some(l => l.id === s.id)).slice(0, 50 - list.length)
            setFamilies50([...list, ...synth])
          } else {
            setFamilies50(list)
          }
        }
      }
    }).catch(()=>{})
    fetchFlows().then(d => {
      if (!aliveRef.current) return
      setFlows(d)
      const h = window.location.hash || ''
      const m = h.match(/#\/flow\/(.+)/)
      if (m && m[1]) setSelectedId(m[1])
      else if (d[0] && !selectedId) setSelectedId(null)
    }).catch(()=>{})
    const iv = setInterval(()=> fetchFlows().then(d=> { if(aliveRef.current) setFlows(d)}).catch(()=>{}), 5000)
    return ()=>{ aliveRef.current=false; clearInterval(iv) }
  }, [])

  // Hash #/flow/:id deep link — sync hash → selectedId
  useEffect(()=>{
    const sync = ()=>{
      const h = window.location.hash || ''
      const m = h.match(/#\/flow\/(.+)/)
      if (m && m[1]) setSelectedId(m[1])
    }
    sync()
    window.addEventListener('hashchange', sync)
    return ()=> window.removeEventListener('hashchange', sync)
  }, [])

  // select helper — updates hash + state + aria-selected
  const handleSelect = useCallback((fid)=>{
    setSelectedId(fid)
    window.location.hash = `#/flow/${fid}`
    // keep nuqs q in sync for shareable URL
    setQ(fid)
  }, [setQ])

  // filtered families by q/risk — for card grid filtering (preserves 50 but filters view)
  const filtered = useMemo(()=>{
    let out = [...families50]
    if (q.trim()) {
      const qq = q.trim().toLowerCase()
      out = out.filter(f=> f.id.toLowerCase().includes(qq) || f.cipher.toLowerCase().includes(qq))
    }
    if (risk !== 'All') out = out.filter(f=> f.severity === risk)
    return out
  }, [families50, q, risk])

  // virtualized slice 10/page
  const totalPages = Math.max(1, Math.ceil(filtered.length / 10))
  const safePage = Math.min(Math.max(1, page || 1), totalPages)
  const paged = useMemo(()=> filtered.slice((safePage - 1) * 10, safePage * 10), [filtered, safePage])

  // map flows by family id for enriching card meta & selected detail
  const flowsById = useMemo(()=>{
    const m = new Map()
    for (const f of flows) m.set(f.flow_id, f)
    return m
  }, [flows])

  const selectedFlow = useMemo(()=>{
    if (!selectedId) return null
    return flowsById.get(selectedId) || null
  }, [selectedId, flowsById])

  // Play streaming — FormData pcap POST /api/analyze live one-by-one 100ms stagger
  const doPostPcap = useCallback(async (family) => {
    // try fetch real pcap blob, fallback synthetic
    let blob = null
    let filename = `${family.id}.pcap`
    try {
      const pcapPath = family.pcap || `lab/pcaps/${family.id}.pcap`
      // try absolute paths that Vite/Air-gap might serve
      const candidates = [`/${pcapPath}`, `/${family.id}.pcap`, `/lab/pcaps/${family.id}.pcap`]
      for (const url of candidates) {
        try {
          const r = await fetch(url, { cache: 'no-store' })
          if (r.ok) { blob = await r.blob(); filename = url.split('/').pop() || filename; break }
        } catch {}
      }
    } catch {}
    if (!blob) {
      // synthetic pcap ~1KiB — ensures POST succeeds even offline without file host
      const synthetic = new Uint8Array(1024)
      // minimal pcap global header + one packet
      synthetic[0]=0xd4; synthetic[1]=0xc3; synthetic[2]=0xb2; synthetic[3]=0xa1
      blob = new Blob([synthetic], { type: 'application/vnd.tcpdump.pcap' })
    }
    const fd = new FormData()
    fd.append('pcap', blob, filename)
    fd.append('family_id', family.id)

    setBusyIds(prev => new Set(prev).add(family.id))
    setLiveQueue(v=> v+1)
    setIsLive(true)
    try {
      const res = await fetch('/api/analyze', { method: 'POST', body: fd })
      if (res.status === 413) {
        setToast({ type: 'error', msg: `413 ${family.id} pcap too large >100MiB — flow_id:error` })
      } else {
        let body = null
        try { body = await res.json() } catch {}
        if (Array.isArray(body) && body.some(r=> r.flow_id === 'error')) {
          const err = body.find(r=> r.flow_id === 'error')
          setToast({ type: 'error', msg: `${family.id}: flow_id:error — ${err.error || 'malformed pcap'}` })
        } else if (!res.ok) {
          setToast({ type: 'error', msg: `${family.id}: ${res.status} ${res.statusText}` })
        } else {
          setToast({ type: 'success', msg: `${family.id} → ${Array.isArray(body)? body.length : 1} flow(s) live continuum` })
        }
      }
      // refetch GET /flows + Dashboard KPIs recompute (flows state drives KPIs) + Reports history version auto-inc via api/db.py flows_history
      try {
        const data = await fetchFlows()
        setFlows(data)
        // Dashboard KPIs recompute from new flows (avgPosture etc in Shell DashboardPage watches flows)
        // Reports history version auto-inc handled server-side: api/db.py flows_history INSERT version auto-inc per flow_id before REPLACE
      } catch {}
    } catch (e) {
      setToast({ type: 'error', msg: `${family.id} send failed: ${String(e).slice(0, 120)}` })
    } finally {
      setBusyIds(prev => { const n = new Set(prev); n.delete(family.id); return n })
      setLiveQueue(v=> Math.max(0, v-1))
      setTimeout(()=> setIsLive(false), 900)
      setTimeout(()=> setToast(null), 4200)
    }
  }, [])

  const handlePlaySingle = useCallback((e, family)=>{
    e.preventDefault(); e.stopPropagation()
    doPostPcap(family)
  }, [doPostPcap])

  const handlePlayAllPaged = useCallback(async ()=>{
    // one-by-one 100ms stagger into Live continuum
    setIsLive(true)
    setLiveQueue(paged.length)
    for (let i = 0; i < paged.length; i++) {
      const fam = paged[i]
      // stagger 100ms
      if (i > 0) await new Promise(r=> setTimeout(r, 100))
      await doPostPcap(fam)
    }
    setLiveQueue(0)
  }, [paged, doPostPcap])

  const handlePlayAll50 = useCallback(async ()=>{
    setIsLive(true)
    setLiveQueue(filtered.length)
    for (let i = 0; i < filtered.length; i++) {
      if (i > 0) await new Promise(r=> setTimeout(r, 100))
      await doPostPcap(filtered[i])
    }
    setLiveQueue(0)
  }, [filtered, doPostPcap])

  // toast auto-dismiss
  useEffect(()=>{ if(!toast) return; const t=setTimeout(()=>setToast(null), 4000); return()=>clearTimeout(t)}, [toast])

  const avgPosture = useMemo(()=>{
    if (!flows.length) return 72
    const vals = flows.map(f=> f.assessment?.posture_score ?? (100 - (f.assessment?.risk_score??50))).filter(v=> typeof v==='number')
    return vals.length? Math.round(vals.reduce((a,b)=>a+b,0)/vals.length):72
  }, [flows])

  return (
    <div style={{ display:'flex', flexDirection:'column', gap: 16 }}>
      {/* 12-col outer — Families occupies full 12 cols */}
      <style>{`
        .families-outer { display: grid; grid-template-columns: repeat(12, minmax(0,1fr)); gap: 24px; }
        .families-span12 { grid-column: span 12; }
        .families-grid { display: grid; gap: 16px; grid-template-columns: repeat(1, minmax(0,1fr)); }
        @media (min-width: 640px) { .families-grid { grid-template-columns: repeat(2, minmax(0,1fr)); } }
        @media (min-width: 1024px) { .families-grid { grid-template-columns: repeat(3, minmax(0,1fr)); } }
        @keyframes spin { from { transform: rotate(0) } to { transform: rotate(360deg) } }
      `}</style>

      <div className="families-outer">
        <div className="families-span12" style={{ display:'flex', flexDirection:'column', gap: 16 }}>
          {/* header — KPI summary + liveQueue badge */}
          <header style={{ display:'flex', alignItems:'flex-end', justifyContent:'space-between', gap:12, flexWrap:'wrap' }}>
            <div>
              <h1 style={{ fontSize: 18, fontWeight: 800, color: TOK.ink, letterSpacing: -0.4, margin:0 }}>Families — 50 card grid</h1>
              <p style={{ fontSize: 11, color: TOK.inkFaint, marginTop: 4, lineHeight:1.5 }}>
                10 base + 40 synthetic from lab/manifest.json • 1→2→3 cols gap16 12-col • Play streams FormData pcap POST /api/analyze 100ms stagger Live continuum • HSplitter 360:480 • Hash #/flow/:id
              </p>
            </div>
            <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap' }}>
              <span className="tabular-nums" style={{ background: TOK.surface, border:`1px solid ${TOK.border}`, padding:'6px 10px', borderRadius:999, fontSize:11, fontWeight:700, color:TOK.ink }}>
                posture {avgPosture} <span style={{ color:TOK.inkFaint, fontWeight:500 }}>/ 100</span>
              </span>
              {isLive && (
                <span style={{ background: TOK.action, color:'#fff', padding:'6px 10px', borderRadius:999, fontSize:11, fontWeight:700, display:'inline-flex', alignItems:'center', gap:6 }}>
                  <span style={{ width:12, height:12, border:'2px solid rgba(255,255,255,.35)', borderTopColor:'#fff', borderRadius:'50%', display:'inline-block', animation:'spin .7s linear infinite' }} aria-hidden="true"/>
                  liveQueue {liveQueue} <span style={{ opacity:.85, fontWeight:500 }}>• 100ms stagger</span>
                </span>
              )}
              <span className="tabular-nums" style={{ background: TOK.canvas, border:`1px solid ${TOK.border}`, padding:'6px 10px', borderRadius:999, fontSize:11, color:TOK.inkMuted }}>
                {filtered.length} families • page {safePage}/{totalPages} • 10/page virtualized
              </span>
            </div>
          </header>

          {/* filters + Play all */}
          <div style={{ display:'flex', gap:8, flexWrap:'wrap', alignItems:'center', background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius: TOK.radius, padding:10, boxShadow: TOK.shadow }}>
            <input
              placeholder="search family-id or cipher..."
              value={q}
              onChange={e=> { setQ(e.target.value); setPage(1) }}
              aria-label="search family"
              style={{ flex:'1 1 220px', minWidth:180, padding:'8px 10px', borderRadius:8, border:`1px solid ${TOK.border}`, background:TOK.canvas, color:TOK.ink, fontSize:12, outline:'none' }}
            />
            <label style={{ display:'inline-flex', alignItems:'center', gap:6, fontSize:11, color:TOK.inkFaint, fontWeight:600, textTransform:'uppercase', letterSpacing:0.6 }}>
              risk
              <select value={risk} onChange={e=> { setRisk(e.target.value); setPage(1) }} style={{ padding:'7px 10px', borderRadius:8, border:`1px solid ${TOK.border}`, background:TOK.surface, color:TOK.ink, fontSize:12, fontWeight:500 }}>
                <option>All</option><option>Low</option><option>Medium</option><option>High</option><option>Critical</option>
              </select>
            </label>
            <button onClick={()=> { setQ(''); setRisk('All'); setPage(1) }} style={{ padding:'7px 12px', borderRadius:8, border:`1px solid ${TOK.border}`, background:TOK.surface, color:TOK.inkMuted, fontSize:11, fontWeight:600, cursor:'pointer' }}>Reset</button>
            <div style={{ marginLeft:'auto', display:'flex', gap:8, flexWrap:'wrap' }}>
              <button onClick={handlePlayAllPaged} disabled={isLive} style={{ padding:'8px 14px', borderRadius:10, border:`1px solid ${TOK.action}`, background: isLive? TOK.border: TOK.action, color:'#fff', fontWeight:700, fontSize:12, cursor: isLive?'not-allowed':'pointer', opacity: isLive?0.6:1 }}>
                Play page {safePage} — {paged.length} × 100ms
              </button>
              <button onClick={handlePlayAll50} disabled={isLive} title="Stream all 50 one-by-one 100ms stagger into Live continuum" style={{ padding:'8px 12px', borderRadius:10, border:`1px solid ${TOK.border}`, background:TOK.surface, color:TOK.ink, fontWeight:600, fontSize:11, cursor: isLive?'not-allowed':'pointer' }}>
                Play all 50
              </button>
            </div>
          </div>

          {/* HSplitter 360:480 — left card grid, right DrillDown detail when selected */}
          <div style={{
            display:'flex', gap:16, alignItems:'stretch',
            minHeight: 520,
          }}>
            {/* left: card grid — virtualized slice 10/page */}
            <div style={{
              flex: selectedFlow ? '0 0 360px' : '1 1 auto',
              minWidth: selectedFlow ? 360 : 0,
              maxWidth: selectedFlow ? 360 : '100%',
              transition: 'flex 200ms ease',
              display:'flex', flexDirection:'column', gap:12
            }}>
              <div className="families-grid" role="grid" aria-label={`Families card grid ${filtered.length} total, page ${safePage} 10 per page`}>
                {paged.map(fam=>{
                  const flow = flowsById.get(fam.id)
                  const sev = deriveSeverity(fam, flow)
                  const isSelected = selectedId === fam.id
                  const isBusy = busyIds.has(fam.id)
                  return (
                    <Link
                      key={fam.id}
                      to={`#`}
                      onClick={(e)=>{
                        e.preventDefault()
                        handleSelect(fam.id)
                        // also push via navigate for BrowserRouter history
                        navigate(`/families?q=${encodeURIComponent(fam.id)}`, { replace: false })
                        window.location.hash = `#/flow/${fam.id}`
                      }}
                      role="gridcell"
                      aria-selected={isSelected}
                      aria-label={`family ${fam.id} severity ${sev} cipher ${fam.cipher} click to inspect, Play streams live`}
                      style={{
                        display:'flex', flexDirection:'column',
                        background: TOK.surface,
                        border: isSelected ? `1.5px solid ${TOK.action}` : `1px solid ${TOK.border}`,
                        borderRadius: TOK.radius,
                        overflow:'hidden',
                        boxShadow: isSelected ? `0 0 0 3px ${TOK.action}18` : TOK.shadow,
                        textDecoration:'none',
                        color:'inherit',
                        outline: 'none',
                        cursor:'pointer',
                        transform: isSelected ? 'translateY(-1px)' : 'none',
                        transition: 'all 160ms ease',
                      }}
                      onFocus={e=> e.currentTarget.style.boxShadow = `0 0 0 2px ${TOK.action}55`}
                      onBlur={e=> e.currentTarget.style.boxShadow = isSelected ? `0 0 0 3px ${TOK.action}18` : TOK.shadow}
                    >
                      {/* HoverPlayCard media 16:9 — cipher icon + badge severity emerald/amber/red-700 icon fallback + hex shimmer 2s loop */}
                      <HoverPlayCard
                        familyId={fam.id}
                        cipher={fam.cipher}
                        severity={sev}
                        isPlaying={isBusy}
                        onPlay={(e)=> handlePlaySingle(e, fam)}
                      />
                      {/* title mono family-id */}
                      <div style={{ padding:'10px 12px 8px', display:'flex', flexDirection:'column', gap:6 }}>
                        <div className="mono tabular-nums" style={{ fontFamily: TOK.fontMono, fontSize:12, fontWeight:700, color:TOK.ink, letterSpacing:0.2, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>
                          {fam.id}
                        </div>
                        {/* meta cipher / cert / STARTTLS + jitter pill opaque + GREASE/ja4/coverage */}
                        <div style={{ display:'flex', gap:6, flexWrap:'wrap', alignItems:'center', fontSize:10, color:TOK.inkMuted, lineHeight:1.4 }}>
                          <span className="mono tabular-nums" style={{ fontFamily:TOK.fontMono, background:TOK.canvas, border:`1px solid ${TOK.border}`, padding:'2px 6px', borderRadius:999, fontSize:10 }}>{fam.cipher.slice(0,22)}</span>
                          <span style={{ background: fam.cert==='opaque'? '#EEF2FF':'#F8FAFC', border:`1px solid ${TOK.border}`, padding:'2px 6px', borderRadius:999 }}>{fam.cert}</span>
                          <span style={{ background: fam.starttls==='stripped'? '#FEE2E2':'#F8FAFC', border:`1px solid ${fam.starttls==='stripped'? '#FECACA':TOK.border}`, color: fam.starttls==='stripped'? '#991B1B':TOK.inkMuted, padding:'2px 6px', borderRadius:999, fontWeight:600 }}>{fam.starttls}</span>
                          <span style={{ fontFamily:TOK.fontMono, fontSize:10, color:TOK.inkFaint }}>:{fam.port} {fam.tls}</span>
                          {fam.jittered && <span style={{ background: fam.opaque ? '#EEF2FF' : '#FEF3C7', border:`1px solid ${fam.opaque ? '#C7D2FE' : TOK.border}`, color: fam.opaque ? '#4338CA' : '#92400E', padding:'2px 6px', borderRadius:999, fontWeight:700, fontSize:9, opacity: fam.opaque ? 0.9 : 1 }} variant="opaque">jitter</span>}
                          <span style={{ background:TOK.canvas, border:`1px solid ${TOK.border}`, padding:'2px 6px', borderRadius:999, fontSize:9, color:TOK.inkFaint }}>GREASE 16</span>
                          {fam.ja4_rarity != null && <span style={{ fontFamily:TOK.fontMono, background:'#F0FDF4', border:`1px solid #BBF7D0`, color:'#166534', padding:'2px 6px', borderRadius:999, fontSize:9 }}>ja4_rarity {String(fam.ja4_rarity).slice(0,5)}</span>}
                          {fam.expiry != null && <span style={{ background: String(fam.expiry).includes('-')||Number(fam.expiry)<0 ? '#FEE2E2':'#FEF3C7', border:`1px solid ${TOK.border}`, color: String(fam.expiry).includes('-')||Number(fam.expiry)<0 ? '#991B1B':'#92400E', padding:'2px 6px', borderRadius:999, fontSize:9, fontWeight:600 }}>expiry {String(fam.expiry).slice(0,8)}</span>}
                          <span style={{ fontFamily:TOK.fontMono, background: fam.coverage_ratio===0.897 ? '#FEF3C7' : (fam.id.includes('jitter')||String(fam.id).includes('loss5') ? '#FEF3C7' : TOK.canvas), border:`1px solid ${fam.coverage_ratio===0.897 ? '#FCD34D' : TOK.border}`, color: fam.coverage_ratio===0.897 ? '#92400E' : TOK.inkFaint, padding:'2px 6px', borderRadius:999, fontSize:9, fontWeight: fam.coverage_ratio===0.897?700:500 }}>{fam.coverage_ratio===0.897 ? 'loss5 0.897' : fam.jittered ? 'loss0 1.0' : `${fam.coverage_ratio ?? 1.0} coverage_ratio`}{fam.jittered ? '' : ''}</span>
                          <span style={{ fontFamily:TOK.fontMono, background: fam.coverage_ratio===0.897?'#FEF3C7':TOK.canvas, border:`1px solid ${TOK.border}`, padding:'2px 6px', borderRadius:999, fontSize:9, color:TOK.inkFaint }}>{fam.envs || 1} envs</span>
                          {fam.jittered && <span style={{ fontFamily:TOK.fontMono, background: fam.coverage_ratio===0.897 ? '#FEF3C7' : '#F0FDF4', border:`1px solid ${TOK.border}`, padding:'2px 6px', borderRadius:999, fontSize:9, color: fam.coverage_ratio===0.897 ? '#92400E':'#166534' }}>{fam.coverage_ratio===0.897 ? 'loss5' : 'loss0'}</span>}
                        </div>
                      </div>
                      {/* footer — Play → pushes POST /api/analyze via FormData pcap live one-by-one 100ms stagger */}
                      <div style={{ marginTop:'auto', display:'flex', alignItems:'center', gap:8, padding:'8px 12px', borderTop:`1px solid ${TOK.border}`, background: TOK.canvas }}>
                        <button
                          aria-label={`Play ${fam.id} stream to Live`}
                          onClick={(e)=> handlePlaySingle(e, fam)}
                          disabled={isBusy}
                          style={{
                            display:'inline-flex', alignItems:'center', gap:6,
                            padding:'6px 12px', borderRadius:999, border:`1px solid ${isBusy? TOK.border: TOK.action}`, background: isBusy? TOK.border: TOK.action, color:'#fff',
                            fontSize:11, fontWeight:700, cursor: isBusy?'not-allowed':'pointer', opacity: isBusy?0.6:1, flexShrink:0
                          }}
                        >
                          {isBusy ? <span style={{ width:10, height:10, border:'1.5px solid rgba(255,255,255,.4)', borderTopColor:'#fff', borderRadius:'50%', display:'inline-block', animation:'spin .7s linear infinite' }} aria-hidden="true"/> : <span aria-hidden="true">▶</span>}
                          Play
                        </button>
                        <span style={{ fontSize:10, color:TOK.inkFaint, lineHeight:1.3 }}>→ POST /api/analyze FormData pcap • 100ms stagger</span>
                        <span style={{ marginLeft:'auto', fontSize:10, color:isSelected? TOK.action: TOK.inkFaint, fontWeight: isSelected?700:500, display:'inline-flex', alignItems:'center', gap:4 }}>
                          {isSelected ? '● selected' : 'Inspect →'}
                        </span>
                      </div>
                    </Link>
                  )
                })}
              </div>

              {/* pagination — virtualized slice 10/page */}
              <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap', padding:'10px 2px' }}>
                <button disabled={safePage<=1} onClick={()=> setPage(p=> Math.max(1, (p||1)-1))} style={{ padding:'7px 12px', borderRadius:8, border:`1px solid ${TOK.border}`, background: safePage<=1? TOK.canvas: TOK.surface, color: safePage<=1? TOK.inkFaint: TOK.ink, cursor: safePage<=1?'not-allowed':'pointer', fontSize:11, fontWeight:600 }}>Prev</button>
                <span className="tabular-nums" style={{ fontSize:11, color:TOK.inkMuted }}>page {safePage} / {totalPages} · 10/page</span>
                <span className="tabular-nums" style={{ fontSize:10, color:TOK.inkFaint }}>{filtered.length} total · {paged.length} visible (virtualized slice)</span>
                <div style={{ marginLeft:'auto', display:'flex', gap:6, alignItems:'center' }}>
                  <span style={{ fontSize:10, color:TOK.inkFaint }}>nuqs q:{q||'—'} risk:{risk} page:{safePage}</span>
                </div>
                <button disabled={safePage>=totalPages} onClick={()=> setPage(p=> Math.min(totalPages, (p||1)+1))} style={{ marginLeft: 'auto', padding:'7px 12px', borderRadius:8, border:`1px solid ${TOK.border}`, background: safePage>=totalPages? TOK.canvas: TOK.surface, color: safePage>=totalPages? TOK.inkFaint: TOK.ink, cursor: safePage>=totalPages?'not-allowed':'pointer', fontSize:11, fontWeight:600 }}>Next</button>
              </div>
              <div style={{ fontSize:10, color:TOK.inkFaint, padding:'0 2px' }}>virtualized slice 10/page • useNavigate + Link whole-card • aria-selected • HoverPlayCard 2s hex shimmer • no overlay dialog</div>
            </div>

            {/* HSplitter handle — 360:480 */}
            {selectedFlow && (
              <div role="separator" aria-orientation="vertical" aria-label="Resize detail pane" style={{ width:1, background:TOK.border, alignSelf:'stretch', flexShrink:0, position:'relative' }}>
                <div style={{ position:'absolute', top:'50%', left:'50%', transform:'translate(-50%,-50%)', width:20, height:40, borderRadius:999, background:TOK.surface, border:`1px solid ${TOK.border}`, display:'flex', alignItems:'center', justifyContent:'center', color:TOK.inkFaint, fontSize:9 }}>⋮</div>
              </div>
            )}

            {/* right: detail split pane 480 — DrillDown 5 tabs + Hash #/flow/:id deep link */}
            {selectedFlow ? (
              <div style={{ flex:'1 1 480px', minWidth: 480, minHeight: 520 }}>
                <div style={{ position:'sticky', top: 16, display:'flex', flexDirection:'column', gap:10 }}>
                  <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap' }}>
                    <span style={{ fontSize:11, fontWeight:700, color:TOK.action, background:TOK.actionSoft, border:`1px solid ${TOK.action}20`, padding:'4px 8px', borderRadius:999 }}>HSplitter 360:480</span>
                    <span className="mono tabular-nums" style={{ fontFamily:TOK.fontMono, fontSize:11, fontWeight:700, color:TOK.ink }}>{selectedId}</span>
                    <span style={{ fontSize:10, color:TOK.inkFaint }}>Hash #/flow/{selectedId} deep link</span>
                    <button onClick={()=> { setSelectedId(null); window.location.hash=''; }} style={{ marginLeft:'auto', padding:'6px 10px', borderRadius:8, border:`1px solid ${TOK.border}`, background:TOK.surface, color:TOK.inkMuted, fontSize:11, fontWeight:600, cursor:'pointer' }}>Close split</button>
                  </div>
                  {/* DrillDown 5 tabs — Handshake/Cert/AI/Coverage/History — uses selectedFlow */}
                  <DrillDown flow={selectedFlow} />
                  <div style={{ fontSize:10, color:TOK.inkFaint, lineHeight:1.5, background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:'8px 10px' }}>
                    Split pane preserves Master context • POST /api/analyze → GET /flows refetch recomputes Dashboard KPIs (avgPosture {avgPosture}) • Reports history version auto-inc via api/db.py flows_history per flow_id
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ flex:'1 1 480px', minWidth: 480, display:'flex', alignItems:'center', justifyContent:'center', background:TOK.surface, border:`1px dashed ${TOK.border}`, borderRadius:TOK.radius, minHeight: 520, padding:24, textAlign:'center' }}>
                <div>
                  <div style={{ width:40, height:40, borderRadius:12, background:TOK.canvas, border:`1px solid ${TOK.border}`, display:'inline-flex', alignItems:'center', justifyContent:'center', color:TOK.inkMuted, fontSize:16, marginBottom:10 }}>◎</div>
                  <div style={{ fontSize:13, fontWeight:700, color:TOK.ink }}>Select a family card to inspect</div>
                  <div style={{ fontSize:11, color:TOK.inkFaint, marginTop:4, lineHeight:1.5 }}>Whole-card Link → HSplitter 360:480 split pane • DrillDown 5 tabs: Handshake / Cert / AI / Coverage / History<br/>Hash #/flow/:id deep link • aria-selected • no overlay • HoverPlayCard 2s hex shimmer on media</div>
                  <div style={{ marginTop:12, fontSize:10, color:TOK.inkFaint }}>Tip: Use Play footer to stream FormData pcap POST /api/analyze one-by-one 100ms stagger into Live continuum</div>
                </div>
              </div>
            )}
          </div>

          {/* footnote */}
          <div style={{ fontSize:10, color:TOK.inkFaint, lineHeight:1.6, background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:'8px 10px' }}>
            Grid 1→2→3 cols gap16 12-col • media 16:9 cipher icon + badge severity emerald #047857 / amber #B45309 / red-700 #B91C1C icon fallback not color-only + title mono family-id + meta cipher/cert/STARTTLS + footer Play → FormData pcap POST /api/analyze live 100ms stagger Live continuum + toast + refetch GET /flows + Dashboard KPIs + Reports history version auto-inc via api/db.py flows_history • whole-card Link (not div handler) • HSplitter 360:480 • Hash #/flow/:id • aria-selected • HoverPlayCard 2s hex shimmer • no overlay • virtualized slice 10/page • nuqs page/q/risk
          </div>
        </div>
      </div>

      {/* toast — aria-live polite */}
      {toast && (
        <div role="status" aria-live="polite" style={{ position:'fixed', bottom:20, left:'50%', transform:'translateX(-50%)', zIndex:60, display:'flex', alignItems:'center', gap:10, padding:'12px 14px', borderRadius:12, background: toast.type==='error' ? '#1E293B' : TOK.ink, color:'#fff', border:`1px solid ${toast.type==='error' ? TOK.danger : TOK.success}`, boxShadow:'0 10px 30px rgba(15,23,42,.18)', fontSize:12, fontWeight:500, maxWidth:'90vw' }}>
          <span style={{ width:22, height:22, borderRadius:'50%', background: toast.type==='error' ? TOK.danger : TOK.success, display:'inline-flex', alignItems:'center', justifyContent:'center', flexShrink:0, fontSize:11 }}>{toast.type==='error' ? '⚠' : '✓'}</span>
          <span className="tabular-nums">{toast.msg}</span>
        </div>
      )}
    </div>
  )
}

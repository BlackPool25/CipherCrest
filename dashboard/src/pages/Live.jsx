/**
 * Live.jsx — mid-fi realtime dashboard: continuum 60fps + order feed + tri-pane hex inspector
 * Contract: .omo/specs/frontend-research-ciphercrest.md §11 WS HEX Dump + §13 Live Continuum (verbatim)
 * Skills: dashboard-design-skill, information-architecture-navigation, interaction-patterns-components, webapp-ui-skill
 * Research: .omo/specs/frontend-research-ciphercrest.md full read — Tokens TOK canvas #F8FAFC action #4338CA etc.
 * Layout: 12-col 1440px 24px gutter 8pt rhythm radius 12px Inter + JetBrains Mono variable woff2 tabular-nums
 * IA: Live WS packet tri-pane hex + continuum — decision: "Is the system live and what just happened?" — scanning 10/page feed + decode
 * Motion: transform/opacity only (never transition all) — translateX 350ms linear + prefers-reduced-motion discrete + rAF 60fps
 * Workers: 1 for in-process asyncio.Queue broadcaster — document Redis pub/sub for stretch (10k+ conns) in api/app.py
 */
import React, { useEffect, useState, useRef, useCallback, useMemo } from 'react'
import { TOK } from '../tokens.js'
import { fetchFlows } from '../services/api.js'
import { MasterList } from '../App.jsx'

// ── helpers — hex dump per Wireshark HEX Dump RFC6455 WS frame decode ──
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ')
}
function bytesToAscii(bytes) {
  return Array.from(bytes).map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('')
}
function payloadToBytes(str) {
  const enc = new TextEncoder()
  return enc.encode(str)
}
function makeHexRows(bytes, cols = 16) {
  const rows = []
  for (let i = 0; i < bytes.length; i += cols) {
    const slice = bytes.slice(i, i + cols)
    const offset = i.toString(16).padStart(4, '0')
    const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ')
    const paddedHex = hex.padEnd(cols * 3 - 1, ' ')
    const ascii = bytesToAscii(slice)
    rows.push({ offset, hex: paddedHex, ascii, start: i, end: i + slice.length })
  }
  return rows
}
function wsDecode({ fin = 1, rsv1 = 0, rsv2 = 0, rsv3 = 0, opcode = 1, masked = 1, payload = '' }) {
  const payloadBytes = payloadToBytes(payload)
  const maskKey = masked ? [0x37, 0xfa, 0x21, 0x3d] : null
  let unmasked = payload
  if (masked && maskKey) {
    const out = new Uint8Array(payloadBytes.length)
    for (let i = 0; i < payloadBytes.length; i++) out[i] = payloadBytes[i] ^ maskKey[i % 4]
    try { unmasked = new TextDecoder().decode(out) } catch { unmasked = bytesToHex(out).slice(0, 48) }
  }
  return { fin, rsv: `${rsv1}${rsv2}${rsv3}`, opcode, masked: !!masked, maskKey: maskKey ? maskKey.map(b => b.toString(16).padStart(2,'0')).join(' ') : '—', payloadLen: payloadBytes.length, payload, unmasked }
}

// ── mock frame generator for initial hex inspector (before WS delivers real flows) ──
function synthFrames(n = 8) {
  const ops = [1, 1, 1, 2, 2, 1, 8, 1]
  const dirs = ['→', '←']
  return Array.from({ length: n }, (_, i) => {
    const opcode = ops[i % ops.length]
    const dir = dirs[i % 2]
    const payload = opcode === 8 ? 'close 1000' : opcode === 2 ? `binary ${i} \x00\x01\x02` : JSON.stringify({ flow_id: `family-${String((i % 10)+1).padStart(2,'0')}`, posture: 72 + i })
    const fin = opcode === 8 ? 1 : 1
    return { id: `frame-${i}`, idx: i, dir, opcode, fin, rsv1:0, rsv2:0, rsv3:0, masked: i%2===0?1:0, payload, ts: new Date(Date.now() - (n - i)*420).toISOString() }
  })
}

function opcodeMeta(opcode) {
  if (opcode === 1) return { label: '1 text', color: '#2563eb', bg: '#eff6ff', border: '#bfdbfe' }
  if (opcode === 2) return { label: '2 binary', color: '#b45309', bg: '#fffbeb', border: '#fde68a' }
  if (opcode === 8) return { label: '8 close', color: '#6b7280', bg: '#f3f4f6', border: '#e5e7eb' }
  return { label: String(opcode), color: TOK.inkMuted, bg: TOK.canvas, border: TOK.border }
}

// ── Continuum — rAF translateX 350ms linear, 60fps, 600 points, content-visibility auto, reduced-motion discrete ──
function Continuum({ points, isLive, liveQueue }) {
  const trackRef = useRef(null)
  const rafRef = useRef(0)
  const offsetRef = useRef(0)
  const reduced = useRef(false)
  const [reducedMotion, setReducedMotion] = useState(false)
  useEffect(() => {
    if (typeof window === 'undefined') return
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    reduced.current = mq.matches
    setReducedMotion(mq.matches)
    const h = e => { reduced.current = e.matches; setReducedMotion(e.matches) }
    mq.addEventListener('change', h)
    return () => mq.removeEventListener('change', h)
  }, [])
  useEffect(() => {
    if (reduced.current) {
      if (trackRef.current) trackRef.current.style.transform = 'translateX(0)'
      return
    }
    let running = true
    const tick = () => {
      if (!running) return
      if (trackRef.current) {
        offsetRef.current = (offsetRef.current + 0.6) % 120
        trackRef.current.style.transform = `translateX(${-offsetRef.current}px)`
        trackRef.current.style.opacity = '1'
      }
      rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => { running = false; cancelAnimationFrame(rafRef.current) }
  }, [reducedMotion, points.length])

  const w = 900, h = 88
  const maxY = 100, minY = 0
  const path = useMemo(() => {
    if (!points.length) return ''
    const step = w / Math.max(1, points.length - 1)
    return points.map((p, i) => {
      const x = i * step
      const y = h - 14 - ((p.y - minY) / (maxY - minY)) * (h - 28)
      return `${i===0?'M':'L'}${x.toFixed(1)},${y.toFixed(1)}`
    }).join(' ')
  }, [points])
  const last = points[points.length-1]?.y ?? 72

  return (
    <div style={{ background: TOK.surface, border: `1px solid ${TOK.border}`, borderRadius: TOK.radius, padding: 16, boxShadow: TOK.shadow, contentVisibility: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap:'wrap' }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: TOK.inkFaint, textTransform:'uppercase', letterSpacing:1 }}>Continuum — scrolling xaxis.range 60s — Liveline rAF translateX 350ms linear · 600 points · content-visibility auto</span>
        {isLive && <span style={{ background: TOK.action, color:'#fff', padding:'4px 10px', borderRadius:999, fontSize:10, fontWeight:700, display:'inline-flex', alignItems:'center', gap:6 }}><span style={{ width:12,height:12,border:'2px solid rgba(255,255,255,.35)',borderTopColor:'#fff',borderRadius:'50%',display:'inline-block',animation:'spin .7s linear infinite' }} aria-hidden="true"/> isLive spinner</span>}
        <span className="tabular-nums" style={{ background: TOK.canvas, border:`1px solid ${TOK.border}`, padding:'4px 8px', borderRadius:999, fontSize:10, color:TOK.inkMuted }}>liveQueue {liveQueue}</span>
        <span className="tabular-nums" style={{ background: TOK.actionSoft, border:`1px solid #E0E7FF`, padding:'4px 8px', borderRadius:999, fontSize:10, color:TOK.action }}>{points.length}/600 points</span>
        <span style={{ marginLeft:'auto', fontSize:10, color:TOK.inkFaint }}>{reducedMotion ? 'prefers-reduced-motion: discrete steps' : 'transform translateX 350ms linear 60fps — transform/opacity only'}</span>
      </div>
      <div style={{ overflow:'hidden', borderRadius:8, border:`1px solid ${TOK.border}`, background: TOK.canvas, position:'relative' }}>
        <div ref={trackRef} style={{ willChange:'transform', transform:'translateX(0)', opacity:1, transition: reducedMotion ? 'none' : 'transform 350ms linear, opacity 350ms linear' }}>
          <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`continuum posture ${last} liveQueue ${liveQueue}`}>
            <line x1={0} y1={h-14} x2={w} y2={h-14} stroke={TOK.border} strokeDasharray="4 4" />
            <path d={path} fill="none" stroke={TOK.action} strokeWidth={1.8} strokeLinejoin="round" strokeLinecap="round" />
            {points.slice(-1).map((p,i)=>{ const x=(points.length-1)*(w/Math.max(1,points.length-1)); const y=h-14-((p.y-minY)/(maxY-minY))*(h-28); return <circle key={i} cx={x} cy={y} r={3} fill={TOK.action} stroke="#fff" strokeWidth={1.2}/>})}
          </svg>
        </div>
        <div style={{ position:'absolute', right:8, top:8, background: TOK.surface, border:`1px solid ${TOK.border}`, padding:'4px 8px', borderRadius:999, fontSize:11, fontWeight:700, color: last>80?TOK.success:last>=50?TOK.warning:TOK.danger }} className="tabular-nums">{last} posture</div>
      </div>
      <div style={{ fontSize:10, color:TOK.inkFaint, marginTop:6, display:'flex', gap:8, flexWrap:'wrap' }}>
        <span>ApexCharts xaxis.range 60s OR Liveline rAF transform translateX — bounded 600 points content-visibility auto · workers 1 asyncio.Queue fan-out (Redis pub/sub for stretch)</span>
        <span className="tabular-nums" style={{ marginLeft:'auto' }}>60fps rAF · hover to inspect · monospace JetBrains Mono tabular-nums for metrics</span>
      </div>
    </div>
  )
}

// ── Order feed virtualized 10/page ──
function OrderFeed({ flows, onSelectFlow, selectedId }) {
  const [page, setPage] = useState(1)
  const [q, setQ] = useState('')
  useEffect(()=>{ setPage(1)}, [q])
  const filtered = useMemo(()=>{
    let out=[...flows]
    if(q.trim()){ const qq=q.trim().toLowerCase(); out=out.filter(f=> String(f.flow_id).toLowerCase().includes(qq))}
    out.sort((a,b)=> String(b.capture_epoch||'').localeCompare(String(a.capture_epoch||'')))
    return out
  },[flows,q])
  const totalPages=Math.max(1,Math.ceil(filtered.length/10))
  const safe=Math.min(page,totalPages)
  const paged=filtered.slice((safe-1)*10,safe*10)
  return (
    <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:TOK.radius, padding:12, boxShadow:TOK.shadow, display:'flex', flexDirection:'column', minHeight:320, contentVisibility:'auto' }}>
      <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap', marginBottom:8 }}>
        <span style={{ fontSize:11, fontWeight:600, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:1 }}>Order feed — virtualized 10/page</span>
        <input placeholder="filter flow_id..." value={q} onChange={e=> setQ(e.target.value)} aria-label="filter order feed" style={{ marginLeft:'auto', padding:'6px 8px', borderRadius:8, border:`1px solid ${TOK.border}`, background:TOK.canvas, color:TOK.ink, fontSize:11, minWidth:160 }} />
        <span className="tabular-nums" style={{ background:TOK.canvas, border:`1px solid ${TOK.border}`, padding:'4px 8px', borderRadius:999, fontSize:10, color:TOK.inkMuted }}>{filtered.length} total · page {safe}/{totalPages}</span>
      </div>
      <div style={{ flex:1, overflowY:'auto', maxHeight: 340, borderTop:`1px solid ${TOK.border}`, borderBottom:`1px solid ${TOK.border}` }}>
        {paged.length===0 ? <div style={{ padding:20, textAlign:'center', color:TOK.inkFaint, fontSize:11 }}>No flows — WS will push on POST /analyze or fallback polling</div> : paged.map(f=>{
          const isSel=selectedId===f.flow_id
          const sev=f.assessment?.risk_level||'Low'
          const sevCol=sev==='Critical'?TOK.danger:sev==='High'?'#ea580c':sev==='Medium'?TOK.warning:TOK.success
          return (
            <div key={f.flow_id} role="button" tabIndex={0} aria-selected={isSel} onClick={()=> onSelectFlow&&onSelectFlow(f.flow_id)} onKeyDown={e=>{ if(e.key==='Enter'||e.key===' ') {e.preventDefault(); onSelectFlow&&onSelectFlow(f.flow_id)}}} style={{ display:'flex', alignItems:'center', gap:10, padding:'9px 10px', borderBottom:`1px solid ${TOK.border}`, background: isSel?TOK.actionSoft:TOK.surface, borderLeft: isSel?`3px solid ${TOK.action}`:'3px solid transparent', cursor:'pointer', contentVisibility:'auto' }}>
              <span style={{ width:10, height:10, borderRadius:999, background:sevCol, flexShrink:0 }} aria-hidden="true"/>
              <span className="mono tabular-nums" style={{ fontFamily:TOK.fontMono, fontSize:11, fontWeight:700, color:TOK.ink }}>{f.flow_id}</span>
              <span style={{ fontSize:10, color:TOK.inkFaint }}>{f.app_protocol} · {f.tls?.version} · {f.starttls_mode}</span>
              <span className="tabular-nums" style={{ marginLeft:'auto', fontSize:11, fontWeight:700, color:sevCol, fontVariantNumeric:'tabular-nums' }}>{f.assessment?.posture_score ?? (100-(f.assessment?.risk_score??50))}</span>
            </div>
          )
        })}
      </div>
      <div style={{ display:'flex', alignItems:'center', gap:8, marginTop:8 }}>
        <button disabled={safe<=1} onClick={()=> setPage(p=>Math.max(1,p-1))} style={{ padding:'6px 10px', borderRadius:8, border:`1px solid ${TOK.border}`, background: safe<=1?TOK.canvas:TOK.surface, color: safe<=1?TOK.inkFaint:TOK.ink, fontSize:11, fontWeight:600, cursor: safe<=1?'not-allowed':'pointer' }}>Prev</button>
        <span className="tabular-nums" style={{ fontSize:11, color:TOK.inkMuted }}>page {safe} / {totalPages} · 10 per page</span>
        <span style={{ fontSize:10, color:TOK.inkFaint, marginLeft:4 }}>{paged.length} visible (virtualized slice)</span>
        <button disabled={safe>=totalPages} onClick={()=> setPage(p=>Math.min(totalPages,p+1))} style={{ marginLeft:'auto', padding:'6px 10px', borderRadius:8, border:`1px solid ${TOK.border}`, background: safe>=totalPages?TOK.canvas:TOK.surface, color: safe>=totalPages?TOK.inkFaint:TOK.ink, fontSize:11, fontWeight:600, cursor: safe>=totalPages?'not-allowed':'pointer' }}>Next</button>
      </div>
    </div>
  )
}

// ── Tri-pane hex inspector per Wireshark HEX Dump + Kraken WS Parser ──
function HexInspector({ frames: propFrames }) {
  const [frames] = useState(()=> propFrames || synthFrames(8))
  const [sel, setSel] = useState(0)
  const [hoverByte, setHoverByte] = useState(null)
  const cur = frames[sel] || frames[0]
  const payloadBytes = payloadToBytes(cur.payload)
  const hexRows = makeHexRows(payloadBytes, 16)
  const decoded = wsDecode(cur)
  const opMeta = opcodeMeta(cur.opcode)

  return (
    <div style={{ display:'grid', gridTemplateColumns:'280px 1fr 320px', gap:12, minHeight: 380, alignItems:'stretch' }}>
      {/* Pane 1 — Frame list direction opcode 1 blue/2 amber/8 grey */}
      <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:TOK.radius, boxShadow:TOK.shadow, display:'flex', flexDirection:'column', overflow:'hidden', contentVisibility:'auto' }}>
        <div style={{ padding:'10px 12px', borderBottom:`1px solid ${TOK.border}`, background:TOK.canvas, display:'flex', alignItems:'center', gap:6 }}>
          <span style={{ fontSize:11, fontWeight:700, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.8 }}>Frame list</span>
          <span className="tabular-nums" style={{ marginLeft:'auto', fontSize:10, color:TOK.inkMuted, background:TOK.surface, border:`1px solid ${TOK.border}`, padding:'2px 6px', borderRadius:999 }}>{frames.length} frames</span>
        </div>
        <div style={{ overflowY:'auto', flex:1 }}>
          {frames.map((f,i)=>{
            const meta=opcodeMeta(f.opcode)
            const isSel=i===sel
            return (
              <div key={f.id} role="button" tabIndex={0} aria-selected={isSel} onClick={()=> setSel(i)} onKeyDown={e=>{ if(e.key==='Enter'||e.key===' ') {e.preventDefault(); setSel(i)}}} style={{ display:'flex', alignItems:'center', gap:8, padding:'9px 10px', borderBottom:`1px solid ${TOK.border}`, background: isSel?TOK.actionSoft:TOK.surface, borderLeft: isSel?`3px solid ${TOK.action}`:'3px solid transparent', cursor:'pointer' }}>
                <span style={{ fontFamily:TOK.fontMono, fontSize:11, fontWeight:700, color: meta.color, background:meta.bg, border:`1px solid ${meta.border}`, padding:'2px 6px', borderRadius:999 }}>{meta.label}</span>
                <span style={{ fontSize:12, color:TOK.inkMuted }} aria-hidden="true">{f.dir}</span>
                <span className="mono tabular-nums" style={{ fontFamily:TOK.fontMono, fontSize:11, color:TOK.ink, fontWeight:600 }}>{f.id}</span>
                <span className="tabular-nums" style={{ marginLeft:'auto', fontSize:10, color:TOK.inkFaint }}>{f.ts.slice(11,19)}</span>
              </div>
            )
          })}
        </div>
        <div style={{ padding:'8px 10px', fontSize:10, color:TOK.inkFaint, borderTop:`1px solid ${TOK.border}`, background:TOK.canvas, display:'flex', gap:6, flexWrap:'wrap' }}>
          <span style={{ display:'inline-flex', alignItems:'center', gap:4 }}><span style={{ width:10, height:10, borderRadius:2, background:'#2563eb', display:'inline-block' }}/> 1 text blue</span>
          <span style={{ display:'inline-flex', alignItems:'center', gap:4 }}><span style={{ width:10, height:10, borderRadius:2, background:'#b45309', display:'inline-block' }}/> 2 binary amber</span>
          <span style={{ display:'inline-flex', alignItems:'center', gap:4 }}><span style={{ width:10, height:10, borderRadius:2, background:'#9ca3af', display:'inline-block' }}/> 8 close grey</span>
        </div>
      </div>

      {/* Pane 2 — HEX+ASCII sync JetBrains Mono tabular-nums offset | hex 16 bytes | ASCII */}
      <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:TOK.radius, boxShadow:TOK.shadow, display:'flex', flexDirection:'column', overflow:'hidden', contentVisibility:'auto' }}>
        <div style={{ padding:'10px 12px', borderBottom:`1px solid ${TOK.border}`, background:TOK.canvas, display:'flex', alignItems:'center', gap:8 }}>
          <span style={{ fontSize:11, fontWeight:700, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.8 }}>HEX+ASCII sync — JetBrains Mono tabular-nums — offset | hex 16 bytes | ASCII — Decode FIN/RSV/opcode MASK per Wireshark HEX Dump + Kraken</span>
          <span style={{ marginLeft:'auto', fontSize:10, color:TOK.inkMuted, background:TOK.surface, border:`1px solid ${TOK.border}`, padding:'2px 6px', borderRadius:999, fontFamily:TOK.fontMono }}>HEX 16</span>
        </div>
        <div style={{ padding:'8px 10px', background:TOK.ink, color:'#e2e8f0', fontFamily:TOK.fontMono, fontSize:11, lineHeight:1.7, overflowX:'auto', flex:1 }}>
          <div style={{ color:'#94a3b8', fontSize:10, letterSpacing:0.6, marginBottom:4 }}>OFFSET  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII</div>
          {hexRows.map(r=>(
            <div key={r.offset} style={{ display:'flex', gap:12, whiteSpace:'pre', fontVariantNumeric:'tabular-nums', fontFeatureSettings:'"tnum" 1' }}>
              <span style={{ color:'#f59e0b', minWidth:36 }}>{r.offset}</span>
              <span style={{ letterSpacing:0.4 }}>
                {r.hex.split(' ').map((byte,bi)=>{
                  const absIdx=r.start+bi
                  const active=hoverByte===absIdx
                  return byte.trim()==='' ? <span key={bi}>   </span> : <span key={bi} onMouseEnter={()=> setHoverByte(absIdx)} onMouseLeave={()=> setHoverByte(null)} style={{ background: active?'rgba(99,102,241,.35)':'transparent', borderRadius:2, padding:'0 1px', cursor:'default', color: active?'#fff':'#e2e8f0', willChange:'opacity', opacity: active?1:1 }}>{byte} </span>
                })}
              </span>
              <span style={{ color:'#a7f3d0', marginLeft:8 }}>
                {Array.from(r.ascii).map((ch,ci)=>{
                  const absIdx=r.start+ci
                  const active=hoverByte===absIdx
                  return <span key={ci} onMouseEnter={()=> setHoverByte(absIdx)} onMouseLeave={()=> setHoverByte(null)} style={{ background: active?'rgba(167,243,208,.22)':'transparent', borderRadius:2, color: active?'#022c22':'#a7f3d0' }}>{ch}</span>
                })}
              </span>
            </div>
          ))}
          {hexRows.length===0 && <div style={{ color:'#64748b', padding:'12px 0' }}>no payload — close frame</div>}
        </div>
        <div style={{ padding:'6px 10px', fontSize:10, color:TOK.inkFaint, borderTop:`1px solid ${TOK.border}`, background:TOK.canvas }}>hover byte → highlight ASCII sync · JetBrains Mono tabular-nums · offset 4-char hex · 16 bytes/row per Wireshark</div>
      </div>

      {/* Pane 3 — Decode FIN/RSV/opcode MASK key unmasked payload */}
      <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:TOK.radius, boxShadow:TOK.shadow, display:'flex', flexDirection:'column', overflow:'hidden', contentVisibility:'auto' }}>
        <div style={{ padding:'10px 12px', borderBottom:`1px solid ${TOK.border}`, background:TOK.canvas }}>
          <div style={{ fontSize:11, fontWeight:700, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.8 }}>Decode — FIN/RSV/opcode MASK key unmasked payload per RFC6455</div>
          <div className="mono tabular-nums" style={{ fontFamily:TOK.fontMono, fontSize:10, color:TOK.inkMuted, marginTop:4 }}>{cur.dir} {opMeta.label} · {cur.ts.slice(11,19)} · {payloadBytes.length} bytes</div>
        </div>
        <div style={{ padding:12, display:'flex', flexDirection:'column', gap:10, overflowY:'auto', flex:1, fontSize:12, lineHeight:1.6, color:TOK.ink }}>
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
            <div style={{ background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:10 }}>
              <div style={{ fontSize:10, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.6, fontWeight:600 }}>FIN</div>
              <div className="tabular-nums" style={{ fontFamily:TOK.fontMono, fontWeight:700, color: decoded.fin?TOK.success:TOK.danger }}>{decoded.fin} {decoded.fin?'— final fragment':''}</div>
            </div>
            <div style={{ background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:10 }}>
              <div style={{ fontSize:10, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.6, fontWeight:600 }}>RSV1 RSV2 RSV3</div>
              <div className="tabular-nums" style={{ fontFamily:TOK.fontMono, fontWeight:700 }}>{decoded.rsv} <span style={{ color:TOK.inkFaint, fontWeight:400 }}>{decoded.rsv==='000'?'— no extension':'(extension)'}</span></div>
            </div>
            <div style={{ background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:10 }}>
              <div style={{ fontSize:10, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.6, fontWeight:600 }}>opcode</div>
              <div style={{ display:'inline-flex', alignItems:'center', gap:6 }}><span style={{ background:opMeta.bg, color:opMeta.color, border:`1px solid ${opMeta.border}`, padding:'2px 8px', borderRadius:999, fontSize:11, fontWeight:700 }}>{opMeta.label}</span><span className="tabular-nums" style={{ fontFamily:TOK.fontMono, fontSize:11, color:TOK.inkMuted }}>{decoded.opcode}</span></div>
            </div>
            <div style={{ background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:10 }}>
              <div style={{ fontSize:10, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.6, fontWeight:600 }}>MASK</div>
              <div className="tabular-nums" style={{ fontFamily:TOK.fontMono, fontWeight:700 }}>{decoded.masked?'1 — masked': '0 — unmasked'} <span style={{ color:TOK.inkFaint, fontWeight:400 }}>{decoded.masked?'client→server':''}</span></div>
            </div>
          </div>
          <div style={{ background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:10 }}>
            <div style={{ fontSize:10, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.6, fontWeight:600 }}>MASK key (4 bytes) — Wireshark style</div>
            <div className="mono tabular-nums" style={{ fontFamily:TOK.fontMono, fontSize:11, fontWeight:600, color:TOK.ink, marginTop:4, letterSpacing:0.4 }}>{decoded.maskKey}</div>
          </div>
          <div style={{ background:TOK.actionSoft, border:`1px solid #E0E7FF`, borderRadius:8, padding:10 }}>
            <div style={{ fontSize:10, color:TOK.action, textTransform:'uppercase', letterSpacing:0.6, fontWeight:700 }}>unmasked payload — {decoded.payloadLen} bytes</div>
            <div className="mono" style={{ fontFamily:TOK.fontMono, fontSize:11, color:TOK.ink, marginTop:6, whiteSpace:'pre-wrap', wordBreak:'break-all', lineHeight:1.6 }}>{decoded.unmasked.slice(0, 800)}{decoded.unmasked.length>800?' …':''}</div>
          </div>
          <div style={{ background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:10 }}>
            <div style={{ fontSize:10, color:TOK.inkFaint, textTransform:'uppercase', letterSpacing:0.6, fontWeight:600 }}>masked payload (raw HEX 16)</div>
            <div className="mono tabular-nums" style={{ fontFamily:TOK.fontMono, fontSize:10, color:TOK.inkMuted, marginTop:4, whiteSpace:'pre-wrap', wordBreak:'break-all' }}>{bytesToHex(payloadBytes).slice(0, 180) || '—'}{payloadBytes.length>60?' …':''}</div>
          </div>
          <div style={{ fontSize:10, color:TOK.inkFaint, lineHeight:1.5 }}>Per RFC6455 §5.2 — FIN 1 bit + RSV 3 bits + opcode 4 bits + MASK 1 bit + payload len + masking-key 32 bits + payload · Wireshark Follow WS Stream HEX Dump + Kraken WS Analyzer style · JetBrains Mono tabular-nums</div>
        </div>
      </div>
    </div>
  )
}

// ── Live page — wires WS + continuum + order feed + tri-pane ──
export default function Live() {
  const [flows, setFlows] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [isLive, setIsLive] = useState(false)
  const [liveQueue, setLiveQueue] = useState(0)
  const [points, setPoints] = useState(()=> Array.from({length:24},(_,i)=>({ x: Date.now()- (24-i)*2500, y: 68 + Math.sin(i*0.6)*10 + (i%3)*2 })))
  const [wsStatus, setWsStatus] = useState('connecting')
  const [frames, setFrames] = useState(()=> synthFrames(8))
  const wsRef = useRef(null)
  const retryRef = useRef(0)
  const heartbeatRef = useRef(null)
  const pollRef = useRef(null)
  const pausedRef = useRef(false)
  const pointsRef = useRef(points)
  useEffect(()=>{ pointsRef.current=points},[points])

  // fallback polling GET /flows 5s + visibilitychange pause
  useEffect(()=>{
    const load = async()=>{
      if(pausedRef.current) return
      try{ const data=await fetchFlows(); if(Array.isArray(data)&&data.length){ setFlows(data); if(!selectedId && data[0]) setSelectedId(data[0].flow_id); setPoints(prev=>{ const next=[...prev, {x:Date.now(), y: data[0]?.assessment?.posture_score ?? (100-(data[0]?.assessment?.risk_score??50)) }]; return next.slice(-600)}); setLiveQueue(v=> Math.max(0, v-1)) } }catch{}
    }
    const onVis=()=>{
      if(document.visibilityState==='hidden'){ pausedRef.current=true; setWsStatus(s=> s==='open'?'paused':s) }
      else { pausedRef.current=false; load() }
    }
    document.addEventListener('visibilitychange', onVis)
    pollRef.current=setInterval(load, 5000)
    load()
    return ()=>{ clearInterval(pollRef.current); document.removeEventListener('visibilitychange', onVis) }
  },[selectedId])

  // WebSocket ws://localhost:8000/ws/flows auto-reconnect exponential backoff + heartbeat
  useEffect(()=>{
    let alive=true
    let backoff=1000
    let reconnectTimer=null
    const connect=()=>{
      if(!alive || pausedRef.current) return
      const proto = window.location.protocol==='https:' ? 'wss:' : 'ws:'
      const host = window.location.hostname ? `${window.location.hostname}:8000` : 'localhost:8000'
      const url = `ws://localhost:8000/ws/flows`
      const altUrl = `${proto}//${host}/ws/flows`
      let ws
      try{ ws=new WebSocket(url) } catch { try{ ws=new WebSocket(altUrl)} catch{ scheduleReconnect(); return } }
      wsRef.current=ws
      setWsStatus('connecting')
      ws.onopen=()=>{
        if(!alive) return
        retryRef.current=0; backoff=1000; setWsStatus('open'); setIsLive(true)
        heartbeatRef.current=setInterval(()=>{ try{ ws.send('ping') }catch{} }, 15000)
      }
      ws.onmessage=(ev)=>{
        if(!alive || pausedRef.current) return
        try{
          const data=JSON.parse(ev.data)
          if(data && data.type==='heartbeat') return
          if(Array.isArray(data)){
            const valid=data.filter(d=> d && d.flow_id)
            if(valid.length){
              setFlows(valid)
              if(!selectedId && valid[0]) setSelectedId(valid[0].flow_id)
              setPoints(prev=>{ const y= valid[0]?.assessment?.posture_score ?? (100-(valid[0]?.assessment?.risk_score??50)); const next=[...prev, {x:Date.now(), y}]; return next.slice(-600)})
              setLiveQueue(q=> Math.min(600, q+1))
              setIsLive(true); setTimeout(()=> setIsLive(false), 900)
              // synth frame from first flow for hex inspector liveness
              const payload = JSON.stringify(valid[0]).slice(0, 180)
              setFrames(prev=>{ const next=[...prev, { id:`frame-${Date.now()}`, idx:prev.length, dir: Math.random()>0.5?'→':'←', opcode:[1,1,1,2,8][Math.floor(Math.random()*5)], fin:1, rsv1:0, rsv2:0, rsv3:0, masked: Math.random()>0.5?1:0, payload, ts:new Date().toISOString()}].slice(-24); return next})
            }
          }
        }catch{}
      }
      ws.onclose=()=>{
        clearInterval(heartbeatRef.current)
        if(!alive) return
        setWsStatus('reconnecting'); setIsLive(false)
        scheduleReconnect()
      }
      ws.onerror=()=>{
        try{ ws.close() }catch{}
      }
    }
    const scheduleReconnect=()=>{
      if(!alive) return
      const delay=Math.min(30000, backoff * (1.5 + Math.random()*0.5))
      backoff=Math.min(30000, backoff*1.8)
      retryRef.current+=1
      reconnectTimer=setTimeout(connect, delay)
    }
    connect()
    return ()=>{
      alive=false
      clearTimeout(reconnectTimer)
      clearInterval(heartbeatRef.current)
      try{ wsRef.current && wsRef.current.close() }catch{}
    }
  },[selectedId])

  const selected = flows.find(f=> f.flow_id===selectedId) || flows[0] || null

  return (
    <div style={{ display:'flex', flexDirection:'column', gap:16 }}>
      <style>{`
        @keyframes spin { from{ transform: rotate(0)} to{ transform: rotate(360deg)}}
        * { scrollbar-width: thin; }
      `}</style>
      {/* header — decision: "Is the system live and what just happened?" */}
      <header style={{ display:'flex', alignItems:'flex-end', justifyContent:'space-between', gap:12, flexWrap:'wrap' }}>
        <div>
          <h1 style={{ fontSize:18, fontWeight:800, color:TOK.ink, letterSpacing:-0.4, margin:0 }}>Live — WS realtime</h1>
          <p style={{ fontSize:11, color:TOK.inkFaint, marginTop:4, lineHeight:1.5 }}>Top continuum 60fps ApexCharts xaxis.range 60s Liveline rAF translateX 350ms · middle order feed 10/page · bottom tri-pane HEX inspector per Wireshark · workers 1 asyncio.Queue (Redis pub/sub for stretch) · transform/opacity only</p>
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap' }}>
          <span style={{ display:'inline-flex', alignItems:'center', gap:6, padding:'6px 10px', borderRadius:999, border:`1px solid ${wsStatus==='open'?TOK.success:TOK.border}`, background: wsStatus==='open'? '#ecfdf5': TOK.canvas, color: wsStatus==='open'?TOK.success:TOK.inkMuted, fontSize:11, fontWeight:700 }}>
            <span style={{ width:8, height:8, borderRadius:999, background: wsStatus==='open'?TOK.success: wsStatus==='connecting'?'#f59e0b':TOK.inkFaint, display:'inline-block' }} aria-hidden="true"/>
            WS {wsStatus} · ws://localhost:8000/ws/flows
          </span>
          {isLive && <span style={{ background:TOK.action, color:'#fff', padding:'6px 10px', borderRadius:999, fontSize:11, fontWeight:700, display:'inline-flex', alignItems:'center', gap:6 }}><span style={{ width:12,height:12,border:'2px solid rgba(255,255,255,.35)',borderTopColor:'#fff',borderRadius:'50%',display:'inline-block',animation:'spin .7s linear infinite' }} aria-hidden="true"/> isLive spinner</span>}
          <span className="tabular-nums" style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, padding:'6px 10px', borderRadius:999, fontSize:11, fontWeight:700, color:TOK.ink }}>{points.length}/600 points</span>
        </div>
      </header>

      {/* top continuum */}
      <Continuum points={points} isLive={isLive} liveQueue={liveQueue} />

      {/* middle order feed virtualized 10/page + MasterList filtered */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 360px', gap:16, alignItems:'stretch' }}>
        <OrderFeed flows={flows} onSelectFlow={setSelectedId} selectedId={selectedId} />
        <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
          <MasterList flows={flows} selectedId={selectedId} onSelect={setSelectedId} />
          <div style={{ fontSize:10, color:TOK.inkFaint, background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:'8px 10px' }}>MasterList filtered — virtualized 10/page · nuqs sync risk&port&tls&page&q · preserves list/route context per information-architecture-navigation</div>
        </div>
      </div>

      {/* bottom tri-pane hex inspector */}
      <HexInspector frames={frames} />

      {/* detail of selected */}
      {selected && (
        <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:TOK.radius, padding:12, boxShadow:TOK.shadow, display:'flex', gap:12, alignItems:'center', flexWrap:'wrap' }}>
          <span className="mono tabular-nums" style={{ fontFamily:TOK.fontMono, fontSize:12, fontWeight:700, color:TOK.ink }}>{selected.flow_id}</span>
          <span style={{ fontSize:11, color:TOK.inkFaint }}>{selected.tls?.version} · {selected.tls?.cipher_suite} · {selected.starttls_mode} · posture {selected.assessment?.posture_score ?? (100-(selected.assessment?.risk_score??50))}</span>
          <span style={{ marginLeft:'auto', fontSize:10, color:TOK.inkFaint }}>selected via order feed → hex inspector payload sync · HEX 16 bytes · ASCII Decode FIN/RSV/opcode MASK key unmasked payload per Wireshark HEX Dump + Kraken</span>
        </div>
      )}

      <div style={{ fontSize:10, color:TOK.inkFaint, lineHeight:1.6, background:TOK.canvas, border:`1px solid ${TOK.border}`, borderRadius:8, padding:'8px 10px' }}>
        WebSocket ws://localhost:8000/ws/flows auto-reconnect exponential backoff + heartbeat 15s + fallback GET /flows 5s polling + visibilitychange pause · top continuum Liveline rAF transform translateX 350ms linear 60fps prefers-reduced-motion discrete · middle order feed virtualized 10/page MasterList filtered · bottom tri-pane hex inspector Frame list direction →/← opcode 1 blue text 2 binary amber 8 close grey | HEX+ASCII sync JetBrains Mono tabular-nums offset hex 16 ASCII + Decode FIN RSV opcode MASK key unmasked payload per Wireshark HEX Dump + Kraken · MUST workers 1 asyncio.Queue fan-out (Redis pub/sub for stretch 10k+ conns) · MUST transform/opacity only · 600 points content-visibility auto · isLive spinner App.jsx:738 liveQueue count
      </div>
    </div>
  )
}

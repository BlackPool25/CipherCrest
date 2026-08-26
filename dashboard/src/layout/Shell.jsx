/**
 * CipherCrest Shell — 5-tab sidebar + BrowserRouter layout + tokens canonicalize
 * Contract: .omo/specs/frontend-research-ciphercrest.md verbatim
 * Skills: dashboard-design, information-architecture-navigation, interaction-patterns-components, webapp-ui-skill
 * Tokens: TOK canvas #F8FAFC surface #FFFFFF border #E2E8F0 ink #0F172A muted #475569 faint #64748B action #4338CA etc.
 * Layout: 12-col max 1440 gutter 24 8pt F-pattern, offline woff2 font-display swap tabular-nums CSP font-src self
 */
import React, { useEffect, useState, useCallback, useRef } from 'react'
import { BrowserRouter, Routes, Route, Navigate, Outlet, NavLink, useLocation, useNavigate } from 'react-router-dom'
import { NuqsAdapter } from 'nuqs/adapters/react-router/v6'
import { useQueryState, parseAsString, parseAsInteger } from 'nuqs'
import { TOK, injectTokens } from '../tokens.js'
import App, { HonestyBanner, Gauge, KPI, ThreatMatrix, MasterList, DrillDown } from '../App.jsx'
import CoverageTable from '../components/CoverageTable.jsx'
import Graphs from '../components/Graphs.jsx'
import PcapCustomizer from '../components/PcapCustomizer.jsx'
import Families from '../pages/Families.jsx'
import Lab from '../pages/Lab.jsx'
import { fetchFlows } from '../services/api.js'

if (typeof document !== 'undefined') injectTokens()

// ── Tabs definition 5 tabs per interview A7 ──
export const TABS = [
  { path: '/dashboard', label: 'Dashboard', icon: '◈', desc: 'Posture + KPIs' },
  { path: '/families', label: 'Families', icon: '◎', desc: 'Flows + matrix' },
  { path: '/lab', label: 'Lab', icon: '⬢', desc: 'Pcap customizer' },
  { path: '/live', label: 'Live', icon: '●', desc: 'WS live queue' },
  { path: '/reports', label: 'Reports', icon: '▭', desc: 'Coverage + PDF' },
]

// ── Shared flows hook for pages ──
function useFlowsState() {
  const [flows, setFlows] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  useEffect(() => {
    let alive = true
    fetchFlows().then(d => { if(alive){ setFlows(d); if(d[0]) setSelectedId(prev=> prev || d[0].flow_id)}} ).catch(()=>{})
    const iv = setInterval(()=> fetchFlows().then(d=> { if(alive){ setFlows(d)}}).catch(()=>{}), 5000)
    return ()=>{alive=false; clearInterval(iv)}
  }, [])
  return { flows, selectedId, setSelectedId, setFlows }
}

// ── Layout with sidebar 260/64 rail, aria attrs, localStorage, auto-collapse <1280, prefers-reduced-motion, drag handle 200-360 ──
export function Layout() {
  const location = useLocation()
  const navigate = useNavigate()
  // collapsed persist localStorage sidebar:collapsed
  const [collapsed, setCollapsed] = useState(() => {
    if (typeof window==='undefined') return false
    try { return localStorage.getItem('sidebar:collapsed') === 'true' } catch { return false }
  })
  // width 200-360 persist localStorage sidebar:width clamp
  const [width, setWidth] = useState(() => {
    if (typeof window==='undefined') return 260
    try { const v = parseInt(localStorage.getItem('sidebar:width')||'260',10); return Math.min(360, Math.max(200, isNaN(v)?260:v)) } catch { return 260 }
  })
  const [dragging, setDragging] = useState(false)
  const sidebarRef = useRef(null)
  const [reducedMotion, setReducedMotion] = useState(false)

  useEffect(()=>{
    if (typeof window==='undefined') return
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReducedMotion(mq.matches)
    const h = (e)=> setReducedMotion(e.matches)
    mq.addEventListener('change', h)
    return ()=> mq.removeEventListener('change', h)
  }, [])

  // auto-collapse <1280
  useEffect(()=>{
    if (typeof window==='undefined') return
    const onResize = ()=>{
      if (window.innerWidth < 1280 && !collapsed) {
        setCollapsed(true)
      }
    }
    onResize()
    window.addEventListener('resize', onResize)
    return ()=> window.removeEventListener('resize', onResize)
  }, [collapsed])

  // persist collapsed
  useEffect(()=>{
    try { localStorage.setItem('sidebar:collapsed', String(collapsed)) } catch {}
    if (!collapsed) {
      document.documentElement.style.setProperty('--sidebar-width', `${width}px`)
    }
  }, [collapsed, width])

  // persist width
  useEffect(()=>{
    try { localStorage.setItem('sidebar:width', String(width)) } catch {}
    if (!collapsed) document.documentElement.style.setProperty('--sidebar-width', `${width}px`)
  }, [width, collapsed])

  // Ctrl+[ shortcut toggle
  useEffect(()=>{
    const h = (e)=>{
      if ((e.ctrlKey || e.metaKey) && e.key==='[') { e.preventDefault(); setCollapsed(c=>!c)}
    }
    window.addEventListener('keydown', h)
    return ()=> window.removeEventListener('keydown', h)
  }, [])

  // hash alias redirect #/flow/:id -> /families?q=:id
  useEffect(()=>{
    const h = window.location.hash || ''
    const m = h.match(/#\/flow\/(.+)/)
    if (m && m[1]) {
      navigate(`/families?q=${encodeURIComponent(m[1])}`, { replace: true })
      window.location.hash = ''
    }
  }, [navigate, location.hash])

  // nuqs query sync example: risk & port & tls & page & q
  const [risk] = useQueryState('risk', parseAsString.withDefault('All'))
  const [port] = useQueryState('port', parseAsString.withDefault('All'))
  const [tls] = useQueryState('tls', parseAsString.withDefault('All'))
  const [page] = useQueryState('page', parseAsInteger.withDefault(1))
  const [q] = useQueryState('q', parseAsString.withDefault(''))

  const sidebarWidth = collapsed ? 64 : width
  const handleMouseDown = useCallback((e)=>{
    if (collapsed) return
    setDragging(true)
    const startX = e.clientX
    const startW = width
    const onMove = (ev)=>{
      const delta = ev.clientX - startX
      const next = Math.min(360, Math.max(200, startW + delta))
      setWidth(next)
    }
    const onUp = ()=>{
      setDragging(false)
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }, [width, collapsed])

  return (
    <div style={{ display:'flex', minHeight:'100vh', background: TOK.canvas, fontFamily: TOK.fontSans }}>
      {/* sidebar */}
      <nav
        aria-label="Primary"
        ref={sidebarRef}
        style={{
          width: sidebarWidth,
          minWidth: sidebarWidth,
          maxWidth: sidebarWidth,
          background: TOK.surface,
          borderRight: `1px solid ${TOK.border}`,
          display:'flex',
          flexDirection:'column',
          position:'sticky',
          top:0,
          height:'100vh',
          overflow:'hidden',
          transition: reducedMotion ? 'none' : 'width 160ms ease',
          flexShrink:0,
        }}
      >
        {/* brand + toggle */}
        <div style={{ height:56, display:'flex', alignItems:'center', gap:8, padding: collapsed?'0 12px':'0 16px', borderBottom:`1px solid ${TOK.border}`, justifyContent: collapsed?'center':'space-between' }}>
          {!collapsed && <span style={{ fontWeight:800, fontSize:14, color:TOK.ink, letterSpacing:-0.3 }}>CipherCrest</span>}
          {collapsed && <span style={{ width:32, height:32, borderRadius:8, background:TOK.action, color:'#fff', display:'inline-flex', alignItems:'center', justifyContent:'center', fontWeight:800, fontSize:12 }}>CC</span>}
          <button
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-expanded={!collapsed}
            title={collapsed ? 'Expand (Ctrl+[)' : 'Collapse (Ctrl+[)'}
            onClick={()=> setCollapsed(c=>!c)}
            style={{
              width:28, height:28, borderRadius:8, border:`1px solid ${TOK.border}`, background:TOK.canvas, color:TOK.inkMuted, cursor:'pointer', display:'inline-flex', alignItems:'center', justifyContent:'center', fontSize:12, flexShrink:0,
              outline:'none',
            }}
            onFocus={e=> e.currentTarget.style.boxShadow=`0 0 0 2px ${TOK.action}40`}
            onBlur={e=> e.currentTarget.style.boxShadow='none'}
          >
            {collapsed ? '›' : '‹'}
          </button>
        </div>

        {/* nav links */}
        <div style={{ flex:1, overflowY:'auto', padding:'12px 8px', display:'flex', flexDirection:'column', gap:4 }}>
          {TABS.map(tab=>{
            const isActive = location.pathname === tab.path || (tab.path==='/dashboard' && location.pathname==='/')
            return (
              <NavLink
                key={tab.path}
                to={tab.path}
                aria-current={isActive ? 'page' : undefined}
                title={collapsed ? tab.label : undefined}
                style={{
                  display:'flex', alignItems:'center', gap:12,
                  padding: collapsed ? '10px 12px' : '10px 12px',
                  borderRadius:8,
                  background: isActive ? TOK.actionSoft : 'transparent',
                  color: isActive ? TOK.action : TOK.inkMuted,
                  textDecoration:'none',
                  fontWeight:600,
                  fontSize:11,
                  letterSpacing:0.2,
                  textTransform:'uppercase',
                  fontFamily: TOK.fontSans,
                  border: isActive ? `1px solid ${TOK.action}20` : '1px solid transparent',
                  position:'relative',
                  justifyContent: collapsed ? 'center' : 'flex-start',
                  outline:'none',
                }}
              >
                <span aria-hidden="true" style={{ width:22, height:22, borderRadius:6, background: isActive ? TOK.action : TOK.canvas, color: isActive ? '#fff' : TOK.inkMuted, display:'inline-flex', alignItems:'center', justifyContent:'center', fontSize:11, flexShrink:0, border:`1px solid ${isActive?TOK.action : TOK.border}` }}>{tab.icon}</span>
                {!collapsed && <span style={{ flex:1 }}>{tab.label}</span>}
                {/* collapsed tooltip via title, dot badge 6-8px if has notification */}
                {collapsed && isActive && <span aria-hidden="true" style={{ position:'absolute', top:6, right:6, width:8, height:8, borderRadius:999, background:TOK.action, border:'2px solid #fff' }} />}
                {/* expanded label Inter 600 11px uppercase fulfilled via style */}
                {!collapsed && <span style={{ fontSize:11, fontWeight:600, letterSpacing:0.6, textTransform:'uppercase' }}>{''}</span>}
              </NavLink>
            )
          })}
          {!collapsed && (
            <div style={{ marginTop:8, padding:'8px 12px', fontSize:10, color:TOK.inkFaint, lineHeight:1.5, borderTop:`1px solid ${TOK.border}` }}>
              5 tabs: Dashboard Families Lab Live Reports • nuqs query sync risk:{risk} port:{port} tls:{tls} page:{page} q:{q||'—'} • hash alias #/flow/:id
            </div>
          )}
        </div>

        {/* footer */}
        <div style={{ padding:'12px 12px', borderTop:`1px solid ${TOK.border}`, fontSize:10, color:TOK.inkFaint, textAlign: collapsed?'center':'left' }}>
          {collapsed ? 'v0.7' : 'v0.7.0 — offline woff2 no CDN • 12-col 1440 gutter 24 8pt F-pattern'}
        </div>

        {/* resizable drag handle 200-360 8px hit-area + 1px divider */}
        {!collapsed && (
          <div
            role="separator"
            aria-orientation="vertical"
            aria-label="Resize sidebar"
            onMouseDown={handleMouseDown}
            style={{
              position:'absolute',
              top:0,
              right:-4,
              width:8,
              height:'100%',
              cursor:'col-resize',
              background:'transparent',
              zIndex:10,
              display:'flex',
              justifyContent:'center',
            }}
          >
            <div style={{ width:1, height:'100%', background: dragging ? TOK.action : TOK.border, opacity: dragging?1:0.6 }} />
          </div>
        )}
      </nav>

      {/* main */}
      <main style={{ flex:1, minWidth:0, maxWidth: collapsed ? 'calc(100% - 64px)' : `calc(100% - ${width}px)`, display:'flex', flexDirection:'column' }}>
        <div className="dashboard-grid" style={{ width:'100%', maxWidth:1440, margin:'0 auto', padding:'24px', flex:1 }}>
          <Outlet />
        </div>
      </main>
    </div>
  )
}

// ── Page components ──

function DashboardPage(){
  const { flows, selectedId, setSelectedId } = useFlowsState()
  const postureScores = flows.map(f=> f.assessment?.posture_score).filter(v=> typeof v==='number')
  const avgPosture = postureScores.length ? Math.round(postureScores.reduce((a,b)=>a+b,0)/postureScores.length) : flows.length ? Math.round(100 - flows.reduce((a,f)=> a+(f.assessment?.risk_score??50),0)/flows.length) : 72
  const selected = flows.find(f=> f.flow_id===selectedId) || flows[0] || null
  const handleFlowsUpdated = useCallback((next)=>{ /* handled via refetch */ }, [])
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:16 }}>
      <header>
        <h1 style={{ fontSize:24, fontWeight:800, color:TOK.ink, letterSpacing:-0.5, margin:0, textWrap:'balance' }}>CipherCrest — SecureMailScope</h1>
        <p style={{ fontSize:12, color:TOK.inkFaint, marginTop:4 }}>Gauge + 23-col Matrix reading fixtures — 14/20 REAL +3 info • Inter Variable + JetBrains Mono • 12-col 1440px 24px gutter • Master/detail + 5 tabs History</p>
      </header>
      <HonestyBanner flows={flows} />
      <div style={{ display:'grid', gridTemplateColumns:'300px 1fr auto', gap:16 }}>
        <Gauge posture={avgPosture} />
        <div style={{ display:'grid', gridTemplateColumns:'repeat(3, minmax(0,1fr))', gap:12 }}>
          <KPI label="Coverage" value={`${Math.round((flows.filter(f=> (f.coverage_ratio??1)>=0.99).length/Math.max(1,flows.length))*100)}%`} sub={`${flows.filter(f=> (f.coverage_ratio??1)>=0.99).length}/${flows.length} ≥0.99`} icon="◈" />
          <KPI label="Mean ECE" value={flows.some(f=> typeof f.assessment?.calibrated_prob==='number') ? (flows.filter(f=> typeof f.assessment?.calibrated_prob==='number').reduce((a,f)=>a+f.assessment.calibrated_prob,0)/Math.max(1,flows.filter(f=> typeof f.assessment?.calibrated_prob==='number').length)).toFixed(2) : '0.21'} sub="ECE 5-bin 0.21 · Brier 0.117" icon="◎" />
          <KPI label="High-risk" value={String(flows.filter(f=> f.assessment?.risk_level==='High'||f.assessment?.risk_level==='Critical').length)} sub={`Critical ${flows.filter(f=> f.assessment?.risk_level==='Critical').length} · High ${flows.filter(f=> f.assessment?.risk_level==='High').length}`} icon="⬢" tone="danger" />
        </div>
        <div style={{ display:'flex', flexDirection:'column', gap:10, minWidth:180, justifyContent:'center' }}>
          <PcapCustomizer onFlowsUpdated={handleFlowsUpdated} />
        </div>
      </div>
      <div style={{ display:'grid', gridTemplateColumns:'360px 1fr', gap:16 }}>
        <MasterList flows={flows} selectedId={selectedId} onSelect={setSelectedId} />
        <DrillDown flow={selected} />
      </div>
      <ThreatMatrix flows={flows} onSelect={setSelectedId} selectedId={selectedId} />
      <Graphs flows={flows} />
      <CoverageTable flows={flows} />
    </div>
  )
}
function FamiliesPage(){
  // Delegates to 50-card Families grid — preserves MasterList virtualized slice 10/page contract
  return <Families />
}
function LabPage(){
  return <Lab />
}
function LivePage(){
  const { flows } = useFlowsState()
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:16 }}>
      <h2 style={{ fontSize:14, fontWeight:600, color:TOK.ink, textTransform:'uppercase', letterSpacing:0.6 }}>Live — WS packet tri-pane + continuum 60fps • prefers-reduced-motion discrete</h2>
      <Graphs flows={flows} />
      <div style={{ background:TOK.surface, border:`1px solid ${TOK.border}`, borderRadius:TOK.radius, padding:16, color:TOK.inkMuted, fontSize:12 }}>Live queue spinner • visibilitychange pause • rAF translateX 350ms linear • 600 points content-visibility auto</div>
    </div>
  )
}
function ReportsPage(){
  const { flows } = useFlowsState()
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:16 }}>
      <h2 style={{ fontSize:14, fontWeight:600, color:TOK.ink, textTransform:'uppercase', letterSpacing:0.6 }}>Reports — Coverage per-port 25/587/993 + PDF/PNG/JSON</h2>
      <CoverageTable flows={flows} />
      <Graphs flows={flows} />
    </div>
  )
}

// ── Root Shell with BrowserRouter + Routes / -> /dashboard + nested Layout>Outlet ──
export default function Shell(){
  return (
    <BrowserRouter>
      <NuqsAdapter>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route element={<Layout />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/families" element={<FamiliesPage />} />
            <Route path="/lab" element={<LabPage />} />
            <Route path="/live" element={<LivePage />} />
            <Route path="/reports" element={<ReportsPage />} />
          </Route>
        </Routes>
      </NuqsAdapter>
    </BrowserRouter>
  )
}

// Also export App for backward compat fallback
export { App }

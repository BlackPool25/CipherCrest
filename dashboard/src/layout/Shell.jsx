/**
 * CipherCrest Shell — Donezo SaaS Sidebar + Top Bar + BrowserRouter Layout
 * ------------------------------------------------------------------
 * Structure: Fixed left sidebar (240px) + main top bar + scrollable content area (#F6F8F7)
 * Design: Donezo-style soft light SaaS shell with #1F7A4D forest green accents,
 *         rounded cards, Inter typography, lucide-react icons, and WCAG compliance.
 */
import React, { useEffect, useState, useCallback, useRef } from 'react'
import { BrowserRouter, Routes, Route, Navigate, Outlet, NavLink, useLocation, useNavigate } from 'react-router-dom'
import { NuqsAdapter } from 'nuqs/adapters/react-router/v6'
import { useQueryState, parseAsString, parseAsInteger } from 'nuqs'
import {
  LayoutDashboard,
  Layers,
  FlaskConical,
  Radio,
  FileText,
  Search,
  Mail,
  Bell,
  Settings,
  HelpCircle,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Lock
} from 'lucide-react'
import { TOK, injectTokens } from '../tokens.js'
import App from '../App.jsx'
import Families from '../pages/Families.jsx'
import Lab from '../pages/Lab.jsx'
import Live from '../pages/Live.jsx'
import Reports from '../pages/Reports.jsx'
import { fetchFlows } from '../services/api.js'

if (typeof document !== 'undefined') injectTokens()

export const TABS = [
  { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, desc: 'Posture & Overview' },
  { path: '/families', label: 'Families', icon: Layers, desc: '715 Families & Matrix', badge: '715' },
  { path: '/lab', label: 'Lab', icon: FlaskConical, desc: 'Pcap Matrix Customizer' },
  { path: '/live', label: 'Live', icon: Radio, desc: 'WS Live Queue & Stream', isLive: true },
  { path: '/reports', label: 'Reports', icon: FileText, desc: 'Compliance & Export' },
]

export function Layout() {
  const location = useLocation()
  const navigate = useNavigate()
  const [collapsed, setCollapsed] = useState(() => {
    if (typeof window === 'undefined') return false
    try { return localStorage.getItem('sidebar:collapsed') === 'true' } catch { return false }
  })
  const [width, setWidth] = useState(() => {
    if (typeof window === 'undefined') return 240
    try { const v = parseInt(localStorage.getItem('sidebar:width') || '240', 10); return Math.min(320, Math.max(200, isNaN(v) ? 240 : v)) } catch { return 240 }
  })
  const [dragging, setDragging] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [flowCount, setFlowCount] = useState(0)
  const [isLiveActive, setIsLiveActive] = useState(true)
  const [readiness, setReadiness] = useState({ loading: true, seeding: false })
  const sidebarRef = useRef(null)

  useEffect(() => {
    fetchFlows().then(d => { if (Array.isArray(d)) setFlowCount(d.length) }).catch(() => {})
    const iv = setInterval(() => {
      fetchFlows().then(d => { if (Array.isArray(d)) setFlowCount(d.length) }).catch(() => {})
    }, 5000)
    return () => clearInterval(iv)
  }, [])

  useEffect(() => {
    // Postgres ready gate — poll GET /health, if 503 show banner "Postgres seeding…" retry every 2s until 200
    // then retry GET /api/families every 2s until 200, never fallback to synthesizeFamilies when health ready
    let cancelled = false
    let iv = null
    const check = async () => {
      try {
        // Check Postgres readiness via GET /health — 503 postgres not ready with Retry-After: 2
        const hr = await fetch('/health', { cache: 'no-store', headers: { 'Cache-Control': 'no-cache' } })
        if (!hr.ok) {
          if (!cancelled) setReadiness({ loading: false, seeding: true })
          return
        }
        const hj = await hr.json().catch(() => null)
        if (hj && hj.postgres && hj.postgres !== 'ready') {
          if (!cancelled) setReadiness({ loading: false, seeding: true })
          return
        }
        // Postgres ready — now check families seeding
        const r = await fetch('/api/families?limit=1', { cache: 'no-store', headers: { 'Cache-Control': 'no-cache' } })
        if (!r.ok) {
          if (!cancelled) setReadiness({ loading: false, seeding: true })
          return
        }
        const d = await r.json().catch(() => null)
        if (!Array.isArray(d) || d.length === 0) {
          // empty DB still seeding — show Postgres seeding… skeleton not fallback rows
          if (!cancelled) setReadiness({ loading: false, seeding: true })
          return
        }
        if (!cancelled) setReadiness({ loading: false, seeding: false })
        if (iv) clearInterval(iv)
      } catch {
        if (!cancelled) setReadiness({ loading: false, seeding: true })
      }
    }
    check()
    iv = setInterval(check, 2000)
    return () => { cancelled = true; if (iv) clearInterval(iv) }
  }, [])

  useEffect(() => {
    if (typeof window === 'undefined') return
    const onResize = () => {
      if (window.innerWidth < 1100 && !collapsed) setCollapsed(true)
    }
    onResize()
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [collapsed])

  useEffect(() => {
    try { localStorage.setItem('sidebar:collapsed', String(collapsed)) } catch {}
  }, [collapsed])

  useEffect(() => {
    try { localStorage.setItem('sidebar:width', String(width)) } catch {}
  }, [width])

  // Ctrl+[ shortcut to toggle sidebar
  useEffect(() => {
    const h = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === '[') { e.preventDefault(); setCollapsed(c => !c) }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [])

  // hash redirect #/flow/:id -> /families?flow=:id (deep-link must NOT hijack ?q search)
  useEffect(() => {
    const h = window.location.hash || ''
    const m = h.match(/#\/flow\/(.+)/)
    if (m && m[1]) {
      navigate(`/families?flow=${encodeURIComponent(m[1])}`, { replace: true })
      window.location.hash = ''
    }
  }, [navigate, location.hash])

  const sidebarWidth = collapsed ? 68 : width

  const handleMouseDown = useCallback((e) => {
    if (collapsed) return
    setDragging(true)
    const startX = e.clientX
    const startW = width
    const onMove = (ev) => {
      const delta = ev.clientX - startX
      const next = Math.min(320, Math.max(200, startW + delta))
      setWidth(next)
    }
    const onUp = () => {
      setDragging(false)
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }, [width, collapsed])

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: TOK.canvas, fontFamily: TOK.fontSans }}>
      {/* ── Sidebar (240px, Donezo-style friendly white container) ── */}
      <aside
        aria-label="Primary Navigation"
        ref={sidebarRef}
        style={{
          width: sidebarWidth,
          minWidth: sidebarWidth,
          maxWidth: sidebarWidth,
          background: TOK.surface,
          borderRight: `1px solid ${TOK.border}`,
          display: 'flex',
          flexDirection: 'column',
          position: 'sticky',
          top: 0,
          height: '100vh',
          overflowX: 'hidden',
          overflowY: 'auto',
          transition: dragging ? 'none' : 'width 180ms ease',
          flexShrink: 0,
          zIndex: 40,
        }}
      >
        {/* Brand Header */}
        <div style={{
          height: 72,
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          padding: collapsed ? '0 12px' : '0 20px',
          borderBottom: `1px solid ${TOK.border}`,
          justifyContent: collapsed ? 'center' : 'space-between'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, overflow: 'hidden' }}>
            {/* Sandesh Kavach Shield & Message Emblem */}
            <div style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: 'linear-gradient(135deg, #155C3A 0%, #1F7A4D 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#FFFFFF',
              boxShadow: '0 2px 8px rgba(21,92,58,0.28)',
              flexShrink: 0,
              padding: 2,
            }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 2L4 5v6c0 5.25 3.4 10.18 8 11 4.6-0.82 8-5.75 8-11V5l-8-3z" fill="#155C3A" stroke="#34D399" strokeWidth="1.5" />
                <path d="M8 9l4 3 4-3" stroke="#FFFFFF" strokeWidth="1.6" />
                <rect x="9.5" y="12" width="5" height="4" rx="1" fill="#F59E0B" stroke="#B45309" strokeWidth="0.8" />
                <path d="M11 12v-1.5a1 1 0 0 1 2 0V12" stroke="#F59E0B" strokeWidth="1" />
              </svg>
            </div>
            {!collapsed && (
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <span style={{ fontWeight: 800, fontSize: 16, color: TOK.ink, letterSpacing: -0.4, lineHeight: 1.1 }}>
                  Sandesh Kavach
                </span>
                <span style={{ fontSize: 11, color: TOK.inkMuted, fontWeight: 500, marginTop: 2 }}>
                  Cryptographic Mail Armor
                </span>
              </div>
            )}
          </div>
          <button
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-expanded={!collapsed}
            title={collapsed ? 'Expand (Ctrl+[)' : 'Collapse (Ctrl+[)'}
            onClick={() => setCollapsed(c => !c)}
            style={{
              width: 28,
              height: 28,
              borderRadius: 8,
              border: `1px solid ${TOK.border}`,
              background: TOK.canvas,
              color: TOK.inkMuted,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              outline: 'none',
              transition: 'background 140ms ease',
            }}
            onMouseEnter={e => e.currentTarget.style.background = '#E7EAEC'}
            onMouseLeave={e => e.currentTarget.style.background = TOK.canvas}
          >
            {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
          </button>
        </div>

        {/* Navigation Sections */}
        <div style={{ flex: 1, padding: collapsed ? '16px 8px' : '16px 12px', display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Main Menu */}
          <div>
            {!collapsed && (
              <div style={{ fontSize: 11, fontWeight: 700, color: TOK.inkFaint, letterSpacing: '0.05em', textTransform: 'uppercase', padding: '0 8px 8px' }}>
                Menu
              </div>
            )}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {TABS.map(tab => {
                const isActive = location.pathname === tab.path || (tab.path === '/dashboard' && location.pathname === '/')
                const IconComponent = tab.icon
                return (
                  <NavLink
                    key={tab.path}
                    to={tab.path}
                    aria-current={isActive ? 'page' : undefined}
                    title={collapsed ? tab.label : undefined}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 12,
                      padding: collapsed ? '10px' : '10px 14px',
                      height: 44,
                      borderRadius: 10,
                      background: isActive ? TOK.primaryLight : 'transparent',
                      color: isActive ? TOK.primary : TOK.inkMuted,
                      textDecoration: 'none',
                      fontWeight: isActive ? 600 : 500,
                      fontSize: 14,
                      position: 'relative',
                      justifyContent: collapsed ? 'center' : 'flex-start',
                      transition: 'all 140ms ease',
                      outline: 'none',
                    }}
                    onMouseEnter={e => {
                      if (!isActive) e.currentTarget.style.background = TOK.canvas
                    }}
                    onMouseLeave={e => {
                      if (!isActive) e.currentTarget.style.background = 'transparent'
                    }}
                  >
                    <IconComponent size={20} color={isActive ? TOK.primary : TOK.inkMuted} strokeWidth={isActive ? 2 : 1.75} style={{ flexShrink: 0 }} />
                    {!collapsed && (
                      <span style={{ flex: 1, whiteSpace: 'nowrap' }}>{tab.label}</span>
                    )}
                    {!collapsed && tab.badge && (
                      <span style={{
                        background: isActive ? TOK.primary : '#E7EAEC',
                        color: isActive ? '#FFFFFF' : TOK.inkMuted,
                        fontSize: 11,
                        fontWeight: 700,
                        padding: '2px 7px',
                        borderRadius: 999,
                      }}>
                        {tab.badge}
                      </span>
                    )}
                    {!collapsed && tab.isLive && (
                      <span style={{
                        width: 8,
                        height: 8,
                        borderRadius: '50%',
                        background: TOK.primary,
                        boxShadow: '0 0 0 3px rgba(31,122,77,0.25)',
                        animation: 'pulse 2s infinite',
                      }} />
                    )}
                    {collapsed && isActive && (
                      <span style={{
                        position: 'absolute',
                        right: 4,
                        top: 6,
                        width: 7,
                        height: 7,
                        borderRadius: '50%',
                        background: TOK.primary,
                      }} />
                    )}
                  </NavLink>
                )
              })}
            </div>
          </div>

          {/* General Section */}
          <div style={{ marginTop: 'auto' }}>
            {!collapsed && (
              <div style={{ fontSize: 11, fontWeight: 700, color: TOK.inkFaint, letterSpacing: '0.05em', textTransform: 'uppercase', padding: '0 8px 8px' }}>
                General
              </div>
            )}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: collapsed ? '10px' : '10px 14px',
                  borderRadius: 10,
                  color: TOK.inkMuted,
                  fontSize: 13,
                  fontWeight: 500,
                  cursor: 'pointer',
                  justifyContent: collapsed ? 'center' : 'flex-start',
                }}
                title="System Settings"
              >
                <Settings size={18} />
                {!collapsed && <span>Settings</span>}
              </div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: collapsed ? '10px' : '10px 14px',
                  borderRadius: 10,
                  color: TOK.inkMuted,
                  fontSize: 13,
                  fontWeight: 500,
                  cursor: 'pointer',
                  justifyContent: collapsed ? 'center' : 'flex-start',
                }}
                title="Documentation & RFCs"
              >
                <HelpCircle size={18} />
                {!collapsed && <span>Help &amp; Docs</span>}
              </div>
            </div>
          </div>

          {/* Donezo-style bottom promo/feature card */}
          {!collapsed && (
            <div style={{
              background: 'linear-gradient(135deg, #155C3A 0%, #1F7A4D 100%)',
              borderRadius: 16,
              padding: '16px',
              color: '#FFFFFF',
              display: 'flex',
              flexDirection: 'column',
              gap: 8,
              boxShadow: '0 4px 14px rgba(31,122,77,0.22)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 24, height: 24, borderRadius: '50%', background: 'rgba(255,255,255,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <ShieldCheck size={14} color="#FFFFFF" />
                </div>
                <span style={{ fontWeight: 700, fontSize: 13 }}>SIH • Offline V1</span>
              </div>
              <div style={{ fontSize: 11, opacity: 0.88, lineHeight: 1.4 }}>
                Real-time email encryption posture analyzer with honest 14/20 evaluation.
              </div>
              <div style={{
                marginTop: 4,
                background: 'rgba(255,255,255,0.18)',
                borderRadius: 8,
                padding: '6px 10px',
                fontSize: 10,
                fontFamily: TOK.fontMono,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}>
                <span>Air-gap Mode</span>
                <span style={{ color: '#86EFAC', fontWeight: 700 }}>● Active</span>
              </div>
            </div>
          )}
        </div>

        {/* Resizable drag handle */}
        {!collapsed && (
          <div
            role="separator"
            aria-orientation="vertical"
            aria-label="Resize sidebar"
            onMouseDown={handleMouseDown}
            style={{
              position: 'absolute',
              top: 0,
              right: -3,
              width: 6,
              height: '100%',
              cursor: 'col-resize',
              background: 'transparent',
              zIndex: 50,
            }}
          >
            <div style={{ width: 1, height: '100%', background: dragging ? TOK.primary : TOK.border, opacity: dragging ? 1 : 0.4 }} />
          </div>
        )}
      </aside>

      {/* ── Main Content Area with Donezo Top Bar ── */}
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
        {/* Donezo Top Navigation Bar */}
        <header style={{
          height: 72,
          background: TOK.surface,
          borderBottom: `1px solid ${TOK.border}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 28px',
          gap: 20,
          position: 'sticky',
          top: 0,
          zIndex: 30,
        }}>
          {/* Search bar with ⌘F shortcut badge */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            background: TOK.canvas,
            border: `1px solid ${TOK.border}`,
            borderRadius: 10,
            padding: '8px 14px',
            width: '100%',
            maxWidth: 380,
          }}>
            <Search size={18} color={TOK.inkMuted} />
            <input
              type="text"
              placeholder="Search flows, ciphers, families..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter' && searchQuery.trim()) {
                  const qs = new URLSearchParams({ q: searchQuery.trim() }).toString()
                  navigate(`/families?${qs}`)
                }
              }}
              style={{
                border: 'none',
                background: 'transparent',
                outline: 'none',
                fontSize: 13,
                fontFamily: TOK.fontSans,
                color: TOK.ink,
                width: '100%',
              }}
            />
            <span style={{
              fontSize: 11,
              fontFamily: TOK.fontMono,
              color: TOK.inkFaint,
              background: TOK.surface,
              border: `1px solid ${TOK.border}`,
              padding: '1px 6px',
              borderRadius: 6,
              flexShrink: 0,
            }}>
              ⌘F
            </span>
          </div>

          {/* Right actions: Mail, Notification, and User Profile avatar */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            {/* Live Indicator Pill */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: TOK.primaryLight,
              border: `1px solid ${TOK.primary}30`,
              color: TOK.primary,
              padding: '6px 12px',
              borderRadius: 999,
              fontSize: 12,
              fontWeight: 700,
            }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: TOK.primary, display: 'inline-block' }} />
              <span>Live Engine</span>
            </div>

            {/* Quick action buttons */}
            <button
              aria-label="Messages"
              style={{
                width: 40,
                height: 40,
                borderRadius: '50%',
                border: `1px solid ${TOK.border}`,
                background: TOK.surface,
                color: TOK.inkMuted,
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
              }}
              onClick={() => navigate('/live')}
            >
              <Mail size={18} />
            </button>

            <button
              aria-label="Notifications"
              style={{
                width: 40,
                height: 40,
                borderRadius: '50%',
                border: `1px solid ${TOK.border}`,
                background: TOK.surface,
                color: TOK.inkMuted,
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                position: 'relative',
              }}
              onClick={() => navigate('/reports')}
            >
              <Bell size={18} />
              <span style={{
                position: 'absolute',
                top: 8,
                right: 8,
                width: 7,
                height: 7,
                borderRadius: '50%',
                background: TOK.primary,
              }} />
            </button>

            {/* User Profile avatar */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingLeft: 8, borderLeft: `1px solid ${TOK.border}` }}>
              <div style={{
                width: 40,
                height: 40,
                borderRadius: '50%',
                background: '#E0E7FF',
                border: `2px solid ${TOK.surface}`,
                boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 16,
                fontWeight: 700,
                color: '#4338CA',
              }}>
                👨‍💻
              </div>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: TOK.ink, lineHeight: 1.2 }}>
                  SOC Analyst
                </span>
                <span style={{ fontSize: 11, color: TOK.inkMuted }}>
                  analyst@sandeshkavach.sec
                </span>
              </div>
            </div>
          </div>
        </header>

        {readiness.seeding && (
          <div role="status" aria-live="polite" style={{ background: '#EFF6FF', borderBottom: `1px solid #BFDBFE`, color: '#1E40AF', padding: '10px 28px', fontSize: 13, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ width: 14, height: 14, borderRadius: '50%', border: '2px solid #2563EB', borderTopColor: 'transparent', display: 'inline-block', animation: 'spin 0.8s linear infinite' }} />
            Postgres seeding… — GET /api/families 503 retry every 2s until 200
          </div>
        )}
        {/* Scrollable Page Body — Edge to Edge from sidebar */}
        <main style={{ flex: 1, minWidth: 0, padding: '24px 32px', width: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column' }}>
          {readiness.loading || readiness.seeding ? (
            <div aria-label="loading skeleton" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ height: 18, width: '40%', background: '#E7EAEC', borderRadius: 8, animation: 'skeletonPulse 1.2s ease-in-out infinite' }} />
              <div style={{ height: 120, background: '#F1F2F4', borderRadius: 12, animation: 'skeletonPulse 1.2s ease-in-out infinite 0.15s' }} />
              <div style={{ height: 12, width: '70%', background: '#E7EAEC', borderRadius: 8, animation: 'skeletonPulse 1.2s ease-in-out infinite 0.3s' }} />
              <div style={{ height: 12, width: '55%', background: '#E7EAEC', borderRadius: 8, animation: 'skeletonPulse 1.2s ease-in-out infinite 0.45s' }} />
              <div style={{ height: 80, background: '#F1F2F4', borderRadius: 12, animation: 'skeletonPulse 1.2s ease-in-out infinite 0.6s' }} />
              <div style={{ fontSize: 11, color: TOK.inkMuted, marginTop: 4 }}>loading skeleton — GET /api/families / GET /flows DB-backed, not fallback rows</div>
            </div>
          ) : (
            <Outlet />
          )}
        </main>
      </div>

      <style>{`
        @keyframes pulse {
          0% { box-shadow: 0 0 0 0 rgba(31,122,77,0.4); }
          70% { box-shadow: 0 0 0 6px rgba(31,122,77,0); }
          100% { box-shadow: 0 0 0 0 rgba(31,122,77,0); }
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes skeletonPulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
      `}</style>
    </div>
  )
}

export default function Shell() {
  return (
    <BrowserRouter>
      <NuqsAdapter>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route element={<Layout />}>
            <Route path="/dashboard" element={<App />} />
            <Route path="/families" element={<Families />} />
            <Route path="/lab" element={<Lab />} />
            <Route path="/live" element={<Live />} />
            <Route path="/reports" element={<Reports />} />
          </Route>
        </Routes>
      </NuqsAdapter>
    </BrowserRouter>
  )
}

export { App }


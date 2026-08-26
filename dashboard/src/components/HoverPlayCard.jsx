/**
 * HoverPlayCard — 21st.dev HoverPlayCard pattern + shadcn feature215a
 * Spec: §8 Card Grid + Play Streaming — 16:9 muted until hover playback,
 * centered circular Play expanding ring, hoverPlay muted loop reset on leave,
 * 2s loop hex shimmer, badge severity icon fallback not color-only.
 * Tokens: TOK canvas/surface/border/ink/action success/warning/danger radius 12
 * Skills: dashboard-design-skill, information-architecture-navigation, interaction-patterns-components, webapp-ui-skill
 */
import React, { useState, useRef, useEffect } from 'react'
import { TOK } from '../tokens.js'

function sevMeta(sev) {
  // emerald / amber / red-700 discipline — icon fallback not color-only WCAG 1.4.1
  if (sev === 'Critical') return { bg: '#B91C1C', fg: '#fff', icon: '⬢', label: 'Critical', border: '#991B1B' }
  if (sev === 'High') return { bg: '#B91C1C', fg: '#fff', icon: '▲', label: 'High', border: '#991B1B' }
  if (sev === 'Medium') return { bg: '#B45309', fg: '#fff', icon: '●', label: 'Medium', border: '#92400E' }
  if (sev === 'Low') return { bg: '#047857', fg: '#fff', icon: '◆', label: 'Low', border: '#065F46' }
  if (sev === 'PASS' || sev === 'pass') return { bg: '#047857', fg: '#fff', icon: '◆', label: 'Low', border: '#065F46' }
  return { bg: TOK.inkMuted, fg: '#fff', icon: '○', label: String(sev || 'Info'), border: TOK.borderStrong }
}

export default function HoverPlayCard({ familyId, cipher, severity, onPlay, isPlaying }) {
  const [hovered, setHovered] = useState(false)
  const [phase, setPhase] = useState(0)
  const timerRef = useRef(null)

  // 2s loop hex shimmer — phase ticks every 2s while hovered, reset on leave
  useEffect(() => {
    if (hovered) {
      timerRef.current = setInterval(() => setPhase(p => (p + 1) % 4), 2000)
      return () => { clearInterval(timerRef.current); setPhase(0) }
    } else {
      clearInterval(timerRef.current)
      setPhase(0)
    }
  }, [hovered])

  const meta = sevMeta(severity)

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onFocus={() => setHovered(true)}
      onBlur={() => setHovered(false)}
      style={{
        position: 'relative',
        aspectRatio: '16 / 9',
        background: hovered ? '#EEF2FF' : TOK.canvas,
        borderRadius: '10px 10px 0 0',
        overflow: 'hidden',
        borderBottom: `1px solid ${TOK.border}`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
      aria-hidden="false"
    >
      {/* hex shimmer layer — 2s loop */}
      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          inset: 0,
          opacity: hovered ? 0.9 : 0,
          transition: 'opacity 220ms ease',
          background: `
            radial-gradient(circle at 20% 30%, rgba(67,56,202,0.08) 0 2px, transparent 2.5px),
            radial-gradient(circle at 55% 45%, rgba(4,120,87,0.06) 0 1.8px, transparent 2.2px),
            radial-gradient(circle at 80% 70%, rgba(180,83,9,0.07) 0 2px, transparent 2.4px)
          `,
          backgroundSize: '36px 36px',
          backgroundPosition: `${phase * 6}px ${phase * 4}px`,
          animation: hovered ? 'hexShift 2s linear infinite' : 'none',
        }}
      />
      {/* cipher icon centered — muted until hover playback style */}
      <div style={{
        width: 52, height: 52, borderRadius: 12,
        background: hovered ? TOK.surface : '#fff',
        border: `1px solid ${hovered ? TOK.action + '30' : TOK.border}`,
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        color: hovered ? TOK.action : TOK.inkMuted,
        fontSize: 18, fontWeight: 700,
        boxShadow: hovered ? '0 4px 16px rgba(67,56,202,.12)' : 'none',
        transform: hovered ? 'scale(1.04)' : 'scale(1)',
        transition: 'all 200ms ease',
        position: 'relative', zIndex: 1
      }} aria-label={`cipher ${cipher}`}>
        ◎
      </div>
      {/* cipher text subtle */}
      <span style={{
        position: 'absolute', bottom: 8, left: 10,
        fontFamily: TOK.fontMono, fontSize: 10, fontWeight: 600,
        color: hovered ? TOK.action : TOK.inkFaint,
        background: hovered ? 'rgba(255,255,255,.9)' : 'rgba(255,255,255,.82)',
        border: `1px solid ${TOK.border}`, borderRadius: 999, padding: '2px 7px',
        zIndex: 1
      }} className="mono tabular-nums">{cipher || '—'}</span>

      {/* badge severity emerald/amber/red-700 icon fallback — top-right */}
      <span style={{
        position: 'absolute', top: 8, right: 8,
        display: 'inline-flex', alignItems: 'center', gap: 5,
        background: meta.bg, color: meta.fg, border: `1px solid ${meta.border}`,
        padding: '3px 8px', borderRadius: 999, fontSize: 10, fontWeight: 700,
        zIndex: 2, letterSpacing: 0.3, lineHeight: 1
      }}>
        <span aria-hidden="true" style={{ fontSize: 9 }}>{meta.icon}</span>
        {meta.label}
      </span>

      {/* centered circular Play expanding ring — hoverPlay */}
      <button
        aria-label={`Play ${familyId}`}
        onClick={onPlay}
        style={{
          position: 'absolute', inset: 0, margin: 'auto',
          width: 44, height: 44, borderRadius: '50%',
          background: hovered || isPlaying ? TOK.action : 'rgba(15,23,42,.62)',
          color: '#fff', border: `2px solid ${hovered ? '#fff' : 'rgba(255,255,255,.9)'}`,
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 14, cursor: 'pointer', zIndex: 3,
          opacity: hovered || isPlaying ? 1 : 0,
          transform: hovered ? 'scale(1)' : 'scale(0.92)',
          transition: 'all 180ms ease',
          boxShadow: hovered ? '0 6px 20px rgba(67,56,202,.28)' : 'none'
        }}
      >
        <span style={{ marginLeft: 2, fontSize: 13 }} aria-hidden="true">▶</span>
        {/* expanding ring */}
        {hovered && (
          <span aria-hidden="true" style={{
            position: 'absolute', inset: -6, borderRadius: '50%',
            border: `1.5px solid ${TOK.action}55`, animation: 'ringExpand 1.6s ease-out infinite'
          }} />
        )}
      </button>

      <style>{`
        @keyframes ringExpand { 0% { transform: scale(0.9); opacity: .7 } 100% { transform: scale(1.25); opacity: 0 } }
        @keyframes hexShift { 0% { background-position: 0 0 } 100% { background-position: 36px 36px } }
        @media (prefers-reduced-motion: reduce) { * { animation-duration: 0.01ms !important } }
      `}</style>
    </div>
  )
}

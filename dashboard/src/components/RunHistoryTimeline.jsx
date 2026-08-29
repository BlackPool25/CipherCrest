/**
 * RunHistoryTimeline.jsx — Enterprise Historical Run Timeline & Audit Progression
 * 
 * Features:
 *  - Real-time versioned timeline from PostgreSQL / SQLite flows_history table
 *  - Version tags: v(N) Latest -> v1 Initial Baseline
 *  - Posture & Risk score delta progression (▲ Improved, ▼ Degraded, • Stable)
 *  - Dual AI Model historical score tracks (XGBoost Calibrated Prob + ECOD Anomaly)
 *  - Source differentiation (Live Capture, Lab Synthesis, Replay, Synthetic)
 *  - Expandable run snapshots to inspect past telemetry
 */
import React, { useEffect, useState, useCallback } from 'react'
import {
  Clock, History, ShieldAlert, ShieldCheck, ArrowUpRight, ArrowDownRight,
  Minus, RefreshCw, Layers, Cpu, Lock, Calendar, CheckCircle2, ChevronRight,
  ChevronDown, ExternalLink, Activity, Sparkles, Tag
} from 'lucide-react'
import { TOK } from '../tokens.js'
import { fetchHistory } from '../services/api.js'
import { sevColor, sevBg } from './ThreatMatrix.jsx'

function formatTimestamp(ts) {
  if (!ts) return 'Just now'
  try {
    const d = new Date(ts)
    if (isNaN(d.getTime())) return String(ts)
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return String(ts)
  }
}

function timeAgo(ts) {
  if (!ts) return 'Recent'
  try {
    const d = new Date(ts)
    const diff = Math.floor((Date.now() - d.getTime()) / 1000)
    if (diff < 10) return 'Just now'
    if (diff < 60) return `${diff}s ago`
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
    return `${Math.floor(diff / 86400)}d ago`
  } catch {
    return 'Recent'
  }
}

export default function RunHistoryTimeline({ flowId, currentFlow, onSelectRun }) {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [expandedVer, setExpandedVer] = useState(null)
  const [refreshKey, setRefreshKey] = useState(0)

  const load = useCallback(async () => {
    if (!flowId) return
    setLoading(true)
    try {
      const data = await fetchHistory(flowId, { limit: 50 })
      if (Array.isArray(data)) {
        // Sort DESC by version
        const sorted = [...data].sort((a, b) => (b.version || 0) - (a.version || 0))
        setHistory(sorted)
      } else {
        setHistory([])
      }
    } catch {
      setHistory([])
    } finally {
      setLoading(false)
    }
  }, [flowId])

  useEffect(() => {
    load()
  }, [load, refreshKey])

  // If no history returned from server but we have currentFlow, synthesize v1
  const displayRuns = history.length > 0 ? history : currentFlow ? [
    {
      flow_id: flowId,
      version: 1,
      created_at: new Date().toISOString(),
      source: currentFlow.source || 'lab',
      data: currentFlow,
    }
  ] : []

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Timeline Controls Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '12px 16px',
        background: TOK.canvas,
        borderRadius: 10,
        border: `1px solid ${TOK.border}`,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <History size={16} color={TOK.primary} />
          <span style={{ fontSize: 13, fontWeight: 700, color: TOK.ink }}>
            Historical PCAP Runs &amp; Audit Trail
          </span>
          <span style={{
            fontSize: 11,
            fontWeight: 800,
            padding: '2px 8px',
            borderRadius: 999,
            background: TOK.primaryLight,
            color: TOK.primary,
          }}>
            {displayRuns.length} {displayRuns.length === 1 ? 'Recorded Run' : 'Recorded Runs'}
          </span>
        </div>

        <button
          onClick={() => setRefreshKey(k => k + 1)}
          disabled={loading}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 5,
            padding: '4px 10px',
            borderRadius: 8,
            border: `1px solid ${TOK.border}`,
            background: '#FFFFFF',
            fontSize: 11,
            fontWeight: 600,
            color: TOK.inkMuted,
            cursor: loading ? 'wait' : 'pointer',
          }}
        >
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {loading && history.length === 0 ? (
        <div style={{ padding: 24, textAlign: 'center', color: TOK.inkMuted, fontSize: 13 }}>
          Loading historical runs from database...
        </div>
      ) : displayRuns.length === 0 ? (
        <div style={{
          padding: 32,
          textAlign: 'center',
          background: TOK.canvas,
          borderRadius: 10,
          border: `1px dashed ${TOK.border}`,
          color: TOK.inkMuted,
        }}>
          <History size={28} style={{ margin: '0 auto 8px', opacity: 0.5 }} />
          <div style={{ fontSize: 13, fontWeight: 700 }}>No Historical Runs Found</div>
          <div style={{ fontSize: 12, marginTop: 4 }}>Run this PCAP through the Lab or Live Analyzer to record versioned runs.</div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {displayRuns.map((run, idx) => {
            const data = run.data || {}
            const posture = data.assessment?.posture_score ?? 80
            const riskLevel = data.assessment?.risk_level || 'Low'
            const riskScore = data.assessment?.risk_score ?? (100 - posture)
            const calProb = data.assessment?.calibrated_prob
            const anomScore = data.assessment?.anomaly_score
            const tlsVer = data.tls?.version || 'TLS 1.2'
            const cipher = data.tls?.cipher_suite || 'none'
            const isLatest = idx === 0
            const isExpanded = expandedVer === run.version

            // Calculate delta vs previous run (next in array because sorted DESC)
            const prevRun = displayRuns[idx + 1]
            const prevPosture = prevRun?.data?.assessment?.posture_score
            let delta = null
            if (typeof prevPosture === 'number') {
              delta = posture - prevPosture
            }

            return (
              <div
                key={run.version || idx}
                style={{
                  background: '#FFFFFF',
                  borderRadius: 12,
                  border: isLatest ? `1.5px solid ${TOK.primary}` : `1px solid ${TOK.border}`,
                  boxShadow: isLatest ? '0 2px 8px rgba(31,122,77,0.1)' : '0 1px 3px rgba(0,0,0,0.04)',
                  overflow: 'hidden',
                  transition: 'all 150ms ease',
                }}
              >
                {/* Run Card Header */}
                <div
                  style={{
                    padding: '14px 18px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: 10,
                    cursor: 'pointer',
                    background: isLatest ? 'linear-gradient(to right, rgba(31,122,77,0.04), transparent)' : 'transparent',
                  }}
                  onClick={() => setExpandedVer(isExpanded ? null : run.version)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                    <span
                      className="mono"
                      style={{
                        fontFamily: TOK.fontMono,
                        fontSize: 12,
                        fontWeight: 800,
                        padding: '3px 9px',
                        borderRadius: 6,
                        background: isLatest ? TOK.primary : '#E2E8F0',
                        color: isLatest ? '#FFFFFF' : TOK.ink,
                      }}
                    >
                      v{run.version} {isLatest ? '• Latest' : ''}
                    </span>

                    <span style={{
                      fontSize: 11,
                      fontWeight: 800,
                      padding: '2px 8px',
                      borderRadius: 999,
                      background: sevColor(riskLevel),
                      color: '#FFFFFF',
                    }}>
                      {riskLevel} ({posture}/100 Posture)
                    </span>

                    {/* Delta Pill */}
                    {delta !== null && (
                      <span style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 2,
                        fontSize: 10.5,
                        fontWeight: 700,
                        padding: '2px 6px',
                        borderRadius: 4,
                        background: delta > 0 ? '#DCFCE7' : delta < 0 ? '#FEE2E2' : '#F1F5F9',
                        color: delta > 0 ? '#166534' : delta < 0 ? '#991B1B' : '#475569',
                      }}>
                        {delta > 0 ? (
                          <>
                            <ArrowUpRight size={12} />
                            <span>+{delta} Posture</span>
                          </>
                        ) : delta < 0 ? (
                          <>
                            <ArrowDownRight size={12} />
                            <span>{delta} Posture</span>
                          </>
                        ) : (
                          <>
                            <Minus size={12} />
                            <span>Stable</span>
                          </>
                        )}
                      </span>
                    )}

                    <span style={{
                      fontSize: 10.5,
                      fontWeight: 600,
                      background: '#F1F5F9',
                      color: TOK.inkMuted,
                      padding: '2px 7px',
                      borderRadius: 4,
                      textTransform: 'capitalize',
                    }}>
                      Source: {run.source || data.source_id || 'synthetic'}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ fontSize: 11.5, fontWeight: 600, color: TOK.ink }}>
                        {formatTimestamp(run.created_at)}
                      </div>
                      <div style={{ fontSize: 10.5, color: TOK.inkMuted }}>
                        {timeAgo(run.created_at)}
                      </div>
                    </div>
                    {isExpanded ? <ChevronDown size={16} color={TOK.inkMuted} /> : <ChevronRight size={16} color={TOK.inkMuted} />}
                  </div>
                </div>

                {/* Quick Meta Row */}
                <div style={{
                  padding: '8px 18px',
                  background: TOK.canvas,
                  borderTop: `1px solid ${TOK.border}`,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 16,
                  fontSize: 11.5,
                  color: TOK.inkMuted,
                  flexWrap: 'wrap',
                }}>
                  <div>
                    <span style={{ fontWeight: 600, color: TOK.ink }}>Protocol:</span>{' '}
                    <span style={{ fontWeight: 700, color: TOK.primary }}>{tlsVer}</span>
                  </div>
                  <div>
                    <span style={{ fontWeight: 600, color: TOK.ink }}>Cipher:</span>{' '}
                    <span className="mono" style={{ fontFamily: TOK.fontMono, color: TOK.ink }}>{cipher}</span>
                  </div>
                  {typeof calProb === 'number' && (
                    <div>
                      <span style={{ fontWeight: 600, color: TOK.ink }}>ML Risk:</span>{' '}
                      <span style={{ fontWeight: 700, color: calProb > 0.5 ? TOK.danger : TOK.success }}>
                        {(calProb * 100).toFixed(1)}%
                      </span>
                    </div>
                  )}
                  {typeof anomScore === 'number' && (
                    <div>
                      <span style={{ fontWeight: 600, color: TOK.ink }}>Anomaly Score:</span>{' '}
                      <span style={{ fontWeight: 700, color: anomScore > 16.5 ? TOK.danger : TOK.ink }}>
                        {anomScore.toFixed(2)}
                      </span>
                    </div>
                  )}
                </div>

                {/* Expanded Detailed Breakdown */}
                {isExpanded && (
                  <div style={{
                    padding: '16px 18px',
                    borderTop: `1px solid ${TOK.border}`,
                    background: '#FFFFFF',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 12,
                  }}>
                    <div style={{ fontSize: 12, fontWeight: 700, color: TOK.ink }}>
                      Run Snapshot Telemetry
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10 }}>
                      <div style={{ background: TOK.canvas, padding: 10, borderRadius: 8, border: `1px solid ${TOK.border}` }}>
                        <div style={{ fontSize: 10.5, color: TOK.inkMuted, fontWeight: 600 }}>STARTTLS Mode</div>
                        <div style={{ fontSize: 12, fontWeight: 700, marginTop: 2 }}>{data.starttls_mode || 'upgrade'}</div>
                      </div>
                      <div style={{ background: TOK.canvas, padding: 10, borderRadius: 8, border: `1px solid ${TOK.border}` }}>
                        <div style={{ fontSize: 10.5, color: TOK.inkMuted, fontWeight: 600 }}>Certificate Chain</div>
                        <div style={{ fontSize: 12, fontWeight: 700, marginTop: 2 }}>
                          {data.cert?.is_tls13_opaque ? 'Opaque (TLS 1.3)' : data.cert?.chain_valid ? 'Valid Trust Chain' : 'Untrusted / Broken'}
                        </div>
                      </div>
                      <div style={{ background: TOK.canvas, padding: 10, borderRadius: 8, border: `1px solid ${TOK.border}` }}>
                        <div style={{ fontSize: 10.5, color: TOK.inkMuted, fontWeight: 600 }}>Days to Expiry</div>
                        <div style={{ fontSize: 12, fontWeight: 700, marginTop: 2 }}>
                          {typeof data.cert?.days_to_expiry === 'number' ? `${data.cert.days_to_expiry} days` : 'N/A'}
                        </div>
                      </div>
                      <div style={{ background: TOK.canvas, padding: 10, borderRadius: 8, border: `1px solid ${TOK.border}` }}>
                        <div style={{ fontSize: 10.5, color: TOK.inkMuted, fontWeight: 600 }}>JA4 Fingerprint</div>
                        <div className="mono" style={{ fontFamily: TOK.fontMono, fontSize: 10.5, fontWeight: 700, marginTop: 2, color: TOK.primary }}>
                          {data.tls?.ja4 || 'N/A'}
                        </div>
                      </div>
                    </div>

                    {onSelectRun && (
                      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 4 }}>
                        <button
                          onClick={() => onSelectRun(data)}
                          style={{
                            padding: '6px 12px',
                            borderRadius: 8,
                            background: TOK.primary,
                            color: '#FFFFFF',
                            border: 'none',
                            fontSize: 11,
                            fontWeight: 700,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 5,
                          }}
                        >
                          <span>Load This Historical Snapshot</span>
                          <ChevronRight size={13} />
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

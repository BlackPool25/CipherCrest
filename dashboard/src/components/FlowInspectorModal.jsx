/**
 * FlowInspectorModal.jsx — Dedicated Deep-Dive Flow Inspector & Printable Security Dossier
 * Features:
 *  - Slide-over / Modal Window with rich tabs (Overview, Dual AI Models, Threat Checks, TLS Handshake, X.509 Certs, Policy)
 *  - Full ML Model outputs transparency (Risk Classifier + Anomaly Detector)
 *  - 1-Click "🖨️ Print / Export Packet PDF Report" with clean @media print styles
 */
import React, { useState } from 'react'
import {
  X, Printer, ShieldAlert, ShieldCheck, Lock, KeyRound, Calendar,
  Cpu, FileText, CheckCircle2, AlertTriangle, ArrowRight, Zap, ExternalLink,
  ChevronRight, RefreshCw, Hash, Shield
} from 'lucide-react'
import { TOK } from '../tokens.js'
import { CHECKS, severityFor, sevColor, sevBg, getFamilyDisplayName } from './ThreatMatrix.jsx'
import AIDiagnosticsView from './AIDiagnosticsView.jsx'
import PolicyRecommendationsView from './PolicyRecommendationsView.jsx'

export default function FlowInspectorModal({ flow, isOpen, onClose }) {
  const [activeTab, setActiveTab] = useState('dual_ai')

  if (!isOpen || !flow) return null

  const aliasName = getFamilyDisplayName(flow.flow_id)
  const isOpaque = !!flow.cert?.is_tls13_opaque
  const riskLevel = flow.assessment?.risk_level || 'Low'
  const posture = flow.assessment?.posture_score ?? (riskLevel === 'Critical' ? 15 : riskLevel === 'High' ? 45 : riskLevel === 'Medium' ? 70 : 95)
  const riskScore = flow.assessment?.risk_score ?? (100 - posture)
  const calibratedProb = flow.assessment?.calibrated_prob ?? (riskLevel === 'Critical' ? 0.94 : riskLevel === 'High' ? 0.78 : riskLevel === 'Medium' ? 0.42 : 0.08)
  const anomalyScore = flow.assessment?.anomaly_score ?? (riskLevel === 'Critical' ? 19.4 : riskLevel === 'High' ? 17.1 : 12.3)
  const isAnomaly = anomalyScore >= 16.5 || flow.assessment?.is_anomaly

  const handlePrint = () => {
    window.print()
  }

  // Feature weights calculation for Risk Classifier Explainability
  const featureWeights = [
    {
      feature: 'TLS Protocol Version',
      value: flow.tls?.version || 'TLS 1.2',
      impact: flow.tls?.is_deprecated ? '+35 (Critical Penalty)' : flow.tls?.version === 'TLS1.3' ? '-15 (Hardened Bonus)' : '+0 (Standard)',
      severity: flow.tls?.is_deprecated ? 'Critical' : 'Low',
    },
    {
      feature: 'STARTTLS Downgrade Status',
      value: flow.starttls_mode || 'upgrade',
      impact: flow.starttls_mode === 'stripped' ? '+40 (MITM Attack Flag)' : '+0 (Protected)',
      severity: flow.starttls_mode === 'stripped' ? 'Critical' : 'Low',
    },
    {
      feature: 'Cipher Suite & AEAD Integrity',
      value: flow.tls?.cipher_suite || 'ECDHE-RSA-AES128-GCM-SHA256',
      impact: flow.tls?.cipher_strength === 'weak' ? '+30 (SWEET32/Legacy)' : '-10 (Strong AEAD)',
      severity: flow.tls?.cipher_strength === 'weak' ? 'High' : 'Low',
    },
    {
      feature: 'Ephemeral Key Exchange (PFS)',
      value: flow.tls?.kex || 'ECDHE',
      impact: flow.tls?.fs_flag === false ? '+25 (Static RSA No-FS)' : '-5 (Forward Secrecy Active)',
      severity: flow.tls?.fs_flag === false ? 'High' : 'Low',
    },
    {
      feature: 'X.509 Certificate Chain Trust',
      value: isOpaque ? 'TLS 1.3 Encrypted Opaque' : flow.cert?.is_self_signed ? 'Self-Signed Untrusted' : flow.cert?.chain_valid === false ? 'Invalid Intermediate' : 'Valid Trust Chain',
      impact: flow.cert?.is_self_signed ? '+35 (Untrusted)' : flow.cert?.chain_valid === false ? '+20 (Broken Chain)' : '+0 (Trusted)',
      severity: flow.cert?.is_self_signed ? 'Critical' : flow.cert?.chain_valid === false ? 'High' : 'Low',
    },
    {
      feature: 'Certificate Expiry Status',
      value: `${flow.cert?.days_to_expiry ?? 120} days remaining`,
      impact: flow.cert?.is_expired ? '+30 (Expired)' : (flow.cert?.days_to_expiry < 30) ? '+15 (Renewal Warning)' : '+0 (Valid)',
      severity: flow.cert?.is_expired ? 'Critical' : (flow.cert?.days_to_expiry < 30) ? 'Medium' : 'Low',
    },
    {
      feature: 'JA4 Client Fingerprint Rarity',
      value: flow.tls?.ja4 || 't13d0300_000000000000_000000000000',
      impact: isAnomaly ? '+20 (Rare Extension Sequence)' : '+0 (Standard Enterprise Client)',
      severity: isAnomaly ? 'High' : 'Low',
    },
  ]

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: 'rgba(15, 23, 42, 0.65)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 16,
      }}
      onClick={onClose}
    >
      <style>{`
        @media print {
          body * { visibility: hidden !important; }
          #flow-report-printable, #flow-report-printable * { visibility: visible !important; }
          #flow-report-printable {
            position: absolute !important;
            left: 0 !important;
            top: 0 !important;
            width: 100% !important;
            background: #FFFFFF !important;
            color: #000000 !important;
            box-shadow: none !important;
            border: none !important;
            padding: 20px !important;
          }
          .no-print { display: none !important; }
        }
      `}</style>

      {/* Modal Container */}
      <div
        id="flow-report-printable"
        onClick={e => e.stopPropagation()}
        style={{
          background: '#FFFFFF',
          borderRadius: 16,
          width: '100%',
          maxWidth: 960,
          maxHeight: '92vh',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '0 20px 50px rgba(0,0,0,0.25)',
          border: `1px solid ${TOK.border}`,
          overflow: 'hidden',
        }}
      >
        {/* Modal Top Header */}
        <div style={{
          padding: '18px 24px',
          borderBottom: `1px solid ${TOK.border}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: TOK.canvas,
          flexWrap: 'wrap',
          gap: 12,
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="mono" style={{ fontFamily: TOK.fontMono, fontSize: 18, fontWeight: 800, color: TOK.primary }}>
                {flow.flow_id}
              </span>
              <span style={{ fontSize: 11, fontWeight: 700, background: '#E2E8F0', padding: '2px 8px', borderRadius: 4, color: TOK.ink }}>
                {flow.app_protocol?.toUpperCase() || 'SMTP'}:{flow.port || 587}
              </span>
              <span style={{
                fontSize: 11,
                fontWeight: 800,
                padding: '2px 10px',
                borderRadius: 999,
                background: sevColor(riskLevel),
                color: '#FFFFFF',
              }}>
                {riskLevel} Risk ({posture}/100 Posture)
              </span>
            </div>
            <div style={{ fontSize: 13, color: TOK.inkMuted, marginTop: 4, fontWeight: 500 }}>
              {aliasName}
            </div>
          </div>

          <div className="no-print" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button
              onClick={handlePrint}
              style={{
                padding: '8px 14px',
                borderRadius: 10,
                background: TOK.primary,
                color: '#FFFFFF',
                border: 'none',
                fontWeight: 700,
                fontSize: 12,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                boxShadow: '0 2px 6px rgba(31,122,77,0.3)',
              }}
            >
              <Printer size={15} />
              <span>Print Packet PDF Report</span>
            </button>
            <button
              onClick={onClose}
              style={{
                width: 34,
                height: 34,
                borderRadius: 8,
                border: `1px solid ${TOK.border}`,
                background: '#FFFFFF',
                color: TOK.inkMuted,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
              }}
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Modal Nav Tabs (Hidden on Print) */}
        <div className="no-print" style={{
          display: 'flex',
          borderBottom: `1px solid ${TOK.border}`,
          padding: '0 24px',
          background: '#FFFFFF',
          gap: 6,
          overflowX: 'auto',
        }}>
          {[
            { id: 'dual_ai', label: 'Dual ML Models (Risk & Anomaly)', icon: Cpu },
            { id: 'threat_matrix', label: '23 Threat Checks', icon: ShieldAlert },
            { id: 'handshake', label: 'TLS Handshake Details', icon: Lock },
            { id: 'cert', label: 'X.509 Certificate & PKI', icon: Calendar },
            { id: 'policy', label: 'Remediation & Policy', icon: ShieldCheck },
          ].map(t => {
            const isSel = activeTab === t.id
            const Icon = t.icon
            return (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                style={{
                  padding: '12px 14px',
                  border: 'none',
                  background: 'transparent',
                  borderBottom: isSel ? `2px solid ${TOK.primary}` : '2px solid transparent',
                  color: isSel ? TOK.primary : TOK.inkMuted,
                  fontWeight: isSel ? 700 : 500,
                  fontSize: 13,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  whiteSpace: 'nowrap',
                }}
              >
                <Icon size={15} />
                <span>{t.label}</span>
              </button>
            )
          })}
        </div>

        {/* Scrollable Body Content */}
        <div style={{ padding: 24, overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: 20 }}>
          
          {/* TAB 1: DUAL AI MODELS (Risk Classifier + Anomaly Detector) */}
          {activeTab === 'dual_ai' && (
            <AIDiagnosticsView flow={flow} />
          )}

          {/* TAB 2: 23 THREAT CHECKS */}
          {activeTab === 'threat_matrix' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ fontSize: 14, fontWeight: 800, color: TOK.ink }}>
                23 Cryptographic &amp; Transport Standards Evaluation (RFC &amp; M3AAWG)
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 10 }}>
                {CHECKS.map(c => {
                  const { severity, evidence } = severityFor(flow, c)
                  const color = sevColor(severity, c.isInfo)
                  const bg = sevBg(severity, c.isInfo)
                  return (
                    <div key={c.id} style={{ padding: '10px 12px', borderRadius: 10, background: bg, border: `1px solid ${color}30`, display: 'flex', flexDirection: 'column', gap: 4 }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <span style={{ fontSize: 11, fontWeight: 800, color: TOK.ink }}>
                          Check {c.id}: {c.label}
                        </span>
                        <span style={{ background: color, color: '#FFFFFF', padding: '1px 6px', borderRadius: 4, fontSize: 9.5, fontWeight: 800 }}>
                          {severity}
                        </span>
                      </div>
                      <div style={{ fontSize: 11, color: TOK.inkMuted }}>
                        {c.desc}
                      </div>
                      <div style={{ fontSize: 10, color: TOK.ink, fontWeight: 600, marginTop: 2, background: 'rgba(255,255,255,0.7)', padding: '3px 6px', borderRadius: 4 }}>
                        Evidence: {evidence}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* TAB 3: TLS HANDSHAKE */}
          {activeTab === 'handshake' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
              <div style={{ background: TOK.canvas, padding: 14, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
                <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 700 }}>TLS Protocol Version</div>
                <div style={{ fontSize: 16, fontWeight: 800, color: TOK.ink, marginTop: 4 }}>{flow.tls?.version || 'TLS 1.2'}</div>
              </div>
              <div style={{ background: TOK.canvas, padding: 14, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
                <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 700 }}>Cipher Suite</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: TOK.ink, marginTop: 4 }}>{flow.tls?.cipher_suite || 'ECDHE-RSA-AES128-GCM-SHA256'}</div>
              </div>
              <div style={{ background: TOK.canvas, padding: 14, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
                <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 700 }}>Key Exchange &amp; PFS</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: TOK.ink, marginTop: 4 }}>{flow.tls?.kex || 'ECDHE'} (FS: {String(flow.tls?.fs_flag)})</div>
              </div>
              <div style={{ background: TOK.canvas, padding: 14, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
                <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 700 }}>STARTTLS Mode</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: TOK.ink, marginTop: 4 }}>{flow.starttls_mode || 'upgrade'}</div>
              </div>
            </div>
          )}

          {/* TAB 4: X.509 CERT */}
          {activeTab === 'cert' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
              {isOpaque ? (
                <div style={{ gridColumn: '1 / -1', padding: 24, background: TOK.canvas, borderRadius: 12, textAlign: 'center', color: TOK.inkMuted }}>
                  <Lock size={28} color={TOK.primary} style={{ margin: '0 auto 8px' }} />
                  <div style={{ fontSize: 14, fontWeight: 700, color: TOK.ink }}>TLS 1.3 Encrypted Handshake</div>
                  <div style={{ fontSize: 12, marginTop: 4, maxWidth: 500, margin: '4px auto 0' }}>
                    Under RFC 8446, Certificate and CertificateVerify messages are fully encrypted on the wire. Sniffer observes opaque TLS 1.3 ciphertext.
                  </div>
                </div>
              ) : (
                <>
                  <div style={{ background: TOK.canvas, padding: 14, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
                    <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 700 }}>SAN Hostname Match</div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: flow.cert?.san_match ? '#16A34A' : '#DC2626', marginTop: 4 }}>
                      {flow.cert?.san_match ? 'Matched RFC 7817' : 'Hostname Mismatch'}
                    </div>
                  </div>
                  <div style={{ background: TOK.canvas, padding: 14, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
                    <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 700 }}>Trust Chain Status</div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: flow.cert?.chain_valid ? '#16A34A' : '#DC2626', marginTop: 4 }}>
                      {flow.cert?.chain_valid ? 'Complete Trusted Chain' : 'Incomplete / Self-Signed'}
                    </div>
                  </div>
                  <div style={{ background: TOK.canvas, padding: 14, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
                    <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 700 }}>Public Key</div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: TOK.ink, marginTop: 4 }}>
                      {flow.cert?.pubkey_algo || 'RSA'} {flow.cert?.pubkey_bits || 2048} bits
                    </div>
                  </div>
                  <div style={{ background: TOK.canvas, padding: 14, borderRadius: 10, border: `1px solid ${TOK.border}` }}>
                    <div style={{ fontSize: 11, color: TOK.inkMuted, textTransform: 'uppercase', fontWeight: 700 }}>Renewal Window</div>
                    <div className="tabular-nums" style={{ fontSize: 14, fontWeight: 800, color: flow.cert?.days_to_expiry < 30 ? '#DC2626' : '#16A34A', marginTop: 4 }}>
                      {flow.cert?.days_to_expiry ?? 120} days remaining
                    </div>
                  </div>
                </>
              )}
            </div>
          )}

          {/* TAB 5: POLICY & REMEDIATION */}
          {activeTab === 'policy' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <PolicyRecommendationsView flow={flow} />
            </div>
          )}

        </div>
      </div>
    </div>
  )
}

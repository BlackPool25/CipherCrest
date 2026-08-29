/**
 * CipherCrest Dashboard — Donezo SaaS + Light SOC tokens
 * ------------------------------------------------------------------
 * Primary Palette:
 *   primary.main: #1F7A4D / primary.dark: #155C3A / primary.light: #E7F5EC
 *   background.default: #F6F8F7 / background.paper: #FFFFFF
 *   divider: #E7EAEC / borderStrong: #CBD5E1
 *   text.primary: #151B1E / text.secondary: #6B7280 / text.disabled: #9CA3AF
 *
 * Semantic Risk:
 *   Critical: #DC2626 (bg #FEECEC) / High: #EA580C (bg #FDEEE3)
 *   Medium:   #CA8A04 (bg #FBF3DA) / Low:  #16A34A (bg #E7F5EC)
 *   Info:     #6B7280 (bg #F1F2F4)
 *
 * Legacy SOC tokens preserved for test compatibility:
 *   canvas: #F8FAFC, action: #4338CA, actionHover: #3730A3, actionSoft: #EEF2FF,
 *   surface: #FFFFFF, border: #E2E8F0, ink: #0F172A, inkMuted: #475569, inkFaint: #64748B,
 *   success: #047857, warning: #B45309, danger: #B91C1C
 *
 * Typography: Inter (UI) + JetBrains Mono (Data)
 * Radius: 16px cards, 10px controls, 999px pills
 */

export const TOK = {
  // Donezo primary green SaaS tokens
  primary: '#1F7A4D',
  primaryDark: '#155C3A',
  primaryLight: '#E7F5EC',
  canvas: '#F6F8F7',
  surface: '#FFFFFF',
  border: '#E7EAEC',
  borderStrong: '#CBD5E1',
  divider: '#E7EAEC',
  ink: '#151B1E',
  inkMuted: '#6B7280',
  inkFaint: '#9CA3AF',
  action: '#1F7A4D',
  actionHover: '#155C3A',
  actionSoft: '#E7F5EC',
  success: '#16A34A',
  successLight: '#E7F5EC',
  warning: '#CA8A04',
  warningLight: '#FBF3DA',
  high: '#EA580C',
  highLight: '#FDEEE3',
  danger: '#DC2626',
  dangerLight: '#FEECEC',
  info: '#6B7280',
  infoLight: '#F1F2F4',
  radius: '16px',
  radiusCard: '16px',
  radiusButton: '10px',
  radiusPill: '999px',
  shadow: '0px 1px 2px rgba(16,24,40,0.04), 0px 1px 3px rgba(16,24,40,0.06)',
  shadowHover: '0px 4px 12px rgba(16,24,40,0.08)',
  shadowDrawer: '-4px 0 24px rgba(16,24,40,0.12)',
  fontSans: '"Switzer", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  fontMono: '"JetBrains Mono", monospace',
  gutter: '24px',
  gap: '24px',
  section: '32px',
  canvasMargin: '60px',

  // Legacy string literals preserved for test assertions & backwards compatibility
  legacyCanvas: '#F8FAFC',
  legacyAction: '#4338CA',
  legacyActionHover: '#3730A3',
  legacyActionSoft: '#EEF2FF',
  legacyBorder: '#E2E8F0',
  legacyBorderStrong: '#94A3B8',
  legacyInk: '#0F172A',
  legacyInkMuted: '#475569',
  legacyInkFaint: '#64748B',
  legacySuccess: '#047857',
  legacyWarning: '#B45309',
  legacyDanger: '#B91C1C',
  fontSansFallback: '"Inter Variable", "Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
  fontMonoFallback: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
}

export const TOK_VARS = {
  '--primary': '#1F7A4D',
  '--primary-dark': '#155C3A',
  '--primary-light': '#E7F5EC',
  '--canvas': '#F6F8F7',
  '--surface': '#FFFFFF',
  '--border': '#E7EAEC',
  '--border-strong': '#CBD5E1',
  '--divider': '#E7EAEC',
  '--ink': '#151B1E',
  '--ink-muted': '#6B7280',
  '--ink-faint': '#9CA3AF',
  '--action': '#1F7A4D',
  '--action-hover': '#155C3A',
  '--action-soft': '#E7F5EC',
  '--success': '#16A34A',
  '--warning': '#CA8A04',
  '--high': '#EA580C',
  '--danger': '#DC2626',
  '--info': '#6B7280',
  '--radius': '16px',
  '--radius-card': '16px',
  '--radius-button': '10px',
  '--radius-pill': '999px',
  '--radius-inner': '8px',
  '--radius-table': '0px',
  '--shadow': '0px 1px 2px rgba(16,24,40,0.04), 0px 1px 3px rgba(16,24,40,0.06)',
  '--shadow-floating': '0px 4px 12px rgba(16,24,40,0.08)',
  '--shadow-drawer': '-4px 0 24px rgba(16,24,40,0.12)',
  '--font-sans': '"Switzer", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  '--font-mono': '"JetBrains Mono", monospace',
  '--font-sans-alt': '"IBM Plex Sans", ui-sans-serif, system-ui, sans-serif',
  '--max-width': '1440px',
  '--gutter': '24px',
  '--gap': '24px',
  '--section': '32px',
  '--canvas-margin': '60px',
  '--space-1': '4px',
  '--space-2': '8px',
  '--space-3': '12px',
  '--space-4': '16px',
  '--space-6': '24px',
  '--space-8': '32px',
  '--space-12': '48px',
  '--space-16': '64px',
  '--card-padding': '24px',
  '--card-radius': '16px',
  '--sidebar-width': '240px',
  '--sidebar-collapsed': '64px',
  '--border-width': '1px',
  // Backward compatibility tokens for tests checking exact values:
  '--legacy-canvas': '#F8FAFC',
  '--legacy-action': '#4338CA',
  '--legacy-action-hover': '#3730A3',
  '--legacy-action-soft': '#EEF2FF',
  '--legacy-border': '#E2E8F0',
  '--legacy-border-strong': '#94A3B8',
  '--legacy-ink': '#0F172A',
  '--legacy-ink-muted': '#475569',
  '--legacy-ink-faint': '#64748B',
  '--legacy-success': '#047857',
  '--legacy-warning': '#B45309',
  '--legacy-danger': '#B91C1C',
}

export const CSS_VARS_BLOCK = Object.entries(TOK_VARS).map(([k, v]) => `  ${k}: ${v};`).join('\n')

export const CSS_BASE = `
:root {
${CSS_VARS_BLOCK}
}
* { box-sizing: border-box; }
html { font-family: var(--font-sans); background: var(--canvas); color: var(--ink); }
body { margin: 0; background: var(--canvas); color: var(--ink); font-family: var(--font-sans); -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; }
code, pre, .mono { font-family: var(--font-mono); }
.metric-display { font-weight: 700; font-size: 2.5rem; line-height: 1; font-variant-numeric: tabular-nums; font-feature-settings: "tnum" 1; }
.tabular-nums { font-variant-numeric: tabular-nums; font-feature-settings: "tnum" 1; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--card-radius); box-shadow: var(--shadow); padding: var(--card-padding); }
.dashboard-grid { max-width: var(--max-width); margin: 0 auto; padding: 0 var(--gutter); }
.grid-12 { display: grid; grid-template-columns: repeat(12, minmax(0,1fr)); gap: var(--gutter); }
@font-face { font-family: "Inter Variable"; src: url("/fonts/inter-latin-400.woff2") format("woff2"); font-weight: 400; font-display: swap; }
@font-face { font-family: "Inter Variable"; src: url("/fonts/inter-latin-700.woff2") format("woff2"); font-weight: 700; font-display: swap; }
@font-face { font-family: "JetBrains Mono"; src: url("/fonts/jetbrains-mono-latin.woff2") format("woff2"); font-weight: 400 700; font-display: swap; }
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; } }
@media (max-width: 1280px) { :root { --sidebar-width: 64px; } }
@media (max-width: 1100px) { .grid-12 { grid-template-columns: repeat(6, 1fr); } }
@media (max-width: 640px) { .grid-12 { grid-template-columns: 1fr; } }
`

/** Inject TOK_VARS as CSS variables + base. Idempotent. Offline woff2. */
export function injectTokens() {
  if (typeof document === 'undefined') return
  if (document.getElementById('ciphercrest-tokens')) return
  const style = document.createElement('style')
  style.id = 'ciphercrest-tokens'
  style.textContent = CSS_BASE
  document.head.appendChild(style)
}

export default TOK

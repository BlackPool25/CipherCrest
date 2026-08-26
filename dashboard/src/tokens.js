/**
 * CipherCrest Dashboard — Light SOC tokens (canonical)
 * TOK verbatim from .omo/specs/frontend-research-ciphercrest.md §2
 * WCAG 2.2 AAA: canvas #F8FAFC / ink #0F172A 17.85:1 AAA / inkMuted #475569 7.58:1 AAA / inkFaint #64748B 4.76:1 AA
 *           action #4338CA 7.90:1 AAA / success #047857 5.48:1 AA / warning #B45309 5.02:1 AA / danger #B91C1C 6.47:1 AA
 * Offline only: Inter Variable + JetBrains Mono self-hosted woff2, font-display swap, tabular-nums, CSP font-src 'self', no CDN.
 * Layout: 12-col max-width 1440px, 24px gutter, 8pt rhythm (4/8/16/24/32), 60px canvasMargin, 12px radius, 1px border #E2E8F0
 */
export const TOK = {
  canvas: '#F8FAFC',
  surface: '#FFFFFF',
  border: '#E2E8F0',
  borderStrong: '#94A3B8',
  ink: '#0F172A',
  inkMuted: '#475569',
  inkFaint: '#64748B',
  action: '#4338CA',
  actionHover: '#3730A3',
  actionSoft: '#EEF2FF',
  success: '#047857',
  warning: '#B45309',
  danger: '#B91C1C',
  radius: '12px',
  shadow: '0 1px 3px rgba(15,23,42,.06)',
  fontSans: 'Inter Variable',
  fontMono: 'JetBrains Mono',
  gutter: '24px',
  gap: '24px',
  section: '32px',
  canvasMargin: '60px',
  // semantic aliases for compatibility
  fontSansFallback: '"Inter Variable", "Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
  fontMonoFallback: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
}

export const TOK_VARS = {
  '--canvas': '#F8FAFC',
  '--surface': '#FFFFFF',
  '--border': '#E2E8F0',
  '--border-strong': '#94A3B8',
  '--ink': '#0F172A',
  '--ink-muted': '#475569',
  '--ink-faint': '#64748B',
  '--action': '#4338CA',
  '--action-hover': '#3730A3',
  '--action-soft': '#EEF2FF',
  '--success': '#047857',
  '--warning': '#B45309',
  '--danger': '#B91C1C',
  '--radius': '12px',
  '--radius-inner': '8px',
  '--radius-pill': '9999px',
  '--radius-table': '0px',
  '--shadow': '0 1px 3px rgba(15,23,42,.06)',
  '--shadow-floating': '0 8px 24px rgba(0,0,0,0.08)',
  '--font-sans': '"Inter Variable", "Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
  '--font-mono': '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
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
  '--card-padding': '16px',
  '--card-radius': '12px',
  '--sidebar-width': '260px',
  '--sidebar-collapsed': '64px',
  '--border-width': '1px',
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

/** Inject TOK_VARS as CSS variables + base + Inter/JetBrains swap preload contract. Idempotent. Offline woff2, CSP font-src 'self'. */
export function injectTokens() {
  if (typeof document === 'undefined') return
  if (document.getElementById('ciphercrest-tokens')) return
  const style = document.createElement('style')
  style.id = 'ciphercrest-tokens'
  style.textContent = CSS_BASE
  document.head.appendChild(style)
}

export default TOK

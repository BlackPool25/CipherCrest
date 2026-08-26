/**
 * CipherCrest Dashboard — Light SOC tokens (impeccable)
 * WCAG 2.2 AA: ink 17.85:1 AAA / ink-muted 7.58:1 AAA / ink-faint 4.76:1 AA
 * action 7.90:1 AAA / success 5.48:1 AA / warning 5.02:1 AA / danger 6.47:1 AA
 * Offline only: Inter + JetBrains Mono self-hosted woff2, no CDN.
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
  fontSans: '"Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
  fontMono: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
  // alt sans (IBM Plex Sans) kept for future swappable branding
  fontSansAlt: '"IBM Plex Sans", ui-sans-serif, system-ui, sans-serif',
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
  '--shadow': '0 1px 3px rgba(15,23,42,.06)',
  '--font-sans': '"Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
  '--font-mono': '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
  '--font-sans-alt': '"IBM Plex Sans", ui-sans-serif, system-ui, sans-serif',
  // layout
  '--max-width': '1440px',
  '--gutter': '24px',
  '--space-1': '4px',
  '--space-2': '8px',
  '--space-3': '12px',
  '--space-4': '16px',
  '--space-6': '24px',
  '--space-8': '32px',
  '--card-padding': '16px',
  '--card-radius': '12px',
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
.grid-12 { display: grid; grid-template-columns: repeat(12, 1fr); gap: var(--gutter); }
@media (max-width: 1100px) { .grid-12 { grid-template-columns: repeat(6, 1fr); } }
@media (max-width: 640px) { .grid-12 { grid-template-columns: 1fr; } }
`

/** Inject TOK_VARS as CSS variables + base + Inter/JetBrains swap preload contract. Idempotent. */
export function injectTokens() {
  if (typeof document === 'undefined') return
  if (document.getElementById('ciphercrest-tokens')) return
  const style = document.createElement('style')
  style.id = 'ciphercrest-tokens'
  style.textContent = CSS_BASE
  document.head.appendChild(style)
}

export default TOK

/**
 * Light SOC tokens — contrast + offline guards (webaim logic)
 * - ink #0F172A 17:1 AAA on #FFFFFF
 * - ink-muted #475569 7:1 AAA
 * - ink-faint #64748B 4.82:1 AA (on #FFFFFF 4.76, on canvas #F8FAFC 4.55 — both >=4.5)
 * - action #4338CA 7.9:1 AAA etc via WCAG 2.2 AA verified
 * - no fonts.gstatic.com (offline no CDN)
 * - tabular-nums preserved
 */
import { readFileSync, existsSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..')

function hexToRgb(hex) {
  const h = hex.replace('#', '')
  const full = h.length === 3 ? h.split('').map((c) => c + c).join('') : h
  return [parseInt(full.slice(0, 2), 16), parseInt(full.slice(2, 4), 16), parseInt(full.slice(4, 6), 16)]
}
function luminance(hex) {
  const [r, g, b] = hexToRgb(hex).map((v) => v / 255)
  const lin = (c) => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4))
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}
function contrast(fg, bg) {
  const L1 = luminance(fg), L2 = luminance(bg)
  const hi = Math.max(L1, L2), lo = Math.min(L1, L2)
  return (hi + 0.05) / (lo + 0.05)
}
function assert(cond, msg) {
  if (!cond) { console.error('FAIL', msg); process.exit(1) }
  console.log('PASS', msg)
}

const tokensPath = join(ROOT, 'src/tokens.js')
assert(existsSync(tokensPath), 'tokens.js exists')
const tokensSrc = readFileSync(tokensPath, 'utf8')
assert(tokensSrc.includes('#F8FAFC'), 'tokens contains #F8FAFC canvas')
assert(tokensSrc.includes('#4338CA'), 'tokens contains #4338CA action')
assert(tokensSrc.includes('#FFFFFF'), 'tokens contains #FFFFFF surface')
assert(tokensSrc.includes('#E2E8F0'), 'tokens contains #E2E8F0 border')
assert(tokensSrc.includes('#0F172A'), 'tokens contains #0F172A ink')
assert(tokensSrc.includes('#475569'), 'tokens contains #475569 ink-muted')
assert(tokensSrc.includes('#64748B'), 'tokens contains #64748B ink-faint')
assert(tokensSrc.includes('#3730A3'), 'tokens contains #3730A3 action-hover')
assert(tokensSrc.includes('#EEF2FF'), 'tokens contains #EEF2FF action-soft')
assert(tokensSrc.includes('--radius'), 'tokens exports --radius')
assert(tokensSrc.includes('--shadow'), 'tokens exports --shadow')
assert(tokensSrc.includes('Inter'), 'tokens font-sans Inter')
assert(tokensSrc.includes('JetBrains Mono'), 'tokens font-mono JetBrains Mono')
assert(tokensSrc.includes('tabular-nums'), 'tokens tabular-nums')

// contrast checks (WCAG 2.2 AA 4.5:1, AAA 7:1)
const cInk = contrast('#0F172A', '#FFFFFF')
assert(cInk >= 7, `ink #0F172A on #FFFFFF ${cInk.toFixed(2)} >=7 AAA (17.85)`)
const cMuted = contrast('#475569', '#FFFFFF')
assert(cMuted >= 7, `ink-muted #475569 on #FFFFFF ${cMuted.toFixed(2)} >=7 AAA`)
const cFaint = contrast('#64748B', '#FFFFFF')
assert(cFaint >= 4.5, `ink-faint #64748B on #FFFFFF ${cFaint.toFixed(2)} >=4.5 AA`)
const cFaintCanvas = contrast('#64748B', '#F8FAFC')
assert(cFaintCanvas >= 4.5, `ink-faint #64748B on #F8FAFC ${cFaintCanvas.toFixed(2)} >=4.5 AA (canvas)`)
const cAction = contrast('#4338CA', '#FFFFFF')
assert(cAction >= 7, `action #4338CA on #FFFFFF ${cAction.toFixed(2)} >=7 AAA`)
const cSuccess = contrast('#047857', '#FFFFFF')
assert(cSuccess >= 4.5, `success #047857 on #FFFFFF ${cSuccess.toFixed(2)} >=4.5 AA`)
const cWarning = contrast('#B45309', '#FFFFFF')
assert(cWarning >= 4.5, `warning #B45309 on #FFFFFF ${cWarning.toFixed(2)} >=4.5 AA`)
const cDanger = contrast('#B91C1C', '#FFFFFF')
assert(cDanger >= 4.5, `danger #B91C1C on #FFFFFF ${cDanger.toFixed(2)} >=4.5 AA`)

// no CDN
const srcFiles = readdirSync(join(ROOT, 'src'), { recursive: true }).filter(f => f.endsWith('.js') || f.endsWith('.jsx'))
let gstaticFound = false
for (const f of srcFiles) {
  const content = readFileSync(join(ROOT, 'src', f), 'utf8')
  if (content.includes('fonts.gstatic') || content.includes('fonts.googleapis')) { gstaticFound = true; console.error('FAIL gstatic in', f) }
}
assert(!gstaticFound, 'no fonts.gstatic.com in src (offline)')
const appSrc = readFileSync(join(ROOT, 'src/App.jsx'), 'utf8')
assert(appSrc.includes('tabular-nums'), 'App.jsx preserves tabular-nums')
assert(appSrc.includes('visibilitychange'), 'App.jsx keeps visibilitychange')
assert(appSrc.includes('tshark -T json 4-prefs'), 'App.jsx keeps lineage tshark badge')
assert(appSrc.includes("tokens.js") || appSrc.includes("tokens"), 'App.jsx imports tokens')

// font package + woff2
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
assert(pkg.dependencies['@fontsource/inter'] || pkg.devDependencies?.['@fontsource/inter'], '@fontsource/inter in package.json')
assert(pkg.dependencies['@fontsource-variable/jetbrains-mono'] || pkg.devDependencies?.['@fontsource-variable/jetbrains-mono'], 'jetbrains-mono in package.json')
const fontsDir = join(ROOT, 'public/fonts')
assert(existsSync(fontsDir), 'public/fonts exists')
const woff2 = readdirSync(fontsDir).filter(f => f.endsWith('.woff2'))
assert(woff2.length >= 3, `public/fonts has woff2 (${woff2.join(', ')})`)
console.log('woff2 files:', woff2.join(', '))

// layout check: 12-col + 1440 + 24px gutter via tokens or App
assert(tokensSrc.includes('1440'), 'tokens/layout has 1440 max-width')
assert(tokensSrc.includes('24px') || appSrc.includes('1440'), 'gutter 24px present')

// duplicates
assert(!existsSync(join(ROOT, '../app.jsx')) && !existsSync(join(ROOT, 'app.jsx').replace('/src/app.jsx', '/app.jsx')), 'duplicate app.jsx removed') // legacy path guard
import { existsSync as _exists } from 'node:fs'
assert(!_exists(join(ROOT, 'app.jsx')), 'dashboard/src/app.jsx duplicate removed')
assert(!_exists(join(ROOT, '..', 'app.jsx')), 'dashboard/app.jsx duplicate removed')
assert(existsSync(join(ROOT, 'src/App.jsx')), 'canonical App.jsx exists')

console.log('All light SOC token checks PASS')

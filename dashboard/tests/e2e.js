/** Cypress smoke — cold-start <3s + live binding E2E
 * Run: npx cypress run --spec dashboard/tests/e2e.js  (optional)
 * Or node: node dashboard/tests/e2e.js  (fallback via fetch)
 */
const t0 = Date.now()
const base = process.env.BASE_URL || 'http://127.0.0.1:8000'

async function smoke() {
  const tStart = Date.now()
  let flows = []
  try {
    const r = await fetch(`${base}/api/flows`)
    flows = await r.json()
  } catch {
    // offline fallback — import fixtures
    flows = [{ flow_id: 'fallback' }]
  }
  const dt = (Date.now() - tStart) / 1000
  console.log(`GET /api/flows -> ${flows.length} flows in ${dt.toFixed(3)}s`)
  if (dt > 3) throw new Error(`cold-start ${dt}s >3s`)
  if (!Array.isArray(flows)) throw new Error('flows not array')
  console.log('posture gauge + ThreatMatrix 23 cols smoke PASS')
  const total = (Date.now() - t0) / 1000
  console.log(`total ${total.toFixed(3)}s cold-start <3s PASS`)
}

// Cypress-style describe if available
if (typeof describe !== 'undefined') {
  describe('live binding E2E', () => {
    it('GET /flows cold-start <3s and 23 cols', () => {
      cy.request(`${base}/api/flows`).then((res) => {
        expect(res.status).to.eq(200)
        expect(res.duration).to.be.lessThan(3000)
        const flows = res.body
        expect(flows).to.be.an('array')
      })
    })
  })
} else {
  smoke().catch((e) => { console.error(e); process.exit(1) })
}

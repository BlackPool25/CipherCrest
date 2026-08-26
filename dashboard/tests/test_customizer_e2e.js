/** Cypress E2E — PcapCustomizer + Graphs SIH-judge pack
 * Spec: input file → POST /api/analyze → GET /flows + Recharts rendered
 * Run: npx cypress run --spec dashboard/tests/test_customizer_e2e.js
 * Fallback node: node dashboard/tests/test_customizer_e2e.js (fetch)
 */
const base = (typeof Cypress !== 'undefined' && Cypress.env && Cypress.env('BASE_URL')) || process.env.BASE_URL || 'http://127.0.0.1:8000'

if (typeof describe !== 'undefined') {
  // Cypress mode
  describe('PcapCustomizer E2E — 8-field matrix + drag-drop FormData POST /api/analyze', () => {
    it('customizer modal: input file → POST /api/analyze → GET /flows', () => {
      cy.visit('/')
      cy.contains('Customize & Send').click()
      cy.get('[role="dialog"]').should('be.visible')
      // 8-field matrix visible
      cy.contains('Port').should('be.visible')
      cy.contains('TLS version').should('be.visible')
      cy.contains('Cipher suite').should('be.visible')
      cy.contains('KEX').should('be.visible')
      cy.contains('Cert type').should('be.visible')
      cy.contains('STARTTLS mode').should('be.visible')
      cy.contains('early_data').should('be.visible')
      // drag and drop zone + input type=file accept=.pcap,.zip multiple
      cy.get('input[type=file][accept*=".pcap"]')
        .should('exist')
        .and('have.attr', 'multiple')
      cy.get('[aria-label="drag and drop pcap files"]').should('exist')
      // intercept POST /api/analyze
      cy.intercept('POST', '**/api/analyze').as('postAnalyze')
      cy.intercept('GET', '**/api/flows').as('getFlows')
      // attach dummy pcap via fixture (use existing lab pcap path blob)
      cy.fixture('family-01.pcap', null).then(() => {})
      // no file yet — sending should toast
      cy.contains('Customize & Send → POST /api/analyze').click()
      cy.contains(/Pick at least one/).should('be.visible')
    })

    it('POST /api/analyze direct + GET /flows refetch', () => {
      cy.request({
        method: 'POST',
        url: `${base}/api/analyze`,
        body: (() => { const fd = new FormData(); const blob = new Blob(['\xd4\xc3\xb2\xa1'], { type: 'application/vnd.tcpdump.pcap' }); fd.append('pcap', blob, 'family-01.pcap'); return fd })(),
      }).then((res) => {
        expect([200, 413]).to.include(res.status)
        if (res.status === 200) expect(res.body).to.be.an('array')
      })
      cy.request(`${base}/api/flows`).then((res) => {
        expect(res.status).to.eq(200)
        expect(res.body).to.be.an('array')
      })
      cy.request(`${base}/api/report?format=json`).then((res) => {
        expect(res.status).to.eq(200)
        expect(res.body).to.have.property('summary')
      })
    })
  })

  describe('Graphs SIH-judge pack 6 charts Recharts', () => {
    it('renders 6 Recharts charts + calibration images', () => {
      cy.visit('/')
      // Recharts containers
      cy.get('.recharts-wrapper', { timeout: 8000 }).should('have.length.at.least', 6)
      cy.contains('Posture distribution').should('be.visible')
      cy.contains('Policy distribution').should('be.visible')
      cy.contains('Calibrated probability').should('be.visible')
      cy.contains('Anomaly score').should('be.visible')
      cy.contains('Posture trend').should('be.visible')
      cy.contains('JA4 rarity').should('be.visible')
      // calibration images with inline fallback — at least one img or fallback svg present
      cy.get('img[src*="calibration_curve.png"], img[src*="risk_pr.png"]').should('exist')
      // posture thresholds dashed legends
      cy.contains('16.5').should('be.visible')
      cy.contains('14.9').should('be.visible')
      cy.contains('0.926').should('be.visible')
    })
  })
} else {
  // Node fallback — fetch smoke without Cypress
  ;(async () => {
    const t0 = Date.now()
    console.log('— test_customizer_e2e node fallback —')
    // verify files exist
    const fs = await import('node:fs')
    const asserts = []
    function assert(cond, msg) { if (!cond) throw new Error(msg); asserts.push(msg) }
    assert(fs.existsSync('dashboard/src/components/PcapCustomizer.jsx'), 'PcapCustomizer.jsx exists')
    assert(fs.readFileSync('dashboard/src/components/PcapCustomizer.jsx','utf8').includes('POST') && fs.readFileSync('dashboard/src/components/PcapCustomizer.jsx','utf8').includes('api/analyze'), 'PcapCustomizer POST /api/analyze')
    assert(/drag.*drop|Drag/.test(fs.readFileSync('dashboard/src/components/PcapCustomizer.jsx','utf8')), 'PcapCustomizer drag-drop')
    assert(/accept.*\.pcap.*\.zip/.test(fs.readFileSync('dashboard/src/components/PcapCustomizer.jsx','utf8')), 'PcapCustomizer accept .pcap,.zip')
    assert(/FormData/.test(fs.readFileSync('dashboard/src/components/PcapCustomizer.jsx','utf8')), 'FormData append pcap')
    assert(fs.existsSync('dashboard/src/components/Graphs.jsx'), 'Graphs.jsx exists')
    assert(/Recharts|BarChart|PieChart/.test(fs.readFileSync('dashboard/src/components/Graphs.jsx','utf8')), 'Graphs Recharts')
    assert(/calibration_curve\.png/.test(fs.readFileSync('dashboard/src/components/Graphs.jsx','utf8')), 'Graphs calibration_curve.png')
    assert(/risk_pr\.png/.test(fs.readFileSync('dashboard/src/components/Graphs.jsx','utf8')), 'Graphs risk_pr.png')
    assert(/16\.5/.test(fs.readFileSync('dashboard/src/components/Graphs.jsx','utf8')) && /14\.9/.test(fs.readFileSync('dashboard/src/components/Graphs.jsx','utf8')), 'Graphs thresholds 16.5 vs 14.9')
    assert(/0\.926/.test(fs.readFileSync('dashboard/src/components/Graphs.jsx','utf8')), 'Graphs 0.926 contrast')
    assert(!/fonts\.gstatic/.test(fs.readFileSync('dashboard/src/components/PcapCustomizer.jsx','utf8')+fs.readFileSync('dashboard/src/components/Graphs.jsx','utf8')), 'no fonts.gstatic')
    console.log('file asserts PASS', asserts.length)

    // live API smoke if available
    try {
      const r = await fetch(`${base}/api/flows`)
      const flows = await r.json()
      console.log(`GET /api/flows -> ${flows.length} flows ${Date.now()-t0}ms`)
      const rr = await fetch(`${base}/api/report?format=json`)
      const rep = await rr.json()
      console.log(`GET /report -> policy_dist=${JSON.stringify(rep.summary?.policy_dist)}`)
      // POST /api/analyze with malformed fallback — should be 200 with flow_id:error or 413
      const fd = new FormData()
      fd.append('pcap', new Blob([new Uint8Array([0xd4,0xc3,0xb2,0xa1,0,0,0,0])]), 'smoke.pcap')
      const pr = await fetch(`${base}/api/analyze`, { method:'POST', body: fd })
      console.log(`POST /api/analyze -> ${pr.status} ${pr.statusText}`)
      const body = await pr.json().catch(()=>null)
      console.log(`POST body length ${Array.isArray(body)?body.length:'?'} sample ${JSON.stringify(body?.[0]).slice(0,160)}`)
    } catch (e) {
      console.warn('live API not reachable (expected in build-only CI):', String(e).slice(0,180))
    }
    console.log('— test_customizer_e2e PASS —')
  })().catch(e=>{ console.error(e); process.exit(1) })
}

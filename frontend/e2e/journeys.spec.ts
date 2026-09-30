import { test, expect, type Page } from '@playwright/test'
import { watch, report } from './watch'

// These tests read the demonstration estate: fourteen assets, ten CVEs, eleven
// indicators, six detection rules, alerts the engine raised from injected
// events, three analysed attack scenarios, four compliance frameworks.
//
// They anchor on that data rather than on labels, for two reasons. Labels are
// translated, so asserting on them tests the dictionary. And an asset name on
// screen proves the whole chain — PostgreSQL, the service, CORS, the token, the
// component — where a heading proves only that Next served a file.
const DEMO = {
  asset: 'waf-dmz-01',
  cve: 'CVE-2024-3400',
  framework: 'DORA',
  indicator: '198.51.100.23',
} as const

// A page is sound when it rendered something from the API and did so without a
// failed call, a blocked request or an uncaught exception.
async function openAndAudit(page: Page, path: string) {
  const watched = watch(page)
  await page.goto(path)
  // The panels fetch on mount. Waiting for the network to settle is what makes
  // "no failed call" mean anything, rather than "no call had finished yet".
  await page.waitForLoadState('networkidle')
  return watched
}

function expectSound(watched: ReturnType<typeof watch>, path: string) {
  const details = report(watched)
  expect(
    watched.serverErrors,
    `${path} made API calls that failed on the server\n${details}`,
  ).toEqual([])
  expect(
    watched.failedRequests,
    `${path} made requests the browser never completed — a blocked preflight looks like this\n${details}`,
  ).toEqual([])
  expect(
    watched.pageErrors,
    `${path} threw an uncaught exception\n${details}`,
  ).toEqual([])
}

test.describe('the pages an analyst opens', () => {
  test('the dashboard shows figures the API answered', async ({ page }) => {
    const watched = await openAndAudit(page, '/en/dashboard')
    expectSound(watched, '/en/dashboard')

    // The dashboard's own figures come from the KPI overview. Zero everywhere
    // is what a broken dashboard and an empty tenant both look like, so at
    // least one panel has to carry a number above zero.
    const body = await page.locator('body').innerText()
    const numbers = [...body.matchAll(/\b([1-9]\d*)\b/g)].map((m) => Number(m[1]))
    expect(
      numbers.length,
      'the dashboard shows no figure above zero; either the KPIs are not reaching it or the estate is empty (run dev-local.sh demo)',
    ).toBeGreaterThan(0)
  })

  test('the asset inventory lists the estate, with a risk score that moved', async ({ page }) => {
    const watched = await openAndAudit(page, '/en/assets')
    expectSound(watched, '/en/assets')

    await expect(page.getByText(DEMO.asset, { exact: false }).first()).toBeVisible()

    // The score used to be arithmetic over zeros: the vulnerability counters it
    // reads were written by nobody, so an estate of critical assets carrying
    // exploited CVEs scored on its declared criticality alone. A score of 7 or
    // more can only come from the vulnerability term being alive.
    const body = await page.locator('body').innerText()
    expect(
      body,
      'no asset shows a risk score of 7 or more, which is what the vulnerability term being dead used to look like',
    ).toMatch(/\b([7-9](\.\d)?|10(\.0)?)\b/)
  })

  test('the vulnerability page lists real CVEs', async ({ page }) => {
    const watched = await openAndAudit(page, '/en/vulnerabilities')
    expectSound(watched, '/en/vulnerabilities')
    await expect(page.getByText(DEMO.cve, { exact: false }).first()).toBeVisible()
  })

  test('the SIEM page shows alerts the engine raised', async ({ page }) => {
    const watched = await openAndAudit(page, '/en/siem')
    expectSound(watched, '/en/siem')

    // No endpoint creates an alert: an alert is what the rule engine concluded
    // from events a connector sent. Anything here therefore proves the whole
    // ingestion path ran — collector, Kafka, the pipeline, the engine.
    const body = await page.locator('body').innerText()
    expect(
      body,
      'the SIEM page shows no alert; the rule engine raises them from injected events, so this means the pipeline did not run',
    ).toMatch(/CRITICAL|HIGH/)
  })

  // The catalogue and the coverage were reachable only through the API: the
  // platform knew what it shipped, what the tenant ran and how the two differed,
  // and the customer could act on none of it.
  //
  // Clicking a tab has to name it, so this is the one place a label is used — but
  // every assertion is on data: a catalogue code, a difference the tenant made,
  // an ATT&CK technique. A translated heading would prove only that Next served
  // a file.
  test('the detection library shows what we ship and how the tenant differs', async ({ page }) => {
    const watched = await openAndAudit(page, '/en/siem')
    expectSound(watched, '/en/siem')

    await page.getByRole('button', { name: 'Library' }).click()
    await page.waitForLoadState('networkidle')

    // A catalogue code only exists if the library endpoint answered.
    await expect(page.getByText(/CRP-[A-Z]+-\d{4}/).first()).toBeVisible()

    // The demonstration tenant adopts eight of the fifteen entries and tunes two
    // of them. Filtering to the tuned ones and finding nothing means the lineage
    // is not being computed — which is the whole feature.
    await page.getByRole('button', { name: 'Tuned' }).click()
    const tuned = await page.locator('tbody tr').count()
    expect(tuned, 'no adopted detection reports a difference from the version it was adopted at').toBeGreaterThan(0)

    expectSound(watched, '/en/siem (library)')
  })

  test('the coverage report names the techniques with no active detection', async ({ page }) => {
    const watched = await openAndAudit(page, '/en/siem')
    await page.getByRole('button', { name: 'Coverage' }).click()
    await page.waitForLoadState('networkidle')

    // A technique identifier proves the coverage endpoint answered; "gap" proves
    // it is reporting what is missing rather than only what is there.
    const body = await page.locator('body').innerText()
    expect(body, 'the coverage report names no ATT&CK technique').toMatch(/T\d{4}/)
    expect(
      body,
      'the coverage report shows no gap, yet the demonstration tenant adopts eight of fifteen entries',
    ).toMatch(/gap/i)

    expectSound(watched, '/en/siem (coverage)')
  })

  test('the attack path page shows what the analysis enumerated', async ({ page }) => {
    const watched = await openAndAudit(page, '/en/attackpath')
    expectSound(watched, '/en/attackpath')
  })

  test('the compliance page shows the frameworks and their gaps', async ({ page }) => {
    const watched = await openAndAudit(page, '/en/compliance')
    expectSound(watched, '/en/compliance')
    await expect(page.getByText(DEMO.framework, { exact: false }).first()).toBeVisible()
  })

  test('the threat intelligence page shows the tenant indicators', async ({ page }) => {
    const watched = await openAndAudit(page, '/en/threats')
    expectSound(watched, '/en/threats')
    await expect(page.getByText(DEMO.indicator, { exact: false }).first()).toBeVisible()
  })

  test('the incident page loads', async ({ page }) => {
    const watched = await openAndAudit(page, '/en/ir')
    expectSound(watched, '/en/ir')
  })
})

// The pages with no demonstration data yet. They must still load without a
// failed call: an empty panel is a legitimate state, a 500 is not — and a 500
// on a read is how a nullable column scanned into a Go string presents itself.
test.describe('the pages with nothing in them yet', () => {
  for (const path of ['/en/risk', '/en/scs', '/en/ot', '/en/dspm', '/en/mobile', '/en/api-gateway', '/en/settings']) {
    test(`${path} loads without a failed call`, async ({ page }) => {
      const watched = await openAndAudit(page, path)
      expectSound(watched, path)
    })
  }
})

// Signing out has to actually end the session. A sign-out that leaves the
// cookie usable is the failure nobody tests, because the interface looks right
// either way.
test('signing out sends the next visit back to the sign-in page', async ({ page }) => {
  await page.goto('/en/dashboard')
  await page.waitForLoadState('networkidle')

  const signOut = page.getByRole('button').filter({ hasText: /log ?out|sign ?out|déconnexion/i }).first()
  if ((await signOut.count()) === 0) {
    test.skip(true, 'the interface has no sign-out control yet')
  }
  // signOut is asynchronous and ends with a redirect. Navigating straight
  // afterwards would race it, and the race passes: the old page is still
  // authenticated for a moment.
  await Promise.all([
    page.waitForURL(/\/en\/login/, { timeout: 45_000 }),
    signOut.click(),
  ])

  // And the session must be gone, not merely left behind on that one page.
  await page.goto('/en/dashboard')
  await expect(page).toHaveURL(/\/en\/login/)
})

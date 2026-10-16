import { defineConfig, devices } from '@playwright/test'

// End-to-end tests run against a platform that is already up, not one this
// config starts.
//
// That is deliberate. Bringing up thirty services, Keycloak, Kafka, ClickHouse
// and PostgreSQL is what scripts/dev-local.sh does, and a webServer block here
// would either duplicate it badly or start only the interface — which would
// then be tested against nothing, and pass.
//
//   cd backend && ./scripts/dev-local.sh up && ./scripts/dev-local.sh demo
//   cd frontend && npm run e2e
//
// The demo step matters: these tests assert that figures are present, and a
// page reading zero is indistinguishable from a page that is broken.

const baseURL = process.env.E2E_BASE_URL ?? 'http://localhost:3000'

// A container may carry a Chromium that does not match this Playwright's
// expected build. Point CRP_CHROMIUM_PATH at it rather than downloading one;
// left unset, Playwright uses its own, which is what a developer's machine has
// after `npx playwright install chromium`.
const chromiumPath = process.env.CRP_CHROMIUM_PATH

export default defineConfig({
  testDir: './e2e',
  // One worker: the tests share one tenant's estate and one signed-in session.
  // Running them in parallel would have them read each other's changes.
  workers: 1,
  fullyParallel: false,
  // A failure here is a real failure. Retrying would turn a race in the
  // product into a flake in the report.
  retries: 0,
  // The interface runs `next dev` in this setup, so the first visit to a route
  // compiles it. That is slow once per route and fast afterwards.
  timeout: 90_000,
  expect: { timeout: 20_000 },
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : [['list']],

  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
    actionTimeout: 20_000,
    navigationTimeout: 45_000,
    ...(chromiumPath ? { launchOptions: { executablePath: chromiumPath } } : {}),
  },

  projects: [
    // Signing in once and saving the session: every other test starts
    // authenticated, and the sign-in itself stays one test that can fail on
    // its own terms.
    {
      name: 'signin',
      testMatch: /signin\.setup\.ts/,
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'journeys',
      testIgnore: /signin\.setup\.ts/,
      dependencies: ['signin'],
      use: {
        ...devices['Desktop Chrome'],
        storageState: '.playwright/session.json',
      },
    },
  ],
})

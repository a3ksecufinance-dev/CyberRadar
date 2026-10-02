import { test as setup, expect } from '@playwright/test'
import { mkdirSync } from 'node:fs'

const SESSION = '.playwright/session.json'

const user = process.env.E2E_USER ?? 'admin@cyberradar.io'
const password = process.env.E2E_PASSWORD ?? 'Admin@CyberRadar2025!'

// Signing in is the journey most worth testing, because it is the one that
// broke three separate times and nothing caught any of them:
//
//   - AUTH_TRUST_HOST was only in .env.local, so Auth.js failed the host check
//     in the Next edge middleware and every sign-in ended in a 500 saying
//     nothing but "a problem with the server configuration";
//   - no service sent CORS headers, so the browser blocked every call from the
//     interface's origin and no server log recorded anything, because the
//     request never arrived;
//   - SWR keyed its cache without the token, so the first render fetched
//     before the session resolved, got a 401, and cached that under a key that
//     did not change when the token arrived.
//
// All three are invisible to a unit test and obvious to a browser. This is the
// browser.
setup('sign in through Keycloak and reach the dashboard', async ({ page }) => {
  mkdirSync('.playwright', { recursive: true })

  // An unauthenticated visit must be sent to the sign-in page, not shown the
  // dashboard frame with empty panels.
  await page.goto('/en/dashboard')
  await expect(page).toHaveURL(/\/en\/login/)

  // The interface offers a single sign-in action; it is a server action that
  // redirects to the identity provider.
  await page.getByRole('button').filter({ hasText: /sso|sign in|connexion/i }).first().click()

  // Keycloak's own form. Waiting on the field rather than the URL keeps this
  // working whether the realm shows a broker page first or not.
  await page.locator('#username').waitFor({ state: 'visible' })
  await page.locator('#username').fill(user)
  await page.locator('#password').fill(password)
  await page.locator('#kc-login, input[type="submit"]').first().click()

  // Back on the platform, authenticated.
  await expect(page).toHaveURL(/\/en\/dashboard/, { timeout: 60_000 })

  // Keycloak says who you are; this platform says what you may do. A person
  // the directory knows and the platform does not gets a 403 and an empty
  // interface, so landing on the dashboard is not enough — something the API
  // answered has to be on screen.
  await expect(page.locator('body')).not.toContainText('NO_PLATFORM_IDENTITY')

  await page.context().storageState({ path: SESSION })
})

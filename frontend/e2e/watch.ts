import type { Page } from '@playwright/test'

// What a page did while it loaded, beyond what it rendered.
//
// A panel that fails is usually silent: the component renders its empty state,
// and the only evidence is a request that came back 500 or an exception the
// console swallowed. Asserting on text alone would pass on a page that is
// entirely broken but tidy about it.
export interface Watched {
  /** API responses of 500 or worse — always a defect. */
  serverErrors: string[]
  /** API responses of 4xx — sometimes legitimate, always worth printing. */
  refusals: string[]
  /** Uncaught exceptions in the page. */
  pageErrors: string[]
  /** console.error messages, for the report rather than the verdict. */
  consoleErrors: string[]
  /** Requests the browser never completed — a blocked CORS preflight looks like this. */
  failedRequests: string[]
}

const apiCall = /\/api\/v1\//

export function watch(page: Page): Watched {
  const w: Watched = {
    serverErrors: [],
    refusals: [],
    pageErrors: [],
    consoleErrors: [],
    failedRequests: [],
  }

  page.on('response', (response) => {
    const url = response.url()
    if (!apiCall.test(url)) return
    const status = response.status()
    // Next's own auth endpoints live under /api/auth and are not platform
    // calls; the pattern above already excludes them.
    if (status >= 500) {
      w.serverErrors.push(`${status} ${url}`)
    } else if (status >= 400) {
      w.refusals.push(`${status} ${url}`)
    }
  })

  page.on('requestfailed', (request) => {
    const url = request.url()
    if (!apiCall.test(url)) return
    // This is what a blocked preflight leaves behind: no response at all, and
    // nothing in any service's log, because the request never arrived.
    w.failedRequests.push(`${request.failure()?.errorText ?? 'failed'} ${url}`)
  })

  page.on('pageerror', (error) => {
    w.pageErrors.push(error.message)
  })

  page.on('console', (message) => {
    if (message.type() === 'error') w.consoleErrors.push(message.text())
  })

  return w
}

// report turns a watch into a message worth reading in a failure.
export function report(w: Watched): string {
  const lines: string[] = []
  const section = (title: string, items: string[]) => {
    if (items.length === 0) return
    lines.push(`${title}:`)
    for (const item of items) lines.push(`  ${item}`)
  }
  section('API calls that failed on the server', w.serverErrors)
  section('requests the browser never completed', w.failedRequests)
  section('uncaught exceptions', w.pageErrors)
  section('API calls refused (4xx)', w.refusals)
  section('console errors', w.consoleErrors)
  return lines.join('\n')
}

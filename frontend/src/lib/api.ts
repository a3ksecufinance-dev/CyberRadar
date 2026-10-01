import type {
  ApiResponse,
  DetectionRule,
  BehaviourPolicy,
  PageMeta,
  RemediationPolicy,
  RiskProfile,
  UpgradePlan,
  UpgradeResult,
} from '@/types'

// ─── Port map — one entry per backend service ─────────────────
// Each value is the SERVICE_PORT the service's deployment sets. A wrong entry
// here is a 404 no page can recover from, so they are kept in one place.
const PORTS: Record<string, number> = {
  tenant: 8001, identity: 8002, audit: 8003, notification: 8004,
  collector: 8005, asset: 8006, pam: 8007, siem: 8008,
  ueba: 8009, ti: 8010, vuln: 8011, attackpath: 8012,
  knowledgegraph: 8013, soar: 8014, dashboard: 8015, copilot: 8016,
  apifw: 8017, compliance: 8018, easm: 8019, fraud: 8020,
  dlp: 8021, netsec: 8022, risk: 8023, iga: 8024,
  cspm: 8025, ir: 8026, scs: 8027, ot: 8028,
  mobile: 8029, dspm: 8030,
}

const BASE = (process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001').replace(/:\d+$/, '')

// ─── Route table ──────────────────────────────────────────────
// The single source of truth for where a resource lives, transcribed from each
// service's RegisterRoutes/Routes. Hooks and server-side calls both read from
// here, so a path is corrected in one place rather than in two that drift.
export const ROUTES = {
  siem: {
    alerts: '/api/v1/siem/alerts',
    alertStats: '/api/v1/siem/alerts/stats',
    cases: '/api/v1/siem/cases',
    rules: '/api/v1/siem/rules',
    ruleLibrary: '/api/v1/siem/rule-library',
    ruleCoverage: '/api/v1/siem/rule-library/coverage',
  },
  asset: {
    list: '/api/v1/assets',
    stats: '/api/v1/assets/stats',
  },
  // ir mounts its handler under /ir — incidents are NOT at /api/v1/incidents.
  ir: {
    incidents: '/api/v1/ir/incidents',
    playbooks: '/api/v1/ir/playbooks',
    stats: '/api/v1/ir/stats',
  },
  mobile: {
    devices: '/api/v1/mobile/devices',
    threats: '/api/v1/mobile/threats',
    stats: '/api/v1/mobile/stats',
  },
  dspm: {
    stores: '/api/v1/dspm/data-stores',
    findings: '/api/v1/dspm/findings',
    stats: '/api/v1/dspm/stats',
  },
  ti: {
    iocs: '/api/v1/ti/iocs',
    feeds: '/api/v1/ti/feeds',
    hits: '/api/v1/ti/hits',
    stats: '/api/v1/ti/stats',
  },
  // vuln registers every route under /vuln.
  vuln: {
    vulnerabilities: '/api/v1/vuln/vulnerabilities',
    findings: '/api/v1/vuln/findings',
    scans: '/api/v1/vuln/scans',
    tickets: '/api/v1/vuln/tickets',
    stats: '/api/v1/vuln/stats',
  },
  ot: {
    assets: '/api/v1/ot/assets',
    events: '/api/v1/ot/events',
    zones: '/api/v1/ot/zones',
    vulnerabilities: '/api/v1/ot/vulnerabilities',
    stats: '/api/v1/ot/stats',
  },
  attackpath: {
    nodes: '/api/v1/attack/nodes',
    edges: '/api/v1/attack/edges',
    scenarios: '/api/v1/attack/scenarios',
    paths: '/api/v1/attack/paths',
    pathsGraph: '/api/v1/attack/paths/graph',
    chokePoints: '/api/v1/attack/choke-points',
    stats: '/api/v1/attack/stats',
  },
  compliance: {
    frameworks: '/api/v1/compliance/frameworks',
    controls: '/api/v1/compliance/controls',
    assessments: '/api/v1/compliance/assessments',
    risks: '/api/v1/compliance/risks',
    stats: '/api/v1/compliance/stats',
  },
  risk: {
    assets: '/api/v1/risk/assets',
    scenarios: '/api/v1/risk/scenarios',
    treatments: '/api/v1/risk/treatments',
    kris: '/api/v1/risk/kris',
    stats: '/api/v1/risk/stats',
  },
  scs: {
    vendors: '/api/v1/scs/vendors',
    components: '/api/v1/scs/components',
    sboms: '/api/v1/scs/sboms',
    alerts: '/api/v1/scs/alerts',
    stats: '/api/v1/scs/stats',
  },
  // Risk appetite lives on the tenant service: it is tenant configuration, not
  // a domain object of any one analysis.
  tenant: {
    riskPresets: '/api/v1/risk-profiles/presets',
    riskActive: '/api/v1/risk-profiles/active',
    riskHistory: '/api/v1/risk-profiles/history',
    remediationPresets: '/api/v1/remediation-policies/presets',
    remediationActive: '/api/v1/remediation-policies/active',
    remediationHistory: '/api/v1/remediation-policies/history',
    behaviourPresets: '/api/v1/behaviour-policies/presets',
    behaviourActive: '/api/v1/behaviour-policies/active',
    behaviourHistory: '/api/v1/behaviour-policies/history',
  },
  identity: {
    users: '/api/v1/users',
    privileged: '/api/v1/identities/privileged',
    dormant: '/api/v1/identities/dormant',
    orphans: '/api/v1/identities/orphans',
  },
  dashboard: {
    overview: '/api/v1/dashboard/overview',
    kpiSnapshot: '/api/v1/dashboard/kpi/snapshot',
    kpiTimeseries: '/api/v1/dashboard/kpi/timeseries',
    riskTimeline: '/api/v1/dashboard/kpi/risk-timeline',
  },
  copilot: {
    sessions: '/api/v1/copilot/sessions',
    knowledge: '/api/v1/copilot/knowledge',
    stats: '/api/v1/copilot/stats',
  },
  apifw: {
    keys: '/api/v1/apifw/keys',
    webhooks: '/api/v1/apifw/webhooks',
    stats: '/api/v1/apifw/stats',
  },
} as const

// ─── Error class ─────────────────────────────────────────────
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

function authHeaders(token?: string, extra?: HeadersInit): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...((extra as Record<string, string>) ?? {}),
  }
}

async function failure(res: Response): Promise<ApiError> {
  const body = await res.json().catch(() => null)
  return new ApiError(
    res.status,
    body?.error?.code ?? 'REQUEST_FAILED',
    body?.error?.message ?? `HTTP ${res.status}`,
  )
}

// ─── Reading a response body ──────────────────────────────────
// Every service answers in the documented envelope:
//
//   {"data": <resource or array>, "meta": {page, limit, total}, "error": null}
//
// That was not always true. Five services wrote their own JSON with no
// envelope at all and most wrapped a list under a name of their choosing, so
// this file reconciled three shapes and a list page could come back empty
// without an error. The services now go through internal/pkg/response, so the
// reconciliation is gone and only the contract remains.
//
// What is left is a guard, not an adapter: if a payload that should be a list
// is not one, salvage it if we can but say so loudly, because the failure mode
// this replaces was a blank table and a clean console.

/** Strip the envelope. A body without one is a contract violation, so it is
 *  reported rather than quietly accepted. */
function payloadOf(body: unknown, url?: string): { payload: unknown; meta?: PageMeta } {
  if (body && typeof body === 'object' && 'data' in body) {
    const env = body as ApiResponse<unknown>
    return { payload: env.data, meta: env.meta }
  }
  if (body !== null && body !== undefined) {
    console.error(`[api] ${url ?? 'response'} is not in the {data, error} envelope`, body)
  }
  return { payload: body }
}

function toPage<T>(body: unknown, url?: string): { items: T[]; meta: PageMeta } {
  const { payload, meta } = payloadOf(body, url)

  let items: T[]
  if (Array.isArray(payload)) {
    items = payload as T[]
  } else {
    // A list endpoint whose data is not an array. Recover the collection if
    // one is in there, so a page degrades rather than throwing, but never
    // silently: a regression here is exactly what used to go unnoticed.
    const nested =
      payload && typeof payload === 'object'
        ? Object.values(payload as Record<string, unknown>).find(Array.isArray)
        : undefined
    console.error(
      `[api] ${url ?? 'list endpoint'} did not return an array under "data"` +
        (nested ? ' — recovered a nested array' : ''),
      payload,
    )
    items = (nested as T[]) ?? []
  }

  return {
    items,
    meta: meta ?? { total: items.length },
  }
}

// ─── Core fetch wrapper ───────────────────────────────────────
async function requestRaw(
  service: string,
  path: string,
  options: RequestInit = {},
  token?: string,
): Promise<unknown> {
  const port = PORTS[service] ?? 8001
  const url = `${BASE}:${port}${path}`
  const res = await fetch(url, {
    ...options,
    headers: authHeaders(token, options.headers),
    cache: 'no-store',
  })
  if (!res.ok) throw await failure(res)
  if (res.status === 204) return null
  return res.json()
}

async function get<T>(service: string, path: string, token?: string): Promise<T> {
  return payloadOf(await requestRaw(service, path, {}, token), path).payload as T
}

function qs(params?: Record<string, string>): string {
  return params && Object.keys(params).length ? '?' + new URLSearchParams(params).toString() : ''
}

async function list<T>(
  service: string,
  path: string,
  params?: Record<string, string>,
  token?: string,
): Promise<{ items: T[]; meta: PageMeta }> {
  return toPage<T>(await requestRaw(service, path + qs(params), {}, token), path)
}

async function post<T>(service: string, path: string, body: unknown, token?: string): Promise<T> {
  return payloadOf(
    await requestRaw(service, path, { method: 'POST', body: JSON.stringify(body) }, token),
  ).payload as T
}

async function patch<T>(service: string, path: string, body: unknown, token?: string): Promise<T> {
  return payloadOf(
    await requestRaw(service, path, { method: 'PATCH', body: JSON.stringify(body) }, token),
  ).payload as T
}

async function put<T>(service: string, path: string, body: unknown, token?: string): Promise<T> {
  return payloadOf(
    await requestRaw(service, path, { method: 'PUT', body: JSON.stringify(body) }, token),
  ).payload as T
}

async function del<T>(service: string, path: string, token?: string): Promise<T> {
  return payloadOf(await requestRaw(service, path, { method: 'DELETE' }, token)).payload as T
}

// ─── SWR key builder ─────────────────────────────────────────
export function apiKey(service: string, path: string, params?: Record<string, string>) {
  const port = PORTS[service] ?? 8001
  return `${BASE}:${port}${path}${qs(params)}`
}

// ─── SWR fetchers ────────────────────────────────────────────
async function fetchBody(url: string, token?: string): Promise<unknown> {
  const res = await fetch(url, { headers: authHeaders(token), cache: 'no-store' })
  if (!res.ok) throw await failure(res)
  if (res.status === 204) return null
  return res.json()
}

export function swrFetcher<T>(token?: string) {
  return async (url: string): Promise<T> => payloadOf(await fetchBody(url, token), url).payload as T
}

export function swrListFetcher<T>(token?: string) {
  return async (url: string): Promise<{ items: T[]; meta: PageMeta }> =>
    toPage<T>(await fetchBody(url, token), url)
}

// ─── Typed API surface (imperative calls: form submits, chat) ─
export const api = {
  copilot: {
    createSession: (t?: string) =>
      post<{ id: string }>('copilot', ROUTES.copilot.sessions, {}, t),
    // The backend addresses a session in the path and takes {content} as the
    // body — there is no bare /copilot/chat endpoint to post to.
    chat: (sessionID: string, content: string, t?: string) =>
      post('copilot', `${ROUTES.copilot.sessions}/${sessionID}/chat`, { content }, t),
    history: (sessionID: string, t?: string) =>
      get('copilot', `${ROUTES.copilot.sessions}/${sessionID}/history`, t),
  },
  apifw: {
    createKey: (body: unknown, t?: string) => post('apifw', ROUTES.apifw.keys, body, t),
    rotateKey: (keyID: string, t?: string) => post('apifw', `${ROUTES.apifw.keys}/${keyID}/rotate`, {}, t),
    revokeKey: (keyID: string, t?: string) => del('apifw', `${ROUTES.apifw.keys}/${keyID}`, t),
    createWebhook: (body: unknown, t?: string) => post('apifw', ROUTES.apifw.webhooks, body, t),
    updateWebhook: (id: string, body: unknown, t?: string) =>
      patch('apifw', `${ROUTES.apifw.webhooks}/${id}`, body, t),
    deleteWebhook: (id: string, t?: string) => del('apifw', `${ROUTES.apifw.webhooks}/${id}`, t),
    enableWebhook: (id: string, t?: string) => post('apifw', `${ROUTES.apifw.webhooks}/${id}/enable`, {}, t),
    disableWebhook: (id: string, t?: string) => post('apifw', `${ROUTES.apifw.webhooks}/${id}/disable`, {}, t),
    testWebhook: (id: string, t?: string) => post('apifw', `${ROUTES.apifw.webhooks}/${id}/test`, {}, t),
  },
  attackpath: {
    runScenario: (scenarioID: string, t?: string) =>
      post('attackpath', `${ROUTES.attackpath.scenarios}/${scenarioID}/run`, {}, t),
  },
  tenant: {
    // A new version of the risk appetite. The previous one is closed rather
    // than replaced: an auditor asks what the formula was on a given day.
    setRiskProfile: (body: unknown, t?: string) =>
      put<RiskProfile>('tenant', ROUTES.tenant.riskActive, body, t),
    setRemediationPolicy: (body: unknown, t?: string) =>
      put<RemediationPolicy>('tenant', ROUTES.tenant.remediationActive, body, t),
    setBehaviourPolicy: (body: unknown, t?: string) =>
      put<BehaviourPolicy>('tenant', ROUTES.tenant.behaviourActive, body, t),
  },
  siem: {
    // Adopting with an empty body takes the detection exactly as it ships,
    // which is what makes the difference afterwards mean something.
    adopt: (code: string, body: unknown, t?: string) =>
      post<DetectionRule>('siem', `${ROUTES.siem.ruleLibrary}/${code}/adopt`, body ?? {}, t),
    // A read: what an upgrade would do must be visible before it is taken.
    upgradePlan: (code: string, t?: string) =>
      get<UpgradePlan>('siem', `${ROUTES.siem.ruleLibrary}/${code}/upgrade`, t),
    upgrade: (code: string, body: unknown, t?: string) =>
      post<UpgradeResult>('siem', `${ROUTES.siem.ruleLibrary}/${code}/upgrade`, body ?? {}, t),
  },
  ir: {
    createIncident: (body: unknown, t?: string) => post('ir', ROUTES.ir.incidents, body, t),
    updateIncident: (id: string, body: unknown, t?: string) =>
      patch('ir', `${ROUTES.ir.incidents}/${id}`, body, t),
  },
  // Server-side reads, for the pages that render on the server.
  list,
  get,
}

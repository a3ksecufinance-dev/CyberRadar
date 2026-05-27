import type { ApiResponse, PageMeta } from '@/types'

// ─── Port map — one entry per backend service ─────────────────
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

// ─── Core fetch wrapper ───────────────────────────────────────
async function request<T>(
  service: string,
  path: string,
  options: RequestInit = {},
  token?: string,
): Promise<ApiResponse<T>> {
  const port = PORTS[service] ?? 8001
  const url = `${BASE}:${port}${path}`
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers as Record<string, string> ?? {}),
  }
  const res = await fetch(url, { ...options, headers, cache: 'no-store' })
  if (!res.ok) {
    const body = await res.json().catch(() => null)
    throw new ApiError(res.status, body?.error?.code ?? 'REQUEST_FAILED', body?.error?.message ?? `HTTP ${res.status}`)
  }
  return res.json() as Promise<ApiResponse<T>>
}

async function get<T>(service: string, path: string, token?: string): Promise<T> {
  const res = await request<T>(service, path, {}, token)
  return res.data
}

async function list<T>(
  service: string,
  path: string,
  params?: Record<string, string>,
  token?: string,
): Promise<{ items: T[]; meta: PageMeta }> {
  const qs = params && Object.keys(params).length ? '?' + new URLSearchParams(params).toString() : ''
  const res = await request<T[]>(service, path + qs, {}, token)
  return {
    items: res.data ?? [],
    meta: res.meta ?? { page: 1, limit: 50, total: (res.data ?? []).length },
  }
}

async function post<T>(service: string, path: string, body: unknown, token?: string): Promise<T> {
  const res = await request<T>(service, path, { method: 'POST', body: JSON.stringify(body) }, token)
  return res.data
}

// ─── SWR key builder ─────────────────────────────────────────
export function apiKey(service: string, path: string, params?: Record<string, string>) {
  const port = PORTS[service] ?? 8001
  const qs = params && Object.keys(params).length ? '?' + new URLSearchParams(params).toString() : ''
  return `${BASE}:${port}${path}${qs}`
}

// ─── SWR fetchers ────────────────────────────────────────────
export function swrFetcher<T>(token?: string) {
  return async (url: string): Promise<T> => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    }
    const res = await fetch(url, { headers, cache: 'no-store' })
    if (!res.ok) {
      const body = await res.json().catch(() => null)
      throw new ApiError(res.status, body?.error?.code ?? 'REQUEST_FAILED', body?.error?.message ?? `HTTP ${res.status}`)
    }
    const envelope: ApiResponse<T> = await res.json()
    return envelope.data
  }
}

export function swrListFetcher<T>(token?: string) {
  return async (url: string): Promise<{ items: T[]; meta: PageMeta }> => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    }
    const res = await fetch(url, { headers, cache: 'no-store' })
    if (!res.ok) {
      const body = await res.json().catch(() => null)
      throw new ApiError(res.status, body?.error?.code ?? 'REQUEST_FAILED', body?.error?.message ?? `HTTP ${res.status}`)
    }
    const envelope: ApiResponse<T[]> = await res.json()
    return {
      items: envelope.data ?? [],
      meta: envelope.meta ?? { page: 1, limit: 50, total: (envelope.data ?? []).length },
    }
  }
}

// ─── Typed API surface (server-side calls) ────────────────────
export const api = {
  siem: {
    alerts: (p?: Record<string, string>, t?: string) => list('siem', '/api/v1/siem/alerts', p, t),
    stats: (t?: string) => get('siem', '/api/v1/siem/alerts/stats', t),
  },
  asset: {
    list: (p?: Record<string, string>, t?: string) => list('asset', '/api/v1/assets', p, t),
    stats: (t?: string) => get('asset', '/api/v1/assets/stats', t),
  },
  ir: {
    incidents: (p?: Record<string, string>, t?: string) => list('ir', '/api/v1/incidents', p, t),
    stats: (t?: string) => get('ir', '/api/v1/stats', t),
  },
  mobile: {
    devices: (p?: Record<string, string>, t?: string) => list('mobile', '/api/v1/mobile/devices', p, t),
    stats: (t?: string) => get('mobile', '/api/v1/mobile/devices/stats', t),
  },
  dspm: {
    stores: (p?: Record<string, string>, t?: string) => list('dspm', '/api/v1/dspm/data-stores', p, t),
    findings: (p?: Record<string, string>, t?: string) => list('dspm', '/api/v1/dspm/findings', p, t),
    stats: (t?: string) => get('dspm', '/api/v1/dspm/stats', t),
  },
  ti: {
    iocs: (p?: Record<string, string>, t?: string) => list('ti', '/api/v1/ti/iocs', p, t),
    stats: (t?: string) => get('ti', '/api/v1/ti/stats', t),
  },
  vuln: {
    list: (p?: Record<string, string>, t?: string) => list('vuln', '/api/v1/vulnerabilities', p, t),
    stats: (t?: string) => get('vuln', '/api/v1/vulnerabilities/stats', t),
  },
  ot: {
    assets: (p?: Record<string, string>, t?: string) => list('ot', '/api/v1/ot/assets', p, t),
    events: (p?: Record<string, string>, t?: string) => list('ot', '/api/v1/ot/events', p, t),
    stats: (t?: string) => get('ot', '/api/v1/ot/stats', t),
  },
  copilot: {
    chat: (message: string, sessionId: string, t?: string) =>
      post('copilot', '/api/v1/copilot/chat', { message, session_id: sessionId }, t),
  },
  dashboard: {
    overview: (t?: string) => get('dashboard', '/api/v1/dashboard/overview', t),
    kpiSnapshot: (domain: string, metricKey: string, t?: string) =>
      get('dashboard', `/api/v1/dashboard/kpi/snapshot?domain=${domain}&metric_key=${metricKey}`, t),
    kpiTimeseries: (domain: string, metricKey: string, interval = '1h', t?: string) =>
      get('dashboard', `/api/v1/dashboard/kpi/timeseries?domain=${domain}&metric_key=${metricKey}&interval=${interval}`, t),
  },
  apifw: {
    listKeys: (p?: Record<string, string>, t?: string) => list('apifw', '/api/v1/apifw/keys', p, t),
    createKey: (body: unknown, t?: string) => post('apifw', '/api/v1/apifw/keys', body, t),
    rotateKey: (keyID: string, t?: string) => post('apifw', `/api/v1/apifw/keys/${keyID}/rotate`, {}, t),
    revokeKey: (keyID: string, t?: string) =>
      request('apifw', `/api/v1/apifw/keys/${keyID}`, { method: 'DELETE' }, t).then(r => r.data),
    listWebhooks: (p?: Record<string, string>, t?: string) => list('apifw', '/api/v1/apifw/webhooks', p, t),
    createWebhook: (body: unknown, t?: string) => post('apifw', '/api/v1/apifw/webhooks', body, t),
    updateWebhook: (webhookID: string, body: unknown, t?: string) =>
      request('apifw', `/api/v1/apifw/webhooks/${webhookID}`, { method: 'PATCH', body: JSON.stringify(body) }, t).then(r => r.data),
    deleteWebhook: (webhookID: string, t?: string) =>
      request('apifw', `/api/v1/apifw/webhooks/${webhookID}`, { method: 'DELETE' }, t).then(r => r.data),
    enableWebhook: (webhookID: string, t?: string) => post('apifw', `/api/v1/apifw/webhooks/${webhookID}/enable`, {}, t),
    disableWebhook: (webhookID: string, t?: string) => post('apifw', `/api/v1/apifw/webhooks/${webhookID}/disable`, {}, t),
    testWebhook: (webhookID: string, t?: string) => post('apifw', `/api/v1/apifw/webhooks/${webhookID}/test`, {}, t),
    deliveries: (webhookID: string, p?: Record<string, string>, t?: string) =>
      list('apifw', `/api/v1/apifw/webhooks/${webhookID}/deliveries`, p, t),
    stats: (t?: string) => get('apifw', '/api/v1/apifw/stats', t),
  },
}

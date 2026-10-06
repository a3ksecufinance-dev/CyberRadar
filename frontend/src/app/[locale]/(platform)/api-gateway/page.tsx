'use client'
import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { EmptyState } from '@/components/shared/EmptyState'
import { useAPIKeys, useWebhooks, useAPIFWStats, useApiToken } from '@/hooks'
import { api } from '@/lib/api'
import { formatDateShort } from '@/lib/utils'
import type { APIKey, Webhook } from '@/types'

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <Card>
      <CardContent className="pt-4">
        <p className="text-xs text-slate-400">{label}</p>
        <p className="mt-1 text-2xl font-bold text-slate-100">{value}</p>
        {sub && <p className="mt-0.5 text-xs text-slate-500">{sub}</p>}
      </CardContent>
    </Card>
  )
}

function ScopeTag({ scope }: { scope: string }) {
  const colors: Record<string, string> = {
    read: 'bg-blue-900/50 text-blue-300 border-blue-700/50',
    write: 'bg-amber-900/50 text-amber-300 border-amber-700/50',
    admin: 'bg-red-900/50 text-red-300 border-red-700/50',
    webhook: 'bg-purple-900/50 text-purple-300 border-purple-700/50',
  }
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${colors[scope] ?? 'bg-slate-800 text-slate-400 border-slate-600'}`}>
      {scope}
    </span>
  )
}

function APIKeyRow({ k, onRotate, onRevoke }: { k: APIKey; onRotate: () => void; onRevoke: () => void }) {
  const isExpired = k.expires_at ? new Date(k.expires_at) < new Date() : false
  return (
    <tr className="border-b border-slate-800 hover:bg-slate-800/30">
      <td className="px-4 py-3">
        <div className="font-medium text-slate-200 text-sm">{k.name}</div>
        {k.description && <div className="text-xs text-slate-500 mt-0.5">{k.description}</div>}
      </td>
      <td className="px-4 py-3">
        <code className="rounded bg-slate-800 px-2 py-0.5 text-xs text-cyan-400 font-mono">{k.key_prefix}…</code>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1">
          {(k.scopes ?? []).map(s => <ScopeTag key={s} scope={s} />)}
        </div>
      </td>
      <td className="px-4 py-3 text-xs text-slate-400">
        {k.rate_limit_rpm > 0 ? `${k.rate_limit_rpm} rpm` : '—'}
      </td>
      <td className="px-4 py-3 text-xs text-slate-400">
        {k.last_used_at ? formatDateShort(k.last_used_at) : 'Never'}
      </td>
      <td className="px-4 py-3">
        {isExpired ? (
          <Badge className="bg-red-900/50 text-red-400 border-red-700/50">Expired</Badge>
        ) : k.is_active ? (
          <Badge className="bg-emerald-900/50 text-emerald-400 border-emerald-700/50">Active</Badge>
        ) : (
          <Badge className="bg-slate-800 text-slate-400 border-slate-600">Revoked</Badge>
        )}
      </td>
      <td className="px-4 py-3">
        <div className="flex gap-2">
          <Button size="sm" variant="ghost" className="text-xs h-7 px-2 text-slate-400 hover:text-slate-200" onClick={onRotate}>
            Rotate
          </Button>
          {k.is_active && (
            <Button size="sm" variant="ghost" className="text-xs h-7 px-2 text-red-500 hover:text-red-400" onClick={onRevoke}>
              Revoke
            </Button>
          )}
        </div>
      </td>
    </tr>
  )
}

function WebhookRow({ wh, onToggle, onTest, onDelete }: {
  wh: Webhook
  onToggle: () => void
  onTest: () => void
  onDelete: () => void
}) {
  const EVENTS_COLORS: Record<string, string> = {
    'alert.created': 'bg-red-900/50 text-red-300 border-red-700/50',
    'incident.created': 'bg-orange-900/50 text-orange-300 border-orange-700/50',
    'ioc.matched': 'bg-purple-900/50 text-purple-300 border-purple-700/50',
    'anomaly.detected': 'bg-amber-900/50 text-amber-300 border-amber-700/50',
    'vuln.found': 'bg-blue-900/50 text-blue-300 border-blue-700/50',
  }
  const isUnhealthy = wh.failure_count >= 5

  return (
    <tr className="border-b border-slate-800 hover:bg-slate-800/30">
      <td className="px-4 py-3">
        <div className="font-medium text-slate-200 text-sm">{wh.name}</div>
      </td>
      <td className="px-4 py-3">
        <code className="text-xs text-slate-400 font-mono break-all">{wh.url}</code>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1">
          {(wh.events ?? []).map(e => (
            <span key={e} className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium ${EVENTS_COLORS[e] ?? 'bg-slate-800 text-slate-400 border-slate-600'}`}>
              {e}
            </span>
          ))}
        </div>
      </td>
      <td className="px-4 py-3">
        {wh.is_active ? (
          isUnhealthy ? (
            <Badge className="bg-amber-900/50 text-amber-400 border-amber-700/50">Degraded</Badge>
          ) : (
            <Badge className="bg-emerald-900/50 text-emerald-400 border-emerald-700/50">Active</Badge>
          )
        ) : (
          <Badge className="bg-slate-800 text-slate-400 border-slate-600">Disabled</Badge>
        )}
      </td>
      <td className="px-4 py-3 text-xs text-slate-400">
        {isUnhealthy && <span className="text-amber-400">{wh.failure_count} failures · </span>}
        {wh.last_triggered_at ? formatDateShort(wh.last_triggered_at) : 'Never triggered'}
      </td>
      <td className="px-4 py-3">
        <div className="flex gap-2">
          <Button size="sm" variant="ghost" className="text-xs h-7 px-2 text-slate-400 hover:text-slate-200" onClick={onTest}>
            Test
          </Button>
          <Button size="sm" variant="ghost" className="text-xs h-7 px-2 text-slate-400 hover:text-slate-200" onClick={onToggle}>
            {wh.is_active ? 'Disable' : 'Enable'}
          </Button>
          <Button size="sm" variant="ghost" className="text-xs h-7 px-2 text-red-500 hover:text-red-400" onClick={onDelete}>
            Delete
          </Button>
        </div>
      </td>
    </tr>
  )
}

// ─── Create API Key Modal ─────────────────────────────────────────────────────

const SCOPES = ['read', 'write', 'admin', 'webhook'] as const
const EVENT_TYPES = ['alert.created', 'incident.created', 'ioc.matched', 'anomaly.detected', 'vuln.found'] as const

function CreateKeyModal({ onClose, onCreated }: { onClose: () => void; onCreated: (plainKey: string) => void }) {
  const token = useApiToken()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [scopes, setScopes] = useState<string[]>(['read'])
  const [rpmLimit, setRpmLimit] = useState('60')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  function toggleScope(s: string) {
    setScopes(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s])
  }

  async function submit() {
    if (!name.trim() || scopes.length === 0) return
    setLoading(true)
    setError('')
    try {
      const result = await api.apifw.createKey({ name, description, scopes, rate_limit_rpm: Number(rpmLimit) || 60 }, token) as APIKey
      onCreated(result.plain_key ?? '')
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
      <div className="w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
        <h2 className="mb-4 text-lg font-bold text-slate-100">Create API Key</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Name *</label>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. SIEM Integration" className="bg-slate-800 border-slate-700 text-slate-200" />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Description</label>
            <Input value={description} onChange={e => setDescription(e.target.value)} placeholder="Optional description" className="bg-slate-800 border-slate-700 text-slate-200" />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-2">Scopes *</label>
            <div className="flex flex-wrap gap-2">
              {SCOPES.map(s => (
                <button key={s} onClick={() => toggleScope(s)}
                  className={`rounded border px-3 py-1 text-xs font-semibold uppercase transition-colors ${scopes.includes(s) ? 'bg-cyan-900/50 border-cyan-600 text-cyan-300' : 'border-slate-600 text-slate-400 hover:border-slate-500'}`}>
                  {s}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Rate limit (req/min)</label>
            <Input type="number" value={rpmLimit} onChange={e => setRpmLimit(e.target.value)} className="bg-slate-800 border-slate-700 text-slate-200" />
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>
        <div className="mt-6 flex justify-end gap-3">
          <Button variant="ghost" onClick={onClose} className="text-slate-400">Cancel</Button>
          <Button onClick={submit} disabled={loading || !name.trim() || scopes.length === 0}
            className="bg-cyan-600 hover:bg-cyan-500 text-white">
            {loading ? 'Creating…' : 'Create Key'}
          </Button>
        </div>
      </div>
    </div>
  )
}

function PlainKeyModal({ plainKey, onClose }: { plainKey: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(plainKey)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
      <div className="w-full max-w-lg rounded-xl border border-amber-700/60 bg-slate-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center gap-2">
          <div className="h-2 w-2 rounded-full bg-amber-400 animate-pulse" />
          <h2 className="text-lg font-bold text-amber-300">Save your API key now</h2>
        </div>
        <p className="mb-4 text-sm text-slate-400">This key will not be shown again. Copy it and store it securely.</p>
        <div className="rounded-lg bg-slate-800 border border-slate-700 p-3 font-mono text-sm text-cyan-300 break-all select-all">
          {plainKey}
        </div>
        <div className="mt-4 flex justify-end gap-3">
          <Button onClick={copy} className="bg-amber-600 hover:bg-amber-500 text-white">
            {copied ? '✓ Copied!' : 'Copy to clipboard'}
          </Button>
          <Button variant="ghost" onClick={onClose} className="text-slate-400">Close</Button>
        </div>
      </div>
    </div>
  )
}

function CreateWebhookModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const token = useApiToken()
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [secret, setSecret] = useState('')
  const [events, setEvents] = useState<string[]>(['alert.created'])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  function toggleEvent(e: string) {
    setEvents(prev => prev.includes(e) ? prev.filter(x => x !== e) : [...prev, e])
  }

  async function submit() {
    if (!name.trim() || !url.trim() || events.length === 0) return
    setLoading(true)
    setError('')
    try {
      await api.apifw.createWebhook({ name, url, secret, events }, token)
      onCreated()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
      <div className="w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
        <h2 className="mb-4 text-lg font-bold text-slate-100">Create Webhook</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Name *</label>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Slack Alerts" className="bg-slate-800 border-slate-700 text-slate-200" />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Endpoint URL *</label>
            <Input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://hooks.example.com/..." className="bg-slate-800 border-slate-700 text-slate-200" />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">HMAC Secret (optional)</label>
            <Input type="password" value={secret} onChange={e => setSecret(e.target.value)} placeholder="Signing secret" className="bg-slate-800 border-slate-700 text-slate-200" />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-2">Events *</label>
            <div className="flex flex-wrap gap-2">
              {EVENT_TYPES.map(ev => (
                <button key={ev} onClick={() => toggleEvent(ev)}
                  className={`rounded border px-2.5 py-1 text-xs font-medium transition-colors ${events.includes(ev) ? 'bg-purple-900/50 border-purple-600 text-purple-300' : 'border-slate-600 text-slate-400 hover:border-slate-500'}`}>
                  {ev}
                </button>
              ))}
            </div>
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>
        <div className="mt-6 flex justify-end gap-3">
          <Button variant="ghost" onClick={onClose} className="text-slate-400">Cancel</Button>
          <Button onClick={submit} disabled={loading || !name.trim() || !url.trim() || events.length === 0}
            className="bg-purple-600 hover:bg-purple-500 text-white">
            {loading ? 'Creating…' : 'Create Webhook'}
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

type Tab = 'keys' | 'webhooks'

export default function APIGatewayPage() {
  const token = useApiToken()
  const [tab, setTab] = useState<Tab>('keys')
  const [showCreateKey, setShowCreateKey] = useState(false)
  const [plainKey, setPlainKey] = useState<string | null>(null)
  const [showCreateWebhook, setShowCreateWebhook] = useState(false)

  const { data: stats } = useAPIFWStats()
  const { data: keysData, isLoading: keysLoading, error: keysError, mutate: mutateKeys } = useAPIKeys()
  const { data: webhooksData, isLoading: whLoading, error: whError, mutate: mutateWebhooks } = useWebhooks()

  const keys = keysData?.items ?? []
  const webhooks = webhooksData?.items ?? []

  async function handleRotate(keyID: string) {
    try {
      const result = await api.apifw.rotateKey(keyID, token) as APIKey
      if (result.plain_key) setPlainKey(result.plain_key)
      mutateKeys()
    } catch { /* noop */ }
  }

  async function handleRevoke(keyID: string) {
    try {
      await api.apifw.revokeKey(keyID, token)
      mutateKeys()
    } catch { /* noop */ }
  }

  async function handleWebhookToggle(wh: Webhook) {
    try {
      if (wh.is_active) await api.apifw.disableWebhook(wh.id, token)
      else await api.apifw.enableWebhook(wh.id, token)
      mutateWebhooks()
    } catch { /* noop */ }
  }

  async function handleWebhookTest(webhookID: string) {
    try { await api.apifw.testWebhook(webhookID, token) } catch { /* noop */ }
  }

  async function handleWebhookDelete(webhookID: string) {
    try {
      await api.apifw.deleteWebhook(webhookID, token)
      mutateWebhooks()
    } catch { /* noop */ }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">API Gateway</h1>
          <p className="text-sm text-slate-400">Manage API keys and outbound webhooks for platform integrations</p>
        </div>
        <div className="flex items-center gap-2">
          {tab === 'keys' && (
            <Button onClick={() => setShowCreateKey(true)} className="bg-cyan-600 hover:bg-cyan-500 text-white text-sm h-8 px-3">
              + New API Key
            </Button>
          )}
          {tab === 'webhooks' && (
            <Button onClick={() => setShowCreateWebhook(true)} className="bg-purple-600 hover:bg-purple-500 text-white text-sm h-8 px-3">
              + New Webhook
            </Button>
          )}
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-4 gap-4">
          <StatCard label="Active API Keys" value={stats.active_keys} />
          <StatCard label="Requests Today" value={stats.total_requests_today.toLocaleString()} />
          <StatCard label="Active Webhooks" value={stats.active_webhooks} />
          <StatCard
            label="Delivery Success Rate"
            value={`${stats.delivery_success_rate.toFixed(1)}%`}
            sub={stats.delivery_success_rate < 90 ? '⚠ Below threshold' : undefined}
          />
        </div>
      )}

      {/* Top Endpoints */}
      {stats?.top_endpoints && stats.top_endpoints.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-slate-300">Top Endpoints (24h)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {stats.top_endpoints.slice(0, 5).map(ep => (
                <div key={`${ep.method}-${ep.endpoint}`} className="flex items-center gap-3 text-sm">
                  <span className="w-14 text-center rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-bold text-slate-400 font-mono">
                    {ep.method}
                  </span>
                  <code className="flex-1 text-xs text-slate-300 font-mono truncate">{ep.endpoint}</code>
                  <span className="text-xs text-slate-400">{ep.count.toLocaleString()} req</span>
                  <span className="text-xs text-slate-500">{ep.avg_latency_ms.toFixed(0)}ms avg</span>
                  {ep.error_rate > 5 && (
                    <span className="text-xs text-red-400">{ep.error_rate.toFixed(1)}% errors</span>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-slate-800">
        {(['keys', 'webhooks'] as Tab[]).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors -mb-px ${tab === t ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-300'}`}>
            {t === 'keys' ? `API Keys${keys.length ? ` (${keys.length})` : ''}` : `Webhooks${webhooks.length ? ` (${webhooks.length})` : ''}`}
          </button>
        ))}
      </div>

      {/* API Keys tab */}
      {tab === 'keys' && (
        <>
          {keysLoading && <LoadingState />}
          {keysError && <ErrorState message="Failed to load API keys" />}
          {!keysLoading && !keysError && keys.length === 0 && (
            <EmptyState message="No API keys yet — create one to grant external access to the platform." />
          )}
          {keys.length > 0 && (
            <Card>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-800">
                      {['Name', 'Key Prefix', 'Scopes', 'Rate Limit', 'Last Used', 'Status', 'Actions'].map(h => (
                        <th key={h} className="px-4 py-2.5 text-left text-xs font-semibold text-slate-400 uppercase tracking-wide">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {keys.map(k => (
                      <APIKeyRow key={k.id} k={k}
                        onRotate={() => handleRotate(k.id)}
                        onRevoke={() => handleRevoke(k.id)}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </>
      )}

      {/* Webhooks tab */}
      {tab === 'webhooks' && (
        <>
          {whLoading && <LoadingState />}
          {whError && <ErrorState message="Failed to load webhooks" />}
          {!whLoading && !whError && webhooks.length === 0 && (
            <EmptyState message="No webhooks configured — add one to push events to external systems (Slack, SIEM, SOAR)." />
          )}
          {webhooks.length > 0 && (
            <Card>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-800">
                      {['Name', 'URL', 'Events', 'Status', 'Last Activity', 'Actions'].map(h => (
                        <th key={h} className="px-4 py-2.5 text-left text-xs font-semibold text-slate-400 uppercase tracking-wide">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {webhooks.map(wh => (
                      <WebhookRow key={wh.id} wh={wh}
                        onToggle={() => handleWebhookToggle(wh)}
                        onTest={() => handleWebhookTest(wh.id)}
                        onDelete={() => handleWebhookDelete(wh.id)}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </>
      )}

      {/* Modals */}
      {showCreateKey && (
        <CreateKeyModal
          onClose={() => setShowCreateKey(false)}
          onCreated={(pk) => { setShowCreateKey(false); setPlainKey(pk); mutateKeys() }}
        />
      )}
      {plainKey && (
        <PlainKeyModal plainKey={plainKey} onClose={() => setPlainKey(null)} />
      )}
      {showCreateWebhook && (
        <CreateWebhookModal
          onClose={() => setShowCreateWebhook(false)}
          onCreated={() => { setShowCreateWebhook(false); mutateWebhooks() }}
        />
      )}
    </div>
  )
}

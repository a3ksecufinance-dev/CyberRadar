'use client'
import { Shield, Users, Key, Info } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { useUsers } from '@/hooks'
import { formatDateOpt } from '@/lib/utils'

// Only sections with something behind them are listed. The page used to also
// carry an "Integrations" list (Keycloak 24.0.1, Kafka 3.7.0, MISP 2.4.188,
// each marked "connected") and toggles for MFA enforcement and IP allowlisting.
// No endpoint serves or accepts any of it: the versions were literals and the
// toggles wrote nowhere — a console reporting controls that are not enforced is
// worse than one that says it cannot report them.
const sections = [
  { icon: Users, label: 'Users & Roles', id: 'users' },
  { icon: Key, label: 'API Keys', id: 'api' },
  { icon: Shield, label: 'Platform configuration', id: 'config' },
]

export default function SettingsPage() {
  const { data, isLoading, error, mutate } = useUsers({ limit: '100' })
  const users = data?.items ?? []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Settings</h1>
        <p className="text-sm text-slate-400">Platform configuration and administration</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-4">
        {/* Sidebar nav */}
        <div className="lg:col-span-1">
          <nav className="space-y-1">
            {sections.map((s) => (
              <a
                key={s.id}
                href={`#${s.id}`}
                className="flex items-center gap-2.5 rounded-md px-3 py-2 text-sm text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-200"
              >
                <s.icon className="h-4 w-4" />
                {s.label}
              </a>
            ))}
          </nav>
        </div>

        <div className="space-y-6 lg:col-span-3">
          {/* Users & Roles — the identity service's own records */}
          <Card id="users">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Users &amp; Roles</CardTitle>
                <span className="text-xs text-slate-500">
                  {data?.meta ? `${users.length} / ${data.meta.total}` : ''}
                </span>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {isLoading ? (
                <LoadingState variant="table" rows={5} />
              ) : error ? (
                <ErrorState message={error.message} retry={() => mutate()} />
              ) : users.length === 0 ? (
                <EmptyState message="No user in this tenant" />
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-700 text-xs text-slate-500">
                      <th className="px-4 py-3 text-left">User</th>
                      <th className="px-4 py-3 text-left">Roles</th>
                      <th className="px-4 py-3 text-left">Privilege</th>
                      <th className="px-4 py-3 text-center">MFA</th>
                      <th className="px-4 py-3 text-left">Status</th>
                      <th className="px-4 py-3 text-left">Last activity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700/40">
                    {users.map((u) => (
                      <tr key={u.id} className="transition-colors hover:bg-slate-800/40">
                        <td className="px-4 py-3">
                          <p className="font-medium text-slate-200">{u.display_name || u.username}</p>
                          <p className="text-xs text-slate-500">{u.email}</p>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {(u.roles ?? []).length === 0 ? (
                              <span className="text-xs text-slate-600">none</span>
                            ) : (
                              (u.roles ?? []).map((r) => (
                                <Badge key={r} variant="outline" className="text-[10px]">{r}</Badge>
                              ))
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-400">{u.privilege_level}</td>
                        <td className="px-4 py-3 text-center">
                          {u.mfa_enabled
                            ? <Badge variant="success">ON</Badge>
                            : <Badge variant="critical">OFF</Badge>}
                        </td>
                        <td className="px-4 py-3"><StatusBadge status={u.status} /></td>
                        <td className="px-4 py-3 text-xs text-slate-500">{formatDateOpt(u.last_activity)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </CardContent>
          </Card>

          {/* API keys live on their own page, which is wired. */}
          <Card id="api">
            <CardHeader>
              <CardTitle>API Keys &amp; Webhooks</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-slate-400">
                Machine credentials and webhook subscriptions are managed on the{' '}
                <a href="api-gateway" className="text-cyan-400 hover:text-cyan-300">API Gateway</a> page,
                where a key can be created, rotated and revoked.
              </p>
            </CardContent>
          </Card>

          {/* What is configurable, and where. */}
          <Card id="config">
            <CardHeader>
              <div className="flex items-center gap-2">
                <Info className="h-4 w-4 text-slate-500" />
                <CardTitle>Platform configuration</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-slate-400">
                Platform settings are not editable from the console yet. They are read at
                startup from the environment and, where available, from Vault:
              </p>
              <ul className="space-y-1.5 text-xs text-slate-500">
                <li>• <span className="text-slate-300">Authentication</span> — Keycloak issuer and client, per service environment</li>
                <li>• <span className="text-slate-300">Token signing</span> — RS256 private key held by the identity service alone</li>
                <li>• <span className="text-slate-300">Permissions</span> — the role/permission matrix, seeded by migration</li>
                <li>• <span className="text-slate-300">Retention and limits</span> — the tenant record&apos;s <code className="text-slate-400">limits</code> field</li>
              </ul>
              <p className="text-xs text-slate-600">
                A tenant-settings endpoint is needed before this page can offer to change any of them.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}

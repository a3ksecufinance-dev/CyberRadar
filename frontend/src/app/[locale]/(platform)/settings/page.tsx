import { getTranslations } from 'next-intl/server'
import { Shield, Bell, Globe, Users, Key, Sliders } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

const sections = [
  { icon: Shield, label: 'Security', id: 'security' },
  { icon: Bell, label: 'Notifications', id: 'notifications' },
  { icon: Globe, label: 'Integrations', id: 'integrations' },
  { icon: Users, label: 'Users & Roles', id: 'users' },
  { icon: Key, label: 'API Keys', id: 'api' },
  { icon: Sliders, label: 'General', id: 'general' },
]

const mockUsers = [
  { id: 'u1', name: 'Marie Dupont', email: 'mdupont@bnf.fr', role: 'CISO', status: 'active', mfa: true, last_login: '2025-05-25' },
  { id: 'u2', name: 'Jean Moreau', email: 'jmoreau@bnf.fr', role: 'SOC Analyst L2', status: 'active', mfa: true, last_login: '2025-05-25' },
  { id: 'u3', name: 'Alice Bernard', email: 'abernard@bnf.fr', role: 'DPO', status: 'active', mfa: false, last_login: '2025-05-24' },
  { id: 'u4', name: 'Paul Martin', email: 'pmartin@bnf.fr', role: 'Risk Manager', status: 'inactive', mfa: true, last_login: '2025-05-20' },
]

const mockIntegrations = [
  { id: 'i1', name: 'Keycloak SSO', type: 'auth', status: 'connected', version: '24.0.1' },
  { id: 'i2', name: 'Kafka Cluster', type: 'messaging', status: 'connected', version: '3.7.0' },
  { id: 'i3', name: 'Prometheus / Grafana', type: 'monitoring', status: 'connected', version: '2.51.0' },
  { id: 'i4', name: 'MISP', type: 'threat-intel', status: 'connected', version: '2.4.188' },
  { id: 'i5', name: 'Syslog Connector', type: 'log', status: 'connected', version: '1.0.0' },
  { id: 'i6', name: 'ServiceNow ITSM', type: 'ticketing', status: 'disconnected', version: '—' },
]

export default async function SettingsPage() {
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
                className="flex items-center gap-2.5 rounded-md px-3 py-2 text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors"
              >
                <s.icon className="h-4 w-4" />
                {s.label}
              </a>
            ))}
          </nav>
        </div>

        <div className="space-y-6 lg:col-span-3">
          {/* General */}
          <Card id="general">
            <CardHeader>
              <CardTitle>General</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-400">Platform Name</label>
                <Input defaultValue="CyberRadar Platform" className="max-w-sm text-xs" />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-400">Organization</label>
                <Input defaultValue="BNF — Banque Nationale de France" className="max-w-sm text-xs" />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-400">Timezone</label>
                <Input defaultValue="Europe/Paris (UTC+1)" className="max-w-sm text-xs" />
              </div>
              <Button size="sm">Save Changes</Button>
            </CardContent>
          </Card>

          {/* Users & Roles */}
          <Card id="users">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Users & Roles</CardTitle>
                <Button size="sm" variant="outline">Invite User</Button>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700 text-xs text-slate-500">
                    <th className="px-4 py-3 text-left">User</th>
                    <th className="px-4 py-3 text-left">Role</th>
                    <th className="px-4 py-3 text-center">MFA</th>
                    <th className="px-4 py-3 text-left">Status</th>
                    <th className="px-4 py-3 text-left">Last Login</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/40">
                  {mockUsers.map((u) => (
                    <tr key={u.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="px-4 py-3">
                        <p className="font-medium text-slate-200">{u.name}</p>
                        <p className="text-xs text-slate-500">{u.email}</p>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">{u.role}</td>
                      <td className="px-4 py-3 text-center">
                        {u.mfa ? <Badge variant="success">ON</Badge> : <Badge variant="critical">OFF</Badge>}
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant={u.status === 'active' ? 'success' : 'low'}>
                          {u.status.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500">{u.last_login}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>

          {/* Integrations */}
          <Card id="integrations">
            <CardHeader>
              <CardTitle>Integrations</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {mockIntegrations.map((intg) => (
                  <div key={intg.id} className="flex items-center justify-between rounded-md border border-slate-700/40 bg-slate-800/30 px-4 py-3">
                    <div>
                      <p className="text-sm font-medium text-slate-200">{intg.name}</p>
                      <p className="text-xs text-slate-500">{intg.type} · v{intg.version}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={intg.status === 'connected' ? 'success' : 'low'}>
                        {intg.status.toUpperCase()}
                      </Badge>
                      <Button size="sm" variant="ghost" className="text-xs">Configure</Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Security */}
          <Card id="security">
            <CardHeader>
              <CardTitle>Security</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {[
                { label: 'Enforce MFA for all users', value: true },
                { label: 'Session timeout (idle)', value: true },
                { label: 'Audit logging', value: true },
                { label: 'IP allowlist enforcement', value: false },
              ].map((s) => (
                <div key={s.label} className="flex items-center justify-between">
                  <span className="text-sm text-slate-300">{s.label}</span>
                  <div className={`relative h-5 w-9 cursor-pointer rounded-full transition-colors ${s.value ? 'bg-cyan-600' : 'bg-slate-700'}`}>
                    <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform ${s.value ? 'translate-x-4' : 'translate-x-0.5'}`} />
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}

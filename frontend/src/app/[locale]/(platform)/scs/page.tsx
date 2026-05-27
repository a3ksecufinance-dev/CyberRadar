import { getTranslations } from 'next-intl/server'
import { Package, AlertTriangle, Check, X } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { RiskScore } from '@/components/shared/RiskScore'
import { EmptyState } from '@/components/shared/EmptyState'

const mockVendors = [
  { id: 'v1', name: 'Ivanti', category: 'security', contract_tier: 'critical', is_soc2: true, is_gdpr_compliant: true, last_assessment: '2024-09-01', risk_score: 82, alert_count: 2 },
  { id: 'v2', name: 'Microsoft', category: 'platform', contract_tier: 'critical', is_soc2: true, is_gdpr_compliant: true, last_assessment: '2024-11-15', risk_score: 35, alert_count: 0 },
  { id: 'v3', name: 'Fortinet', category: 'security', contract_tier: 'high', is_soc2: true, is_gdpr_compliant: true, last_assessment: '2024-08-20', risk_score: 55, alert_count: 1 },
  { id: 'v4', name: 'OSIsoft (AVEVA)', category: 'ot', contract_tier: 'high', is_soc2: false, is_gdpr_compliant: false, last_assessment: '2023-12-01', risk_score: 71, alert_count: 0 },
  { id: 'v5', name: 'Payfirma (PSP)', category: 'fintech', contract_tier: 'critical', is_soc2: true, is_gdpr_compliant: true, last_assessment: '2024-10-05', risk_score: 48, alert_count: 0 },
]

const mockComponents = [
  { id: 'c1', name: 'log4j-core', version: '2.14.1', language: 'java', license: 'Apache-2.0', is_vulnerable: true, cve_count: 3, used_in: ['Core Banking System', 'Customer Portal'] },
  { id: 'c2', name: 'openssl', version: '3.0.2', language: 'c', license: 'OpenSSL', is_vulnerable: true, cve_count: 1, used_in: ['SWIFT Gateway', 'API Gateway'] },
  { id: 'c3', name: 'react', version: '18.2.0', language: 'javascript', license: 'MIT', is_vulnerable: false, cve_count: 0, used_in: ['Customer Portal'] },
  { id: 'c4', name: 'spring-security', version: '5.7.5', language: 'java', license: 'Apache-2.0', is_vulnerable: false, cve_count: 0, used_in: ['Core Banking System'] },
]

const mockSCSAlerts = [
  { id: 'sa1', title: 'Ivanti CVE-2025-0282 — active exploitation in the wild', severity: 'critical', vendor: 'Ivanti', created_at: '2025-01-09' },
  { id: 'sa2', title: 'Ivanti EPMM zero-day patched — assess exposure', severity: 'high', vendor: 'Ivanti', created_at: '2024-12-20' },
  { id: 'sa3', title: 'Fortinet FortiManager FGFM auth bypass — patch available', severity: 'critical', vendor: 'Fortinet', created_at: '2024-10-23' },
]

const tierColors: Record<string, string> = {
  critical: 'bg-red-950 text-red-400 border-red-800',
  high: 'bg-orange-950 text-orange-400 border-orange-800',
  medium: 'bg-amber-950 text-amber-400 border-amber-800',
  low: 'bg-slate-800 text-slate-400 border-slate-700',
}

export default async function SCSPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Supply Chain Security</h1>
        <p className="text-sm text-slate-400">Vendor risk, SBOM, and third-party component monitoring</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Vendors', value: mockVendors.length, color: 'text-slate-200' },
          { label: 'Active Alerts', value: mockSCSAlerts.length, color: 'text-red-400' },
          { label: 'Vulnerable Components', value: mockComponents.filter(c => c.is_vulnerable).length, color: 'text-orange-400' },
          { label: 'Non-SOC2 Critical', value: mockVendors.filter(v => v.contract_tier === 'critical' && !v.is_soc2).length, color: 'text-amber-400' },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-4">
              <p className="text-xs text-slate-400">{s.label}</p>
              <p className={`mt-1 text-2xl font-bold ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Active SCS Alerts */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-300">Active Alerts</h2>
        <div className="space-y-2">
          {mockSCSAlerts.map((alert) => (
            <Card key={alert.id}>
              <CardContent className="flex items-center justify-between py-3">
                <div className="flex items-center gap-3">
                  <AlertTriangle className="h-4 w-4 text-orange-400 flex-shrink-0" />
                  <SeverityBadge severity={alert.severity} />
                  <p className="text-sm text-slate-200">{alert.title}</p>
                  <span className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">{alert.vendor}</span>
                </div>
                <span className="text-xs text-slate-500 whitespace-nowrap">{alert.created_at}</span>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Vendors */}
        <div>
          <h2 className="mb-3 text-sm font-semibold text-slate-300">Vendors</h2>
          <Card>
            <CardContent className="p-0">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700 text-xs text-slate-500">
                    <th className="px-4 py-3 text-left">Vendor</th>
                    <th className="px-4 py-3 text-left">Tier</th>
                    <th className="px-4 py-3 text-center">SOC2</th>
                    <th className="px-4 py-3 text-center">GDPR</th>
                    <th className="px-4 py-3 text-left">Risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/40">
                  {mockVendors.map((v) => (
                    <tr key={v.id} className="hover:bg-slate-800/40 cursor-pointer transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Package className="h-4 w-4 text-slate-500" />
                          <div>
                            <p className="font-medium text-slate-200">{v.name}</p>
                            <p className="text-xs text-slate-500">{v.category}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${tierColors[v.contract_tier] ?? tierColors.low}`}>
                          {v.contract_tier.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        {v.is_soc2 ? <Check className="mx-auto h-4 w-4 text-emerald-400" /> : <X className="mx-auto h-4 w-4 text-red-400" />}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {v.is_gdpr_compliant ? <Check className="mx-auto h-4 w-4 text-emerald-400" /> : <X className="mx-auto h-4 w-4 text-red-400" />}
                      </td>
                      <td className="px-4 py-3"><RiskScore score={v.risk_score} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>
        </div>

        {/* SBOM */}
        <div>
          <h2 className="mb-3 text-sm font-semibold text-slate-300">SBOM — Vulnerable Components</h2>
          <Card>
            <CardContent className="p-0">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700 text-xs text-slate-500">
                    <th className="px-4 py-3 text-left">Component</th>
                    <th className="px-4 py-3 text-left">Version</th>
                    <th className="px-4 py-3 text-center">CVEs</th>
                    <th className="px-4 py-3 text-left">Used In</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/40">
                  {mockComponents.map((c) => (
                    <tr key={c.id} className={`hover:bg-slate-800/40 cursor-pointer transition-colors ${c.is_vulnerable ? 'bg-red-950/10' : ''}`}>
                      <td className="px-4 py-3">
                        <p className="font-mono text-xs text-slate-200">{c.name}</p>
                        <p className="text-[10px] text-slate-500">{c.language} · {c.license}</p>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-400">{c.version}</td>
                      <td className="px-4 py-3 text-center">
                        {c.cve_count > 0
                          ? <Badge variant="critical">{c.cve_count}</Badge>
                          : <Badge variant="success">0</Badge>}
                      </td>
                      <td className="px-4 py-3">
                        <div className="space-y-0.5">
                          {c.used_in.map((u) => (
                            <p key={u} className="text-[10px] text-slate-500 truncate max-w-[140px]">{u}</p>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}

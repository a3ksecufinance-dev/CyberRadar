'use client'
import { Package, AlertTriangle, Check, X } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { RiskScore } from '@/components/shared/RiskScore'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { SeverityBars } from '@/components/charts/SeverityBars'
import { useComponents, useSCSAlerts, useSCSStats, useVendors } from '@/hooks'
import { formatDateOpt } from '@/lib/utils'

// A vendor's tier is a number 1–4 in the service (1 being the most critical
// dependency), not a word. It is labelled here rather than renamed in the API.
const tierLabel: Record<number, string> = {
  1: 'TIER 1 — CRITICAL',
  2: 'TIER 2 — HIGH',
  3: 'TIER 3 — MEDIUM',
  4: 'TIER 4 — LOW',
}

const tierColors: Record<number, string> = {
  1: 'bg-red-950 text-red-400 border-red-800',
  2: 'bg-orange-950 text-orange-400 border-orange-800',
  3: 'bg-amber-950 text-amber-400 border-amber-800',
  4: 'bg-slate-800 text-slate-400 border-slate-700',
}

const UNKNOWN_TIER = 'bg-slate-800 text-slate-400 border-slate-700'

export default function SCSPage() {
  const { data: vendorsData, isLoading: vendorsLoading, error: vendorsError, mutate: retryVendors } = useVendors({ limit: '100' })
  // The SBOM view is about what is exposed, so the vulnerable components come
  // first; the service can filter them server-side.
  const { data: componentsData } = useComponents({ limit: '100', has_vulns: 'true' })
  const { data: alertsData } = useSCSAlerts({ limit: '10', status: 'open' })
  const { data: stats } = useSCSStats()

  const vendors = vendorsData?.items ?? []
  const components = componentsData?.items ?? []
  const alerts = alertsData?.items ?? []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Supply Chain Security</h1>
        <p className="text-sm text-slate-400">Vendor risk, SBOM, and third-party component monitoring</p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Vendors', value: stats?.total_vendors ?? vendors.length, color: 'text-slate-200' },
          { label: 'Open Alerts', value: stats?.open_alerts ?? alerts.length, color: 'text-red-400' },
          { label: 'Vulnerable Components', value: stats?.vulnerable_components ?? components.length, color: 'text-orange-400' },
          { label: 'Overdue Assessments', value: stats?.overdue_assessments ?? 0, color: 'text-amber-400' },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-4">
              <p className="text-xs text-slate-400">{s.label}</p>
              <p className={`mt-1 text-2xl font-bold ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {stats && (
        <div className="grid gap-4 lg:grid-cols-2">
          <SeverityBars
            title="Supply chain alerts by severity"
            breakdown={stats.alerts_by_severity}
            emptyMessage="No supply chain alerts raised"
          />
          <SeverityBars
            title="Vendors by tier"
            breakdown={stats.vendors_by_tier}
            palette="status"
            emptyMessage="No vendors registered"
          />
        </div>
      )}

      {/* Alerts */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-300">Active Alerts</h2>
        {alerts.length === 0 ? (
          <Card>
            <CardContent className="py-6 text-center text-xs text-slate-500">
              No open supply chain alerts
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-2">
            {alerts.map((alert) => (
              <Card key={alert.id}>
                <CardContent className="flex items-center justify-between py-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <AlertTriangle className="h-4 w-4 flex-shrink-0 text-orange-400" />
                    <SeverityBadge severity={alert.severity} />
                    <div className="min-w-0">
                      <p className="truncate text-sm text-slate-200">{alert.title}</p>
                      {alert.cve_ids?.length ? (
                        <p className="font-mono text-[10px] text-slate-500">{alert.cve_ids.join(', ')}</p>
                      ) : null}
                    </div>
                  </div>
                  <span className="whitespace-nowrap text-xs text-slate-500">
                    {formatDateOpt(alert.detected_at)}
                  </span>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* Vendors */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-300">Vendors</h2>
        <Card>
          <CardContent className="p-0">
            {vendorsLoading ? (
              <LoadingState variant="table" rows={5} />
            ) : vendorsError ? (
              <ErrorState message={vendorsError.message} retry={() => retryVendors()} />
            ) : vendors.length === 0 ? (
              <EmptyState message="No vendors registered" />
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700 text-xs text-slate-500">
                    <th className="px-4 py-3 text-left">Vendor</th>
                    <th className="px-4 py-3 text-left">Tier</th>
                    <th className="px-4 py-3 text-center">SOC 2</th>
                    <th className="px-4 py-3 text-center">ISO 27001</th>
                    <th className="px-4 py-3 text-center">PCI-DSS</th>
                    <th className="px-4 py-3 text-left">Last assessed</th>
                    <th className="px-4 py-3 text-left">Risk</th>
                    <th className="px-4 py-3 text-right">Open alerts</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/40">
                  {vendors.map((v) => (
                    <tr key={v.id} className="cursor-pointer transition-colors hover:bg-slate-800/40">
                      <td className="px-4 py-3">
                        <p className="font-medium text-slate-200">{v.name}</p>
                        <p className="text-xs text-slate-500">{v.vendor_type}</p>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-medium ${tierColors[v.risk_tier] ?? UNKNOWN_TIER}`}>
                          {tierLabel[v.risk_tier] ?? `TIER ${v.risk_tier}`}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        {v.has_soc2 ? <Check className="mx-auto h-4 w-4 text-emerald-400" /> : <X className="mx-auto h-4 w-4 text-red-400" />}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {v.has_iso27001 ? <Check className="mx-auto h-4 w-4 text-emerald-400" /> : <X className="mx-auto h-4 w-4 text-red-400" />}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {v.has_pci_dss ? <Check className="mx-auto h-4 w-4 text-emerald-400" /> : <X className="mx-auto h-4 w-4 text-slate-600" />}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500">{formatDateOpt(v.last_assessment_at)}</td>
                      <td className="px-4 py-3"><RiskScore score={v.risk_score} /></td>
                      <td className="px-4 py-3 text-right">
                        {v.open_alert_count
                          ? <Badge variant="critical" className="text-[10px]">{v.open_alert_count}</Badge>
                          : <span className="text-xs text-slate-600">0</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>
      </div>

      {/* SBOM */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-300">SBOM — Vulnerable Components</h2>
        <Card>
          <CardContent className="p-0">
            {components.length === 0 ? (
              <EmptyState message="No vulnerable components in the SBOM" />
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700 text-xs text-slate-500">
                    <th className="px-4 py-3 text-left">Component</th>
                    <th className="px-4 py-3 text-left">Ecosystem</th>
                    <th className="px-4 py-3 text-left">License</th>
                    <th className="px-4 py-3 text-right">CVEs</th>
                    <th className="px-4 py-3 text-center">Direct</th>
                    <th className="px-4 py-3 text-left">Used in</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/40">
                  {components.map((c) => (
                    <tr key={c.id} className="transition-colors hover:bg-slate-800/40">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Package className="h-4 w-4 text-slate-500" />
                          <div>
                            <p className="font-mono text-xs font-medium text-slate-200">{c.name}</p>
                            <p className="text-[10px] text-slate-500">
                              {c.version}
                              {c.is_end_of_life && <span className="ml-1 text-red-400">EOL</span>}
                              {c.is_deprecated && <span className="ml-1 text-amber-400">deprecated</span>}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">{c.ecosystem ?? c.component_type}</td>
                      <td className="px-4 py-3 text-xs text-slate-400">{c.license ?? '—'}</td>
                      <td className="px-4 py-3 text-right">
                        {c.vuln_count > 0 ? (
                          <Badge variant={c.critical_vuln_count > 0 ? 'critical' : 'high'} className="text-[10px]">
                            {c.vuln_count}
                            {c.critical_vuln_count > 0 && ` (${c.critical_vuln_count} crit)`}
                          </Badge>
                        ) : (
                          <span className="text-xs text-slate-600">0</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-center text-xs text-slate-400">
                        {c.is_direct ? 'direct' : 'transitive'}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {(c.used_in ?? []).map((u) => (
                            <Badge key={u} variant="outline" className="text-[10px]">{u}</Badge>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

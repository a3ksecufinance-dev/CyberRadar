'use client'
import { useTranslations } from 'next-intl'
import { CheckCircle, XCircle, AlertCircle, CircleDashed, MinusCircle } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { useComplianceRisks, useComplianceStats } from '@/hooks'
import type { ComplianceScore } from '@/types'

// Framework scores are computed by the compliance service from the tenant's
// own assessments — this page used to hold four constants (DORA 78, PCI 83,
// GDPR 91, NIS2 87) that no assessment could ever move.

const scoreColor = (s: number) =>
  s >= 85 ? 'text-emerald-400' : s >= 70 ? 'text-amber-400' : 'text-red-400'

const barColor = (s: number) =>
  s >= 85 ? 'bg-emerald-500' : s >= 70 ? 'bg-amber-500' : 'bg-red-500'

/** The five assessment outcomes the service tracks per control. */
function outcomes(fw: ComplianceScore) {
  return [
    { key: 'compliant', label: 'Compliant', count: fw.compliant, icon: CheckCircle, color: 'text-emerald-400' },
    { key: 'partial', label: 'Partial', count: fw.partial, icon: AlertCircle, color: 'text-amber-400' },
    { key: 'non_compliant', label: 'Non-compliant', count: fw.non_compliant, icon: XCircle, color: 'text-red-400' },
    { key: 'not_assessed', label: 'Not assessed', count: fw.not_assessed, icon: CircleDashed, color: 'text-slate-500' },
    { key: 'not_applicable', label: 'Not applicable', count: fw.not_applicable, icon: MinusCircle, color: 'text-slate-600' },
  ].filter((o) => o.count > 0)
}

export default function CompliancePage() {
  const t = useTranslations('compliance')

  const { data: stats, isLoading, error, mutate } = useComplianceStats()
  const { data: risksData } = useComplianceRisks({ limit: '10', status: 'open' })

  const frameworks = stats?.frameworks ?? []
  const risks = stats?.top_risks ?? risksData?.items ?? []

  if (isLoading) return <LoadingState variant="page" cols={4} rows={4} />
  if (error) {
    return (
      <Card>
        <CardContent className="p-0">
          <ErrorState message={error.message} retry={() => mutate()} />
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-400">{t('subtitle')}</p>
      </div>

      {frameworks.length === 0 ? (
        <Card>
          <CardContent className="p-0">
            <EmptyState message="No framework activated for this tenant. Activate one to start scoring." />
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Score overview */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {frameworks.map((fw) => (
              <Card key={fw.framework_id}>
                <CardContent className="pt-4">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-xs font-bold text-slate-400">{fw.framework_code}</p>
                      <p className={`mt-1 text-3xl font-bold ${scoreColor(fw.score_pct)}`}>
                        {Math.round(fw.score_pct)}%
                      </p>
                    </div>
                    <span className="rounded bg-slate-700 px-1.5 py-0.5 text-[9px] font-bold text-slate-400">
                      {fw.assessed}/{fw.total_controls}
                    </span>
                  </div>
                  <div className="mt-3 h-1.5 w-full rounded-full bg-slate-700">
                    <div
                      className={`h-1.5 rounded-full ${barColor(fw.score_pct)}`}
                      style={{ width: `${Math.min(100, fw.score_pct)}%` }}
                    />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Per-framework assessment outcomes */}
          <div className="grid gap-4 lg:grid-cols-2">
            {frameworks.map((fw) => {
              const rows = outcomes(fw)
              return (
                <Card key={fw.framework_id}>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle>{fw.framework_name}</CardTitle>
                      <span className={`text-lg font-bold ${scoreColor(fw.score_pct)}`}>
                        {Math.round(fw.score_pct)}%
                      </span>
                    </div>
                    <p className="text-xs text-slate-500">
                      {fw.framework_code} · {fw.total_controls} controls
                    </p>
                  </CardHeader>
                  <CardContent>
                    {rows.length === 0 ? (
                      <p className="py-4 text-center text-xs text-slate-500">
                        No control assessed yet for this framework
                      </p>
                    ) : (
                      <div className="space-y-2">
                        {rows.map((o) => {
                          const Icon = o.icon
                          const pct = fw.total_controls > 0 ? (o.count / fw.total_controls) * 100 : 0
                          return (
                            <div key={o.key} className="flex items-center gap-2.5 rounded-md bg-slate-800/50 px-3 py-2">
                              <Icon className={`h-4 w-4 flex-shrink-0 ${o.color}`} />
                              <span className="text-xs text-slate-300">{o.label}</span>
                              <span className="ml-auto text-xs font-bold text-slate-200">{o.count}</span>
                              <span className="w-10 text-right text-[10px] text-slate-600">
                                {pct.toFixed(0)}%
                              </span>
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </CardContent>
                </Card>
              )
            })}
          </div>
        </>
      )}

      {/* Open compliance risks */}
      <Card>
        <CardHeader>
          <CardTitle>Open compliance risks</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {risks.length === 0 ? (
            <EmptyState message="No open compliance risk" />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-xs text-slate-500">
                  <th className="px-4 py-3 text-left">Risk</th>
                  <th className="px-4 py-3 text-left">Category</th>
                  <th className="px-4 py-3 text-center">L × I</th>
                  <th className="px-4 py-3 text-center">Score</th>
                  <th className="px-4 py-3 text-left">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40">
                {risks.map((r) => (
                  <tr key={r.id} className="transition-colors hover:bg-slate-800/40">
                    <td className="px-4 py-3 text-xs font-medium text-slate-200">{r.title}</td>
                    <td className="px-4 py-3 text-xs text-slate-400">{r.category}</td>
                    <td className="px-4 py-3 text-center text-xs text-slate-400">
                      {r.likelihood} × {r.impact}
                    </td>
                    <td className="px-4 py-3 text-center text-xs font-bold text-slate-200">{r.risk_score}</td>
                    <td className="px-4 py-3"><StatusBadge status={r.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

'use client'
import { TrendingUp, TrendingDown, Minus } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { SeverityBars } from '@/components/charts/SeverityBars'
import { useComplianceRisks, useKRIs, useRiskScenarios, useRiskStats } from '@/hooks'
import { formatMoney } from '@/lib/utils'
import type { ComplianceRisk } from '@/types'

// Two registers feed this page, because the platform keeps two:
//
//   - the compliance service holds the ISO 27005-style register — a risk with
//     a 1–5 likelihood and a 1–5 impact, which is what a heat map plots;
//   - the risk service holds FAIR scenarios — annual probability and a loss in
//     euros, which is what an ALE column shows.
//
// Neither can stand in for the other, so both are shown for what they are.

const categoryColors: Record<string, string> = {
  cyber: 'bg-red-950 text-red-400 border-red-800',
  compliance: 'bg-amber-950 text-amber-400 border-amber-800',
  regulatory: 'bg-purple-950 text-purple-400 border-purple-800',
  operational: 'bg-blue-950 text-blue-400 border-blue-800',
  financial: 'bg-emerald-950 text-emerald-400 border-emerald-800',
}

const NEUTRAL_CATEGORY = 'bg-slate-800 text-slate-300 border-slate-600'

function TrendIcon({ trend }: { trend: string }) {
  if (trend === 'up' || trend === 'worsening') return <TrendingUp className="h-4 w-4 text-red-400" />
  if (trend === 'down' || trend === 'improving') return <TrendingDown className="h-4 w-4 text-emerald-400" />
  return <Minus className="h-4 w-4 text-slate-500" />
}

const cellColor = (score: number) =>
  score >= 20 ? 'bg-red-500' : score >= 12 ? 'bg-orange-500' : score >= 6 ? 'bg-amber-500' : 'bg-emerald-600'

const kriDot = (status: string) =>
  status === 'red' || status === 'breached' ? 'bg-red-400'
    : status === 'amber' || status === 'warning' ? 'bg-amber-400'
      : 'bg-emerald-400'

/** Count the register entries that land in one 5×5 cell. */
function cellRisks(risks: ComplianceRisk[], likelihood: number, impact: number): ComplianceRisk[] {
  return risks.filter((r) => r.likelihood === likelihood && r.impact === impact)
}

export default function RiskPage() {
  const { data: risksData, isLoading: risksLoading, error: risksError, mutate: retryRisks } = useComplianceRisks({ limit: '200' })
  const { data: scenariosData } = useRiskScenarios({ limit: '50' })
  const { data: krisData } = useKRIs({ limit: '20' })
  const { data: stats } = useRiskStats()

  const risks = risksData?.items ?? []
  const scenarios = scenariosData?.items ?? []
  const kris = krisData?.items ?? []

  const openRisks = risks.filter((r) => r.status === 'open').length

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Risk Management</h1>
        <p className="text-sm text-slate-400">Enterprise risk register and heat map — ISO 27005 aligned</p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Register Entries', value: risks.length, color: 'text-slate-200' },
          { label: 'Open', value: openRisks, color: 'text-red-400' },
          { label: 'FAIR Scenarios', value: stats?.total_scenarios ?? scenarios.length, color: 'text-orange-400' },
          {
            label: 'Aggregate ALE',
            value: stats?.total_ale != null ? formatMoney(stats.total_ale) : '—',
            color: 'text-amber-400',
          },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-4">
              <p className="text-xs text-slate-400">{s.label}</p>
              <p className={`mt-1 text-2xl font-bold ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        {/* Heat map — plotted from the register's own likelihood/impact pairs. */}
        <Card>
          <CardHeader>
            <CardTitle>Risk Heat Map</CardTitle>
            <p className="text-xs text-slate-500">Likelihood × Impact (5×5)</p>
          </CardHeader>
          <CardContent>
            {risks.length === 0 ? (
              <p className="py-8 text-center text-xs text-slate-500">No risks in the register yet</p>
            ) : (
              <>
                <div className="space-y-1">
                  {[5, 4, 3, 2, 1].map((impact) => (
                    <div key={impact} className="flex items-center gap-1">
                      <span className="w-3 text-center text-[10px] text-slate-600">{impact}</span>
                      {[1, 2, 3, 4, 5].map((likelihood) => {
                        const inCell = cellRisks(risks, likelihood, impact)
                        const score = likelihood * impact
                        return (
                          <div
                            key={likelihood}
                            title={inCell.map((r) => r.title).join('\n') || 'No risks'}
                            className={`flex h-8 flex-1 items-center justify-center rounded text-xs font-bold text-white ${
                              inCell.length ? cellColor(score) : 'bg-slate-800/60 text-slate-600'
                            }`}
                          >
                            {inCell.length || ''}
                          </div>
                        )
                      })}
                    </div>
                  ))}
                  <div className="flex items-center gap-1 pt-1">
                    <span className="w-3" />
                    {[1, 2, 3, 4, 5].map((l) => (
                      <span key={l} className="flex-1 text-center text-[10px] text-slate-600">{l}</span>
                    ))}
                  </div>
                </div>
                <p className="mt-2 text-center text-[10px] text-slate-600">Likelihood →</p>
              </>
            )}
          </CardContent>
        </Card>

        {/* Register */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Risk register</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {risksLoading ? (
                <LoadingState variant="table" rows={6} />
              ) : risksError ? (
                <ErrorState message={risksError.message} retry={() => retryRisks()} />
              ) : risks.length === 0 ? (
                <EmptyState message="No risks recorded" />
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
                        <td className="px-4 py-3">
                          <p className="text-xs font-medium text-slate-200">{r.title}</p>
                          {r.residual_impact != null && r.residual_likelihood != null && (
                            <p className="text-[10px] text-slate-600">
                              residual {r.residual_likelihood} × {r.residual_impact}
                            </p>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-medium ${categoryColors[r.category] ?? NEUTRAL_CATEGORY}`}>
                            {r.category.toUpperCase()}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-center text-xs text-slate-400">
                          {r.likelihood} × {r.impact}
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span className="text-xs font-bold text-slate-200">{r.risk_score}</span>
                        </td>
                        <td className="px-4 py-3"><StatusBadge status={r.status} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {stats && (
        <div className="grid gap-4 lg:grid-cols-2">
          <SeverityBars
            title="FAIR scenarios by risk level"
            breakdown={stats.scenarios_by_level}
            emptyMessage="No FAIR scenarios modelled yet"
          />
          <SeverityBars
            title="Assets by criticality"
            breakdown={stats.assets_by_criticality}
            emptyMessage="No risk assets registered yet"
          />
        </div>
      )}

      {/* FAIR scenarios — the money view */}
      <Card>
        <CardHeader>
          <CardTitle>FAIR loss scenarios</CardTitle>
          <p className="text-xs text-slate-500">Annualised loss expectancy, before and after controls</p>
        </CardHeader>
        <CardContent className="p-0">
          {scenarios.length === 0 ? (
            <EmptyState message="No loss scenarios modelled" />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-xs text-slate-500">
                  <th className="px-4 py-3 text-left">Scenario</th>
                  <th className="px-4 py-3 text-left">Threat actor</th>
                  <th className="px-4 py-3 text-right">Annual prob.</th>
                  <th className="px-4 py-3 text-right">Total loss</th>
                  <th className="px-4 py-3 text-right">Residual loss</th>
                  <th className="px-4 py-3 text-left">Level</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40">
                {scenarios.map((sc) => (
                  <tr key={sc.id} className="transition-colors hover:bg-slate-800/40">
                    <td className="px-4 py-3">
                      <p className="text-xs font-medium text-slate-200">{sc.name}</p>
                      <p className="text-[10px] text-slate-600">{sc.scenario_type}</p>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">{sc.threat_actor ?? '—'}</td>
                    <td className="px-4 py-3 text-right text-xs text-slate-300">
                      {(sc.annual_probability * 100).toFixed(1)}%
                    </td>
                    <td className="px-4 py-3 text-right text-xs font-bold text-red-400">
                      {formatMoney(sc.total_loss)}
                    </td>
                    <td className="px-4 py-3 text-right text-xs text-emerald-400">
                      {formatMoney(sc.residual_loss)}
                    </td>
                    <td className="px-4 py-3"><StatusBadge status={sc.risk_level} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {/* KRIs */}
      {kris.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Key risk indicators</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {kris.map((k) => (
                <div key={k.id} className="rounded-md border border-slate-700/60 bg-slate-800/40 p-3">
                  <div className="flex items-start justify-between">
                    <div className="min-w-0">
                      <p className="truncate text-xs font-medium text-slate-200">{k.name}</p>
                      <p className="text-[10px] text-slate-600">{k.category}</p>
                    </div>
                    <TrendIcon trend={k.trend} />
                  </div>
                  <div className="mt-2 flex items-center gap-2">
                    <span className={`h-2 w-2 rounded-full ${kriDot(k.status)}`} />
                    <span className="text-lg font-bold text-slate-100">
                      {k.current_value.toLocaleString()}
                    </span>
                    <span className="text-[10px] text-slate-500">{k.unit}</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

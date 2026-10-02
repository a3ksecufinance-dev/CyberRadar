'use client'
import { useTranslations } from 'next-intl'
import type { ElementType } from 'react'
import { AlertTriangle, Siren, Bug, Server, TrendingUp } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { formatDate } from '@/lib/utils'
import { SeverityBars } from '@/components/charts/SeverityBars'
import { useComplianceStats, useDashboardOverview, useSIEMAlerts, useSIEMStats } from '@/hooks'
import type { ComplianceScore } from '@/types'

// Framework scores are computed by the compliance service from its own
// assessments. They used to be four constants in this file — numbers that
// looked like a posture and answered to nothing.
const scoreBar = (pct: number) =>
  pct >= 85 ? 'bg-emerald-500' : pct >= 70 ? 'bg-amber-500' : 'bg-red-500'

const scoreText = (pct: number) =>
  pct >= 85 ? 'text-emerald-400' : pct >= 70 ? 'text-amber-400' : 'text-red-400'

// ─── Security score ring ───────────────────────────────────────────────────────
function ScoreRing({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score))
  const circumference = 213.6 // 2π × 34
  const color = pct >= 75 ? '#06b6d4' : pct >= 50 ? '#f59e0b' : '#ef4444'
  return (
    <div className="relative flex h-20 w-20 flex-shrink-0 items-center justify-center">
      <svg className="h-20 w-20 -rotate-90" viewBox="0 0 80 80">
        <circle cx="40" cy="40" r="34" fill="none" stroke="#1e293b" strokeWidth="7" />
        <circle
          cx="40" cy="40" r="34" fill="none"
          stroke={color} strokeWidth="7"
          strokeDasharray={`${(pct / 100) * circumference} ${circumference}`}
          strokeLinecap="round"
        />
      </svg>
      <span className="absolute text-xl font-bold" style={{ color }}>{Math.round(pct)}</span>
    </div>
  )
}

// ─── Compliance mini rings ─────────────────────────────────────────────────────
function ComplianceRing({ score }: { score: ComplianceScore }) {
  const circumference = 125.7 // 2π × 20
  const pct = Math.round(score.score_pct)
  return (
    <div className="text-center">
      <div className="relative mx-auto h-12 w-12">
        <svg className="h-12 w-12 -rotate-90" viewBox="0 0 48 48">
          <circle cx="24" cy="24" r="20" fill="none" stroke="#1e293b" strokeWidth="4" />
          <circle
            cx="24" cy="24" r="20" fill="none"
            strokeWidth="4" strokeLinecap="round"
            className={scoreText(pct)}
            strokeDasharray={`${(pct / 100) * circumference} ${circumference}`}
            stroke="currentColor"
          />
        </svg>
        <span className="absolute inset-0 flex items-center justify-center text-[10px] font-bold text-slate-300">
          {pct}%
        </span>
      </div>
      <p className="mt-1 text-[10px] text-slate-500">{score.framework_code}</p>
    </div>
  )
}

// ─── Metric card ──────────────────────────────────────────────────────────────
function MetricCard({
  icon: Icon, label, value, sub, color, bg,
}: {
  icon: ElementType; label: string; value: string | number
  sub: string; color: string; bg: string
}) {
  return (
    <Card>
      <CardContent className="pt-4">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs text-slate-400">{label}</p>
            <p className={`mt-1 text-2xl font-bold ${color}`}>{value}</p>
            <p className="mt-0.5 text-xs text-slate-500">{sub}</p>
          </div>
          <div className={`rounded-lg p-2 ${bg}`}>
            <Icon className={`h-5 w-5 ${color}`} />
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const t = useTranslations('dashboard')

  const { data: overview, isLoading: overviewLoading, error: overviewError, mutate: retryOverview } = useDashboardOverview()
  const { data: alertsData, isLoading: alertsLoading } = useSIEMAlerts({ limit: '5', status: 'open' })
  const { data: alertStats } = useSIEMStats()
  const { data: complianceStats } = useComplianceStats()

  const alerts = alertsData?.items ?? []
  const frameworks = complianceStats?.frameworks ?? []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-400">{t('subtitle')}</p>
      </div>

      {/* Security Score Banner */}
      {overviewLoading ? (
        <LoadingState variant="cards" cols={1} />
      ) : overviewError ? (
        <ErrorState message={overviewError.message} retry={() => retryOverview()} />
      ) : (
        <div className="flex flex-wrap items-center gap-6 rounded-xl border border-cyan-800/50 bg-cyan-950/20 p-5">
          <ScoreRing score={overview?.overall_risk_score ?? 0} />
          <div>
            <p className="text-sm font-semibold text-slate-200">{t('securityScore')}</p>
            <p className="text-xs text-slate-500">
              {t('lastUpdated')}: {overview?.generated_at ? formatDate(overview.generated_at) : '—'}
            </p>
          </div>

          {/* IOC / anomaly summary */}
          <div className="flex gap-6 text-center">
            <div>
              <p className="text-xl font-bold text-amber-400">{overview?.active_iocs ?? '—'}</p>
              <p className="text-[10px] text-slate-500">Active IOCs</p>
            </div>
            <div>
              <p className="text-xl font-bold text-orange-400">{overview?.active_anomalies ?? '—'}</p>
              <p className="text-[10px] text-slate-500">Anomalies</p>
            </div>
            <div>
              <p className="text-xl font-bold text-purple-400">{overview?.attack_paths ?? '—'}</p>
              <p className="text-[10px] text-slate-500">Attack Paths</p>
            </div>
          </div>

          {/* Compliance rings — one per framework the tenant has activated */}
          {frameworks.length > 0 && (
            <div className="ml-auto flex gap-4">
              {frameworks.slice(0, 4).map((f) => (
                <ComplianceRing key={f.framework_id} score={f} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Metric Cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <MetricCard
          icon={AlertTriangle}
          label={t('activeThreats')}
          value={overview?.open_alerts ?? '—'}
          sub={`${overview?.critical_alerts ?? 0} critical`}
          color="text-red-400"
          bg="bg-red-950/60"
        />
        <MetricCard
          icon={Siren}
          label={t('openIncidents')}
          value={overview?.open_incidents ?? '—'}
          sub={`${overview?.sla_breached_incidents ?? 0} SLA breached`}
          color="text-orange-400"
          bg="bg-orange-950/60"
        />
        <MetricCard
          icon={Bug}
          label={t('criticalVulns')}
          value={overview?.critical_vulns ?? '—'}
          sub={`${overview?.sla_breached_vulns ?? 0} SLA breached`}
          color="text-amber-400"
          bg="bg-amber-950/60"
        />
        <MetricCard
          icon={TrendingUp}
          label="IOC Hits Today"
          value={overview?.ioc_hits_today ?? '—'}
          sub={`${overview?.high_risk_entities ?? 0} high-risk entities`}
          color="text-purple-400"
          bg="bg-purple-950/60"
        />
      </div>

      {/* Recent Alerts + Compliance */}
      <div className="grid gap-4 lg:grid-cols-3">
        {/* Alerts — 2/3 width */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>{t('recentAlerts')}</CardTitle>
                <button className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors">{t('viewAll')} →</button>
              </div>
            </CardHeader>
            <CardContent>
              {alertsLoading ? (
                <LoadingState variant="table" rows={5} />
              ) : alerts.length === 0 ? (
                <p className="py-6 text-center text-sm text-slate-500">No open alerts</p>
              ) : (
                <div className="space-y-2">
                  {alerts.map((a) => (
                    <div
                      key={a.alert_id}
                      className="flex items-center gap-3 rounded-lg border border-slate-700/60 bg-slate-800/40 p-3 hover:bg-slate-800/80 transition-colors cursor-pointer"
                    >
                      <SeverityBadge severity={a.severity} />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-slate-200">{a.title}</p>
                        <p className="text-xs text-slate-500">
                          {a.category} · {formatDate(a.event_time)}
                        </p>
                      </div>
                      <StatusBadge status={a.status ?? 'open'} />
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Compliance — 1/3 width */}
        <Card>
          <CardHeader>
            <CardTitle>{t('doraStatus')}</CardTitle>
          </CardHeader>
          <CardContent>
            {frameworks.length === 0 ? (
              <p className="py-6 text-center text-xs text-slate-500">
                No framework activated for this tenant yet
              </p>
            ) : (
              <div className="space-y-4">
                {frameworks.map((f) => (
                  <div key={f.framework_id}>
                    <div className="mb-1 flex items-center justify-between text-xs">
                      <span className="font-medium text-slate-300">{f.framework_code}</span>
                      <span className="text-slate-400">{Math.round(f.score_pct)}%</span>
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-slate-700">
                      <div
                        className={`h-1.5 rounded-full transition-all ${scoreBar(f.score_pct)}`}
                        style={{ width: `${Math.min(100, f.score_pct)}%` }}
                      />
                    </div>
                    <p className="mt-1 text-[10px] text-slate-600">
                      {f.compliant} compliant · {f.partial} partial · {f.non_compliant} failing
                      {f.not_assessed > 0 && ` · ${f.not_assessed} not assessed`}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Alert distribution — straight from the SIEM's own counters */}
      {alertStats && (
        <div className="grid gap-4 lg:grid-cols-2">
          <SeverityBars title="Open alerts by severity" breakdown={alertStats.by_severity} />
          <SeverityBars
            title="Alerts by category"
            breakdown={alertStats.by_category}
            palette="status"
            emptyMessage="No alerts categorised yet"
          />
        </div>
      )}
    </div>
  )
}

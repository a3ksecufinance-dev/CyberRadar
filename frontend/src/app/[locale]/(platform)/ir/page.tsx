'use client'
import { useTranslations } from 'next-intl'
import { useState } from 'react'
import { Plus } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { SeverityBars } from '@/components/charts/SeverityBars'
import { useIncidents, useIRStats } from '@/hooks'
import { formatDate } from '@/lib/utils'

// ListIncidents reads status, severity and incident_type — nothing else — so
// these are the filters that can actually narrow the query server-side.
const FILTERS = [
  { label: 'All', params: {} },
  { label: 'Critical', params: { severity: 'critical' } },
  { label: 'High', params: { severity: 'high' } },
  { label: 'Open', params: { status: 'open' } },
  { label: 'Investigating', params: { status: 'investigating' } },
] as const

/** MTTD/MTTR arrive in minutes and are null until the milestone is reached. */
function minutes(value?: number): string {
  if (value == null) return '—'
  if (value < 90) return `${value} min`
  return `${(value / 60).toFixed(1)} h`
}

export default function IRPage() {
  const t = useTranslations('incidents')
  const [filter, setFilter] = useState<string>('All')

  const active = FILTERS.find((f) => f.label === filter) ?? FILTERS[0]
  const params: Record<string, string> = { limit: '100', ...active.params }

  const { data, isLoading, error, mutate } = useIncidents(params)
  const { data: stats } = useIRStats()

  const incidents = data?.items ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">{t('title')}</h1>
          <p className="text-sm text-slate-400">{t('subtitle')}</p>
        </div>
        <Button size="sm">
          <Plus className="h-4 w-4" />
          {t('newIncident')}
        </Button>
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Open', value: stats?.open_incidents ?? 0, color: 'text-red-400' },
          { label: 'Critical', value: stats?.critical_incidents ?? 0, color: 'text-red-400' },
          { label: 'Avg MTTD', value: minutes(stats?.avg_mttd_minutes), color: 'text-amber-400' },
          { label: 'Avg MTTR', value: minutes(stats?.avg_mttr_minutes), color: 'text-cyan-400' },
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
          <SeverityBars title="Incidents by severity" breakdown={stats.by_severity} />
          <SeverityBars title="Incidents by status" breakdown={stats.by_status} palette="status" />
        </div>
      )}

      <div className="flex gap-3">
        {FILTERS.map((f) => (
          <button key={f.label}
            onClick={() => setFilter(f.label)}
            className={`rounded-md border px-3 py-1 text-xs transition-colors ${
              filter === f.label
                ? 'border-cyan-600 bg-cyan-950/40 text-cyan-400'
                : 'border-slate-700 text-slate-400 hover:border-slate-600 hover:text-slate-200'
            }`}>
            {f.label}
          </button>
        ))}
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <LoadingState variant="table" rows={6} />
          ) : error ? (
            <ErrorState message={error.message} retry={() => mutate()} />
          ) : incidents.length === 0 ? (
            <EmptyState message={t('noIncidents')} />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-xs text-slate-500">
                  <th className="px-4 py-3 text-left">{t('incidentId')}</th>
                  <th className="px-4 py-3 text-left">Title</th>
                  <th className="px-4 py-3 text-left">{t('incidentType')}</th>
                  <th className="px-4 py-3 text-left">{t('severity')}</th>
                  <th className="px-4 py-3 text-left">{t('status')}</th>
                  <th className="px-4 py-3 text-left">{t('mttd')}</th>
                  <th className="px-4 py-3 text-left">Detected</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {incidents.map((inc) => (
                  <tr key={inc.id} className="cursor-pointer transition-colors hover:bg-slate-800/40">
                    <td className="px-4 py-3 font-mono text-xs text-cyan-400">{inc.incident_number}</td>
                    <td className="px-4 py-3">
                      <p className="font-medium text-slate-200">{inc.title}</p>
                      <p className="text-xs text-slate-500">
                        {inc.lead_name
                          ? `${t('detectedBy')}: ${inc.lead_name}`
                          : inc.source
                            ? `${t('detectedBy')}: ${inc.source}`
                            : 'Unassigned'}
                        {inc.affected_systems?.length
                          ? ` · ${inc.affected_systems.length} system(s)`
                          : ''}
                      </p>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">{inc.incident_type}</td>
                    <td className="px-4 py-3"><SeverityBadge severity={inc.severity} /></td>
                    <td className="px-4 py-3"><StatusBadge status={inc.status} /></td>
                    <td className="px-4 py-3 text-xs text-slate-400">{minutes(inc.mttd_minutes)}</td>
                    <td className="px-4 py-3 text-xs text-slate-500">{formatDate(inc.detected_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {data?.meta && (
        <p className="text-right text-xs text-slate-600">
          {incidents.length} / {data.meta.total} incidents
        </p>
      )}
    </div>
  )
}

'use client'
import { useTranslations } from 'next-intl'
import { useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { useSIEMAlerts, useSIEMStats } from '@/hooks'
import { countOf, formatDateShort } from '@/lib/utils'

const SEVERITY_FILTERS = ['All', 'Critical', 'High', 'Medium', 'Low'] as const

export default function SiemPage() {
  const t = useTranslations('siem')
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('All')

  // ClickHouse stores severity as Enum8('LOW','MEDIUM','HIGH','CRITICAL') and
  // the filter is an exact string match, so a lower-cased value silently
  // matches nothing and empties the table without an error.
  const params: Record<string, string> = { limit: '100' }
  if (filter !== 'All') params.severity = filter.toUpperCase()

  const { data: alertsData, isLoading, error, mutate } = useSIEMAlerts(params)
  const { data: stats } = useSIEMStats()

  // ListAlerts takes no text filter, so the box narrows the page already
  // fetched rather than pretending to query the whole store.
  const term = search.trim().toLowerCase()
  const alerts = (alertsData?.items ?? []).filter((a) =>
    !term ||
    a.title.toLowerCase().includes(term) ||
    a.rule_name.toLowerCase().includes(term) ||
    a.entity_value.toLowerCase().includes(term))

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">{t('title')}</h1>
          <p className="text-sm text-slate-400">{t('subtitle')}</p>
        </div>
        <div className="flex items-center gap-1.5 rounded-md bg-red-950/50 border border-red-800/60 px-2.5 py-1">
          <div className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
          <span className="text-xs font-semibold text-red-400">{t('live')}</span>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: 'Total Alerts', value: stats.total, color: 'text-slate-200' },
            { label: 'Open', value: stats.open, color: 'text-red-400' },
            { label: 'Critical', value: countOf(stats.by_severity, 'critical'), color: 'text-red-400' },
            { label: 'Fired (24h)', value: stats.fired_last_24h.toLocaleString(), color: 'text-cyan-400' },
          ].map((s) => (
            <Card key={s.label}>
              <CardContent className="pt-4">
                <p className="text-xs text-slate-400">{s.label}</p>
                <p className={`mt-1 text-2xl font-bold ${s.color}`}>{s.value}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <div className="flex gap-3">
        <Input
          className="max-w-sm text-xs"
          placeholder="Filter these results…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        {SEVERITY_FILTERS.map((f) => (
          <button key={f}
            onClick={() => setFilter(f)}
            className={`rounded-md border px-3 py-1 text-xs transition-colors ${
              filter === f
                ? 'border-cyan-600 bg-cyan-950/40 text-cyan-400'
                : 'border-slate-700 text-slate-400 hover:text-slate-200'
            }`}>
            {f}
          </button>
        ))}
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <LoadingState variant="table" rows={8} />
          ) : error ? (
            <ErrorState message={error.message} retry={() => mutate()} />
          ) : alerts.length === 0 ? (
            <EmptyState message={t('noEvents')} />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-xs text-slate-500">
                  <th className="px-4 py-3 text-left">{t('detectedAt')}</th>
                  <th className="px-4 py-3 text-left">Rule</th>
                  <th className="px-4 py-3 text-left">Entity</th>
                  <th className="px-4 py-3 text-left">Title</th>
                  <th className="px-4 py-3 text-left">{t('severity')}</th>
                  <th className="px-4 py-3 text-left">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40 font-mono">
                {alerts.map((alert) => (
                  <tr key={alert.alert_id} className="hover:bg-slate-800/40 cursor-pointer transition-colors">
                    <td className="px-4 py-2.5 text-xs text-slate-500 whitespace-nowrap">
                      {formatDateShort(alert.event_time)}
                    </td>
                    <td className="px-4 py-2.5 text-xs">
                      <span className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300">{alert.rule_name}</span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-cyan-400">{alert.entity_value}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-300 max-w-xs truncate font-sans">{alert.title}</td>
                    <td className="px-4 py-2.5"><SeverityBadge severity={alert.severity} /></td>
                    <td className="px-4 py-2.5 text-xs text-slate-400">{alert.status ?? 'open'}</td>
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

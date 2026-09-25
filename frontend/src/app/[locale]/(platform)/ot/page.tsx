'use client'
import { useTranslations } from 'next-intl'
import { Cpu, Check, X } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { RiskScore } from '@/components/shared/RiskScore'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { SeverityBars } from '@/components/charts/SeverityBars'
import { useOTAssets, useOTEvents, useOTStats } from '@/hooks'
import { countOf, formatDate } from '@/lib/utils'

const purdueColors: Record<number, string> = {
  0: 'bg-red-950 text-red-400 border-red-800',
  1: 'bg-orange-950 text-orange-400 border-orange-800',
  2: 'bg-amber-950 text-amber-400 border-amber-800',
  3: 'bg-blue-950 text-blue-400 border-blue-800',
  4: 'bg-slate-800 text-slate-300 border-slate-600',
  5: 'bg-emerald-950 text-emerald-400 border-emerald-800',
}

const purdueLabel: Record<number, string> = {
  0: 'L0 Field',
  1: 'L1 Control',
  2: 'L2 Supervisory',
  3: 'L3 Operations',
  4: 'L4 Enterprise',
  5: 'L5 Cloud',
}

const UNKNOWN_LEVEL = 'bg-slate-800 text-slate-400 border-slate-700'

export default function OTPage() {
  const t = useTranslations('ot')

  const { data: assetsData, isLoading, error, mutate } = useOTAssets({ limit: '100' })
  const { data: eventsData } = useOTEvents({ limit: '10' })
  const { data: stats } = useOTStats()

  const assets = assetsData?.items ?? []
  const events = eventsData?.items ?? []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-400">{t('subtitle')}</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'OT Assets', value: stats?.total_assets ?? assets.length, color: 'text-slate-200' },
          { label: 'Internet Facing', value: stats?.internet_facing_assets ?? 0, color: 'text-red-400' },
          // Safety impact is recorded on a vulnerability, not on the asset:
          // an asset is not "safety critical", a flaw in it is.
          { label: 'Safety-impact Vulns', value: stats?.safety_impact_vulns ?? 0, color: 'text-orange-400' },
          { label: 'Unpatched', value: stats?.unpatched_assets ?? 0, color: 'text-amber-400' },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-4">
              <p className="text-xs text-slate-400">{s.label}</p>
              <p className={`mt-1 text-2xl font-bold ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Purdue distribution — the service counts this itself. */}
      <Card>
        <CardHeader>
          <CardTitle>Purdue Model Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3">
            {[0, 1, 2, 3, 4, 5].map((level) => (
              <div key={level} className="flex flex-1 flex-col items-center gap-2">
                <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${purdueColors[level]}`}>
                  {purdueLabel[level]}
                </span>
                <span className="text-lg font-bold text-slate-200">
                  {/* The service keys this map "level_0".."level_5", not "0".."5". */}
                  {countOf(stats?.assets_by_purdue, `level_${level}`)}
                </span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {stats && (
        <div className="grid gap-4 lg:grid-cols-2">
          <SeverityBars title="OT events by severity" breakdown={stats.events_by_severity} />
          <SeverityBars title="OT vulnerabilities by severity" breakdown={stats.vulns_by_severity} />
        </div>
      )}

      {/* OT assets */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-300">{t('assets')}</h2>
        <Card>
          <CardContent className="p-0">
            {isLoading ? (
              <LoadingState variant="table" rows={6} />
            ) : error ? (
              <ErrorState message={error.message} retry={() => mutate()} />
            ) : assets.length === 0 ? (
              <EmptyState message={t('noAssets')} />
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700 text-xs text-slate-500">
                    <th className="px-4 py-3 text-left">Asset</th>
                    <th className="px-4 py-3 text-left">{t('assetType')}</th>
                    <th className="px-4 py-3 text-left">{t('purdueLevel')}</th>
                    <th className="px-4 py-3 text-left">{t('protocol')}</th>
                    <th className="px-4 py-3 text-center">{t('internetFacing')}</th>
                    <th className="px-4 py-3 text-center">Criticality</th>
                    <th className="px-4 py-3 text-center">Patched</th>
                    <th className="px-4 py-3 text-left">Risk</th>
                    <th className="px-4 py-3 text-left">Updated</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/40">
                  {assets.map((asset) => (
                    <tr key={asset.id} className="cursor-pointer transition-colors hover:bg-slate-800/40">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Cpu className="h-4 w-4 text-cyan-500" />
                          <div>
                            <p className="font-medium text-slate-200">{asset.name}</p>
                            <p className="text-xs text-slate-500">
                              {[asset.vendor, asset.model].filter(Boolean).join(' ') || asset.zone || '—'}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">{asset.asset_type.toUpperCase()}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${purdueColors[asset.purdue_level] ?? UNKNOWN_LEVEL}`}>
                          {purdueLabel[asset.purdue_level] ?? `L${asset.purdue_level}`}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-400">
                        {asset.protocol?.join(', ') || '—'}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {asset.is_internet_facing
                          ? <Badge variant="critical" className="text-[10px]">YES</Badge>
                          : <span className="text-xs text-slate-500">No</span>}
                      </td>
                      <td className="px-4 py-3 text-center">
                        <SeverityBadge severity={asset.criticality} />
                      </td>
                      <td className="px-4 py-3 text-center">
                        {asset.is_patched
                          ? <Check className="mx-auto h-4 w-4 text-emerald-400" />
                          : <X className="mx-auto h-4 w-4 text-red-400" />}
                      </td>
                      <td className="px-4 py-3"><RiskScore score={asset.risk_score} /></td>
                      <td className="px-4 py-3 text-xs text-slate-500">{formatDate(asset.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent events */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-300">{t('events')}</h2>
        {events.length === 0 ? (
          <Card>
            <CardContent className="py-6 text-center text-xs text-slate-500">
              No OT events recorded
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-2">
            {events.map((ev) => (
              <Card key={ev.id}>
                <CardContent className="flex items-center justify-between py-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <SeverityBadge severity={ev.severity} />
                    <p className="truncate text-sm text-slate-200">{ev.title}</p>
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                      {ev.detected_by ?? ev.event_type}
                    </span>
                  </div>
                  <span className="whitespace-nowrap text-xs text-slate-500">{formatDate(ev.event_time)}</span>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

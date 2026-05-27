'use client'
import { useTranslations } from 'next-intl'
import { Database, Check, X } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { RiskScore } from '@/components/shared/RiskScore'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { useDataStores, useDSPMFindings, useDSPMStats } from '@/hooks'

const sensitivityColors: Record<string, string> = {
  public:       'bg-slate-800 text-slate-400 border-slate-700',
  internal:     'bg-blue-950 text-blue-400 border-blue-800',
  confidential: 'bg-amber-950 text-amber-400 border-amber-800',
  restricted:   'bg-orange-950 text-orange-400 border-orange-800',
  top_secret:   'bg-red-950 text-red-400 border-red-800',
}

export default function DSPMPage() {
  const t = useTranslations('dspm')
  const { data: storesData, isLoading: storesLoading, error: storesError, mutate: mutateStores } = useDataStores()
  const { data: findingsData, isLoading: findingsLoading, error: findingsError, mutate: mutateFindings } = useDSPMFindings()
  const { data: stats } = useDSPMStats()

  const stores = storesData?.items ?? []
  const findings = findingsData?.items ?? []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-400">{t('subtitle')}</p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Data Stores', value: stats?.total_stores ?? stores.length, color: 'text-slate-200' },
          { label: 'Open Findings', value: stats?.open_findings ?? findings.length, color: 'text-red-400' },
          { label: 'Unencrypted Stores', value: stats?.unencrypted_stores ?? stores.filter(s => !s.is_encrypted).length, color: 'text-amber-400' },
          { label: 'Records at Risk', value: stats?.records_at_risk ? (stats.records_at_risk / 1_000_000).toFixed(1) + 'M' : '—', color: 'text-red-400' },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-4">
              <p className="text-xs text-slate-400">{s.label}</p>
              <p className={`mt-1 text-2xl font-bold ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Data Stores */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-300">{t('dataStores')}</h2>
        <Card>
          <CardContent className="p-0">
            {storesLoading ? (
              <LoadingState variant="table" rows={4} />
            ) : storesError ? (
              <ErrorState message={storesError.message} retry={() => mutateStores()} />
            ) : stores.length === 0 ? (
              <EmptyState message={t('noStores')} />
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700 text-xs text-slate-500">
                    <th className="px-4 py-3 text-left">{t('name')}</th>
                    <th className="px-4 py-3 text-left">{t('storeType')}</th>
                    <th className="px-4 py-3 text-left">{t('sensitivityLevel')}</th>
                    <th className="px-4 py-3 text-left">{t('dataCategories')}</th>
                    <th className="px-4 py-3 text-center">{t('encrypted')}</th>
                    <th className="px-4 py-3 text-left">Findings</th>
                    <th className="px-4 py-3 text-left">{t('riskScore')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/40">
                  {stores.map((s) => (
                    <tr key={s.id} className="hover:bg-slate-800/40 cursor-pointer transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Database className="h-4 w-4 text-slate-500" />
                          <div>
                            <p className="font-medium text-slate-200">{s.name}</p>
                            <p className="text-xs text-slate-500">{s.cloud_provider ?? 'on_premise'}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">{s.store_type}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${sensitivityColors[s.sensitivity_level] ?? ''}`}>
                          {s.sensitivity_level.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {s.data_categories.map((c) => (
                            <Badge key={c} variant="outline" className="text-[10px]">{c.toUpperCase()}</Badge>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-center">
                        {s.is_encrypted ? <Check className="mx-auto h-4 w-4 text-emerald-400" /> : <X className="mx-auto h-4 w-4 text-red-400" />}
                      </td>
                      <td className="px-4 py-3">
                        {s.open_finding_count > 0
                          ? <Badge variant="critical">{s.open_finding_count} open</Badge>
                          : <Badge variant="success">None</Badge>}
                      </td>
                      <td className="px-4 py-3"><RiskScore score={s.risk_score} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Findings */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-300">{t('findings')}</h2>
        <Card>
          <CardContent className="p-0">
            {findingsLoading ? (
              <LoadingState variant="table" rows={3} />
            ) : findingsError ? (
              <ErrorState message={findingsError.message} retry={() => mutateFindings()} />
            ) : findings.length === 0 ? (
              <EmptyState message={t('noFindings')} />
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700 text-xs text-slate-500">
                    <th className="px-4 py-3 text-left">Title</th>
                    <th className="px-4 py-3 text-left">{t('findingType')}</th>
                    <th className="px-4 py-3 text-left">{t('severity')}</th>
                    <th className="px-4 py-3 text-left">Location</th>
                    <th className="px-4 py-3 text-right">{t('recordCount')}</th>
                    <th className="px-4 py-3 text-center">{t('publiclyAccessible')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/40">
                  {findings.map((f) => (
                    <tr key={f.id} className="hover:bg-slate-800/40 cursor-pointer transition-colors">
                      <td className="px-4 py-3 font-medium text-slate-200">{f.title}</td>
                      <td className="px-4 py-3 text-xs text-slate-400">{f.finding_type}</td>
                      <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-500">{f.location_path}</td>
                      <td className="px-4 py-3 text-right text-xs font-medium text-slate-300">
                        {f.record_count.toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {f.is_public_accessible ? <Badge variant="critical">PUBLIC</Badge> : <Badge variant="low">PRIVATE</Badge>}
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

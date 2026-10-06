'use client'
import { useTranslations } from 'next-intl'
import { useState } from 'react'
import { Plus } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { RiskScore } from '@/components/shared/RiskScore'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { useAssets, useAssetStats } from '@/hooks'
import { countOf, criticalityLabel, formatDateOpt } from '@/lib/utils'

const CRIT_VARIANTS: Record<string, string> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' }
const FILTERS = ['All', 'Critical', 'High', 'Production'] as const

export default function AssetsPage() {
  const t = useTranslations('assets')
  const [search, setSearch] = useState('')
  const [activeFilter, setActiveFilter] = useState('All')

  // The asset service reads `criticality` as an integer (1 low … 4 critical)
  // and names its text filter `q`. Words and `search` were both ignored, so
  // neither the filter buttons nor the search box did anything.
  const params: Record<string, string> = { limit: '100' }
  if (activeFilter === 'Critical') params.criticality = '4'
  if (activeFilter === 'High') params.criticality = '3'
  if (activeFilter === 'Production') params.environment = 'production'
  if (search.trim()) params.q = search.trim()

  const { data: assetsData, isLoading, error, mutate } = useAssets(params)
  const { data: stats } = useAssetStats()

  const assets = assetsData?.items ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">{t('title')}</h1>
          <p className="text-sm text-slate-400">{t('subtitle')}</p>
        </div>
        <Button size="sm">
          <Plus className="h-4 w-4" />
          {t('newAsset')}
        </Button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: 'Total Assets', value: stats.total, color: 'text-slate-200' },
            { label: 'Critical', value: countOf(stats.by_criticality, 'critical'), color: 'text-red-400' },
            { label: 'High Risk', value: stats.high_risk, color: 'text-orange-400' },
            // CBS and SWIFT connectivity is what makes an asset a banking
            // asset; the service counts it, so the page shows it.
            { label: 'CBS / SWIFT', value: `${stats.cbs_connected} / ${stats.swift_connected}`, color: 'text-cyan-400' },
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
          className="max-w-xs text-xs"
          placeholder="Search assets..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        {FILTERS.map((f) => (
          <button key={f}
            onClick={() => setActiveFilter(f)}
            className={`rounded-md border px-3 py-1 text-xs transition-colors ${
              activeFilter === f
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
          ) : assets.length === 0 ? (
            <EmptyState message={t('noAssets')} />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-xs text-slate-500">
                  <th className="px-4 py-3 text-left">{t('name')}</th>
                  <th className="px-4 py-3 text-left">{t('assetType')}</th>
                  <th className="px-4 py-3 text-left">{t('ipAddress')}</th>
                  <th className="px-4 py-3 text-left">{t('criticality')}</th>
                  <th className="px-4 py-3 text-left">{t('department')}</th>
                  <th className="px-4 py-3 text-left">{t('riskScore')}</th>
                  <th className="px-4 py-3 text-left">{t('lastSeen')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40">
                {assets.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-800/40 cursor-pointer transition-colors">
                    <td className="px-4 py-3">
                      <p className="font-medium text-slate-200">{a.name}</p>
                      <p className="text-xs text-slate-500">{a.environment}</p>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">{a.asset_type}</td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">{a.ip_addresses?.[0] ?? '—'}</td>
                    <td className="px-4 py-3">
                      {/* criticality is an int 1–4 on the wire, not a word. */}
                      <Badge variant={(CRIT_VARIANTS[criticalityLabel(a.criticality)] ?? 'default') as any}>
                        {criticalityLabel(a.criticality).toUpperCase()}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">{a.department ?? '—'}</td>
                    <td className="px-4 py-3"><RiskScore score={a.risk_score} /></td>
                    <td className="px-4 py-3 text-xs text-slate-500">{formatDateOpt(a.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {assetsData?.meta && (
        <p className="text-right text-xs text-slate-600">
          {assets.length} / {assetsData.meta.total} assets
        </p>
      )}
    </div>
  )
}

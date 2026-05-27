'use client'
import { useTranslations } from 'next-intl'
import { useState } from 'react'
import { Plus } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { useIOCs, useTIStats } from '@/hooks'
import { formatDate } from '@/lib/utils'

const iocTypeColors: Record<string, string> = {
  ip: 'bg-orange-950 text-orange-400 border-orange-800',
  domain: 'bg-purple-950 text-purple-400 border-purple-800',
  hash_sha256: 'bg-slate-800 text-slate-300 border-slate-600',
  hash_md5: 'bg-slate-800 text-slate-300 border-slate-600',
  url: 'bg-blue-950 text-blue-400 border-blue-800',
  email: 'bg-pink-950 text-pink-400 border-pink-800',
  cve: 'bg-red-950 text-red-400 border-red-800',
}

const confidenceBar = (c: number) =>
  c >= 80 ? 'bg-emerald-500' : c >= 60 ? 'bg-amber-500' : 'bg-red-500'

export default function ThreatsPage() {
  const t = useTranslations('threats')
  const [search, setSearch] = useState('')

  const params: Record<string, string> = { limit: '100' }
  if (search.trim()) params.search = search.trim()

  const { data: iocsData, isLoading, error, mutate } = useIOCs(params)
  const { data: stats } = useTIStats()

  const iocs = iocsData?.items ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">{t('title')}</h1>
          <p className="text-sm text-slate-400">{t('subtitle')}</p>
        </div>
        <Button size="sm">
          <Plus className="h-4 w-4" />
          {t('newIoc')}
        </Button>
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Active IOCs', value: stats?.active_iocs ?? iocs.length, color: 'text-red-400' },
          { label: 'Critical IOCs', value: stats?.critical_iocs ?? iocs.filter(i => i.severity === 'critical').length, color: 'text-red-400' },
          { label: 'Matched Events', value: stats?.matched_events ?? 0, color: 'text-orange-400' },
          { label: 'Total IOCs', value: stats?.total_iocs ?? iocsData?.meta?.total ?? iocs.length, color: 'text-slate-200' },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-4">
              <p className="text-xs text-slate-400">{s.label}</p>
              <p className={`mt-1 text-2xl font-bold ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex gap-3">
        <Input
          className="max-w-sm text-xs"
          placeholder="Search IOCs..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <LoadingState variant="table" rows={8} />
          ) : error ? (
            <ErrorState message={error.message} retry={() => mutate()} />
          ) : iocs.length === 0 ? (
            <EmptyState message={t('noIocs')} />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-xs text-slate-500">
                  <th className="px-4 py-3 text-left">{t('iocType')}</th>
                  <th className="px-4 py-3 text-left">{t('iocValue')}</th>
                  <th className="px-4 py-3 text-left">Tags</th>
                  <th className="px-4 py-3 text-left">{t('source')}</th>
                  <th className="px-4 py-3 text-left">{t('confidence')}</th>
                  <th className="px-4 py-3 text-left">Severity</th>
                  <th className="px-4 py-3 text-left">{t('lastSeen')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40">
                {iocs.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-slate-800/40 cursor-pointer transition-colors">
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${iocTypeColors[ioc.ioc_type] ?? 'bg-slate-800 text-slate-400 border-slate-700'}`}>
                        {ioc.ioc_type.replace(/_/g, ' ').toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-300 max-w-xs truncate">{ioc.value}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {ioc.tags.map((tag) => (
                          <Badge key={tag} variant="outline" className="text-[10px]">{tag}</Badge>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">{ioc.source}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-16 rounded-full bg-slate-700">
                          <div className={`h-1.5 rounded-full ${confidenceBar(ioc.confidence)}`} style={{ width: `${ioc.confidence}%` }} />
                        </div>
                        <span className="text-xs text-slate-400">{ioc.confidence}%</span>
                      </div>
                    </td>
                    <td className="px-4 py-3"><SeverityBadge severity={ioc.severity} /></td>
                    <td className="px-4 py-3 text-xs text-slate-500">{formatDate(ioc.last_seen_at)}</td>
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

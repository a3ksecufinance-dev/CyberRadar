'use client'
import { useTranslations } from 'next-intl'
import { useState } from 'react'
import { Check, X } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { useVulnerabilities, useVulnStats } from '@/hooks'
import { formatDate } from '@/lib/utils'

const cvssColor = (score: number) =>
  score >= 9 ? 'text-red-400' : score >= 7 ? 'text-orange-400' : score >= 4 ? 'text-amber-400' : 'text-emerald-400'

const remediationVariant: Record<string, string> = {
  open: 'critical', in_progress: 'medium', resolved: 'success',
  accepted_risk: 'low', wont_fix: 'low',
}

const FILTERS = ['All', 'Critical', 'High', 'Open'] as const

export default function VulnerabilitiesPage() {
  const t = useTranslations('vulnerabilities')
  const [activeFilter, setActiveFilter] = useState('All')

  const params: Record<string, string> = { limit: '100' }
  if (activeFilter === 'Critical') params.severity = 'critical'
  if (activeFilter === 'High') params.severity = 'high'
  if (activeFilter === 'Open') params.remediation_status = 'open'

  const { data: vulnsData, isLoading, error, mutate } = useVulnerabilities(params)
  const { data: stats } = useVulnStats()

  const vulns = vulnsData?.items ?? []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-400">{t('subtitle')}</p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total', value: stats?.total ?? vulns.length, color: 'text-slate-200' },
          { label: 'Open', value: stats?.open ?? vulns.filter(v => v.remediation_status === 'open').length, color: 'text-red-400' },
          { label: 'Critical', value: stats?.critical ?? vulns.filter(v => v.severity === 'critical').length, color: 'text-red-400' },
          { label: 'Exploit in Wild', value: stats?.exploit_in_wild ?? vulns.filter(v => v.exploit_in_wild).length, color: 'text-orange-400' },
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
          ) : vulns.length === 0 ? (
            <EmptyState message={t('noVulns')} />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-xs text-slate-500">
                  <th className="px-4 py-3 text-left">{t('cveId')}</th>
                  <th className="px-4 py-3 text-left">Title</th>
                  <th className="px-4 py-3 text-left">{t('affectedComponent')}</th>
                  <th className="px-4 py-3 text-left">Severity</th>
                  <th className="px-4 py-3 text-right">{t('cvssScore')}</th>
                  <th className="px-4 py-3 text-right">Assets</th>
                  <th className="px-4 py-3 text-center">{t('patchAvailable')}</th>
                  <th className="px-4 py-3 text-left">{t('remediationStatus')}</th>
                  <th className="px-4 py-3 text-left">Detected</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40">
                {vulns.map((v) => (
                  <tr key={v.id} className="hover:bg-slate-800/40 cursor-pointer transition-colors">
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs text-cyan-400">{v.cve_id}</span>
                    </td>
                    <td className="px-4 py-3 max-w-xs">
                      <p className="font-medium text-slate-200 truncate text-xs">{v.title}</p>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">{v.affected_component}</td>
                    <td className="px-4 py-3"><SeverityBadge severity={v.severity} /></td>
                    <td className="px-4 py-3 text-right">
                      <span className={`font-bold ${cvssColor(v.cvss_score)}`}>{v.cvss_score.toFixed(1)}</span>
                    </td>
                    <td className="px-4 py-3 text-right text-xs text-slate-400">{v.asset_count}</td>
                    <td className="px-4 py-3 text-center">
                      {v.patch_available ? <Check className="mx-auto h-4 w-4 text-emerald-400" /> : <X className="mx-auto h-4 w-4 text-red-400" />}
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant={(remediationVariant[v.remediation_status] ?? 'default') as any}>
                        {v.remediation_status.replace(/_/g, ' ').toUpperCase()}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500">{formatDate(v.first_seen_at)}</td>
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

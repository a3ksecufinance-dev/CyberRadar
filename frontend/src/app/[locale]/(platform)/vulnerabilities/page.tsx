'use client'
import { useTranslations } from 'next-intl'
import { useState } from 'react'
import { Check, X, Flame } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { SeverityBars } from '@/components/charts/SeverityBars'
import { useVulnerabilities, useVulnStats } from '@/hooks'
import { countOf, formatDateOpt } from '@/lib/utils'

const cvssColor = (score: number) =>
  score >= 9 ? 'text-red-400' : score >= 7 ? 'text-orange-400' : score >= 4 ? 'text-amber-400' : 'text-emerald-400'

// The catalogue is filtered by severity and by whether an exploit is known to
// be used in the wild — the two filters ListVulns actually reads. Remediation
// status lives on a finding (a vulnerability on an asset), not on the CVE.
const FILTERS = ['All', 'Critical', 'High', 'Exploited'] as const

export default function VulnerabilitiesPage() {
  const t = useTranslations('vulnerabilities')
  const [activeFilter, setActiveFilter] = useState<string>('All')

  const params: Record<string, string> = { limit: '100' }
  if (activeFilter === 'Critical') params.severity = 'critical'
  if (activeFilter === 'High') params.severity = 'high'
  if (activeFilter === 'Exploited') params.exploited = 'true'

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
          { label: 'Known CVEs', value: stats?.total_vulns ?? vulns.length, color: 'text-slate-200' },
          { label: 'Open Findings', value: stats?.open_findings ?? 0, color: 'text-red-400' },
          { label: 'Critical', value: countOf(stats?.by_severity, 'critical'), color: 'text-red-400' },
          // KEV = exploited in the wild. SLA breach is the other number an
          // analyst acts on first, so both are shown rather than averaged away.
          { label: 'KEV / SLA breached', value: `${stats?.kev_findings ?? 0} / ${stats?.sla_breached ?? 0}`, color: 'text-orange-400' },
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
          <SeverityBars title="Findings by severity" breakdown={stats.by_severity} />
          <SeverityBars title="Findings by status" breakdown={stats.by_status} palette="status" />
        </div>
      )}

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
                  <th className="px-4 py-3 text-right">EPSS</th>
                  <th className="px-4 py-3 text-center">Exploit</th>
                  <th className="px-4 py-3 text-center">{t('patchAvailable')}</th>
                  <th className="px-4 py-3 text-left">Published</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40">
                {vulns.map((v) => (
                  <tr key={v.id} className="hover:bg-slate-800/40 cursor-pointer transition-colors">
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs text-cyan-400">{v.cve_id ?? '—'}</span>
                    </td>
                    <td className="px-4 py-3 max-w-xs">
                      <p className="truncate text-xs font-medium text-slate-200">{v.title}</p>
                      {v.cwe_id && <p className="text-[10px] text-slate-500">{v.cwe_id}</p>}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {v.affected_products?.length
                        ? v.affected_products.slice(0, 2).join(', ') +
                          (v.affected_products.length > 2 ? ` +${v.affected_products.length - 2}` : '')
                        : '—'}
                    </td>
                    <td className="px-4 py-3"><SeverityBadge severity={v.cvss_severity} /></td>
                    <td className="px-4 py-3 text-right">
                      <span className={`font-bold ${cvssColor(v.cvss_score)}`}>{v.cvss_score.toFixed(1)}</span>
                    </td>
                    <td className="px-4 py-3 text-right text-xs text-slate-400">
                      {/* EPSS is a probability in [0,1]; as a percentage it is
                          comparable with the CVSS column beside it. */}
                      {(v.epss_score * 100).toFixed(1)}%
                    </td>
                    <td className="px-4 py-3 text-center">
                      {v.is_exploited ? (
                        <span title="Exploited in the wild">
                          <Flame className="mx-auto h-4 w-4 text-red-400" />
                        </span>
                      ) : v.exploit_available ? (
                        <span className="text-[10px] text-amber-400">PoC</span>
                      ) : (
                        <span className="text-[10px] text-slate-600">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-center">
                      {v.patch_available
                        ? <Check className="mx-auto h-4 w-4 text-emerald-400" />
                        : <X className="mx-auto h-4 w-4 text-red-400" />}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500">{formatDateOpt(v.published_at)}</td>
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

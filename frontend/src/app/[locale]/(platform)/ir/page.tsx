import { getTranslations } from 'next-intl/server'
import { Plus } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { EmptyState } from '@/components/shared/EmptyState'
import { formatDate } from '@/lib/utils'

const mockIncidents = [
  {
    id: 'inc-1', number: 'INC-2026-00012',
    title: 'APT29 Active Intrusion — BNF Trading Systems',
    severity: 'critical', status: 'investigating',
    incident_type: 'apt', detected_by: 'SOC Tier 2',
    affected_systems: ['FX-01', 'Sophie Martin Laptop'],
    mttd: 47, created_at: new Date(Date.now() - 3600000 * 2).toISOString(),
  },
  {
    id: 'inc-2', number: 'INC-2026-00011',
    title: 'Suspicious lateral movement — Trading floor',
    severity: 'high', status: 'contained',
    incident_type: 'unauthorized_access', detected_by: 'UEBA Engine',
    affected_systems: ['Trading Workstation FX-01'],
    mttd: 12, created_at: new Date(Date.now() - 3600000 * 6).toISOString(),
  },
  {
    id: 'inc-3', number: 'INC-2026-00010',
    title: 'Phishing campaign targeting trading department',
    severity: 'medium', status: 'resolved',
    incident_type: 'phishing', detected_by: 'Email Gateway',
    affected_systems: ['Email Infrastructure'],
    mttd: 8, created_at: new Date(Date.now() - 3600000 * 24).toISOString(),
  },
]

export default async function IRPage() {
  const t = await getTranslations('incidents')

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

      {/* Filters */}
      <div className="flex gap-3">
        <Input className="max-w-xs text-xs" placeholder="Search incidents..." />
        {['All', 'Critical', 'High', 'Open', 'Investigating'].map((f) => (
          <button key={f}
            className={`rounded-md border px-3 py-1 text-xs transition-colors ${
              f === 'All'
                ? 'border-cyan-600 bg-cyan-950/40 text-cyan-400'
                : 'border-slate-700 text-slate-400 hover:border-slate-600 hover:text-slate-200'
            }`}>
            {f}
          </button>
        ))}
      </div>

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          {mockIncidents.length === 0 ? (
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
                  <th className="px-4 py-3 text-left">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {mockIncidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-slate-800/40 cursor-pointer transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-cyan-400">{inc.number}</td>
                    <td className="px-4 py-3">
                      <p className="font-medium text-slate-200">{inc.title}</p>
                      <p className="text-xs text-slate-500">{t('detectedBy')}: {inc.detected_by}</p>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">{inc.incident_type}</td>
                    <td className="px-4 py-3"><SeverityBadge severity={inc.severity} /></td>
                    <td className="px-4 py-3"><StatusBadge status={inc.status} /></td>
                    <td className="px-4 py-3 text-xs text-slate-400">{inc.mttd} {t('minutes')}</td>
                    <td className="px-4 py-3 text-xs text-slate-500">{formatDate(inc.created_at)}</td>
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

'use client'
import { useTranslations } from 'next-intl'
import { Smartphone, Check, X } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { RiskScore } from '@/components/shared/RiskScore'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { useDevices, useMobileStats } from '@/hooks'
import { formatDate } from '@/lib/utils'

const platformColors: Record<string, string> = {
  ios: 'bg-blue-950 text-blue-400 border-blue-800',
  android: 'bg-emerald-950 text-emerald-400 border-emerald-800',
  windows: 'bg-slate-800 text-slate-300 border-slate-600',
}
const ownershipColors: Record<string, string> = {
  corporate: 'bg-slate-800 text-slate-300 border-slate-600',
  byod: 'bg-amber-950 text-amber-400 border-amber-800',
  cope: 'bg-violet-950 text-violet-400 border-violet-800',
}

function BoolIcon({ value, danger = true }: { value: boolean; danger?: boolean }) {
  if (value) return <Check className={`h-4 w-4 ${danger ? 'text-emerald-400' : 'text-red-400'}`} />
  return <X className={`h-4 w-4 ${danger ? 'text-red-400' : 'text-emerald-400'}`} />
}

export default function MobilePage() {
  const t = useTranslations('mobile')
  const { data: devicesData, isLoading, error, mutate } = useDevices()
  const { data: stats } = useMobileStats()

  const devices = devicesData?.items ?? []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-400">{t('subtitle')}</p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Devices', value: stats?.total_devices ?? devices.length, color: 'text-slate-200' },
          { label: 'Non-Compliant', value: stats?.non_compliant ?? devices.filter(d => !d.is_compliant).length, color: 'text-red-400' },
          { label: 'Unencrypted', value: stats?.unencrypted ?? devices.filter(d => !d.is_encrypted).length, color: 'text-amber-400' },
          { label: 'Jailbroken/Rooted', value: stats?.jailbroken ?? devices.filter(d => d.is_jailbroken).length, color: 'text-red-400' },
        ].map((stat) => (
          <Card key={stat.label}>
            <CardContent className="pt-4">
              <p className="text-xs text-slate-400">{stat.label}</p>
              <p className={`mt-1 text-2xl font-bold ${stat.color}`}>{stat.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <LoadingState variant="table" rows={6} />
          ) : error ? (
            <ErrorState message={error.message} retry={() => mutate()} />
          ) : devices.length === 0 ? (
            <EmptyState message={t('noDevices')} />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-xs text-slate-500">
                  <th className="px-4 py-3 text-left">{t('devices')}</th>
                  <th className="px-4 py-3 text-left">{t('platform')}</th>
                  <th className="px-4 py-3 text-left">{t('ownership')}</th>
                  <th className="px-4 py-3 text-left">{t('enrollmentStatus')}</th>
                  <th className="px-4 py-3 text-center">{t('encrypted')}</th>
                  <th className="px-4 py-3 text-center">{t('jailbroken')}</th>
                  <th className="px-4 py-3 text-center">{t('compliant')}</th>
                  <th className="px-4 py-3 text-left">{t('riskScore')}</th>
                  <th className="px-4 py-3 text-left">{t('lastSeen')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40">
                {devices.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-800/40 cursor-pointer transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Smartphone className="h-4 w-4 text-slate-500" />
                        <div>
                          <p className="font-medium text-slate-200">{d.device_name}</p>
                          {d.owner_name && <p className="text-xs text-slate-500">{d.owner_name}</p>}
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${platformColors[d.platform] ?? 'bg-slate-800 text-slate-400 border-slate-700'}`}>
                        {d.platform.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${ownershipColors[d.ownership] ?? 'bg-slate-800 text-slate-400 border-slate-700'}`}>
                        {d.ownership.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3"><StatusBadge status={d.enrollment_status} /></td>
                    <td className="px-4 py-3 text-center"><BoolIcon value={d.is_encrypted} /></td>
                    <td className="px-4 py-3 text-center"><BoolIcon value={d.is_jailbroken} danger={false} /></td>
                    <td className="px-4 py-3 text-center"><BoolIcon value={d.is_compliant} /></td>
                    <td className="px-4 py-3"><RiskScore score={d.risk_score} /></td>
                    <td className="px-4 py-3 text-xs text-slate-500">{formatDate(d.last_seen_at)}</td>
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

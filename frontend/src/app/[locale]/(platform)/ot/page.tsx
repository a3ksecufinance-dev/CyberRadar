import { getTranslations } from 'next-intl/server'
import { Cpu, Check, X } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { RiskScore } from '@/components/shared/RiskScore'
import { EmptyState } from '@/components/shared/EmptyState'
import { formatDate } from '@/lib/utils'

const mockOTAssets = [
  { id: 'o1', name: 'PLC-HVAC-01', asset_type: 'plc', vendor: 'Siemens', model: 'S7-300', purdue_level: 1, protocol: 'S7comm', is_internet_facing: false, affects_safety: true, is_patched: false, risk_score: 78, last_seen_at: new Date(Date.now() - 600000).toISOString() },
  { id: 'o2', name: 'RTU-Power-01', asset_type: 'rtu', vendor: 'ABB', model: 'RTU560', purdue_level: 1, protocol: 'IEC 61850', is_internet_facing: false, affects_safety: true, is_patched: true, risk_score: 42, last_seen_at: new Date(Date.now() - 1200000).toISOString() },
  { id: 'o3', name: 'HMI-DataCenter', asset_type: 'hmi', vendor: 'Rockwell', model: 'FactoryTalk', purdue_level: 2, protocol: 'EtherNet/IP', is_internet_facing: false, affects_safety: false, is_patched: false, risk_score: 65, last_seen_at: new Date(Date.now() - 3600000).toISOString() },
  { id: 'o4', name: 'SCADA-BMS', asset_type: 'scada', vendor: 'Honeywell', model: 'EBI R530', purdue_level: 2, protocol: 'BACnet', is_internet_facing: true, affects_safety: false, is_patched: false, risk_score: 91, last_seen_at: new Date(Date.now() - 900000).toISOString() },
  { id: 'o5', name: 'Historian-OT', asset_type: 'historian', vendor: 'OSIsoft', model: 'PI Server', purdue_level: 3, protocol: 'PI-AF', is_internet_facing: false, affects_safety: false, is_patched: true, risk_score: 28, last_seen_at: new Date(Date.now() - 7200000).toISOString() },
]

const mockOTEvents = [
  { id: 'oe1', title: 'Unauthorized Modbus READ on HVAC PLC', severity: 'high', source: 'ids', created_at: new Date(Date.now() - 900000).toISOString() },
  { id: 'oe2', title: 'Abnormal S7comm command sequence detected', severity: 'critical', source: 'ids', created_at: new Date(Date.now() - 3600000).toISOString() },
  { id: 'oe3', title: 'SCADA-BMS external connection attempt', severity: 'medium', source: 'firewall', created_at: new Date(Date.now() - 7200000).toISOString() },
]

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

const assetTypeIcon = (type: string) => {
  return <Cpu className="h-4 w-4 text-cyan-500" />
}

export default async function OTPage() {
  const t = await getTranslations('ot')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-400">{t('subtitle')}</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'OT Assets', value: mockOTAssets.length, color: 'text-slate-200' },
          { label: 'Internet Facing', value: mockOTAssets.filter(a => a.is_internet_facing).length, color: 'text-red-400' },
          { label: 'Safety Critical', value: mockOTAssets.filter(a => a.affects_safety).length, color: 'text-orange-400' },
          { label: 'Unpatched', value: mockOTAssets.filter(a => !a.is_patched).length, color: 'text-amber-400' },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-4">
              <p className="text-xs text-slate-400">{s.label}</p>
              <p className={`mt-1 text-2xl font-bold ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Purdue Model visual summary */}
      <Card>
        <CardHeader>
          <CardTitle>Purdue Model Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3">
            {[0, 1, 2, 3, 4].map((level) => {
              const count = mockOTAssets.filter(a => a.purdue_level === level).length
              return (
                <div key={level} className="flex flex-1 flex-col items-center gap-2">
                  <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${purdueColors[level]}`}>
                    {purdueLabel[level]}
                  </span>
                  <span className="text-lg font-bold text-slate-200">{count}</span>
                </div>
              )
            })}
          </div>
        </CardContent>
      </Card>

      {/* OT Assets Table */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-300">{t('assets')}</h2>
        <Card>
          <CardContent className="p-0">
            {mockOTAssets.length === 0 ? (
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
                    <th className="px-4 py-3 text-center">{t('affectsSafety')}</th>
                    <th className="px-4 py-3 text-center">Patched</th>
                    <th className="px-4 py-3 text-left">Risk</th>
                    <th className="px-4 py-3 text-left">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/40">
                  {mockOTAssets.map((asset) => (
                    <tr key={asset.id} className="hover:bg-slate-800/40 cursor-pointer transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          {assetTypeIcon(asset.asset_type)}
                          <div>
                            <p className="font-medium text-slate-200">{asset.name}</p>
                            <p className="text-xs text-slate-500">{asset.vendor} {asset.model}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">{asset.asset_type.toUpperCase()}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${purdueColors[asset.purdue_level]}`}>
                          {purdueLabel[asset.purdue_level]}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-400">{asset.protocol}</td>
                      <td className="px-4 py-3 text-center">
                        {asset.is_internet_facing
                          ? <Badge variant="critical" className="text-[10px]">YES</Badge>
                          : <span className="text-xs text-slate-500">No</span>}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {asset.affects_safety
                          ? <Badge variant="high" className="text-[10px]">YES</Badge>
                          : <span className="text-xs text-slate-500">No</span>}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {asset.is_patched
                          ? <Check className="mx-auto h-4 w-4 text-emerald-400" />
                          : <X className="mx-auto h-4 w-4 text-red-400" />}
                      </td>
                      <td className="px-4 py-3"><RiskScore score={asset.risk_score} /></td>
                      <td className="px-4 py-3 text-xs text-slate-500">{formatDate(asset.last_seen_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent Events */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-300">{t('events')}</h2>
        <div className="space-y-2">
          {mockOTEvents.map((ev) => (
            <Card key={ev.id}>
              <CardContent className="flex items-center justify-between py-3">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={ev.severity} />
                  <p className="text-sm text-slate-200">{ev.title}</p>
                  <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">{ev.source}</span>
                </div>
                <span className="text-xs text-slate-500">{formatDate(ev.created_at)}</span>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  )
}

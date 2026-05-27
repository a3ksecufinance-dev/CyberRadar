import { getTranslations } from 'next-intl/server'
import { TrendingUp, TrendingDown, Minus } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/shared/SeverityBadge'

const mockRisks = [
  { id: 'r1', name: 'APT29 Intrusion Campaign', category: 'cyber', severity: 'critical', likelihood: 4, impact: 5, risk_score: 92, owner: 'CISO', trend: 'up', status: 'open', treatment: 'mitigate' },
  { id: 'r2', name: 'PCI Data Breach via S3 Exposure', category: 'compliance', severity: 'critical', likelihood: 3, impact: 5, risk_score: 85, owner: 'DPO', trend: 'stable', status: 'open', treatment: 'mitigate' },
  { id: 'r3', name: 'DORA Compliance Gap — TLPT Testing', category: 'regulatory', severity: 'high', likelihood: 4, impact: 4, risk_score: 72, owner: 'Compliance', trend: 'down', status: 'in_treatment', treatment: 'mitigate' },
  { id: 'r4', name: 'OT Flat Network Lateral Movement', category: 'operational', severity: 'high', likelihood: 3, impact: 4, risk_score: 68, owner: 'OT Security', trend: 'stable', status: 'open', treatment: 'mitigate' },
  { id: 'r5', name: 'Jailbroken BYOD Devices', category: 'cyber', severity: 'high', likelihood: 4, impact: 3, risk_score: 61, owner: 'IT Security', trend: 'up', status: 'open', treatment: 'transfer' },
  { id: 'r6', name: 'Third-party Log4j Dependency', category: 'cyber', severity: 'medium', likelihood: 2, impact: 4, risk_score: 44, owner: 'Engineering', trend: 'down', status: 'in_treatment', treatment: 'mitigate' },
  { id: 'r7', name: 'GDPR DPIA Not Completed — New AI Tool', category: 'regulatory', severity: 'medium', likelihood: 3, impact: 3, risk_score: 38, owner: 'DPO', trend: 'stable', status: 'open', treatment: 'accept' },
]

const categoryColors: Record<string, string> = {
  cyber: 'bg-red-950 text-red-400 border-red-800',
  compliance: 'bg-amber-950 text-amber-400 border-amber-800',
  regulatory: 'bg-purple-950 text-purple-400 border-purple-800',
  operational: 'bg-blue-950 text-blue-400 border-blue-800',
}

const treatmentColors: Record<string, string> = {
  mitigate: 'bg-slate-800 text-slate-300 border-slate-600',
  transfer: 'bg-blue-950 text-blue-400 border-blue-800',
  accept: 'bg-emerald-950 text-emerald-400 border-emerald-800',
  avoid: 'bg-red-950 text-red-400 border-red-800',
}

const statusVariant: Record<string, any> = {
  open: 'critical',
  in_treatment: 'medium',
  resolved: 'success',
  accepted: 'low',
}

function TrendIcon({ trend }: { trend: string }) {
  if (trend === 'up') return <TrendingUp className="h-4 w-4 text-red-400" />
  if (trend === 'down') return <TrendingDown className="h-4 w-4 text-emerald-400" />
  return <Minus className="h-4 w-4 text-slate-500" />
}

function HeatCell({ score }: { score: number }) {
  const bg = score >= 80 ? 'bg-red-500' : score >= 60 ? 'bg-orange-500' : score >= 40 ? 'bg-amber-500' : 'bg-emerald-600'
  return (
    <div className={`flex h-8 w-8 items-center justify-center rounded text-xs font-bold text-white ${bg}`}>
      {score}
    </div>
  )
}

// 5x5 risk matrix data
const matrixRisks = mockRisks.map(r => ({ likelihood: r.likelihood, impact: r.impact, name: r.name }))

export default async function RiskPage() {
  const openCount = mockRisks.filter(r => r.status === 'open').length
  const criticalCount = mockRisks.filter(r => r.severity === 'critical').length
  const trendingUp = mockRisks.filter(r => r.trend === 'up').length

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Risk Management</h1>
        <p className="text-sm text-slate-400">Enterprise risk register and heat map — ISO 27005 aligned</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Risks', value: mockRisks.length, color: 'text-slate-200' },
          { label: 'Open', value: openCount, color: 'text-red-400' },
          { label: 'Critical', value: criticalCount, color: 'text-red-400' },
          { label: 'Trending Up', value: trendingUp, color: 'text-orange-400' },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-4">
              <p className="text-xs text-slate-400">{s.label}</p>
              <p className={`mt-1 text-2xl font-bold ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        {/* Risk Heat Map */}
        <Card>
          <CardHeader>
            <CardTitle>Risk Heat Map</CardTitle>
            <p className="text-xs text-slate-500">Likelihood × Impact (5×5)</p>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {/* Y-axis: Impact (5=top, 1=bottom) */}
              {[5, 4, 3, 2, 1].map((impact) => (
                <div key={impact} className="flex items-center gap-1">
                  <span className="w-3 text-center text-[10px] text-slate-600">{impact}</span>
                  {[1, 2, 3, 4, 5].map((likelihood) => {
                    const cellScore = likelihood * impact * 4
                    const hasRisk = matrixRisks.some(r => r.likelihood === likelihood && r.impact === impact)
                    const bg = cellScore >= 72 ? 'bg-red-900/60' : cellScore >= 40 ? 'bg-orange-900/60' : cellScore >= 20 ? 'bg-amber-900/60' : 'bg-emerald-900/30'
                    return (
                      <div key={likelihood} className={`relative flex h-9 w-9 items-center justify-center rounded ${bg}`}>
                        {hasRisk && (
                          <div className="h-3 w-3 rounded-full bg-white/80" title={matrixRisks.find(r => r.likelihood === likelihood && r.impact === impact)?.name} />
                        )}
                      </div>
                    )
                  })}
                </div>
              ))}
              {/* X-axis */}
              <div className="flex gap-1 pl-4">
                {[1, 2, 3, 4, 5].map((l) => (
                  <div key={l} className="w-9 text-center text-[10px] text-slate-600">{l}</div>
                ))}
              </div>
              <div className="pt-1 text-center text-[10px] text-slate-600">← Likelihood →</div>
            </div>
          </CardContent>
        </Card>

        {/* Risk Register */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Risk Register</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-xs text-slate-500">
                  <th className="px-4 py-3 text-left">Risk</th>
                  <th className="px-4 py-3 text-left">Category</th>
                  <th className="px-4 py-3 text-left">Severity</th>
                  <th className="px-4 py-3 text-center">Score</th>
                  <th className="px-4 py-3 text-center">Trend</th>
                  <th className="px-4 py-3 text-left">Treatment</th>
                  <th className="px-4 py-3 text-left">Owner</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40">
                {mockRisks.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-800/40 cursor-pointer transition-colors">
                    <td className="px-4 py-3">
                      <p className="font-medium text-slate-200 max-w-[200px] text-xs leading-tight">{r.name}</p>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-medium ${categoryColors[r.category] ?? ''}`}>
                        {r.category.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3"><SeverityBadge severity={r.severity} /></td>
                    <td className="px-4 py-3 text-center"><HeatCell score={r.risk_score} /></td>
                    <td className="px-4 py-3 text-center"><TrendIcon trend={r.trend} /></td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-medium ${treatmentColors[r.treatment] ?? ''}`}>
                        {r.treatment.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">{r.owner}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

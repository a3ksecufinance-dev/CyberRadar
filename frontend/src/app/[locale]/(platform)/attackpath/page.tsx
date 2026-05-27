import { getTranslations } from 'next-intl/server'
import { ArrowRight, AlertTriangle } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/shared/SeverityBadge'

const mockPaths = [
  {
    id: 'p1',
    severity: 'critical',
    title: 'Internet → SWIFT Gateway via Phishing + Credential Theft',
    risk_score: 94,
    steps: [
      { node: 'Internet', type: 'external' },
      { node: 'Email Gateway', type: 'service', finding: 'Phishing email — APT29 IOC' },
      { node: 'FX-Trader Workstation', type: 'endpoint', finding: 'ISO dropper executed' },
      { node: 'svc_corebanking_admin', type: 'credential', finding: 'Service account compromised' },
      { node: 'SWIFT Gateway', type: 'critical_asset', finding: 'Potential SWIFT fraud' },
    ],
  },
  {
    id: 'p2',
    severity: 'high',
    title: 'Jailbroken Device → PII Database via Uncontrolled S3 Access',
    risk_score: 81,
    steps: [
      { node: 'Pixel 7 (Rooted)', type: 'mobile', finding: 'MDM bypass possible' },
      { node: 'Corporate VPN', type: 'service', finding: 'No device compliance check' },
      { node: 'S3 Archive Bucket', type: 'data_store', finding: 'No auth required' },
      { node: 'PCI Data (2.4M records)', type: 'critical_asset', finding: 'Unencrypted exfiltration risk' },
    ],
  },
  {
    id: 'p3',
    severity: 'high',
    title: 'OT Network Lateral Movement via BACnet Exposure',
    risk_score: 76,
    steps: [
      { node: 'External Actor', type: 'external' },
      { node: 'SCADA-BMS (Internet-Facing)', type: 'ot', finding: 'Unpatched BACnet service' },
      { node: 'OT Network L2', type: 'network', finding: 'Flat network — no segmentation' },
      { node: 'PLC-HVAC-01', type: 'ot', finding: 'S7comm command injection possible' },
      { node: 'Building Safety Systems', type: 'critical_asset', finding: 'Physical safety impact' },
    ],
  },
]

const nodeColors: Record<string, string> = {
  external: 'border-red-700 bg-red-950 text-red-300',
  service: 'border-slate-600 bg-slate-800 text-slate-300',
  endpoint: 'border-orange-700 bg-orange-950 text-orange-300',
  credential: 'border-purple-700 bg-purple-950 text-purple-300',
  critical_asset: 'border-red-500 bg-red-900 text-red-200 font-bold',
  mobile: 'border-amber-700 bg-amber-950 text-amber-300',
  data_store: 'border-blue-700 bg-blue-950 text-blue-300',
  network: 'border-slate-600 bg-slate-800 text-slate-300',
  ot: 'border-cyan-700 bg-cyan-950 text-cyan-300',
}

const riskColor = (score: number) =>
  score >= 85 ? 'text-red-400' : score >= 70 ? 'text-orange-400' : 'text-amber-400'

export default async function AttackPathPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Attack Path Analysis</h1>
        <p className="text-sm text-slate-400">Automated lateral movement and blast radius simulation</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Attack Paths', value: mockPaths.length, color: 'text-slate-200' },
          { label: 'Critical Paths', value: mockPaths.filter(p => p.severity === 'critical').length, color: 'text-red-400' },
          { label: 'Critical Assets at Risk', value: 3, color: 'text-red-400' },
          { label: 'Avg Risk Score', value: Math.round(mockPaths.reduce((a, p) => a + p.risk_score, 0) / mockPaths.length), color: 'text-orange-400' },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-4">
              <p className="text-xs text-slate-400">{s.label}</p>
              <p className={`mt-1 text-2xl font-bold ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Attack Paths */}
      <div className="space-y-4">
        {mockPaths.map((path) => (
          <Card key={path.id}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-orange-400" />
                  <CardTitle className="text-sm">{path.title}</CardTitle>
                </div>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={path.severity} />
                  <span className={`text-sm font-bold ${riskColor(path.risk_score)}`}>{path.risk_score}</span>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {/* Path visualization */}
              <div className="flex flex-wrap items-center gap-2">
                {path.steps.map((step, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <div className="flex flex-col items-center">
                      <div className={`rounded-md border px-2.5 py-1.5 text-xs ${nodeColors[step.type] ?? nodeColors.service}`}>
                        {step.node}
                      </div>
                      {step.finding && (
                        <p className="mt-0.5 max-w-[140px] text-center text-[9px] text-slate-500 leading-tight">{step.finding}</p>
                      )}
                    </div>
                    {idx < path.steps.length - 1 && (
                      <ArrowRight className="h-3 w-3 flex-shrink-0 text-slate-600" />
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

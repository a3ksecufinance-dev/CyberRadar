import { getTranslations } from 'next-intl/server'
import { CheckCircle, XCircle, AlertCircle } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'

const frameworks = [
  {
    key: 'dora', label: 'DORA', score: 78, mandatory: true,
    description: 'EU Digital Operational Resilience Act — mandatory since Jan 2025',
    controls: [
      { label: 'ICT Risk Management', status: 'compliant' },
      { label: 'Incident Classification & Reporting', status: 'compliant' },
      { label: 'Digital Resilience Testing (TLPT)', status: 'partial' },
      { label: 'Third-party ICT Risk (SCS)', status: 'compliant' },
      { label: 'Information Sharing', status: 'partial' },
    ],
  },
  {
    key: 'pci', label: 'PCI-DSS v4', score: 83, mandatory: true,
    description: 'Payment Card Industry Data Security Standard v4.0',
    controls: [
      { label: 'Req 3 — Protect stored account data', status: 'non_compliant' },
      { label: 'Req 6 — Secure systems and software', status: 'compliant' },
      { label: 'Req 10 — Log and monitor all access', status: 'compliant' },
      { label: 'Req 11 — Test security regularly', status: 'partial' },
      { label: 'Req 12 — Support information security', status: 'compliant' },
    ],
  },
  {
    key: 'gdpr', label: 'GDPR', score: 91, mandatory: true,
    description: 'General Data Protection Regulation (EU) 2016/679',
    controls: [
      { label: 'Art. 5 — Data minimization', status: 'compliant' },
      { label: 'Art. 25 — Privacy by design', status: 'compliant' },
      { label: 'Art. 32 — Security of processing', status: 'compliant' },
      { label: 'Art. 33 — Breach notification < 72h', status: 'compliant' },
      { label: 'Art. 35 — DPIA for high-risk processing', status: 'partial' },
    ],
  },
  {
    key: 'nis2', label: 'NIS2', score: 87, mandatory: true,
    description: 'EU Network and Information Security Directive 2022/2555',
    controls: [
      { label: 'Risk management measures', status: 'compliant' },
      { label: 'Incident handling', status: 'compliant' },
      { label: 'Business continuity', status: 'compliant' },
      { label: 'Supply chain security', status: 'partial' },
      { label: 'Vulnerability disclosure', status: 'compliant' },
    ],
  },
]

const statusIcon = (status: string) => {
  if (status === 'compliant') return <CheckCircle className="h-4 w-4 text-emerald-400 flex-shrink-0" />
  if (status === 'non_compliant') return <XCircle className="h-4 w-4 text-red-400 flex-shrink-0" />
  return <AlertCircle className="h-4 w-4 text-amber-400 flex-shrink-0" />
}

const scoreColor = (s: number) =>
  s >= 85 ? 'text-emerald-400' : s >= 70 ? 'text-amber-400' : 'text-red-400'

const barColor = (s: number) =>
  s >= 85 ? 'bg-emerald-500' : s >= 70 ? 'bg-amber-500' : 'bg-red-500'

export default async function CompliancePage() {
  const t = await getTranslations('compliance')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">{t('title')}</h1>
        <p className="text-sm text-slate-400">{t('subtitle')}</p>
      </div>

      {/* Score overview */}
      <div className="grid grid-cols-4 gap-4">
        {frameworks.map((fw) => (
          <Card key={fw.key}>
            <CardContent className="pt-4">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-xs font-bold text-slate-400">{fw.label}</p>
                  <p className={`mt-1 text-3xl font-bold ${scoreColor(fw.score)}`}>{fw.score}%</p>
                </div>
                {fw.mandatory && (
                  <span className="rounded bg-slate-700 px-1.5 py-0.5 text-[9px] font-bold text-slate-400">MANDATORY</span>
                )}
              </div>
              <div className="mt-3 h-1.5 w-full rounded-full bg-slate-700">
                <div className={`h-1.5 rounded-full ${barColor(fw.score)}`} style={{ width: `${fw.score}%` }} />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Per-framework detail */}
      <div className="grid gap-4 lg:grid-cols-2">
        {frameworks.map((fw) => (
          <Card key={fw.key}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>{fw.label}</CardTitle>
                <span className={`text-lg font-bold ${scoreColor(fw.score)}`}>{fw.score}%</span>
              </div>
              <p className="text-xs text-slate-500">{fw.description}</p>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {fw.controls.map((ctrl) => (
                  <div key={ctrl.label} className="flex items-center gap-2.5 rounded-md bg-slate-800/50 px-3 py-2">
                    {statusIcon(ctrl.status)}
                    <span className="text-xs text-slate-300">{ctrl.label}</span>
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

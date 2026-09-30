'use client'
import { useTranslations } from 'next-intl'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { EmptyState } from '@/components/shared/EmptyState'
import { ErrorState } from '@/components/shared/ErrorState'
import { LoadingState } from '@/components/shared/LoadingState'
import { useRuleCoverage } from '@/hooks'

// The MITRE tactic names, keyed by the identifier the catalogue stores.
//
// They are not translated: TA0006 is "Credential Access" in every language a
// security team reads ATT&CK in, and inventing a French name for it would make
// the screen harder to reconcile with the framework it cites.
const TACTIC_NAMES: Record<string, string> = {
  TA0001: 'Initial Access',
  TA0002: 'Execution',
  TA0003: 'Persistence',
  TA0004: 'Privilege Escalation',
  TA0005: 'Defense Evasion',
  TA0006: 'Credential Access',
  TA0007: 'Discovery',
  TA0008: 'Lateral Movement',
  TA0009: 'Collection',
  TA0010: 'Exfiltration',
  TA0011: 'Command and Control',
  TA0040: 'Impact',
}

export function Coverage() {
  const t = useTranslations('siem.coverage')
  const { data, isLoading, error, mutate } = useRuleCoverage()

  if (isLoading) return <LoadingState variant="table" rows={8} />
  if (error) return <ErrorState message={error.message} retry={() => mutate()} />
  if (!data) return <EmptyState message={t('noReport')} />

  const techniques = data.techniques ?? []
  const gaps = techniques.filter((x) => x.enabled === 0).length

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        {[
          { label: t('catalogueSize'), value: data.catalogue_size, color: 'text-slate-200' },
          { label: t('adopted'), value: data.adopted_total, color: 'text-cyan-400' },
          { label: t('enabled'), value: data.enabled_total, color: 'text-emerald-400' },
          { label: t('gaps'), value: gaps, color: gaps > 0 ? 'text-amber-400' : 'text-emerald-400' },
          { label: t('ownRules'), value: data.own_rules, color: 'text-slate-200' },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-4">
              <p className="text-xs text-slate-400">{s.label}</p>
              <p className={`mt-1 text-2xl font-bold ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Rules the tenant wrote are not a defect — the library is a starting
          point, not a cage — but they are not coverage the catalogue can vouch
          for, so they are counted apart and said so rather than folded in. */}
      {data.own_rules > 0 && (
        <p className="text-xs text-slate-500">{t('ownRulesNote', { count: data.own_rules })}</p>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{t('title')}</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {techniques.length === 0 ? (
            <EmptyState message={t('empty')} />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-xs text-slate-500">
                  <th className="px-4 py-3 text-left">{t('colTactic')}</th>
                  <th className="px-4 py-3 text-left">{t('colTechnique')}</th>
                  <th className="px-4 py-3 text-center">{t('colAvailable')}</th>
                  <th className="px-4 py-3 text-center">{t('colAdopted')}</th>
                  <th className="px-4 py-3 text-center">{t('colEnabled')}</th>
                  <th className="px-4 py-3 text-left">{t('colDetections')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40">
                {/* Gaps first — the service sorts them that way, because a
                    coverage report is read to find what is missing. */}
                {techniques.map((x) => {
                  const gap = x.enabled === 0
                  return (
                    <tr key={`${x.mitre_tactic}/${x.mitre_technique}`} className={gap ? 'bg-amber-950/20' : ''}>
                      <td className="px-4 py-2.5 text-xs text-slate-400">
                        <span className="font-mono text-slate-500">{x.mitre_tactic}</span>
                        {TACTIC_NAMES[x.mitre_tactic] && (
                          <span className="ml-2">{TACTIC_NAMES[x.mitre_tactic]}</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-xs text-cyan-400">{x.mitre_technique}</td>
                      <td className="px-4 py-2.5 text-center text-xs text-slate-400">{x.available}</td>
                      <td className="px-4 py-2.5 text-center text-xs text-slate-400">{x.adopted}</td>
                      <td className={`px-4 py-2.5 text-center text-xs font-semibold ${
                        gap ? 'text-amber-400' : 'text-emerald-400'}`}>
                        {gap ? t('gap') : x.enabled}
                      </td>
                      {/* A gap names the entries that would close it: that is what
                          turns a list into a decision. */}
                      <td className="px-4 py-2.5 font-mono text-[11px] text-slate-500">
                        {(x.codes ?? []).join(' · ')}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

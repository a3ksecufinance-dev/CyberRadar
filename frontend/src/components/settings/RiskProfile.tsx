'use client'
import { useTranslations } from 'next-intl'
import { useEffect, useMemo, useState } from 'react'
import { Info } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ErrorState } from '@/components/shared/ErrorState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ApiError, api } from '@/lib/api'
import { useActiveRiskProfile, useApiToken, useRiskPresets, useRiskProfileHistory } from '@/hooks'
import type { RiskFactor, RiskProfile as Profile, RiskWeights } from '@/types'

// The factors, grouped the way the score is built rather than the way the
// columns happen to sit in the table. A ceiling belongs beside the terms it
// caps, or a customer raises a weight and cannot see why nothing moved.
const GROUPS: { key: string; factors: RiskFactor[] }[] = [
  { key: 'groupCriticality',    factors: ['criticality_step', 'criticality_cap'] },
  { key: 'groupVulnerabilities', factors: ['vuln_critical', 'vuln_high', 'vuln_medium', 'vuln_low', 'vuln_cap'] },
  { key: 'groupExposure',       factors: ['cbs_connected', 'swift_connected', 'pci_scope', 'exposure_cap'] },
  { key: 'groupHygiene',        factors: ['never_seen'] },
  { key: 'groupContext',        factors: ['critical_production', 'banking_type', 'context_cap'] },
  { key: 'groupOverall',        factors: ['total_cap', 'high_risk_threshold'] },
]

function day(iso: string) {
  return iso.slice(0, 10)
}

export function RiskProfile() {
  const t = useTranslations('settings.risk')
  const token = useApiToken()

  const active = useActiveRiskProfile()
  const presets = useRiskPresets()
  const history = useRiskProfileHistory()

  const [basedOn, setBasedOn] = useState<string | null>(null)
  // The weights being edited, seeded from the profile in force. Null until the
  // first read answers, because what is running is not known before then.
  const [form, setForm] = useState<RiskWeights | null>(null)
  const [notes, setNotes] = useState('')
  const [saving, setSaving] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  // The profile in force decides both what the form starts at and which standard
  // it is compared against, and neither is known on the first render. Seeding on
  // null rather than on a changed reference is also what makes the reset after a
  // save work: clearing the form hands it back to this effect.
  useEffect(() => {
    if (form === null && active.data) {
      setForm(active.data.profile.weights)
      setBasedOn(active.data.profile.based_on || active.data.profile.code)
    }
  }, [active.data, form])

  const presetList = useMemo(() => presets.data?.items ?? [], [presets.data])
  const base = useMemo(
    () => presetList.find((p) => p.code === basedOn) ?? presetList[0],
    [presetList, basedOn],
  )

  if (active.isLoading || presets.isLoading) return <LoadingState variant="table" rows={6} />
  if (active.error) return <ErrorState message={active.error.message} retry={() => active.mutate()} />
  if (!active.data || !base || !form) return null

  const current = active.data.profile
  const chosen = active.data.chosen
  const inForceBase = current.based_on || current.code

  const valueOf = (f: RiskFactor) => form[f]
  const changed = (Object.keys(form) as RiskFactor[]).filter((f) => form[f] !== base.weights[f])
  const dirty =
    basedOn !== inForceBase ||
    (Object.keys(form) as RiskFactor[]).some((f) => form[f] !== current.weights[f])

  // Choosing a profile means adopting its values.
  //
  // Leaving the old numbers in place and only relabelling what they are compared
  // against would record every one of them as a deliberate override of a standard
  // nobody chose them against — the exact "you changed seventeen things on day
  // one" this screen exists to avoid. Choosing back the one in force restores the
  // tenant's real profile, overrides and all.
  function pick(code: string) {
    const preset = presetList.find((x) => x.code === code)
    if (!preset) return
    setBasedOn(code)
    setForm(code === inForceBase ? current.weights : preset.weights)
    setSaved(false)
  }

  function reset() {
    setForm(current.weights)
    setBasedOn(inForceBase)
    setSaved(false)
  }

  async function save() {
    if (!token) return
    setSaving(true)
    setFailure(null)
    setSaved(false)
    try {
      // Only the factors that differ from the standard are sent. The API
      // applies them over the named profile, so the record says "this preset,
      // with these two changed" rather than seventeen absolute numbers whose
      // origin nobody can reconstruct.
      const weights: Partial<RiskWeights> = {}
      for (const f of changed) weights[f] = valueOf(f)

      const recorded = await api.tenant.setRiskProfile(
        { based_on: basedOn ?? base.code, notes, weights },
        token,
      )
      // Seeded from what the service returned, not by clearing the form and
      // waiting for the re-read. Clearing raced: the effect re-seeded from the
      // profile still in the cache, so a version recorded against one standard
      // was immediately displayed against the previous one, reporting five
      // differences where the customer had made one.
      setForm(recorded.weights)
      setBasedOn(recorded.based_on || recorded.code)
      setNotes('')
      setSaved(true)
      await Promise.all([active.mutate(), history.mutate()])
    } catch (e) {
      setFailure(e instanceof ApiError ? e.message : (e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* What is in force, and whether it is theirs. Presenting a default as a
          choice the customer made is how a vendor ends up defending someone
          else's risk appetite in an audit. */}
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between">
            <div>
              <CardTitle>{t('title')}</CardTitle>
              <p className="mt-1 max-w-3xl text-xs text-slate-400">{t('subtitle')}</p>
            </div>
            <div className="text-right">
              <p className="text-xs text-slate-500">{t('inForce')}</p>
              <p className="text-sm font-semibold text-slate-200">{current.name}</p>
              <p className="text-[11px] text-slate-500">
                {t('version', { version: current.version, date: day(current.effective_from) })}
              </p>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {chosen ? (
            <p className="text-xs text-slate-400">
              {t('chosen', { preset: current.based_on || current.code })}
            </p>
          ) : (
            <div className="flex gap-2 rounded-md border border-amber-800 bg-amber-950/30 px-3 py-2">
              <Info className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
              <div>
                <p className="text-xs font-semibold text-amber-300">{t('notChosenTitle')}</p>
                <p className="mt-0.5 max-w-3xl text-xs text-amber-200/80">{t('notChosen')}</p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('presets')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="max-w-3xl text-xs text-slate-400">{t('presetsHelp')}</p>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {presetList.map((p) => (
              <button key={p.code}
                onClick={() => pick(p.code)}
                className={`rounded-md border p-3 text-left transition-colors ${
                  basedOn === p.code
                    ? 'border-cyan-600 bg-cyan-950/30'
                    : 'border-slate-700 hover:border-slate-600'
                }`}>
                <div className="flex items-center justify-between gap-2">
                  <p className="text-sm font-semibold text-slate-200">{p.name}</p>
                  {basedOn === p.code && <Badge variant="info">{t('selected')}</Badge>}
                </div>
                <p className="mt-1 text-[11px] leading-relaxed text-slate-400">{p.description}</p>
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>{t('factors')}</CardTitle>
            <span className="text-xs text-slate-500">{t('changedCount', { count: changed.length })}</span>
          </div>
        </CardHeader>
        <CardContent className="space-y-5">
          {GROUPS.map((g) => (
            <div key={g.key}>
              <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500">{t(g.key)}</p>
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-[11px] text-slate-600">
                    <th className="py-1.5 pr-3 text-left">{t('colFactor')}</th>
                    <th className="w-24 py-1.5 pr-3 text-right">{t('colStandard')}</th>
                    <th className="w-28 py-1.5 text-right">{t('colYours')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {g.factors.map((f) => {
                    const differs = valueOf(f) !== base.weights[f]
                    return (
                      <tr key={f}>
                        <td className="py-1.5 pr-3">
                          <p className="text-slate-200">{t(`factor.${f}.label`)}</p>
                          <p className="text-slate-500">{t(`factor.${f}.help`)}</p>
                        </td>
                        <td className="py-1.5 pr-3 text-right font-mono text-slate-500">
                          {base.weights[f]}
                        </td>
                        <td className="py-1.5 text-right">
                          <input
                            type="number" step="0.1" min={0} max={10}
                            aria-label={t(`factor.${f}.label`)}
                            value={valueOf(f)}
                            onChange={(e) => {
                              const n = Number(e.target.value)
                              setSaved(false)
                              setForm((w) => (w ? { ...w, [f]: Number.isNaN(n) ? 0 : n } : w))
                            }}
                            className={`w-24 rounded-md border bg-slate-950 px-2 py-1 text-right font-mono text-slate-200 focus:outline-none ${
                              differs ? 'border-cyan-700 text-cyan-300' : 'border-slate-700'
                            }`}
                          />
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ))}

          {/* Why, next to what it decided. */}
          <label className="block">
            <span className="text-xs font-semibold text-slate-300">{t('notes')}</span>
            <span className="ml-2 text-xs text-slate-500">{t('notesHelp')}</span>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={2}
              placeholder={t('notesPlaceholder')}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-cyan-600 focus:outline-none"
            />
          </label>

          {failure && (
            <div className="rounded-md border border-red-800 bg-red-950/40 px-3 py-2 text-xs text-red-300">
              {failure}
              {/* Setting an appetite is a risk authority, not an administrative
                  one, so a tenant administrator is refused here by design. */}
              {failure.toLowerCase().includes('permission') && (
                <p className="mt-1 text-red-400/80">{t('readOnly')}</p>
              )}
            </div>
          )}
          {saved && (
            <div className="rounded-md border border-emerald-800 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-300">
              {t('saved')}
            </div>
          )}

          <div className="flex justify-end gap-2">
            <Button variant="outline" size="sm" disabled={!dirty || saving} onClick={reset}>
              {t('reset')}
            </Button>
            <Button size="sm" disabled={saving} onClick={save}>
              {saving ? t('saving') : t('save')}
            </Button>
          </div>
        </CardContent>
      </Card>

      <History
        entries={history.data?.items ?? []}
        loading={history.isLoading}
        t={t}
      />
    </div>
  )
}

function History({
  entries,
  loading,
  t,
}: {
  entries: Profile[]
  loading: boolean
  t: ReturnType<typeof useTranslations<'settings.risk'>>
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('history')}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <p className="text-xs text-slate-400">{t('historyHelp')}</p>
        {loading ? (
          <LoadingState variant="table" rows={3} />
        ) : entries.length === 0 ? (
          <p className="text-xs text-slate-600">{t('noHistory')}</p>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-600">
                <th className="py-1.5 pr-3 text-left">{t('colVersion')}</th>
                <th className="py-1.5 pr-3 text-left">{t('colFrom')}</th>
                <th className="py-1.5 pr-3 text-left">{t('colTo')}</th>
                <th className="py-1.5 pr-3 text-left">{t('colBasedOn')}</th>
                <th className="py-1.5 text-left">{t('colNotes')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {entries.map((p) => (
                <tr key={p.id}>
                  <td className="py-1.5 pr-3 font-mono text-slate-300">v{p.version}</td>
                  <td className="py-1.5 pr-3 text-slate-400">{day(p.effective_from)}</td>
                  <td className="py-1.5 pr-3 text-slate-400">
                    {p.effective_to ? day(p.effective_to) : <Badge variant="success">{t('current')}</Badge>}
                  </td>
                  <td className="py-1.5 pr-3 font-mono text-slate-500">{p.based_on || '—'}</td>
                  <td className="py-1.5 italic text-slate-400">{p.notes || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  )
}

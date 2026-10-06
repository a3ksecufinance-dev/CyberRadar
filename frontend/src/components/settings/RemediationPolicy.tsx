'use client'
import { useTranslations } from 'next-intl'
import { useEffect, useMemo, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ErrorState } from '@/components/shared/ErrorState'
import { LoadingState } from '@/components/shared/LoadingState'
import { History, InForce, Presets, SaveBar } from '@/components/settings/PolicyParts'
import { ApiError, api } from '@/lib/api'
import {
  useActiveRemediationPolicy,
  useApiToken,
  useRemediationHistory,
  useRemediationPresets,
} from '@/hooks'
import type { DeadlineCeiling, Deadlines } from '@/types'

const BASE = ['critical_days', 'high_days', 'medium_days', 'low_days'] as const

// Each ceiling and the name the API clears it under. A ceiling is nullable in
// a way a number cannot express: unset means "this condition is treated no
// differently", which is a decision rather than a zero.
const CEILINGS: { field: keyof Deadlines; clear: DeadlineCeiling }[] = [
  { field: 'exploited_days', clear: 'exploited' },
  { field: 'dmz_days', clear: 'dmz' },
  { field: 'cbs_days', clear: 'cbs' },
  { field: 'swift_days', clear: 'swift' },
  { field: 'pci_days', clear: 'pci' },
]

export function RemediationPolicy() {
  const t = useTranslations('settings.remediation')
  const token = useApiToken()

  const active = useActiveRemediationPolicy()
  const presets = useRemediationPresets()
  const history = useRemediationHistory()

  const [basedOn, setBasedOn] = useState<string | null>(null)
  const [form, setForm] = useState<Deadlines | null>(null)
  const [notes, setNotes] = useState('')
  const [saving, setSaving] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (form === null && active.data) {
      setForm(active.data.policy.deadlines)
      setBasedOn(active.data.policy.based_on || active.data.policy.code)
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

  const current = active.data.policy
  const inForceBase = current.based_on || current.code

  const fields = Object.keys(base.deadlines) as (keyof Deadlines)[]
  const changed = fields.filter((f) => (form[f] ?? null) !== (base.deadlines[f] ?? null))
  const dirty =
    basedOn !== inForceBase ||
    fields.some((f) => (form[f] ?? null) !== (current.deadlines[f] ?? null))

  function pick(code: string) {
    const preset = presetList.find((x) => x.code === code)
    if (!preset) return
    setBasedOn(code)
    setForm(code === inForceBase ? current.deadlines : preset.deadlines)
    setSaved(false)
  }

  function reset() {
    setForm(current.deadlines)
    setBasedOn(inForceBase)
    setSaved(false)
  }

  async function save() {
    if (!token || !form) return
    setSaving(true)
    setFailure(null)
    setSaved(false)
    try {
      // Only what differs from the standard is sent, plus the ceilings this
      // tenant deliberately removed. An omitted key and a JSON null are the same
      // thing to Go's decoder, so "stop treating card scope specially" has to be
      // said out loud rather than implied by absence.
      const deadlines: Partial<Deadlines> & { clear_ceilings?: DeadlineCeiling[] } = {}
      const clear: DeadlineCeiling[] = []
      for (const f of changed) {
        const value = form[f]
        if (value === null || value === undefined) {
          const ceiling = CEILINGS.find((c) => c.field === f)
          if (ceiling) clear.push(ceiling.clear)
        } else {
          deadlines[f] = value as never
        }
      }
      if (clear.length > 0) deadlines.clear_ceilings = clear

      const recorded = await api.tenant.setRemediationPolicy(
        { based_on: basedOn ?? base.code, notes, deadlines },
        token,
      )
      setForm(recorded.deadlines)
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

  const row = (f: keyof Deadlines) => {
    const value = form[f]
    const differs = (value ?? null) !== (base.deadlines[f] ?? null)
    return (
      <tr key={f}>
        <td className="py-1.5 pr-3 text-slate-200">{t(f)}</td>
        <td className="py-1.5 pr-3 text-right font-mono text-slate-500">
          {base.deadlines[f] ?? t('off')}
        </td>
        <td className="py-1.5 text-right">
          <input
            type="number" min={1} max={3650}
            aria-label={t(f)}
            value={value ?? ''}
            onChange={(e) => {
              const n = Number(e.target.value)
              setSaved(false)
              setForm((d) => (d ? { ...d, [f]: Number.isNaN(n) || n < 1 ? 1 : n } : d))
            }}
            className={`w-24 rounded-md border bg-slate-950 px-2 py-1 text-right font-mono text-slate-200 focus:outline-none ${
              differs ? 'border-cyan-700 text-cyan-300' : 'border-slate-700'
            }`}
          />
          <span className="ml-1.5 text-slate-500">{t('days')}</span>
        </td>
      </tr>
    )
  }

  return (
    <div className="space-y-6">
      <InForce
        title={t('title')} subtitle={t('subtitle')}
        name={current.name} version={current.version} from={current.effective_from}
        chosen={active.data.chosen}
        chosenText={t('chosen', { preset: inForceBase })}
        notChosenTitle={t('notChosenTitle')} notChosenText={t('notChosen')}
        inForceLabel={t('inForce')}
      />

      <Presets
        title={t('presets')} help={t('presetsHelp')}
        presets={presetList} selected={basedOn} selectedLabel={t('selected')}
        onPick={pick}
      />

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>{t('base')}</CardTitle>
            <span className="text-xs text-slate-500">{t('changedCount', { count: changed.length })}</span>
          </div>
        </CardHeader>
        <CardContent className="space-y-5">
          <div>
            <p className="mb-1.5 text-xs text-slate-400">{t('baseHelp')}</p>
            <table className="w-full max-w-2xl text-xs">
              <tbody className="divide-y divide-slate-800/60">{BASE.map(row)}</tbody>
            </table>
          </div>

          <div>
            <p className="mb-0.5 text-xs font-semibold uppercase tracking-wide text-slate-500">{t('ceilings')}</p>
            <p className="mb-1.5 max-w-3xl text-xs text-slate-400">{t('ceilingsHelp')}</p>
            <table className="w-full max-w-2xl text-xs">
              <tbody className="divide-y divide-slate-800/60">
                {CEILINGS.map(({ field }) => {
                  const value = form[field]
                  const on = value !== null && value !== undefined
                  const differs = (value ?? null) !== (base.deadlines[field] ?? null)
                  return (
                    <tr key={field}>
                      <td className="py-1.5 pr-3 text-slate-200">{t(field)}</td>
                      <td className="py-1.5 pr-3 text-right font-mono text-slate-500">
                        {base.deadlines[field] ?? t('off')}
                      </td>
                      <td className="py-1.5 text-right">
                        {on ? (
                          <>
                            <input
                              type="number" min={1} max={3650}
                              aria-label={t(field)}
                              value={value as number}
                              onChange={(e) => {
                                const n = Number(e.target.value)
                                setSaved(false)
                                setForm((d) => (d ? { ...d, [field]: Number.isNaN(n) || n < 1 ? 1 : n } : d))
                              }}
                              className={`w-24 rounded-md border bg-slate-950 px-2 py-1 text-right font-mono text-slate-200 focus:outline-none ${
                                differs ? 'border-cyan-700 text-cyan-300' : 'border-slate-700'
                              }`}
                            />
                            <span className="ml-1.5 text-slate-500">{t('days')}</span>
                            <button
                              onClick={() => { setSaved(false); setForm((d) => (d ? { ...d, [field]: null } : d)) }}
                              className="ml-2 text-[11px] text-slate-500 underline-offset-2 hover:text-slate-300 hover:underline">
                              {t('clear')}
                            </button>
                          </>
                        ) : (
                          <button
                            onClick={() => {
                              setSaved(false)
                              setForm((d) => (d ? { ...d, [field]: base.deadlines[field] ?? 7 } : d))
                            }}
                            className="rounded-md border border-slate-700 px-2 py-1 text-[11px] text-slate-400 transition-colors hover:text-slate-200">
                            {t('enable')}
                          </button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          <div>
            <p className="mb-0.5 text-xs font-semibold uppercase tracking-wide text-slate-500">{t('floor')}</p>
            <p className="mb-1.5 max-w-3xl text-xs text-slate-400">{t('floorHelp')}</p>
            <table className="w-full max-w-2xl text-xs">
              <tbody className="divide-y divide-slate-800/60">{row('minimum_days')}</tbody>
            </table>
          </div>

          <SaveBar
            notes={notes} onNotes={setNotes}
            labels={{
              notes: t('notes'), notesHelp: t('notesHelp'), notesPlaceholder: t('notesPlaceholder'),
              saved: t('saved'), reset: t('reset'), save: t('save'), saving: t('saving'),
              readOnly: t('readOnly'),
            }}
            failure={failure} saved={saved} dirty={dirty} saving={saving}
            onReset={reset} onSave={save}
          />
        </CardContent>
      </Card>

      <History
        title={t('history')} help={t('historyHelp')} empty={t('noHistory')} current={t('current')}
        columns={{
          version: t('colVersion'), from: t('colFrom'), to: t('colTo'),
          basedOn: t('colBasedOn'), notes: t('colNotes'),
        }}
        entries={history.data?.items ?? []} loading={history.isLoading}
      />
    </div>
  )
}

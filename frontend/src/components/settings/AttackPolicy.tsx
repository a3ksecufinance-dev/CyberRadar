'use client'
import { useTranslations } from 'next-intl'
import { useEffect, useMemo, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ErrorState } from '@/components/shared/ErrorState'
import { LoadingState } from '@/components/shared/LoadingState'
import { History, InForce, Presets, SaveBar } from '@/components/settings/PolicyParts'
import { ApiError, api } from '@/lib/api'
import {
  useActiveAttackPolicy,
  useApiToken,
  useAttackHistory,
  useAttackPresets,
} from '@/hooks'
import type { AttackWeightField, AttackWeights } from '@/types'

// Grouped the way the score is built: what a step costs, what distance is
// worth, what the target is worth, and what several ways in add. A reader who
// raises a cost and sees nothing move needs the ceiling that caps it in view.
const GROUPS: { key: string; help: string; step: number; max: number; fields: AttackWeightField[] }[] = [
  {
    key: 'cost', help: 'costHelp', step: 0.1, max: 10,
    fields: ['base_cost', 'complexity_medium', 'complexity_high', 'privilege_low', 'privilege_high'],
  },
  { key: 'distance', help: 'distanceHelp', step: 0.05, max: 1, fields: ['hop_decay'] },
  {
    key: 'impact', help: 'impactHelp', step: 0.5, max: 10,
    fields: ['impact_ceiling', 'unknown_target_impact', 'critical_system_bonus'],
  },
  { key: 'breadth', help: 'breadthHelp', step: 0.1, max: 5, fields: ['many_paths_boost'] },
]

const ALL = GROUPS.flatMap((g) => g.fields)

export function AttackPolicy() {
  const t = useTranslations('settings.attack')
  const token = useApiToken()

  const active = useActiveAttackPolicy()
  const presets = useAttackPresets()
  const history = useAttackHistory()

  const [basedOn, setBasedOn] = useState<string | null>(null)
  const [form, setForm] = useState<AttackWeights | null>(null)
  const [notes, setNotes] = useState('')
  const [saving, setSaving] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (form === null && active.data) {
      setForm(active.data.policy.weights)
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

  const changed = ALL.filter((f) => form[f] !== base.weights[f])
  const dirty = basedOn !== inForceBase || ALL.some((f) => form[f] !== current.weights[f])

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
    if (!token || !form) return
    setSaving(true)
    setFailure(null)
    setSaved(false)
    try {
      const weights: Partial<AttackWeights> = {}
      for (const f of changed) weights[f] = form[f]

      const recorded = await api.tenant.setAttackPolicy(
        { based_on: basedOn ?? base.code, notes, weights },
        token,
      )
      // Seeded from what the service returned rather than from a re-read that
      // races the effect — the mistake the risk appetite screen cost to find.
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
            <CardTitle>{t('title')}</CardTitle>
            <span className="text-xs text-slate-500">{t('changedCount', { count: changed.length })}</span>
          </div>
        </CardHeader>
        <CardContent className="space-y-5">
          {GROUPS.map((g) => (
            <div key={g.key}>
              <p className="mb-0.5 text-xs font-semibold uppercase tracking-wide text-slate-500">{t(g.key)}</p>
              <p className="mb-1.5 max-w-3xl text-xs text-slate-400">{t(g.help)}</p>
              <table className="w-full max-w-3xl text-xs">
                <tbody className="divide-y divide-slate-800/60">
                  {g.fields.map((f) => {
                    const differs = form[f] !== base.weights[f]
                    return (
                      <tr key={f}>
                        <td className="py-1.5 pr-3 text-slate-200">{t(f)}</td>
                        <td className="w-20 py-1.5 pr-3 text-right font-mono text-slate-500">
                          {base.weights[f]}
                        </td>
                        <td className="w-28 py-1.5 text-right">
                          <input
                            type="number" step={g.step} min={0} max={g.max}
                            aria-label={t(f)}
                            value={form[f]}
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

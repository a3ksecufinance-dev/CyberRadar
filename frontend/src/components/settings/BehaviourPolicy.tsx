'use client'
import { useTranslations } from 'next-intl'
import { useEffect, useMemo, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ErrorState } from '@/components/shared/ErrorState'
import { LoadingState } from '@/components/shared/LoadingState'
import { History, InForce, Presets, SaveBar } from '@/components/settings/PolicyParts'
import { ApiError, api } from '@/lib/api'
import {
  useActiveBehaviourPolicy,
  useApiToken,
  useBehaviourHistory,
  useBehaviourPresets,
} from '@/hooks'
import type { RuleSeverity, Signal, SignalName, Signals, ThresholdField, Thresholds } from '@/types'

const THRESHOLDS: ThresholdField[] = [
  'min_hours_for_baseline',
  'min_countries_for_baseline',
  'velocity_threshold',
  'velocity_window_s',
  'brute_force_threshold',
  'brute_force_window_s',
]

const SIGNALS: SignalName[] = [
  'off_hours', 'new_country', 'new_ip_prefix', 'velocity',
  'brute_force', 'priv_escalation', 'lateral_movement', 'data_exfiltration',
]

const SEVERITIES: RuleSeverity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

const SEVERITY_TONE: Record<RuleSeverity, string> = {
  LOW: 'border-emerald-800 bg-emerald-950/40 text-emerald-400',
  MEDIUM: 'border-amber-800 bg-amber-950/40 text-amber-400',
  HIGH: 'border-orange-800 bg-orange-950/40 text-orange-400',
  CRITICAL: 'border-red-800 bg-red-950/40 text-red-400',
}

function sameSignal(a: Signal, b: Signal) {
  return a.enabled === b.enabled && a.severity === b.severity && a.score === b.score
}

export function BehaviourPolicy() {
  const t = useTranslations('settings.behaviour')
  const token = useApiToken()

  const active = useActiveBehaviourPolicy()
  const presets = useBehaviourPresets()
  const history = useBehaviourHistory()

  const [basedOn, setBasedOn] = useState<string | null>(null)
  const [thresholds, setThresholds] = useState<Thresholds | null>(null)
  const [signals, setSignals] = useState<Signals | null>(null)
  const [notes, setNotes] = useState('')
  const [saving, setSaving] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (thresholds === null && active.data) {
      setThresholds(active.data.policy.thresholds)
      setSignals(active.data.policy.signals)
      setBasedOn(active.data.policy.based_on || active.data.policy.code)
    }
  }, [active.data, thresholds])

  const presetList = useMemo(() => presets.data?.items ?? [], [presets.data])
  const base = useMemo(
    () => presetList.find((p) => p.code === basedOn) ?? presetList[0],
    [presetList, basedOn],
  )

  if (active.isLoading || presets.isLoading) return <LoadingState variant="table" rows={6} />
  if (active.error) return <ErrorState message={active.error.message} retry={() => active.mutate()} />
  if (!active.data || !base || !thresholds || !signals) return null

  const current = active.data.policy
  const inForceBase = current.based_on || current.code

  const changed =
    THRESHOLDS.filter((f) => thresholds[f] !== base.thresholds[f]).length +
    SIGNALS.filter((s) => !sameSignal(signals[s], base.signals[s])).length

  const dirty =
    basedOn !== inForceBase ||
    THRESHOLDS.some((f) => thresholds[f] !== current.thresholds[f]) ||
    SIGNALS.some((s) => !sameSignal(signals[s], current.signals[s]))

  function pick(code: string) {
    const preset = presetList.find((x) => x.code === code)
    if (!preset) return
    setBasedOn(code)
    setThresholds(code === inForceBase ? current.thresholds : preset.thresholds)
    setSignals(code === inForceBase ? current.signals : preset.signals)
    setSaved(false)
  }

  function reset() {
    setThresholds(current.thresholds)
    setSignals(current.signals)
    setBasedOn(inForceBase)
    setSaved(false)
  }

  async function save() {
    if (!token || !thresholds || !signals) return
    setSaving(true)
    setFailure(null)
    setSaved(false)
    try {
      const sentThresholds: Partial<Thresholds> = {}
      for (const f of THRESHOLDS) {
        if (thresholds[f] !== base.thresholds[f]) sentThresholds[f] = thresholds[f]
      }
      const sentSignals: Partial<Record<SignalName, Partial<Signal>>> = {}
      for (const s of SIGNALS) {
        if (!sameSignal(signals[s], base.signals[s])) sentSignals[s] = signals[s]
      }

      const recorded = await api.tenant.setBehaviourPolicy(
        { based_on: basedOn ?? base.code, notes, thresholds: sentThresholds, signals: sentSignals },
        token,
      )
      setThresholds(recorded.thresholds)
      setSignals(recorded.signals)
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

  function setSignal(name: SignalName, patch: Partial<Signal>) {
    setSaved(false)
    setSignals((s) => (s ? { ...s, [name]: { ...s[name], ...patch } } : s))
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
            <CardTitle>{t('thresholds')}</CardTitle>
            <span className="text-xs text-slate-500">{t('changedCount', { count: changed })}</span>
          </div>
        </CardHeader>
        <CardContent className="space-y-5">
          <table className="w-full max-w-3xl text-xs">
            <tbody className="divide-y divide-slate-800/60">
              {THRESHOLDS.map((f) => {
                const differs = thresholds[f] !== base.thresholds[f]
                return (
                  <tr key={f}>
                    <td className="py-1.5 pr-3 text-slate-200">{t(f)}</td>
                    <td className="py-1.5 pr-3 text-right font-mono text-slate-500">{base.thresholds[f]}</td>
                    <td className="w-28 py-1.5 text-right">
                      <input
                        type="number" min={1}
                        aria-label={t(f)}
                        value={thresholds[f]}
                        onChange={(e) => {
                          const n = Number(e.target.value)
                          setSaved(false)
                          setThresholds((x) => (x ? { ...x, [f]: Number.isNaN(n) || n < 1 ? 1 : n } : x))
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

          <div>
            <p className="mb-0.5 text-xs font-semibold uppercase tracking-wide text-slate-500">{t('signals')}</p>
            <p className="mb-2 max-w-3xl text-xs text-slate-400">{t('signalsHelp')}</p>
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] text-slate-600">
                  <th className="py-1.5 pr-3 text-left">{t('colSignal')}</th>
                  <th className="w-24 py-1.5 pr-3 text-left" />
                  <th className="py-1.5 pr-3 text-left">{t('colSeverity')}</th>
                  <th className="w-28 py-1.5 text-right">{t('colScore')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {SIGNALS.map((name) => {
                  const sig = signals[name]
                  const differs = !sameSignal(sig, base.signals[name])
                  return (
                    <tr key={name} className={sig.enabled ? '' : 'opacity-60'}>
                      <td className="py-1.5 pr-3 text-slate-200">{t(`sig_${name}`)}</td>
                      <td className="py-1.5 pr-3">
                        {/* Switching one off is a decision anyone can see.
                            Switching it off downstream is one nobody can. */}
                        <button
                          onClick={() => setSignal(name, { enabled: !sig.enabled })}
                          className={`rounded-md border px-2 py-0.5 text-[11px] transition-colors ${
                            sig.enabled
                              ? 'border-emerald-800 bg-emerald-950/40 text-emerald-400'
                              : 'border-slate-700 text-slate-500'
                          }`}>
                          {sig.enabled ? t('enabled') : t('disabled')}
                        </button>
                      </td>
                      <td className="py-1.5 pr-3">
                        <div className="flex gap-1">
                          {SEVERITIES.map((s) => (
                            <button key={s}
                              onClick={() => setSignal(name, { severity: s })}
                              disabled={!sig.enabled}
                              className={`rounded border px-1.5 py-0.5 text-[10px] transition-colors disabled:opacity-40 ${
                                sig.severity === s
                                  ? SEVERITY_TONE[s]
                                  : 'border-slate-700 text-slate-500 hover:text-slate-300'
                              }`}>
                              {s}
                            </button>
                          ))}
                        </div>
                      </td>
                      <td className="py-1.5 text-right">
                        <input
                          type="number" step="0.5" min={0} max={10}
                          aria-label={t(`sig_${name}`)}
                          disabled={!sig.enabled}
                          value={sig.score}
                          onChange={(e) => {
                            const n = Number(e.target.value)
                            setSignal(name, { score: Number.isNaN(n) ? 0 : n })
                          }}
                          className={`w-20 rounded-md border bg-slate-950 px-2 py-1 text-right font-mono text-slate-200 focus:outline-none disabled:opacity-40 ${
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

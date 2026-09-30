'use client'
import { useTranslations } from 'next-intl'
import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, ArrowRight, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { LoadingState } from '@/components/shared/LoadingState'
import { api } from '@/lib/api'
import { useApiToken } from '@/hooks'
import type { UpgradeField, UpgradePlan } from '@/types'

// What each outcome of the three-way merge means, in the words a reviewer needs
// rather than the constant's name.
const TONE: Record<UpgradeField['action'], string> = {
  unchanged:     'text-slate-500',
  take_incoming: 'text-cyan-400',
  keep_tenant:   'text-emerald-400',
  converged:     'text-slate-400',
  conflict:      'text-amber-400',
}
const LABEL_KEY: Record<UpgradeField['action'], string> = {
  unchanged: 'unchanged',
  take_incoming: 'takeIncoming',
  keep_tenant: 'keepTenant',
  converged: 'converged',
  conflict: 'conflict',
}

function truncate(v: string, at = 120) {
  return v.length > at ? v.slice(0, at) + '…' : v
}

interface Props {
  code: string
  title: string
  onClose: () => void
  /** Called after a successful upgrade so the caller can refresh its list. */
  onUpgraded: () => void
}

/** The difference first, the decision second, and nothing written until then.
 *
 *  An upgrade is not a migration: where the customer and the catalogue changed
 *  the same field, only the customer can say which is their intent. This dialog
 *  exists so that question gets asked instead of answered on their behalf. */
export function UpgradeDialog({ code, title, onClose, onUpgraded }: Props) {
  const t = useTranslations('siem.upgrade')
  const token = useApiToken()
  const [plan, setPlan] = useState<UpgradePlan | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [resolve, setResolve] = useState<Record<string, 'incoming' | 'tenant'>>({})
  const [notes, setNotes] = useState('')
  const [applying, setApplying] = useState(false)

  useEffect(() => {
    if (!token) return
    let live = true
    api.siem
      .upgradePlan(code, token)
      .then((p) => { if (live) setPlan(p) })
      .catch((e: Error) => { if (live) setError(e.message) })
    return () => { live = false }
  }, [code, token])

  const apply = useCallback(async () => {
    if (!plan || !token) return
    setApplying(true)
    setError(null)
    try {
      await api.siem.upgrade(code, {
        // The version this plan was computed against. Without it a decision
        // taken on one difference could land on another.
        to_version: plan.to_version,
        resolve,
        notes,
      }, token)
      onUpgraded()
      onClose()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setApplying(false)
    }
  }, [plan, token, code, resolve, notes, onUpgraded, onClose])

  const undecided = (plan?.conflicts ?? []).filter((f) => !resolve[f])

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-950/80 p-6">
      <div className="w-full max-w-4xl rounded-lg border border-slate-700 bg-slate-900 shadow-xl">
        <div className="flex items-start justify-between border-b border-slate-700 px-5 py-4">
          <div>
            <p className="font-mono text-xs text-slate-500">{code}</p>
            <h2 className="text-base font-semibold text-slate-100">{title}</h2>
          </div>
          <button onClick={onClose} aria-label={t('close')}
                  className="rounded p-1 text-slate-500 hover:bg-slate-800 hover:text-slate-300">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4 px-5 py-4">
          {!plan && !error && <LoadingState variant="table" rows={4} />}
          {error && (
            <div className="rounded-md border border-red-800 bg-red-950/40 px-3 py-2 text-xs text-red-300">
              {error}
            </div>
          )}

          {plan?.up_to_date && (
            <p className="text-sm text-slate-400">{t('alreadyCurrent', { version: plan.from_version })}</p>
          )}

          {plan && !plan.up_to_date && (
            <>
              <p className="flex items-center gap-2 text-sm text-slate-300">
                <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs">v{plan.from_version}</span>
                <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
                <span className="rounded bg-cyan-950/60 px-2 py-0.5 font-mono text-xs text-cyan-300">v{plan.to_version}</span>
              </p>

              {(plan.warnings ?? []).map((w) => (
                <div key={w} className="flex gap-2 rounded-md border border-amber-800 bg-amber-950/30 px-3 py-2 text-xs text-amber-300">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span>{w}</span>
                </div>
              ))}

              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700 text-[11px] text-slate-500">
                    <th className="py-2 pr-3 text-left">{t('colField')}</th>
                    <th className="py-2 pr-3 text-left">{t('colAdopted', { version: plan.from_version })}</th>
                    <th className="py-2 pr-3 text-left">{t('colIncoming', { version: plan.to_version })}</th>
                    <th className="py-2 pr-3 text-left">{t('colTenant')}</th>
                    <th className="py-2 text-left">{t('colResult')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {plan.fields
                    .filter((f) => f.action !== 'unchanged')
                    .map((f) => {
                      const conflict = f.action === 'conflict'
                      const chosen = resolve[f.field]
                      return (
                        <tr key={f.field} className={conflict ? 'bg-amber-950/10' : ''}>
                          <td className="py-2 pr-3 align-top">
                            <p className="font-mono text-slate-300">{f.field}</p>
                            <p className={TONE[f.action]}>{t(LABEL_KEY[f.action])}</p>
                          </td>
                          <td className="py-2 pr-3 align-top font-mono text-slate-500">{truncate(f.adopted)}</td>
                          <td className="py-2 pr-3 align-top font-mono text-cyan-400">{truncate(f.incoming)}</td>
                          <td className="py-2 pr-3 align-top font-mono text-slate-300">{truncate(f.tenant)}</td>
                          <td className="py-2 align-top">
                            {!conflict ? (
                              <span className="font-mono text-slate-300">{truncate(f.result ?? '')}</span>
                            ) : (
                              <div className="flex gap-1">
                                {([
                                  ['tenant', t('keepYours')],
                                  ['incoming', t('takeOurs')],
                                ] as const).map(([side, label]) => (
                                  <button key={side}
                                    onClick={() => setResolve((r) => ({ ...r, [f.field]: side }))}
                                    className={`rounded border px-2 py-0.5 transition-colors ${
                                      chosen === side
                                        ? 'border-cyan-600 bg-cyan-950/50 text-cyan-300'
                                        : 'border-slate-700 text-slate-400 hover:text-slate-200'
                                    }`}>
                                    {label}
                                  </button>
                                ))}
                              </div>
                            )}
                          </td>
                        </tr>
                      )
                    })}
                </tbody>
              </table>

              {/* Why, recorded next to what it decided. An auditor reads this
                  before they read the values. */}
              <label className="block">
                <span className="text-xs text-slate-400">
                  {t('notes')}{' '}
                  {plan.conflicts.length > 0 && <span className="text-slate-500">{t('notesHint')}</span>}
                </span>
                <textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  rows={2}
                  placeholder={t('notesPlaceholder')}
                  className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-cyan-600 focus:outline-none"
                />
              </label>
            </>
          )}
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-slate-700 px-5 py-3">
          <p className="text-xs text-slate-500">
            {undecided.length > 0
              ? t('toDecide', { fields: undecided.join(', ') })
              : plan && !plan.up_to_date
                ? t('nothingPending')
                : ''}
          </p>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={onClose}>{t('cancel')}</Button>
            <Button size="sm" onClick={apply}
                    disabled={!plan || plan.up_to_date || applying || undecided.length > 0}>
              {applying ? t('applying') : t('apply', { version: plan?.to_version ?? '' })}
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}

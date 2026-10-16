'use client'
import type { ReactNode } from 'react'
import { Info } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { LoadingState } from '@/components/shared/LoadingState'

// The three things every one of these screens says, extracted once.
//
// The risk appetite, the remediation deadlines and the behavioural thresholds
// are different judgements with different fields, but they are the same
// decision: what is in force, what standard it started from, and what it was on
// a given day. Writing that three times is how the third one quietly stops
// saying "you have not chosen" — which is the sentence that matters most.

export function day(iso: string) {
  return iso.slice(0, 10)
}

/** What is in force, and whether the customer chose it.
 *
 *  Presenting a default as a decision they made is how a vendor ends up
 *  defending someone else's judgement to a regulator, so the distinction is
 *  stated rather than implied. */
export function InForce({
  title,
  subtitle,
  name,
  version,
  from,
  chosen,
  chosenText,
  notChosenTitle,
  notChosenText,
  inForceLabel,
}: {
  title: string
  subtitle: string
  name: string
  version: number
  from: string
  chosen: boolean
  chosenText: ReactNode
  notChosenTitle: string
  notChosenText: string
  inForceLabel: string
}) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div>
            <CardTitle>{title}</CardTitle>
            <p className="mt-1 max-w-3xl text-xs text-slate-400">{subtitle}</p>
          </div>
          <div className="shrink-0 text-right">
            <p className="text-xs text-slate-500">{inForceLabel}</p>
            <p className="text-sm font-semibold text-slate-200">{name}</p>
            <p className="text-[11px] text-slate-500">v{version} · {day(from)}</p>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {chosen ? (
          <p className="text-xs text-slate-400">{chosenText}</p>
        ) : (
          <div className="flex gap-2 rounded-md border border-amber-800 bg-amber-950/30 px-3 py-2">
            <Info className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
            <div>
              <p className="text-xs font-semibold text-amber-300">{notChosenTitle}</p>
              <p className="mt-0.5 max-w-3xl text-xs text-amber-200/80">{notChosenText}</p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

/** The standard policies, as a starting point rather than a cage. */
export function Presets<T extends { code: string; name: string; description?: string }>({
  title,
  help,
  presets,
  selected,
  selectedLabel,
  onPick,
}: {
  title: string
  help: string
  presets: T[]
  selected: string | null
  selectedLabel: string
  onPick: (code: string) => void
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="max-w-3xl text-xs text-slate-400">{help}</p>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {presets.map((p) => (
            <button key={p.code}
              onClick={() => onPick(p.code)}
              className={`rounded-md border p-3 text-left transition-colors ${
                selected === p.code
                  ? 'border-cyan-600 bg-cyan-950/30'
                  : 'border-slate-700 hover:border-slate-600'
              }`}>
              <div className="flex items-center justify-between gap-2">
                <p className="text-sm font-semibold text-slate-200">{p.name}</p>
                {selected === p.code && <Badge variant="info">{selectedLabel}</Badge>}
              </div>
              <p className="mt-1 text-[11px] leading-relaxed text-slate-400">{p.description}</p>
            </button>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

/** Every version with the window it was in force. The audit answer. */
export function History<T extends {
  id: string
  version: number
  effective_from: string
  effective_to?: string
  based_on?: string
  notes?: string
}>({
  title,
  help,
  empty,
  current,
  columns,
  entries,
  loading,
}: {
  title: string
  help: string
  empty: string
  current: string
  columns: { version: string; from: string; to: string; basedOn: string; notes: string }
  entries: T[]
  loading: boolean
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <p className="text-xs text-slate-400">{help}</p>
        {loading ? (
          <LoadingState variant="table" rows={3} />
        ) : entries.length === 0 ? (
          <p className="text-xs text-slate-600">{empty}</p>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-600">
                <th className="py-1.5 pr-3 text-left">{columns.version}</th>
                <th className="py-1.5 pr-3 text-left">{columns.from}</th>
                <th className="py-1.5 pr-3 text-left">{columns.to}</th>
                <th className="py-1.5 pr-3 text-left">{columns.basedOn}</th>
                <th className="py-1.5 text-left">{columns.notes}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {entries.map((p) => (
                <tr key={p.id}>
                  <td className="py-1.5 pr-3 font-mono text-slate-300">v{p.version}</td>
                  <td className="py-1.5 pr-3 text-slate-400">{day(p.effective_from)}</td>
                  <td className="py-1.5 pr-3 text-slate-400">
                    {p.effective_to ? day(p.effective_to) : <Badge variant="success">{current}</Badge>}
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

/** The reason, the error, and the two buttons — identical on all three. */
export function SaveBar({
  notes,
  onNotes,
  labels,
  failure,
  saved,
  dirty,
  saving,
  onReset,
  onSave,
}: {
  notes: string
  onNotes: (v: string) => void
  labels: {
    notes: string
    notesHelp: string
    notesPlaceholder: string
    saved: string
    reset: string
    save: string
    saving: string
    readOnly: string
  }
  failure: string | null
  saved: boolean
  dirty: boolean
  saving: boolean
  onReset: () => void
  onSave: () => void
}) {
  return (
    <>
      <label className="block">
        <span className="text-xs font-semibold text-slate-300">{labels.notes}</span>
        <span className="ml-2 text-xs text-slate-500">{labels.notesHelp}</span>
        <textarea
          value={notes}
          onChange={(e) => onNotes(e.target.value)}
          rows={2}
          placeholder={labels.notesPlaceholder}
          className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-cyan-600 focus:outline-none"
        />
      </label>

      {failure && (
        <div className="rounded-md border border-red-800 bg-red-950/40 px-3 py-2 text-xs text-red-300">
          {failure}
          {failure.toLowerCase().includes('permission') && (
            <p className="mt-1 text-red-400/80">{labels.readOnly}</p>
          )}
        </div>
      )}
      {saved && (
        <div className="rounded-md border border-emerald-800 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-300">
          {labels.saved}
        </div>
      )}

      <div className="flex justify-end gap-2">
        <button disabled={!dirty || saving} onClick={onReset}
          className="rounded-md border border-slate-600 px-2 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-700 disabled:pointer-events-none disabled:opacity-50">
          {labels.reset}
        </button>
        <button disabled={saving} onClick={onSave}
          className="rounded-md bg-cyan-600 px-2 py-1 text-xs font-medium text-white shadow-sm transition-colors hover:bg-cyan-500 disabled:pointer-events-none disabled:opacity-50">
          {saving ? labels.saving : labels.save}
        </button>
      </div>
    </>
  )
}

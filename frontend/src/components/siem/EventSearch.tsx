'use client'
import { useTranslations } from 'next-intl'
import { useState } from 'react'
import { Search, X, ChevronLeft, ChevronRight, Landmark, Crosshair } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { useEventSearch } from '@/hooks'
import { formatDate, formatDateShort } from '@/lib/utils'
import type { NormalizedEvent } from '@/types'

// La recherche d'événements.
//
// La table crp_audit.cyber_events recevait chaque événement depuis le premier
// jour et rien ne la lisait : un analyste qui recevait une alerte ne pouvait
// pas voir ce qui l'entourait. Cet écran est cette boucle-là.
//
// Ce qui en fait un outil de chasse plutôt qu'une liste de journaux, c'est le
// pivot : cliquer une adresse ou un compte dans un résultat relance la
// recherche dessus. C'est le geste que l'analyste répète, et le rendre
// gratuit est tout l'écart entre les deux.

const WINDOWS = ['15m', '1h', '6h', '24h', '7d', '30d'] as const
type Window = (typeof WINDOWS)[number]

// Le backend lit une durée Go, qui ne connaît pas le jour.
const WINDOW_PARAM: Record<Window, string> = {
  '15m': '15m', '1h': '1h', '6h': '6h', '24h': '24h', '7d': '168h', '30d': '720h',
}

// Les valeurs envoyées à l'API restent celles du schéma — elles sont
// comparées telles quelles en base. Seul l'affichage est traduit.
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
const CATEGORIES = ['Security', 'IAM', 'Network', 'Transaction', 'Fraud', 'Compliance', 'Other'] as const
const OUTCOMES = ['success', 'failure', 'unknown'] as const

const PAGE_SIZE = 50

type Filters = {
  q: string
  severity: string
  category: string
  outcome: string
  user_id: string
  ip_source: string
  source_type: string
  banking: boolean
  ioc: boolean
}

const EMPTY: Filters = {
  q: '', severity: '', category: '', outcome: '',
  user_id: '', ip_source: '', source_type: '', banking: false, ioc: false,
}

export function EventSearch() {
  const t = useTranslations('siem.eventSearch')
  const [win, setWin] = useState<Window>('24h')
  const [filters, setFilters] = useState<Filters>(EMPTY)
  // Le texte saisi n'est pas le texte cherché : chaque frappe lancerait un
  // balayage ClickHouse. La recherche part à la validation.
  const [draft, setDraft] = useState('')
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState<NormalizedEvent | null>(null)

  const params: Record<string, string> = {
    window: WINDOW_PARAM[win],
    limit: String(PAGE_SIZE),
    offset: String(page * PAGE_SIZE),
  }
  if (filters.q) params.q = filters.q
  if (filters.severity) params.severity = filters.severity
  if (filters.category) params.category = filters.category
  if (filters.outcome) params.outcome = filters.outcome
  if (filters.user_id) params.user_id = filters.user_id
  if (filters.ip_source) params.ip_source = filters.ip_source
  if (filters.source_type) params.source_type = filters.source_type
  if (filters.banking) params.cbs_impact = '1'
  if (filters.ioc) params.ioc = 'true'

  const { data, isLoading, error, mutate } = useEventSearch(params)
  const events = data?.items ?? []
  const total = data?.meta?.total ?? 0

  // Tout changement de critère ramène à la première page : rester page 4
  // d'une recherche qui n'a plus que deux pages affiche un vide qui ressemble
  // à « aucun résultat ».
  function apply(next: Partial<Filters>) {
    setFilters((f) => ({ ...f, ...next }))
    setPage(0)
    setSelected(null)
  }

  // Le pivot : relancer la recherche sur la valeur cliquée.
  function pivot(key: 'user_id' | 'ip_source', value: string) {
    apply({ [key]: value } as Partial<Filters>)
  }

  function reset() {
    setFilters(EMPTY)
    setDraft('')
    setPage(0)
    setSelected(null)
  }

  const active = Object.entries(filters).filter(([, v]) => v !== '' && v !== false)

  return (
    <div className="space-y-4">
      {/* Barre de recherche et fenêtre */}
      <div className="flex flex-wrap items-center gap-3">
        <form
          className="relative flex-1 min-w-[16rem]"
          onSubmit={(e) => {
            e.preventDefault()
            apply({ q: draft.trim() })
          }}
        >
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <Input
            className="pl-8 text-xs"
            placeholder={t('placeholder')}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
          />
        </form>

        <div className="flex gap-1">
          {WINDOWS.map((w) => (
            <button
              key={w}
              type="button"
              onClick={() => { setWin(w); setPage(0) }}
              className={`rounded-md border px-2.5 py-1 text-xs transition-colors ${
                win === w
                  ? 'border-cyan-600 bg-cyan-950/40 text-cyan-400'
                  : 'border-slate-700 text-slate-400 hover:text-slate-200'
              }`}
            >
              {w}
            </button>
          ))}
        </div>
      </div>

      {/* Filtres */}
      <div className="flex flex-wrap items-center gap-2">
        <Dropdown label={t('severity')} value={filters.severity}
          options={SEVERITIES} onChange={(v) => apply({ severity: v })} />
        <Dropdown label={t('category')} value={filters.category}
          options={CATEGORIES} onChange={(v) => apply({ category: v })} />
        <Dropdown label={t('outcome')} value={filters.outcome}
          options={OUTCOMES} onChange={(v) => apply({ outcome: v })} />

        <Toggle active={filters.banking} onClick={() => apply({ banking: !filters.banking })}
          icon={<Landmark className="h-3 w-3" />} label={t('bankingOnly')} />
        <Toggle active={filters.ioc} onClick={() => apply({ ioc: !filters.ioc })}
          icon={<Crosshair className="h-3 w-3" />} label={t('iocOnly')} />

        {active.length > 0 && (
          <button type="button" onClick={reset}
            className="ml-auto flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200">
            <X className="h-3 w-3" /> {t('clear')}
          </button>
        )}
      </div>

      {/* Les filtres de pivot sont montrés à part : ce sont eux qu'on retire
          le plus souvent, et ils ne figurent dans aucun menu. */}
      {(filters.user_id || filters.ip_source || filters.source_type) && (
        <div className="flex flex-wrap gap-2">
          {filters.user_id && (
            <Chip label={t('user')} value={filters.user_id} onRemove={() => apply({ user_id: '' })} />
          )}
          {filters.ip_source && (
            <Chip label={t('sourceIp')} value={filters.ip_source} onRemove={() => apply({ ip_source: '' })} />
          )}
          {filters.source_type && (
            <Chip label={t('sourceType')} value={filters.source_type} onRemove={() => apply({ source_type: '' })} />
          )}
        </div>
      )}

      {/* Décompte */}
      <p className="text-xs text-slate-500">
        {isLoading ? t('searching') : t('matched', { count: total, window: win })}
      </p>

      <div className="grid gap-4 lg:grid-cols-[1fr_22rem]">
        <Card>
          <CardContent className="p-0">
            {isLoading && events.length === 0 ? (
              <LoadingState variant="table" rows={10} />
            ) : error ? (
              <ErrorState message={error.message} retry={() => mutate()} />
            ) : events.length === 0 ? (
              <EmptyState message={t('noResults')} />
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700 text-xs text-slate-500">
                    <th className="px-3 py-2.5 text-left">{t('colTime')}</th>
                    <th className="px-3 py-2.5 text-left">{t('colSeverity')}</th>
                    <th className="px-3 py-2.5 text-left">{t('colCategory')}</th>
                    <th className="px-3 py-2.5 text-left">{t('colSource')}</th>
                    <th className="px-3 py-2.5 text-left">{t('colActor')}</th>
                    <th className="px-3 py-2.5 text-left">{t('colAction')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/40 font-mono">
                  {events.map((e) => (
                    <tr
                      key={e.event_id}
                      onClick={() => setSelected(e)}
                      className={`cursor-pointer transition-colors hover:bg-slate-800/40 ${
                        selected?.event_id === e.event_id ? 'bg-slate-800/60' : ''
                      }`}
                    >
                      <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-500">
                        {formatDateShort(e.timestamp)}
                      </td>
                      <td className="px-3 py-2"><SeverityBadge severity={e.severity} /></td>
                      <td className="px-3 py-2 text-xs text-slate-300">
                        {e.category}
                        {e.cbs_impact === 1 && (
                          <Landmark className="ml-1 inline h-3 w-3 text-amber-400" aria-label={t('bankingFlow')} />
                        )}
                      </td>
                      <td className="px-3 py-2 text-xs">
                        <Pivot onClick={() => pivot('ip_source', e.ip_source ?? '')} disabled={!e.ip_source}>
                          {e.ip_source || e.source}
                        </Pivot>
                      </td>
                      <td className="px-3 py-2 text-xs">
                        <Pivot onClick={() => pivot('user_id', e.user_id ?? '')} disabled={!e.user_id}>
                          {e.user_id || e.user_name || '—'}
                        </Pivot>
                      </td>
                      <td className="max-w-[14rem] truncate px-3 py-2 text-xs text-slate-400">
                        {e.action || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>

        {selected && <EventDetail event={selected} onClose={() => setSelected(null)} onPivot={pivot} />}
      </div>

      {/* Pagination. Le total vient d'un COUNT sur la même fenêtre, donc il
          est juste et non estimé. */}
      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-xs text-slate-400">
          <span>{t('page', { from: page * PAGE_SIZE + 1, to: Math.min((page + 1) * PAGE_SIZE, total), total })}</span>
          <div className="flex gap-2">
            <button type="button" disabled={page === 0}
              onClick={() => { setPage((p) => p - 1); setSelected(null) }}
              className="flex items-center gap-1 rounded-md border border-slate-700 px-2 py-1 disabled:opacity-40 enabled:hover:text-slate-200">
              <ChevronLeft className="h-3 w-3" /> {t('previous')}
            </button>
            <button type="button" disabled={(page + 1) * PAGE_SIZE >= total}
              onClick={() => { setPage((p) => p + 1); setSelected(null) }}
              className="flex items-center gap-1 rounded-md border border-slate-700 px-2 py-1 disabled:opacity-40 enabled:hover:text-slate-200">
              {t('next')} <ChevronRight className="h-3 w-3" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Le panneau de détail ─────────────────────────────────────
// L'événement canonique n'a pas de colonne pour le montant ni pour la
// contrepartie : pour une transaction, tout cela est dans raw_event, et c'est
// ce que l'analyste vient lire.
function EventDetail({
  event, onClose, onPivot,
}: {
  event: NormalizedEvent
  onClose: () => void
  onPivot: (key: 'user_id' | 'ip_source', value: string) => void
}) {
  const t = useTranslations('siem.eventSearch')

  const rows: Array<[string, React.ReactNode]> = [
    [t('time'), formatDate(event.timestamp)],
    [t('ingested'), formatDate(event.ingested_at)],
    [t('source'), event.source],
    [t('sourceType'), event.source_type],
    [t('category'), event.category],
    [t('outcome'), event.outcome],
    [t('action'), event.action || '—'],
  ]
  if (event.user_id) {
    rows.push([t('user'),
      <Pivot key="u" onClick={() => onPivot('user_id', event.user_id!)}>{event.user_id}</Pivot>])
  }
  if (event.asset_hostname) rows.push([t('asset'), event.asset_hostname])
  if (event.ip_source) {
    rows.push([t('sourceIp'),
      <Pivot key="i" onClick={() => onPivot('ip_source', event.ip_source!)}>{event.ip_source}</Pivot>])
  }
  if (event.ip_destination) rows.push([t('destIp'), event.ip_destination])
  if (event.geo_country) rows.push([t('country'), event.geo_country])
  if (event.mitre_tactic) rows.push(['MITRE', `${event.mitre_tactic} / ${event.mitre_technique ?? '—'}`])
  if (event.business_service) rows.push([t('service'), event.business_service])

  return (
    <Card className="h-fit">
      <CardContent className="space-y-4 p-4">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs text-slate-500">{t('detail')}</p>
            <p className="font-mono text-xs text-slate-300">{event.event_id}</p>
          </div>
          <button type="button" onClick={onClose} aria-label={t('close')}
            className="text-slate-500 hover:text-slate-200">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={event.severity} />
          <span className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-300">
            {t('risk')} {event.risk_score.toFixed(1)}
          </span>
          <span className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-300">
            {t('threat')} {event.threat_score.toFixed(1)}
          </span>
          {event.cbs_impact === 1 && (
            <span className="rounded bg-amber-950/60 px-1.5 py-0.5 text-xs text-amber-400">{t('cbs')}</span>
          )}
          {event.swift_impact === 1 && (
            <span className="rounded bg-amber-950/60 px-1.5 py-0.5 text-xs text-amber-400">SWIFT</span>
          )}
        </div>

        <dl className="space-y-1.5 text-xs">
          {rows.map(([label, value]) => (
            <div key={label} className="flex gap-2">
              <dt className="w-28 shrink-0 text-slate-500">{label}</dt>
              <dd className="break-all font-mono text-slate-300">{value}</dd>
            </div>
          ))}
        </dl>

        {event.ioc_matched && event.ioc_matched.length > 0 && (
          <div>
            <p className="mb-1 text-xs text-slate-500">{t('iocs')}</p>
            <div className="flex flex-wrap gap-1">
              {event.ioc_matched.map((ioc) => (
                <span key={ioc} className="rounded bg-red-950/60 px-1.5 py-0.5 font-mono text-xs text-red-400">
                  {ioc}
                </span>
              ))}
            </div>
          </div>
        )}

        {event.raw_event && (
          <div>
            <p className="mb-1 text-xs text-slate-500">{t('raw')}</p>
            <pre className="max-h-64 overflow-auto rounded bg-slate-950 p-2 font-mono text-[11px] leading-relaxed text-slate-400">
              {event.raw_event}
            </pre>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ─── Petits éléments ──────────────────────────────────────────

function Pivot({
  children, onClick, disabled,
}: {
  children: React.ReactNode
  onClick: () => void
  disabled?: boolean
}) {
  if (disabled) return <span className="text-slate-600">—</span>
  return (
    <button
      type="button"
      onClick={(e) => { e.stopPropagation(); onClick() }}
      className="text-cyan-400 underline decoration-dotted underline-offset-2 hover:text-cyan-300"
    >
      {children}
    </button>
  )
}

function Dropdown({
  label, value, options, onChange,
}: {
  label: string
  value: string
  options: readonly string[]
  onChange: (v: string) => void
}) {
  return (
    <select
      aria-label={label}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={`rounded-md border bg-slate-900 px-2 py-1 text-xs transition-colors ${
        value ? 'border-cyan-600 text-cyan-400' : 'border-slate-700 text-slate-400'
      }`}
    >
      <option value="">{label}</option>
      {options.map((o) => (
        <option key={o} value={o}>{o}</option>
      ))}
    </select>
  )
}

function Toggle({
  active, onClick, icon, label,
}: {
  active: boolean
  onClick: () => void
  icon: React.ReactNode
  label: string
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs transition-colors ${
        active
          ? 'border-cyan-600 bg-cyan-950/40 text-cyan-400'
          : 'border-slate-700 text-slate-400 hover:text-slate-200'
      }`}
    >
      {icon} {label}
    </button>
  )
}

function Chip({ label, value, onRemove }: { label: string; value: string; onRemove: () => void }) {
  return (
    <span className="flex items-center gap-1.5 rounded-md border border-cyan-800 bg-cyan-950/30 px-2 py-1 text-xs">
      <span className="text-slate-400">{label}</span>
      <span className="font-mono text-cyan-400">{value}</span>
      <button type="button" onClick={onRemove} className="text-slate-500 hover:text-slate-200">
        <X className="h-3 w-3" />
      </button>
    </span>
  )
}

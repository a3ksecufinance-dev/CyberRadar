'use client'
import { useTranslations } from 'next-intl'
import { Fragment, useMemo, useState } from 'react'
import { AlertTriangle, ChevronDown, ChevronRight, Lock } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { EmptyState } from '@/components/shared/EmptyState'
import { ErrorState } from '@/components/shared/ErrorState'
import { LoadingState } from '@/components/shared/LoadingState'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { UpgradeDialog } from '@/components/siem/UpgradeDialog'
import { api } from '@/lib/api'
import { useApiToken, useRuleLibrary } from '@/hooks'
import type { LibraryEntry } from '@/types'

type Filter = 'all' | 'adopted' | 'available' | 'drifted' | 'upgradable'

const FILTERS: { id: Filter; key: string }[] = [
  { id: 'all', key: 'filterAll' },
  { id: 'adopted', key: 'filterAdopted' },
  { id: 'available', key: 'filterAvailable' },
  { id: 'drifted', key: 'filterDrifted' },
  { id: 'upgradable', key: 'filterUpgradable' },
]

function matches(e: LibraryEntry, f: Filter): boolean {
  switch (f) {
    case 'adopted':    return !!e.adopted
    case 'available':  return !e.adopted
    case 'drifted':    return (e.adopted?.changes ?? []).length > 0
    case 'upgradable': return !!e.adopted?.update_available
    default:           return true
  }
}

function clip(v: string, at = 90) {
  return v.length > at ? v.slice(0, at) + '…' : v
}

export function RuleLibrary() {
  const t = useTranslations('siem.library')
  const token = useApiToken()
  const { data, isLoading, error, mutate } = useRuleLibrary()
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<Filter>('all')
  const [open, setOpen] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [failed, setFailed] = useState<Record<string, string>>({})
  const [upgrading, setUpgrading] = useState<LibraryEntry | null>(null)

  // Memoised, not because the list is large but because `?? []` would hand the
  // useMemo below a new array on every render and quietly defeat it.
  const entries = useMemo(() => data?.items ?? [], [data])
  const term = search.trim().toLowerCase()

  const shown = useMemo(
    () =>
      entries.filter(
        (e) =>
          matches(e, filter) &&
          (!term ||
            e.content.code.toLowerCase().includes(term) ||
            e.content.title.toLowerCase().includes(term) ||
            (e.content.mitre_technique ?? '').toLowerCase().includes(term) ||
            (e.content.tags ?? []).some((tg) => tg.toLowerCase().includes(term))),
      ),
    [entries, filter, term],
  )

  // Adopting sends no overrides, so the detection runs exactly as it ships. That
  // is deliberate: it is what makes the difference afterwards mean something. A
  // screen that pre-filled a form with the standard values would produce a tenant
  // who looks as though they changed things from the first day.
  async function adopt(code: string) {
    if (!token) return
    setBusy(code)
    setFailed((f) => ({ ...f, [code]: '' }))
    try {
      await api.siem.adopt(code, {}, token)
      await mutate()
    } catch (e) {
      setFailed((f) => ({ ...f, [code]: (e as Error).message }))
    } finally {
      setBusy(null)
    }
  }

  if (isLoading) return <LoadingState variant="table" rows={8} />
  if (error) return <ErrorState message={error.message} retry={() => mutate()} />

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Input
          className="max-w-sm text-xs"
          placeholder={t('search')}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        {FILTERS.map((f) => (
          <button key={f.id}
            onClick={() => setFilter(f.id)}
            className={`rounded-md border px-3 py-1 text-xs transition-colors ${
              filter === f.id
                ? 'border-cyan-600 bg-cyan-950/40 text-cyan-400'
                : 'border-slate-700 text-slate-400 hover:text-slate-200'
            }`}>
            {t(f.key)}
          </button>
        ))}
        <span className="ml-auto text-xs text-slate-500">{shown.length} / {entries.length}</span>
      </div>

      <Card>
        <CardContent className="p-0">
          {shown.length === 0 ? (
            <EmptyState message={t('noMatch')} />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-xs text-slate-500">
                  <th className="w-8 px-2 py-3" />
                  <th className="px-3 py-3 text-left">{t('colCode')}</th>
                  <th className="px-3 py-3 text-left">{t('colDetection')}</th>
                  <th className="px-3 py-3 text-left">{t('colSeverity')}</th>
                  <th className="px-3 py-3 text-left">{t('colAttack')}</th>
                  <th className="px-3 py-3 text-left">{t('colYours')}</th>
                  <th className="px-3 py-3 text-right">{t('colAction')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40">
                {shown.map((e) => {
                  const c = e.content
                  const a = e.adopted
                  const drift = a?.changes ?? []
                  const blocked = (c.requires ?? []).length > 0
                  const expanded = open === c.code
                  return (
                    <Fragment key={c.code}>
                      <tr className="hover:bg-slate-800/40">
                        <td className="px-2 py-2.5">
                          <button onClick={() => setOpen(expanded ? null : c.code)}
                                  aria-label={expanded ? t('collapse') : t('expand')}
                                  className="text-slate-500 hover:text-slate-300">
                            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                          </button>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-xs text-slate-400">
                          {c.code}<span className="ml-1.5 text-slate-600">v{c.version}</span>
                        </td>
                        <td className="px-3 py-2.5 text-xs text-slate-200">
                          {c.title}
                          {blocked && (
                            <Lock className="ml-1.5 inline h-3 w-3 text-amber-500"
                                  aria-label={t('missingPrerequisite')} />
                          )}
                        </td>
                        <td className="px-3 py-2.5"><SeverityBadge severity={c.severity.toLowerCase()} /></td>
                        <td className="px-3 py-2.5 font-mono text-[11px] text-cyan-400">
                          {c.mitre_technique || '—'}
                        </td>
                        <td className="px-3 py-2.5 text-xs">
                          {!a ? (
                            <span className="text-slate-600">{t('notAdopted')}</span>
                          ) : (
                            <div className="flex flex-wrap items-center gap-1.5">
                              <Badge variant={a.enabled ? 'success' : 'outline'}>
                                v{a.at_version}{a.enabled ? '' : ` · ${t('inactive')}`}
                              </Badge>
                              {drift.length > 0 && (
                                <Badge variant="info">{t('drift', { count: drift.length })}</Badge>
                              )}
                              {a.update_available && (
                                <Badge variant="medium">{t('updateAvailable', { version: c.version })}</Badge>
                              )}
                              {a.alerts_total > 0 && (
                                <span className="text-slate-500">{t('alertsRaised', { count: a.alerts_total })}</span>
                              )}
                            </div>
                          )}
                        </td>
                        <td className="px-3 py-2.5 text-right">
                          {!a ? (
                            <Button size="sm" variant="outline" disabled={busy === c.code}
                                    onClick={() => adopt(c.code)}>
                              {busy === c.code ? '…' : t('adopt')}
                            </Button>
                          ) : a.update_available ? (
                            <Button size="sm" onClick={() => setUpgrading(e)}>{t('upgrade')}</Button>
                          ) : (
                            <span className="text-xs text-slate-600">{t('upToDate')}</span>
                          )}
                        </td>
                      </tr>

                      {failed[c.code] && (
                        <tr>
                          <td />
                          <td colSpan={6} className="px-3 pb-2 text-xs text-red-400">{failed[c.code]}</td>
                        </tr>
                      )}

                      {expanded && (
                        <tr className="bg-slate-900/60">
                          <td />
                          <td colSpan={6} className="space-y-3 px-3 py-4 text-xs">
                            {/* The reasoning — the thing an analyst reads at three
                                in the morning, and the thing a rule list never
                                carries. */}
                            <Section title={t('why')}>{c.rationale}</Section>
                            {c.false_positives && (
                              <Section title={t('falsePositives')}>{c.false_positives}</Section>
                            )}
                            {c.response && <Section title={t('response')}>{c.response}</Section>}

                            {blocked && (
                              <div className="flex gap-2 rounded-md border border-amber-800 bg-amber-950/30 px-3 py-2 text-amber-300">
                                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                                <span>{t('requires', { what: (c.requires ?? []).join(', ') })}</span>
                              </div>
                            )}

                            <div className="flex flex-wrap gap-4">
                              {(c.frameworks ?? []).length > 0 && (
                                <p className="text-slate-500">
                                  {t('frameworks')} : <span className="text-slate-300">{(c.frameworks ?? []).join(', ')}</span>
                                </p>
                              )}
                              {(c.controls ?? []).length > 0 && (
                                <p className="text-slate-500">
                                  {t('controls')} : <span className="font-mono text-slate-300">{(c.controls ?? []).join(', ')}</span>
                                </p>
                              )}
                              <p className="text-slate-500">
                                {t('dedupWindow')} : <span className="text-slate-300">{c.dedup_window_s}s</span>
                              </p>
                            </div>

                            {/* The difference from the version they adopted —
                                computed on read, so an edit made directly to the
                                rule shows up here rather than being invisible. */}
                            {a && drift.length > 0 && (
                              <div>
                                <p className="mb-1.5 font-semibold text-slate-300">
                                  {t('driftTitle', { version: a.at_version })}
                                </p>
                                <table className="w-full max-w-3xl">
                                  <thead>
                                    <tr className="text-[11px] text-slate-500">
                                      <th className="py-1 pr-3 text-left">{t('colField')}</th>
                                      <th className="py-1 pr-3 text-left">{t('colStandard')}</th>
                                      <th className="py-1 text-left">{t('colTenant')}</th>
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-slate-800">
                                    {drift.map((d) => (
                                      <tr key={d.field}>
                                        <td className="py-1 pr-3 font-mono text-slate-400">{d.field}</td>
                                        <td className="py-1 pr-3 font-mono text-slate-500">{clip(d.standard)}</td>
                                        <td className="py-1 font-mono text-slate-200">{clip(d.tenant)}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}

                            {a && (
                              <p className="text-slate-500">
                                {t('adoptedOn', { date: a.adopted_at.slice(0, 10) })}
                                {a.upgraded_at && ` · ${t('upgradedOn', { date: a.upgraded_at.slice(0, 10) })}`}
                                {a.notes && <> · <span className="italic text-slate-400">{a.notes}</span></>}
                              </p>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {upgrading && (
        <UpgradeDialog
          code={upgrading.content.code}
          title={upgrading.content.title}
          onClose={() => setUpgrading(null)}
          onUpgraded={() => void mutate()}
        />
      )}
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="font-semibold text-slate-300">{title}</p>
      <p className="mt-0.5 max-w-4xl text-slate-400">{children}</p>
    </div>
  )
}

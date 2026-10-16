import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(date: string | Date): string {
  return new Intl.DateTimeFormat('default', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  }).format(new Date(date))
}

export function formatDateShort(date: string | Date): string {
  return new Intl.DateTimeFormat('default', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  }).format(new Date(date))
}

export function severityVariant(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  const map: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
    critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info',
  }
  return map[severity?.toLowerCase()] ?? 'info'
}

export function riskColor(score: number): string {
  if (score >= 75) return 'text-red-400'
  if (score >= 50) return 'text-orange-400'
  if (score >= 25) return 'text-amber-400'
  return 'text-emerald-400'
}

export function riskBg(score: number): string {
  if (score >= 75) return 'bg-red-950'
  if (score >= 50) return 'bg-orange-950'
  if (score >= 25) return 'bg-amber-950'
  return 'bg-emerald-950'
}

export function statusColors(status: string): string {
  // Every key below is a value some service actually stores: the SIEM's
  // alert_metadata CHECK list, the IR lifecycle, DSPM/SCS finding states and
  // the MDM enrolment states. An unknown value falls through to neutral.
  const map: Record<string, string> = {
    // needs attention
    open: 'text-red-400 bg-red-950 border-red-800',
    detected: 'text-red-400 bg-red-950 border-red-800',
    non_compliant: 'text-red-400 bg-red-950 border-red-800',
    overdue: 'text-red-400 bg-red-950 border-red-800',
    // being worked
    acknowledged: 'text-amber-400 bg-amber-950 border-amber-800',
    investigating: 'text-amber-400 bg-amber-950 border-amber-800',
    in_progress: 'text-amber-400 bg-amber-950 border-amber-800',
    pending: 'text-amber-400 bg-amber-950 border-amber-800',
    partial: 'text-amber-400 bg-amber-950 border-amber-800',
    // held
    contained: 'text-blue-400 bg-blue-950 border-blue-800',
    eradicated: 'text-blue-400 bg-blue-950 border-blue-800',
    // done
    resolved: 'text-emerald-400 bg-emerald-950 border-emerald-800',
    recovered: 'text-emerald-400 bg-emerald-950 border-emerald-800',
    compliant: 'text-emerald-400 bg-emerald-950 border-emerald-800',
    enrolled: 'text-emerald-400 bg-emerald-950 border-emerald-800',
    active: 'text-emerald-400 bg-emerald-950 border-emerald-800',
    // closed out, no longer actionable
    closed: 'text-slate-400 bg-slate-800 border-slate-700',
    suppressed: 'text-slate-400 bg-slate-800 border-slate-700',
    accepted: 'text-slate-400 bg-slate-800 border-slate-700',
    not_applicable: 'text-slate-400 bg-slate-800 border-slate-700',
    false_positive: 'text-slate-400 bg-slate-800 border-slate-700',
  }
  return map[status?.toLowerCase()] ?? 'text-slate-400 bg-slate-800 border-slate-700'
}

export function truncate(str: string, n: number): string {
  return str.length > n ? str.slice(0, n) + '…' : str
}

/** Read one bucket out of a `map[string]int` breakdown.
 *
 *  The lookup is case-insensitive on purpose: the services do not agree on a
 *  casing. The SIEM stores severities as a ClickHouse Enum8 of 'LOW'..'CRITICAL'
 *  and keys its buckets in upper case, while Postgres-backed domains key theirs
 *  in lower case. A caller asking for 'critical' means the critical bucket
 *  whichever service answered.
 *
 *  A bucket with no rows is simply absent from the map, so a missing key is
 *  zero — not missing data. */
export function countOf(breakdown: Record<string, number> | undefined | null, key: string): number {
  if (!breakdown) return 0
  const direct = breakdown[key]
  if (direct !== undefined) return direct
  const wanted = key.toLowerCase()
  for (const [k, v] of Object.entries(breakdown)) {
    if (k.toLowerCase() === wanted) return v
  }
  return 0
}

/** Sum the buckets named, e.g. critical + high. */
export function sumOf(breakdown: Record<string, number> | undefined | null, ...keys: string[]): number {
  return keys.reduce((n, k) => n + countOf(breakdown, k), 0)
}

/** Turn a breakdown into chart rows, largest bucket first.
 *  `name` is the key as the service sent it; `key` is it folded to lower case,
 *  which is what a colour table is indexed by. */
export function breakdownRows(
  breakdown: Record<string, number> | undefined | null,
): { name: string; key: string; value: number }[] {
  if (!breakdown) return []
  return Object.entries(breakdown)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, key: name.toLowerCase(), value }))
    .sort((a, b) => b.value - a.value)
}

/** Asset criticality is an integer 1–4 in the asset service, not a word. */
export function criticalityLabel(level: number): string {
  return ({ 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' } as Record<number, string>)[level] ?? 'unknown'
}

/** Format a timestamp that the API may omit (a nullable column). */
export function formatDateOpt(date?: string | null): string {
  return date ? formatDate(date) : '—'
}

export function formatDateShortOpt(date?: string | null): string {
  return date ? formatDateShort(date) : '—'
}

/** Compact currency for FAIR loss figures, which run to millions. */
export function formatMoney(amount: number): string {
  return new Intl.NumberFormat('default', {
    style: 'currency', currency: 'EUR',
    notation: 'compact', maximumFractionDigits: 1,
  }).format(amount)
}

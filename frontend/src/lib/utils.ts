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
  const map: Record<string, string> = {
    open: 'text-red-400 bg-red-950 border-red-800',
    detected: 'text-red-400 bg-red-950 border-red-800',
    investigating: 'text-amber-400 bg-amber-950 border-amber-800',
    contained: 'text-blue-400 bg-blue-950 border-blue-800',
    resolved: 'text-emerald-400 bg-emerald-950 border-emerald-800',
    closed: 'text-slate-400 bg-slate-800 border-slate-700',
    enrolled: 'text-emerald-400 bg-emerald-950 border-emerald-800',
    pending: 'text-amber-400 bg-amber-950 border-amber-800',
    false_positive: 'text-slate-400 bg-slate-800 border-slate-700',
  }
  return map[status?.toLowerCase()] ?? 'text-slate-400 bg-slate-800 border-slate-700'
}

export function truncate(str: string, n: number): string {
  return str.length > n ? str.slice(0, n) + '…' : str
}

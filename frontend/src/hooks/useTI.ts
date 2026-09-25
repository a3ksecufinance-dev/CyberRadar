'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { IOC, TIStats } from '@/types'

export function useIOCs(params?: Record<string, string>) {
  return useApiList<IOC>('ti', ROUTES.ti.iocs, params, { refreshInterval: 60_000 })
}

export function useTIStats() {
  return useApiGet<TIStats>('ti', ROUTES.ti.stats, undefined, { refreshInterval: 60_000 })
}

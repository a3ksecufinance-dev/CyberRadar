'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { Incident, IRStats } from '@/types'

export function useIncidents(params?: Record<string, string>) {
  return useApiList<Incident>('ir', ROUTES.ir.incidents, params, {
    refreshInterval: 30_000,
  })
}

export function useIRStats() {
  return useApiGet<IRStats>('ir', ROUTES.ir.stats, undefined, {
    refreshInterval: 30_000,
  })
}

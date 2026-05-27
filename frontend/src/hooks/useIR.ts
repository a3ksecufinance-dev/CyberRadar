'use client'
import { useApiGet, useApiList } from './useApi'
import type { Incident, IRStats } from '@/types'

export function useIncidents(params?: Record<string, string>) {
  return useApiList<Incident>('ir', '/api/v1/incidents', params, {
    refreshInterval: 30_000,
  })
}

export function useIRStats() {
  return useApiGet<IRStats>('ir', '/api/v1/stats', undefined, {
    refreshInterval: 30_000,
  })
}

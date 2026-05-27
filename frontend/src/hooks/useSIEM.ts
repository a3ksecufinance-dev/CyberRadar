'use client'
import { useApiGet, useApiList } from './useApi'
import type { SIEMAlert, SIEMStats } from '@/types'

export function useSIEMAlerts(params?: Record<string, string>) {
  return useApiList<SIEMAlert>('siem', '/api/v1/siem/alerts', params, {
    refreshInterval: 15_000, // live feed — refresh every 15s
  })
}

export function useSIEMStats() {
  return useApiGet<SIEMStats>('siem', '/api/v1/siem/alerts/stats', undefined, {
    refreshInterval: 30_000,
  })
}

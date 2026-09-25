'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { SIEMAlert, SIEMStats } from '@/types'

export function useSIEMAlerts(params?: Record<string, string>) {
  return useApiList<SIEMAlert>('siem', ROUTES.siem.alerts, params, {
    refreshInterval: 15_000, // live feed
  })
}

export function useSIEMStats() {
  return useApiGet<SIEMStats>('siem', ROUTES.siem.alertStats, undefined, {
    refreshInterval: 30_000,
  })
}

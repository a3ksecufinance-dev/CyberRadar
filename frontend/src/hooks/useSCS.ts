'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { SCSAlert, SCSComponent, SCSStats, SCSVendor } from '@/types'

export function useVendors(params?: Record<string, string>) {
  return useApiList<SCSVendor>('scs', ROUTES.scs.vendors, params)
}

export function useComponents(params?: Record<string, string>) {
  return useApiList<SCSComponent>('scs', ROUTES.scs.components, params)
}

export function useSCSAlerts(params?: Record<string, string>) {
  return useApiList<SCSAlert>('scs', ROUTES.scs.alerts, params, { refreshInterval: 60_000 })
}

export function useSCSStats() {
  return useApiGet<SCSStats>('scs', ROUTES.scs.stats, undefined, { refreshInterval: 60_000 })
}

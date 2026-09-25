'use client'
import { useApiGet } from './useApi'
import { ROUTES } from '@/lib/api'
import type { PlatformOverview, KPIPoint } from '@/types'

export function useDashboardOverview() {
  return useApiGet<PlatformOverview>('dashboard', ROUTES.dashboard.overview, undefined, {
    refreshInterval: 60_000,
  })
}

export function useKPITimeseries(domain: string, metricKey: string, interval = '1h') {
  return useApiGet<KPIPoint[]>(
    'dashboard',
    ROUTES.dashboard.kpiTimeseries,
    { domain, metric_key: metricKey, interval },
    { refreshInterval: 300_000 },
  )
}

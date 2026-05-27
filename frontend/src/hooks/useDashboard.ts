'use client'
import { useApiGet } from './useApi'
import type { PlatformOverview, KPIPoint } from '@/types'

export function useDashboardOverview() {
  return useApiGet<PlatformOverview>('dashboard', '/api/v1/dashboard/overview', undefined, {
    refreshInterval: 60_000,
  })
}

export function useKPITimeseries(domain: string, metricKey: string, interval = '1h') {
  return useApiGet<KPIPoint[]>(
    'dashboard',
    `/api/v1/dashboard/kpi/timeseries?domain=${domain}&metric_key=${metricKey}&interval=${interval}`,
    undefined,
    { refreshInterval: 300_000 },
  )
}

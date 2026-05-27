'use client'
import { useApiGet, useApiList } from './useApi'
import type { IOC, TIStats } from '@/types'

export function useIOCs(params?: Record<string, string>) {
  return useApiList<IOC>('ti', '/api/v1/ti/iocs', params, {
    refreshInterval: 60_000,
  })
}

export function useTIStats() {
  return useApiGet<TIStats>('ti', '/api/v1/ti/stats', undefined, {
    refreshInterval: 60_000,
  })
}

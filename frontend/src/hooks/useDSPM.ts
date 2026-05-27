'use client'
import { useApiGet, useApiList } from './useApi'
import type { DSPMDataStore, DSPMFinding, DSPMStats } from '@/types'

export function useDataStores(params?: Record<string, string>) {
  return useApiList<DSPMDataStore>('dspm', '/api/v1/dspm/data-stores', params)
}

export function useDSPMFindings(params?: Record<string, string>) {
  return useApiList<DSPMFinding>('dspm', '/api/v1/dspm/findings', params)
}

export function useDSPMStats() {
  return useApiGet<DSPMStats>('dspm', '/api/v1/dspm/stats')
}

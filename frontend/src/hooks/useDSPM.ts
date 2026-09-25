'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { DSPMDataStore, DSPMFinding, DSPMStats } from '@/types'

export function useDataStores(params?: Record<string, string>) {
  return useApiList<DSPMDataStore>('dspm', ROUTES.dspm.stores, params)
}

export function useDSPMFindings(params?: Record<string, string>) {
  return useApiList<DSPMFinding>('dspm', ROUTES.dspm.findings, params)
}

export function useDSPMStats() {
  return useApiGet<DSPMStats>('dspm', ROUTES.dspm.stats)
}

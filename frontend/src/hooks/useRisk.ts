'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { RiskAsset, RiskKRI, RiskScenario, RiskStats } from '@/types'

export function useRiskScenarios(params?: Record<string, string>) {
  return useApiList<RiskScenario>('risk', ROUTES.risk.scenarios, params)
}

export function useRiskAssets(params?: Record<string, string>) {
  return useApiList<RiskAsset>('risk', ROUTES.risk.assets, params)
}

export function useKRIs(params?: Record<string, string>) {
  return useApiList<RiskKRI>('risk', ROUTES.risk.kris, params, { refreshInterval: 60_000 })
}

export function useRiskStats() {
  return useApiGet<RiskStats>('risk', ROUTES.risk.stats, undefined, { refreshInterval: 60_000 })
}

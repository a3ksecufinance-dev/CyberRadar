'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { ComplianceStats, ComplianceRisk, Control, Framework } from '@/types'

export function useFrameworks(params?: Record<string, string>) {
  return useApiList<Framework>('compliance', ROUTES.compliance.frameworks, params)
}

export function useControls(params?: Record<string, string>) {
  return useApiList<Control>('compliance', ROUTES.compliance.controls, params)
}

export function useComplianceRisks(params?: Record<string, string>) {
  return useApiList<ComplianceRisk>('compliance', ROUTES.compliance.risks, params)
}

/** Per-framework scores, computed by the service from its assessments. */
export function useComplianceStats() {
  return useApiGet<ComplianceStats>('compliance', ROUTES.compliance.stats, undefined, {
    refreshInterval: 120_000,
  })
}

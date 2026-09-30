'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { ActiveRiskProfile, RiskProfile } from '@/types'

// The standard profiles the platform ships. They are the starting point a
// customer adjusts from, and the thing their own profile is measured against.
export function useRiskPresets() {
  return useApiList<RiskProfile>('tenant', ROUTES.tenant.riskPresets)
}

// The profile scores are actually produced under, and whether the tenant chose
// it or is running on our values.
export function useActiveRiskProfile() {
  return useApiGet<ActiveRiskProfile>('tenant', ROUTES.tenant.riskActive)
}

// Every version this tenant has had, newest first. This is the audit answer to
// "what was the formula that day".
export function useRiskProfileHistory() {
  return useApiList<RiskProfile>('tenant', ROUTES.tenant.riskHistory)
}

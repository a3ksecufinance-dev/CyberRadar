'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type {
  ActiveBehaviourPolicy,
  ActiveRemediationPolicy,
  ActiveRiskProfile,
  BehaviourPolicy,
  RemediationPolicy,
  RiskProfile,
} from '@/types'

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

// ─── Remediation deadlines ───────────────────────────────────────────────────
export function useRemediationPresets() {
  return useApiList<RemediationPolicy>('tenant', ROUTES.tenant.remediationPresets)
}
export function useActiveRemediationPolicy() {
  return useApiGet<ActiveRemediationPolicy>('tenant', ROUTES.tenant.remediationActive)
}
export function useRemediationHistory() {
  return useApiList<RemediationPolicy>('tenant', ROUTES.tenant.remediationHistory)
}

// ─── Behavioural thresholds ──────────────────────────────────────────────────
export function useBehaviourPresets() {
  return useApiList<BehaviourPolicy>('tenant', ROUTES.tenant.behaviourPresets)
}
export function useActiveBehaviourPolicy() {
  return useApiGet<ActiveBehaviourPolicy>('tenant', ROUTES.tenant.behaviourActive)
}
export function useBehaviourHistory() {
  return useApiList<BehaviourPolicy>('tenant', ROUTES.tenant.behaviourHistory)
}

'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { AttackPath, AttackScenario, AttackGraphStats, ChokePoint } from '@/types'

export function useAttackScenarios(params?: Record<string, string>) {
  return useApiList<AttackScenario>('attackpath', ROUTES.attackpath.scenarios, params)
}

/** Paths with their hops hydrated — /attack/paths returns id sequences only,
 *  which cannot be rendered as a chain of labels. */
export function useAttackPaths(params?: Record<string, string>) {
  return useApiList<AttackPath>('attackpath', ROUTES.attackpath.pathsGraph, params, {
    refreshInterval: 60_000,
  })
}

export function useChokePoints(params?: Record<string, string>) {
  return useApiList<ChokePoint>('attackpath', ROUTES.attackpath.chokePoints, params)
}

export function useAttackStats() {
  return useApiGet<AttackGraphStats>('attackpath', ROUTES.attackpath.stats, undefined, {
    refreshInterval: 60_000,
  })
}

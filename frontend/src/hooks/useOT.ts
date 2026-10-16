'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { OTAsset, OTEvent, OTStats } from '@/types'

export function useOTAssets(params?: Record<string, string>) {
  return useApiList<OTAsset>('ot', ROUTES.ot.assets, params)
}

export function useOTEvents(params?: Record<string, string>) {
  return useApiList<OTEvent>('ot', ROUTES.ot.events, params, { refreshInterval: 30_000 })
}

export function useOTStats() {
  return useApiGet<OTStats>('ot', ROUTES.ot.stats)
}

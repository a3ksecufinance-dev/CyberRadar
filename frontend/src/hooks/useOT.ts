'use client'
import { useApiGet, useApiList } from './useApi'
import type { OTAsset, OTEvent, OTStats } from '@/types'

export function useOTAssets(params?: Record<string, string>) {
  return useApiList<OTAsset>('ot', '/api/v1/ot/assets', params)
}

export function useOTEvents(params?: Record<string, string>) {
  return useApiList<OTEvent>('ot', '/api/v1/ot/events', params, {
    refreshInterval: 30_000,
  })
}

export function useOTStats() {
  return useApiGet<OTStats>('ot', '/api/v1/ot/stats')
}

'use client'
import { useApiGet, useApiList } from './useApi'
import type { Asset, AssetStats } from '@/types'

export function useAssets(params?: Record<string, string>) {
  return useApiList<Asset>('asset', '/api/v1/assets', params)
}

export function useAssetStats() {
  return useApiGet<AssetStats>('asset', '/api/v1/assets/stats')
}

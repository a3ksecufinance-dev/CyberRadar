'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { Asset, AssetStats } from '@/types'

export function useAssets(params?: Record<string, string>) {
  return useApiList<Asset>('asset', ROUTES.asset.list, params)
}

export function useAssetStats() {
  return useApiGet<AssetStats>('asset', ROUTES.asset.stats)
}

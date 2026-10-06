'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { MobDevice, MobileStats } from '@/types'

export function useDevices(params?: Record<string, string>) {
  return useApiList<MobDevice>('mobile', ROUTES.mobile.devices, params)
}

export function useMobileStats() {
  return useApiGet<MobileStats>('mobile', ROUTES.mobile.stats)
}

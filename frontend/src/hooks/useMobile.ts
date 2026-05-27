'use client'
import { useApiGet, useApiList } from './useApi'
import type { MobDevice, MobileStats } from '@/types'

export function useDevices(params?: Record<string, string>) {
  return useApiList<MobDevice>('mobile', '/api/v1/mobile/devices', params)
}

export function useMobileStats() {
  return useApiGet<MobileStats>('mobile', '/api/v1/mobile/devices/stats')
}

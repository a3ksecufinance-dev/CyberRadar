'use client'
import { useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { Identity } from '@/types'

export function useUsers(params?: Record<string, string>) {
  return useApiList<Identity>('identity', ROUTES.identity.users, params)
}

export function usePrivilegedIdentities(params?: Record<string, string>) {
  return useApiList<Identity>('identity', ROUTES.identity.privileged, params)
}

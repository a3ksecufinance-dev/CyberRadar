'use client'
// useApi.ts — base hook that provides the SWR fetcher with automatic auth token injection.
// All domain hooks build on top of this.

import { useSession } from 'next-auth/react'
import useSWR, { type SWRConfiguration } from 'swr'
import { apiKey, swrFetcher, swrListFetcher } from '@/lib/api'
import type { PageMeta } from '@/types'

// ─── useApiGet — single resource ────────────────────────────
export function useApiGet<T>(
  service: string,
  path: string,
  params?: Record<string, string>,
  config?: SWRConfiguration,
) {
  const { data: session } = useSession()
  const token = session?.accessToken
  const key = apiKey(service, path, params)

  return useSWR<T>(key, swrFetcher<T>(token), {
    ...config,
  })
}

// ─── useApiList — paginated list ─────────────────────────────
export function useApiList<T>(
  service: string,
  path: string,
  params?: Record<string, string>,
  config?: SWRConfiguration,
) {
  const { data: session } = useSession()
  const token = session?.accessToken
  const key = apiKey(service, path, params)

  return useSWR<{ items: T[]; meta: PageMeta }>(key, swrListFetcher<T>(token), {
    ...config,
  })
}

// ─── useApiPost — mutations (no SWR cache) ───────────────────
// Returns the token for use in imperative API calls (form submits, etc.)
export function useApiToken() {
  const { data: session } = useSession()
  return session?.accessToken
}

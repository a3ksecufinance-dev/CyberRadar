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
  // Null until there is a token: SWR treats a null key as "do not fetch".
  // Without it the first render fires before the session resolves, the request
  // goes out with no Authorization header, the service answers 401 — and SWR
  // caches that failure under a key that does not change when the token
  // arrives, so the panel reads "Missing Authorization header" for the rest of
  // the session while the very same call from a console returns 200.
  const key = token ? apiKey(service, path, params) : null

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
  // See useApiGet: no key, and so no request, until the session has a token.
  const key = token ? apiKey(service, path, params) : null

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

'use client'
// Providers.tsx — wraps client-side providers: SessionProvider + SWRConfig
// Mounted at the platform layout level so all pages have access to session + SWR cache.

import { SessionProvider } from 'next-auth/react'
import { SWRConfig } from 'swr'

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <SessionProvider>
      <SWRConfig
        value={{
          // Global SWR config: revalidate on focus + reconnect, 60s dedup interval
          revalidateOnFocus: true,
          revalidateOnReconnect: true,
          dedupingInterval: 60_000,
          // Error retry: stop after 3 attempts for API errors
          onErrorRetry: (error, _key, _config, revalidate, { retryCount }) => {
            if (error?.status === 401 || error?.status === 403 || error?.status === 404) return
            if (retryCount >= 3) return
            setTimeout(() => revalidate({ retryCount }), 5000)
          },
        }}
      >
        {children}
      </SWRConfig>
    </SessionProvider>
  )
}

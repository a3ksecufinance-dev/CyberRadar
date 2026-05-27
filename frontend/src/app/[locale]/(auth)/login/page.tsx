import { getTranslations } from 'next-intl/server'
import { Shield, Lock } from 'lucide-react'
import { signIn } from '@/lib/auth'

export default async function LoginPage({
  params,
  searchParams,
}: {
  params: { locale: string }
  searchParams: { callbackUrl?: string; error?: string }
}) {
  const t = await getTranslations('auth')
  const callbackUrl = searchParams.callbackUrl ?? `/${params.locale}/dashboard`

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950">
      {/* Background grid pattern */}
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(6,182,212,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.03)_1px,transparent_1px)] bg-[size:64px_64px]" />

      <div className="relative w-full max-w-sm px-4">
        {/* Glow */}
        <div className="absolute -inset-4 rounded-2xl bg-gradient-to-r from-cyan-600/20 to-blue-600/20 blur-2xl" />

        <div className="relative rounded-xl border border-slate-700 bg-slate-900 p-8 shadow-2xl">
          {/* Logo */}
          <div className="mb-8 flex flex-col items-center gap-3">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg">
              <Shield className="h-9 w-9 text-white" />
            </div>
            <div className="text-center">
              <h1 className="text-xl font-bold text-slate-100">{t('welcome')}</h1>
              <p className="mt-0.5 text-sm text-slate-400">{t('subtitle')}</p>
            </div>
          </div>

          {/* Error banner */}
          {searchParams.error && (
            <div className="mb-4 rounded-md border border-red-800 bg-red-950/50 px-3 py-2 text-xs text-red-400">
              Authentication error: {searchParams.error}. Please try again.
            </div>
          )}

          {/* SSO Sign-in — NextAuth v5 server action */}
          <form
            action={async () => {
              'use server'
              await signIn('keycloak', { redirectTo: callbackUrl })
            }}
          >
            <button
              type="submit"
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2 focus:ring-offset-slate-900"
            >
              <Lock className="h-4 w-4" />
              {t('loginWithSSO')}
            </button>
          </form>

          <p className="mt-4 text-center text-xs text-slate-500">{t('loginDescription')}</p>

          <div className="mt-6 flex items-center justify-center gap-1.5 text-xs text-slate-600">
            <Shield className="h-3 w-3" />
            <span>{t('securedBy')} Keycloak OIDC</span>
          </div>
        </div>

        <p className="mt-4 text-center text-[10px] text-slate-700">
          CyberRadar Platform · Sovereign Security · DORA Ready
        </p>
      </div>
    </div>
  )
}

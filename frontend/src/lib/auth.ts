import NextAuth, { type DefaultSession } from 'next-auth'
import Keycloak from 'next-auth/providers/keycloak'

// ─── Type augmentation ──────────────────────────────────────
declare module 'next-auth' {
  interface Session {
    accessToken: string
    idToken: string
    roles: string[]
    error?: 'RefreshAccessTokenError'
    user: {
      id: string
      roles: string[]
    } & DefaultSession['user']
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    accessToken: string
    idToken: string
    refreshToken: string
    expiresAt: number
    roles: string[]
    error?: 'RefreshAccessTokenError'
  }
}

// ─── Token refresh helper ───────────────────────────────────
async function refreshAccessToken(token: any) {
  try {
    const url = `${process.env.KEYCLOAK_ISSUER}/protocol/openid-connect/token`
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.KEYCLOAK_CLIENT_ID!,
        client_secret: process.env.KEYCLOAK_CLIENT_SECRET!,
        grant_type: 'refresh_token',
        refresh_token: token.refreshToken,
      }),
    })

    const refreshed = await response.json()
    if (!response.ok) throw refreshed

    return {
      ...token,
      accessToken: refreshed.access_token,
      idToken: refreshed.id_token ?? token.idToken,
      refreshToken: refreshed.refresh_token ?? token.refreshToken,
      expiresAt: Math.floor(Date.now() / 1000) + refreshed.expires_in,
      error: undefined,
    }
  } catch {
    return { ...token, error: 'RefreshAccessTokenError' as const }
  }
}

// ─── NextAuth configuration ─────────────────────────────────
export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [
    Keycloak({
      clientId: process.env.KEYCLOAK_CLIENT_ID!,
      clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!,
      issuer: process.env.KEYCLOAK_ISSUER!,
    }),
  ],

  callbacks: {
    async jwt({ token, account, profile }) {
      // Initial sign-in — store tokens and extract roles from Keycloak profile
      if (account && profile) {
        const keycloakProfile = profile as any
        return {
          ...token,
          accessToken: account.access_token!,
          idToken: account.id_token!,
          refreshToken: account.refresh_token!,
          expiresAt: account.expires_at!,
          roles: keycloakProfile.roles ?? [],
        }
      }

      // Token still valid (with 30s buffer)
      if (Date.now() < token.expiresAt * 1000 - 30_000) {
        return token
      }

      // Token expired — attempt refresh
      return refreshAccessToken(token)
    },

    async session({ session, token }) {
      session.accessToken = token.accessToken
      session.idToken = token.idToken
      session.roles = token.roles ?? []
      session.error = token.error
      if (session.user) {
        session.user.roles = token.roles ?? []
      }
      return session
    },
  },

  events: {
    // Propagate logout to Keycloak (end_session_endpoint)
    async signOut(message) {
      if ('token' in message && message.token?.idToken) {
        const issuer = process.env.KEYCLOAK_ISSUER!
        const logoutUrl = `${issuer}/protocol/openid-connect/logout`
        const redirectUri = encodeURIComponent(process.env.NEXTAUTH_URL!)
        await fetch(`${logoutUrl}?id_token_hint=${message.token.idToken}&post_logout_redirect_uri=${redirectUri}`, {
          method: 'GET',
        }).catch(() => {})
      }
    },
  },

  pages: {
    signIn: '/login',
    error: '/login',
  },

  session: { strategy: 'jwt' },
})

// ─── Role constants ─────────────────────────────────────────
export const ROLES = {
  CISO: 'ciso',
  SOC_L1: 'soc_analyst_l1',
  SOC_L2: 'soc_analyst_l2',
  SOC_L3: 'soc_analyst_l3',
  DPO: 'dpo',
  RISK_MANAGER: 'risk_manager',
  AUDITOR: 'auditor',
  IT_ADMIN: 'it_admin',
  PLATFORM_ADMIN: 'platform_admin',
} as const

export type Role = (typeof ROLES)[keyof typeof ROLES]

export function hasRole(roles: string[], ...required: Role[]): boolean {
  return required.some((r) => roles.includes(r))
}

export function canAccessSIEM(roles: string[]): boolean {
  return hasRole(roles, ROLES.CISO, ROLES.SOC_L1, ROLES.SOC_L2, ROLES.SOC_L3, ROLES.PLATFORM_ADMIN)
}

export function canManageIncidents(roles: string[]): boolean {
  return hasRole(roles, ROLES.CISO, ROLES.SOC_L2, ROLES.SOC_L3, ROLES.PLATFORM_ADMIN)
}

export function canAccessDSPM(roles: string[]): boolean {
  return hasRole(roles, ROLES.CISO, ROLES.DPO, ROLES.PLATFORM_ADMIN)
}

export function canAccessRisk(roles: string[]): boolean {
  return hasRole(roles, ROLES.CISO, ROLES.RISK_MANAGER, ROLES.AUDITOR, ROLES.PLATFORM_ADMIN)
}

export function isAdmin(roles: string[]): boolean {
  return hasRole(roles, ROLES.PLATFORM_ADMIN)
}

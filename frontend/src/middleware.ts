import { NextResponse } from 'next/server'
import createMiddleware from 'next-intl/middleware'
import { auth } from './lib/auth'
import { routing } from './i18n/routing'

const intlMiddleware = createMiddleware(routing)

const publicPaths = ['/login', '/api/auth']

function isPublicPath(pathname: string): boolean {
  return publicPaths.some((p) => pathname.includes(p))
}

export default auth((request) => {
  const { pathname } = request.nextUrl

  // API routes and Next internals must bypass next-intl: it would prefix them
  // with a locale, turning /api/auth/* into /en/api/auth/* and breaking every
  // NextAuth endpoint.
  if (pathname.startsWith('/api') || pathname.startsWith('/_next') || pathname.startsWith('/favicon')) {
    return NextResponse.next()
  }

  // Let next-intl handle locale routing first
  const response = intlMiddleware(request)

  // Skip auth check for public paths
  if (isPublicPath(pathname)) {
    return response
  }

  // auth() decrypts and verifies the session token, so an expired, tampered or
  // unrefreshable session yields no usable session here. A cookie-presence
  // check could not distinguish any of those from a valid login.
  const session = request.auth
  if (!session || session.error === 'RefreshAccessTokenError') {
    // Detect locale from pathname (/en/... or /fr/...)
    const locale = pathname.startsWith('/fr') ? 'fr' : 'en'
    const loginUrl = new URL(`/${locale}/login`, request.url)
    loginUrl.searchParams.set('callbackUrl', request.url)
    return NextResponse.redirect(loginUrl)
  }

  return response
})

export const config = {
  // Match all paths except static assets and Next.js internals
  matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)'],
}

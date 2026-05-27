import { NextRequest, NextResponse } from 'next/server'
import createMiddleware from 'next-intl/middleware'
import { routing } from './src/i18n/routing'

const intlMiddleware = createMiddleware(routing)

const publicPaths = ['/login', '/api/auth']

function isPublicPath(pathname: string): boolean {
  return publicPaths.some((p) => pathname.includes(p))
}

export default async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Let next-intl handle locale routing first
  const response = intlMiddleware(request)

  // Skip auth check for public paths and static assets
  if (isPublicPath(pathname) || pathname.startsWith('/_next') || pathname.startsWith('/favicon')) {
    return response
  }

  // Check for session cookie (NextAuth sets next-auth.session-token in prod,
  // __Secure-next-auth.session-token in HTTPS, and next-auth.session-token in HTTP dev)
  const sessionCookie =
    request.cookies.get('next-auth.session-token') ??
    request.cookies.get('__Secure-next-auth.session-token')

  if (!sessionCookie) {
    // Detect locale from pathname (/en/... or /fr/...)
    const locale = pathname.startsWith('/fr') ? 'fr' : 'en'
    const loginUrl = new URL(`/${locale}/login`, request.url)
    loginUrl.searchParams.set('callbackUrl', request.url)
    return NextResponse.redirect(loginUrl)
  }

  return response
}

export const config = {
  // Match all paths except static assets and Next.js internals
  matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)'],
}

import createNextIntlPlugin from 'next-intl/plugin'

const withNextIntl = createNextIntlPlugin('./src/i18n/request.ts')

/** @type {import('next').NextConfig} */
const nextConfig = {
  // output: 'standalone' is not set.
  //
  // It was, and nothing consumed it: there is no Dockerfile for the interface,
  // while `next start` — what the local runner and every developer use — is
  // explicitly unsupported with it. Next says so on startup, and the symptom
  // is worse than the warning: the served HTML asks for chunk hashes that are
  // not the ones in .next/static, so every page loads, renders its frame, and
  // then dies on ChunkLoadError with nothing in it. The end-to-end tests found
  // it; clicking around a warm build did not, because a stale .next happened
  // to agree with itself.
  //
  // Restore it when an image is built for this interface, and then serve
  // `node .next/standalone/server.js` with .next/static and public copied in
  // beside it — not `next start`.
  images: { unoptimized: true },
  async rewrites() {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8001'
    return [
      { source: '/api/v1/:path*', destination: `${apiUrl}/api/v1/:path*` },
    ]
  },
}

export default withNextIntl(nextConfig)

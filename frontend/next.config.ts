import createNextIntlPlugin from 'next-intl/plugin'
import type { NextConfig } from 'next'

const withNextIntl = createNextIntlPlugin('./src/i18n/request.ts')

const nextConfig: NextConfig = {
  output: 'standalone',
  images: { unoptimized: true },
  async rewrites() {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8001'
    return [
      { source: '/api/v1/:path*', destination: `${apiUrl}/api/v1/:path*` },
    ]
  },
}

export default withNextIntl(nextConfig)

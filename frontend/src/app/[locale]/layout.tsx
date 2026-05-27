import { NextIntlClientProvider } from 'next-intl'
import { getMessages } from 'next-intl/server'
import { notFound } from 'next/navigation'
import { routing } from '@/i18n/routing'
import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'CyberRadar — Sovereign Cybersecurity Platform',
  description: 'Next-gen cybersecurity platform for financial institutions. 26 security domains.',
}

export default async function LocaleLayout({
  children,
  params: { locale },
}: {
  children: React.ReactNode
  params: { locale: string }
}) {
  if (!routing.locales.includes(locale as 'en' | 'fr')) notFound()
  const messages = await getMessages()

  return (
    <html lang={locale} className="dark">
      <body className="bg-slate-950 text-slate-100 antialiased">
        <NextIntlClientProvider messages={messages}>
          {children}
        </NextIntlClientProvider>
      </body>
    </html>
  )
}

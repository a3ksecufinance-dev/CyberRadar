import { Sidebar } from '@/components/layout/Sidebar'
import { Header } from '@/components/layout/Header'
import { Providers } from '@/components/providers/Providers'

export default function PlatformLayout({
  children,
  params: { locale },
}: {
  children: React.ReactNode
  params: { locale: string }
}) {
  return (
    <Providers>
      <div className="flex h-screen overflow-hidden">
        <Sidebar locale={locale} />
        <div className="flex flex-1 flex-col overflow-hidden">
          <Header locale={locale} />
          <main className="flex-1 overflow-y-auto bg-slate-950 p-6">
            {children}
          </main>
        </div>
      </div>
    </Providers>
  )
}

'use client'
import { useRouter, usePathname } from 'next/navigation'

export function LanguageSwitcher({ locale }: { locale: string }) {
  const router = useRouter()
  const pathname = usePathname()

  const switchLocale = (next: string) => {
    // Replace /en/... or /fr/... at the start
    const newPath = pathname.replace(/^\/(en|fr)/, `/${next}`)
    router.push(newPath)
  }

  return (
    <div className="flex items-center gap-0.5 rounded-md border border-slate-700 bg-slate-900 p-0.5">
      {(['en', 'fr'] as const).map((l) => (
        <button
          key={l}
          onClick={() => switchLocale(l)}
          className={`rounded px-2 py-0.5 text-xs font-semibold transition-colors ${
            locale === l
              ? 'bg-cyan-600 text-white'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          {l.toUpperCase()}
        </button>
      ))}
    </div>
  )
}

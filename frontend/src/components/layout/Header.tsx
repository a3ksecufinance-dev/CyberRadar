'use client'
import { Search, Bell } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { LanguageSwitcher } from './LanguageSwitcher'

export function Header({ locale }: { locale: string }) {
  return (
    <header className="flex h-14 flex-shrink-0 items-center justify-between border-b border-slate-700/60 bg-slate-900 px-6">
      {/* Search */}
      <div className="relative w-72">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
        <Input className="pl-8 text-xs" placeholder="Search across all domains..." />
      </div>

      {/* Right controls */}
      <div className="flex items-center gap-3">
        {/* Notifications */}
        <button className="relative rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors">
          <Bell className="h-4 w-4" />
          <span className="absolute right-1 top-1 h-1.5 w-1.5 rounded-full bg-red-500" />
        </button>

        {/* Language */}
        <LanguageSwitcher locale={locale} />

        {/* User */}
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 text-xs font-bold text-white">
            AD
          </div>
          <div className="hidden md:block">
            <div className="text-xs font-medium text-slate-200">Admin</div>
            <div className="text-[10px] text-slate-500">SOC Manager</div>
          </div>
        </div>
      </div>
    </header>
  )
}

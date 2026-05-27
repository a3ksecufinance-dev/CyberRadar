'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useTranslations } from 'next-intl'
import { cn } from '@/lib/utils'
import {
  LayoutDashboard, Activity, Siren, Server, Radio, Bug,
  GitBranch, Smartphone, Factory, Database, CheckSquare,
  TrendingUp, Package, Bot, Settings, LogOut, Shield,
} from 'lucide-react'

const groups = [
  {
    key: 'core',
    items: [
      { key: 'dashboard', href: '/dashboard', icon: LayoutDashboard },
      { key: 'copilot',   href: '/copilot',   icon: Bot },
    ],
  },
  {
    key: 'detection',
    items: [
      { key: 'siem',            href: '/siem',           icon: Activity },
      { key: 'incidents',       href: '/ir',             icon: Siren },
      { key: 'threats',         href: '/threats',        icon: Radio },
      { key: 'vulnerabilities', href: '/vulnerabilities',icon: Bug },
      { key: 'attackPath',      href: '/attackpath',     icon: GitBranch },
    ],
  },
  {
    key: 'assets',
    items: [
      { key: 'assets', href: '/assets', icon: Server },
      { key: 'mobile', href: '/mobile', icon: Smartphone },
      { key: 'ot',     href: '/ot',     icon: Factory },
    ],
  },
  {
    key: 'data',
    items: [
      { key: 'dspm',        href: '/dspm', icon: Database },
      { key: 'supplyChain', href: '/scs',  icon: Package },
    ],
  },
  {
    key: 'governance',
    items: [
      { key: 'compliance', href: '/compliance', icon: CheckSquare },
      { key: 'risk',       href: '/risk',       icon: TrendingUp },
    ],
  },
]

export function Sidebar({ locale }: { locale: string }) {
  const pathname = usePathname()
  const t = useTranslations('nav')

  return (
    <aside className="flex h-screen w-56 flex-shrink-0 flex-col border-r border-slate-700/60 bg-slate-900">
      {/* Logo */}
      <div className="flex h-14 items-center gap-2.5 border-b border-slate-700/60 px-4">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg">
          <Shield className="h-4 w-4 text-white" />
        </div>
        <div>
          <span className="text-sm font-bold text-slate-100">CyberRadar</span>
          <div className="text-[9px] font-medium uppercase tracking-widest text-cyan-500">Platform</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-2">
        {groups.map((group) => (
          <div key={group.key} className="mb-3">
            <p className="px-4 pb-1 pt-2 text-[9px] font-bold uppercase tracking-widest text-slate-600">
              {t(`groups.${group.key}`)}
            </p>
            {group.items.map((item) => {
              const href = `/${locale}${item.href}`
              const active = pathname === href || pathname.startsWith(href + '/')
              return (
                <Link
                  key={item.key}
                  href={href}
                  className={cn(
                    'flex items-center gap-2.5 px-4 py-1.5 text-sm transition-all duration-150',
                    active
                      ? 'border-r-2 border-cyan-400 bg-cyan-950/40 text-cyan-400'
                      : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                  )}
                >
                  <item.icon className="h-4 w-4 flex-shrink-0" />
                  <span className="truncate">{t(item.key)}</span>
                </Link>
              )
            })}
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-slate-700/60 p-2 space-y-0.5">
        <Link
          href={`/${locale}/settings`}
          className="flex items-center gap-2.5 rounded-md px-3 py-1.5 text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-200"
        >
          <Settings className="h-4 w-4" />
          {t('settings')}
        </Link>
        <button className="flex w-full items-center gap-2.5 rounded-md px-3 py-1.5 text-sm text-slate-400 hover:bg-slate-800 hover:text-red-400 transition-colors">
          <LogOut className="h-4 w-4" />
          {t('logout')}
        </button>
      </div>
    </aside>
  )
}

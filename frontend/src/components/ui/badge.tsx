import * as React from 'react'
import { cn } from '@/lib/utils'

type Variant = 'default' | 'critical' | 'high' | 'medium' | 'low' | 'info' | 'outline' | 'success'

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: Variant
}

const variants: Record<Variant, string> = {
  default:  'bg-slate-700 text-slate-200 border-slate-600',
  critical: 'bg-red-950 text-red-400 border-red-800',
  high:     'bg-orange-950 text-orange-400 border-orange-800',
  medium:   'bg-amber-950 text-amber-400 border-amber-800',
  low:      'bg-emerald-950 text-emerald-400 border-emerald-800',
  info:     'bg-blue-950 text-blue-400 border-blue-800',
  success:  'bg-emerald-950 text-emerald-400 border-emerald-800',
  outline:  'bg-transparent text-slate-400 border-slate-600',
}

export function Badge({ className, variant = 'default', ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium',
        variants[variant],
        className
      )}
      {...props}
    />
  )
}

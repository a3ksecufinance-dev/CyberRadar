import * as React from 'react'
import { cn } from '@/lib/utils'

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'ghost' | 'outline' | 'danger'
  size?: 'sm' | 'md' | 'lg'
}

const variants = {
  default: 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm',
  ghost:   'hover:bg-slate-700 text-slate-400 hover:text-slate-200',
  outline: 'border border-slate-600 hover:bg-slate-700 text-slate-300',
  danger:  'bg-red-700 hover:bg-red-600 text-white',
}
const sizes = {
  sm: 'px-2 py-1 text-xs gap-1',
  md: 'px-3 py-1.5 text-sm gap-1.5',
  lg: 'px-4 py-2 text-base gap-2',
}

export function Button({ className, variant = 'default', size = 'md', ...props }: ButtonProps) {
  return (
    <button
      className={cn(
        'inline-flex items-center rounded-md font-medium transition-colors',
        'disabled:opacity-50 disabled:pointer-events-none',
        variants[variant], sizes[size], className
      )}
      {...props}
    />
  )
}

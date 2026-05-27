import * as React from 'react'
import { cn } from '@/lib/utils'

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        'w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-1.5 text-sm text-slate-200',
        'placeholder:text-slate-500',
        'focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/50',
        'disabled:opacity-50',
        className
      )}
      {...props}
    />
  )
)
Input.displayName = 'Input'

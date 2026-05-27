import { cn, statusColors } from '@/lib/utils'

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={cn(
      'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium',
      statusColors(status)
    )}>
      {status?.replace(/_/g, ' ').toUpperCase()}
    </span>
  )
}

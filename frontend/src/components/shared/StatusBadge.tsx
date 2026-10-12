'use client'
import { useTranslations } from 'next-intl'
import { cn, statusColors } from '@/lib/utils'

/** The status a service recorded, shown in the reader's language.
 *
 * The badge used to print the raw column value — `false_positive` became
 * "FALSE POSITIVE" on a screen that was otherwise entirely in French, and the
 * `status` catalogue that existed for exactly this sat unused. Statuses come
 * from thirty services and new ones arrive with new features, so a value the
 * catalogue does not know still renders the way it always did rather than
 * showing a missing-key marker to a customer. */
export function StatusBadge({ status }: { status: string }) {
  const t = useTranslations('status')
  const key = status?.toLowerCase()
  const label = key && t.has(key) ? t(key) : status?.replace(/_/g, ' ')
  return (
    <span className={cn(
      'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium',
      statusColors(status)
    )}>
      {label?.toUpperCase()}
    </span>
  )
}

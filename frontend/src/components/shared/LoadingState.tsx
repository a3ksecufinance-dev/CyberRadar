// LoadingState — skeleton placeholders while data is fetching.
// Variants: 'table' for rows, 'cards' for stat cards, 'page' for full page.

interface Props {
  variant?: 'table' | 'cards' | 'page'
  rows?: number
  cols?: number
}

function Skeleton({ className }: { className?: string }) {
  return <div className={`animate-pulse rounded bg-slate-800 ${className ?? ''}`} />
}

function CardsSkeleton({ cols = 4 }: { cols?: number }) {
  return (
    <div className={`grid grid-cols-${cols} gap-4`}>
      {Array.from({ length: cols }).map((_, i) => (
        <div key={i} className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <Skeleton className="mb-2 h-3 w-20" />
          <Skeleton className="h-7 w-14" />
        </div>
      ))}
    </div>
  )
}

function TableSkeleton({ rows = 8 }: { rows?: number }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900">
      {/* Header */}
      <div className="flex gap-6 border-b border-slate-800 px-4 py-3">
        {[180, 100, 80, 120, 80, 80].map((w, i) => (
          <Skeleton key={i} className={`h-3`} style={{ width: w }} />
        ))}
      </div>
      {/* Rows */}
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-6 border-b border-slate-800/50 px-4 py-3 last:border-0">
          <Skeleton className="h-4 w-44" />
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-5 w-16 rounded-full" />
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-4 w-20" />
        </div>
      ))}
    </div>
  )
}

export function LoadingState({ variant = 'page', rows = 8, cols = 4 }: Props) {
  if (variant === 'cards') return <CardsSkeleton cols={cols} />
  if (variant === 'table') return <TableSkeleton rows={rows} />

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <Skeleton className="mb-2 h-5 w-48" />
        <Skeleton className="h-3 w-72" />
      </div>
      {/* Stat cards */}
      <CardsSkeleton cols={cols} />
      {/* Table */}
      <TableSkeleton rows={rows} />
    </div>
  )
}

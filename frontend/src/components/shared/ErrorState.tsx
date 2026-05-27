import { AlertTriangle, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'

interface Props {
  message?: string
  retry?: () => void
}

export function ErrorState({ message = 'Failed to load data', retry }: Props) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-16 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-950/50 border border-red-800">
        <AlertTriangle className="h-6 w-6 text-red-400" />
      </div>
      <div>
        <p className="text-sm font-medium text-slate-200">Unable to load</p>
        <p className="mt-1 text-xs text-slate-500">{message}</p>
      </div>
      {retry && (
        <Button size="sm" variant="outline" onClick={retry}>
          <RefreshCw className="h-3.5 w-3.5" />
          Retry
        </Button>
      )}
    </div>
  )
}

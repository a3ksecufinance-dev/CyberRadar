import { SearchX } from 'lucide-react'

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <SearchX className="mb-3 h-10 w-10 text-slate-600" />
      <p className="text-sm text-slate-500">{message}</p>
    </div>
  )
}

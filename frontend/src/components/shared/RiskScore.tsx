import { cn, riskColor, riskBg } from '@/lib/utils'

export function RiskScore({ score }: { score: number }) {
  const color = riskColor(score)
  const bg = riskBg(score)
  const barColor = score >= 75 ? 'bg-red-500' : score >= 50 ? 'bg-orange-500' : score >= 25 ? 'bg-amber-500' : 'bg-emerald-500'

  return (
    <div className="flex items-center gap-2">
      <div className={cn('h-7 w-7 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0', bg, color)}>
        {score}
      </div>
      <div className="w-14 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full transition-all', barColor)} style={{ width: `${score}%` }} />
      </div>
    </div>
  )
}

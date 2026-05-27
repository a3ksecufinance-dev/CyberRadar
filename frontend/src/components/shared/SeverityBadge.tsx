import { Badge } from '@/components/ui/badge'
import { severityVariant } from '@/lib/utils'

export function SeverityBadge({ severity }: { severity: string }) {
  return <Badge variant={severityVariant(severity)}>{severity?.toUpperCase()}</Badge>
}

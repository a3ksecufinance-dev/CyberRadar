'use client'
import { ArrowRight, AlertTriangle, Scissors } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingState } from '@/components/shared/LoadingState'
import { ErrorState } from '@/components/shared/ErrorState'
import { useAttackPaths, useAttackStats, useChokePoints } from '@/hooks'
import type { AttackEdge, AttackNode, AttackPath } from '@/types'

// A node is coloured by what makes it dangerous, which is what the graph
// records: reachable from the internet, holding privilege, or being the crown
// jewel at the end of the path.
function nodeClass(node: AttackNode, isTarget: boolean): string {
  if (isTarget || node.is_critical_system) return 'border-red-500 bg-red-900 font-bold text-red-200'
  if (node.is_compromised) return 'border-red-700 bg-red-950 text-red-300'
  if (node.is_internet_facing) return 'border-orange-700 bg-orange-950 text-orange-300'
  if (node.is_privileged) return 'border-purple-700 bg-purple-950 text-purple-300'
  return 'border-slate-600 bg-slate-800 text-slate-300'
}

/** What the attacker uses to make this hop — the edge is the evidence. */
function edgeLabel(edge?: AttackEdge): string | null {
  if (!edge) return null
  const parts = [edge.edge_type.replace(/_/g, ' ')]
  if (edge.cve_id) parts.push(edge.cve_id)
  else if (edge.mitre_technique) parts.push(edge.mitre_technique)
  return parts.join(' · ')
}

const scoreColor = (score: number) =>
  score >= 85 ? 'text-red-400' : score >= 70 ? 'text-orange-400' : 'text-amber-400'

/** Order the hydrated nodes by the path's own node_sequence — the API returns
 *  the set, the sequence says in which order the attacker walks it. */
function orderedNodes(path: AttackPath): AttackNode[] {
  const byID = new Map((path.nodes ?? []).map((n) => [n.id, n]))
  const seq = path.node_sequence ?? []
  const ordered = seq.map((id) => byID.get(id)).filter((n): n is AttackNode => !!n)
  // If the sequence and the hydrated set disagree, show what we have rather
  // than an empty chain.
  return ordered.length ? ordered : (path.nodes ?? [])
}

function orderedEdges(path: AttackPath): (AttackEdge | undefined)[] {
  const byID = new Map((path.edges ?? []).map((e) => [e.id, e]))
  return (path.edge_sequence ?? []).map((id) => byID.get(id))
}

export default function AttackPathPage() {
  const { data: pathsData, isLoading, error, mutate } = useAttackPaths({ limit: '20' })
  const { data: chokeData } = useChokePoints({ limit: '5' })
  const { data: stats } = useAttackStats()

  const paths = pathsData?.items ?? []
  const chokePoints = chokeData?.items ?? []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Attack Path Analysis</h1>
        <p className="text-sm text-slate-400">Automated lateral movement and blast radius simulation</p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Attack Paths', value: stats?.total_paths ?? paths.length, color: 'text-slate-200' },
          { label: 'High-risk Paths', value: stats?.high_risk_paths ?? 0, color: 'text-red-400' },
          { label: 'Critical Systems', value: stats?.critical_system_nodes ?? 0, color: 'text-red-400' },
          {
            label: 'Avg Hops',
            value: stats?.avg_path_length ? stats.avg_path_length.toFixed(1) : '—',
            color: 'text-orange-400',
          },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-4">
              <p className="text-xs text-slate-400">{s.label}</p>
              <p className={`mt-1 text-2xl font-bold ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Choke points — the whole point of path analysis: one fix, many paths
          closed. The service ranks them; the page does not re-rank. */}
      {chokePoints.length > 0 && (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Scissors className="h-4 w-4 text-cyan-400" />
              <CardTitle>Choke points — highest remediation leverage</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {chokePoints.map((cp) => (
                <div key={cp.node_id} className="flex items-center justify-between rounded-md bg-slate-800/50 px-3 py-2">
                  <span className="text-xs text-slate-200">{cp.label}</span>
                  <span className="text-xs text-slate-400">
                    blocks <span className="font-bold text-cyan-400">{cp.paths_blocked}</span> path(s)
                    <span className="ml-2 text-slate-600">
                      −{(cp.risk_reduction * 100).toFixed(0)}% risk
                    </span>
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Paths */}
      {isLoading ? (
        <LoadingState variant="table" rows={4} />
      ) : error ? (
        <Card><CardContent className="p-0"><ErrorState message={error.message} retry={() => mutate()} /></CardContent></Card>
      ) : paths.length === 0 ? (
        <Card>
          <CardContent className="p-0">
            <EmptyState message="No attack paths found. Run a scenario to compute them." />
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {paths.map((path) => {
            const nodes = orderedNodes(path)
            const edges = orderedEdges(path)
            const target = nodes[nodes.length - 1]
            return (
              <Card key={path.id}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-orange-400" />
                      <CardTitle className="text-sm">
                        {path.path_type.replace(/_/g, ' ')} → {target?.label ?? 'target'}
                      </CardTitle>
                    </div>
                    <div className="flex items-center gap-3 text-xs">
                      <span className="text-slate-500">{path.hop_count} hops</span>
                      {path.has_exploit_step && (
                        <span className="rounded bg-red-950 px-1.5 py-0.5 text-[10px] text-red-400">EXPLOIT</span>
                      )}
                      {path.has_priv_esc && (
                        <span className="rounded bg-purple-950 px-1.5 py-0.5 text-[10px] text-purple-400">PRIV-ESC</span>
                      )}
                      <span className={`text-sm font-bold ${scoreColor(path.path_score)}`}>
                        {path.path_score.toFixed(0)}
                      </span>
                    </div>
                  </div>
                  <p className="text-xs text-slate-500">
                    likelihood {(path.likelihood * 100).toFixed(0)}% · impact {path.impact.toFixed(1)}
                    {path.mitre_tactics?.length ? ` · ${path.mitre_tactics.join(', ')}` : ''}
                  </p>
                </CardHeader>
                <CardContent>
                  {nodes.length === 0 ? (
                    <p className="text-xs text-slate-500">Path hops not available</p>
                  ) : (
                    <div className="flex flex-wrap items-start gap-2">
                      {nodes.map((node, idx) => (
                        <div key={node.id} className="flex items-start gap-2">
                          <div className="flex flex-col items-center">
                            <div className={`rounded-md border px-2.5 py-1.5 text-xs ${nodeClass(node, idx === nodes.length - 1)}`}>
                              {node.label}
                            </div>
                            <p className="mt-0.5 max-w-[140px] text-center text-[9px] leading-tight text-slate-500">
                              {node.node_type}
                              {node.open_vuln_count > 0 && ` · ${node.open_vuln_count} vuln`}
                            </p>
                          </div>
                          {idx < nodes.length - 1 && (
                            <div className="flex flex-col items-center pt-2">
                              <ArrowRight className="h-3 w-3 flex-shrink-0 text-slate-600" />
                              {edgeLabel(edges[idx]) && (
                                <p className="mt-0.5 max-w-[110px] text-center text-[9px] leading-tight text-slate-600">
                                  {edgeLabel(edges[idx])}
                                </p>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}

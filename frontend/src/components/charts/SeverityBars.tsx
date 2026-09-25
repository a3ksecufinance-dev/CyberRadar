'use client'
// SeverityBars — a `map[string]int` breakdown as horizontal bars.
//
// Colour here is a STATUS scale, not a categorical one: critical/high/medium/
// low have fixed meanings and reuse the exact hexes SeverityBadge paints, so a
// bar and the badge beside it never disagree. Those four fail the categorical
// validator as an identity palette (critical vs high measure ΔE 10.6 to normal
// vision), which is why every bar carries its name as a direct label on the
// axis — identity is read from the label, never from the hue alone.

import {
  Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { breakdownRows } from '@/lib/utils'

// Matches tailwind.config.ts `severity.*` and the status vocabulary the
// services emit. Anything unknown falls back to the neutral ink.
const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f87171',
  high: '#fb923c',
  medium: '#fbbf24',
  low: '#34d399',
  info: '#94a3b8',
}

const STATUS_COLORS: Record<string, string> = {
  open: '#f87171',
  investigating: '#fb923c',
  in_progress: '#fbbf24',
  contained: '#38bdf8',
  resolved: '#34d399',
  closed: '#64748b',
  accepted: '#64748b',
  false_positive: '#64748b',
}

const NEUTRAL = '#64748b'
const SURFACE = '#172033' // slate-800/50 over slate-900 — the card's own surface

// Severity reads worst-first; any other breakdown keeps its magnitude order.
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

interface Props {
  title: string
  breakdown: Record<string, number> | undefined | null
  /** Which fixed vocabulary the keys belong to. */
  palette?: 'severity' | 'status'
  /** Rendered when every bucket is zero. */
  emptyMessage?: string
}

function colorFor(palette: 'severity' | 'status', key: string): string {
  const table = palette === 'status' ? STATUS_COLORS : SEVERITY_COLORS
  return table[key] ?? NEUTRAL
}

function label(key: string): string {
  return key.replace(/_/g, ' ')
}

export function SeverityBars({ title, breakdown, palette = 'severity', emptyMessage }: Props) {
  let rows = breakdownRows(breakdown)
  if (palette === 'severity') {
    rows = [...rows].sort((a, b) => {
      const ia = SEVERITY_ORDER.indexOf(a.key)
      const ib = SEVERITY_ORDER.indexOf(b.key)
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib)
    })
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className="py-8 text-center text-xs text-slate-500">
            {emptyMessage ?? 'Nothing recorded yet'}
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={Math.max(120, rows.length * 34)}>
            <BarChart
              data={rows}
              layout="vertical"
              margin={{ top: 4, right: 28, bottom: 4, left: 4 }}
              barCategoryGap={6}
            >
              <XAxis type="number" hide />
              <YAxis
                type="category"
                dataKey="name"
                width={96}
                tickLine={false}
                axisLine={false}
                tickFormatter={label}
                tick={{ fill: '#94a3b8', fontSize: 11 }}
              />
              <Tooltip
                cursor={{ fill: 'rgba(148,163,184,0.08)' }}
                contentStyle={{
                  background: '#0f172a',
                  border: '1px solid #334155',
                  borderRadius: 6,
                  fontSize: 12,
                }}
                labelStyle={{ color: '#e2e8f0' }}
                itemStyle={{ color: '#cbd5e1' }}
                labelFormatter={label}
                formatter={(value: number) => [value, 'count']}
              />
              <Bar
                dataKey="value"
                radius={[0, 4, 4, 0]}
                barSize={14}
                // A 2px ring in the surface colour keeps adjacent fills from
                // touching, which is what makes two similar reds separable.
                stroke={SURFACE}
                strokeWidth={2}
                label={{ position: 'right', fill: '#cbd5e1', fontSize: 11 }}
              >
                {rows.map((r) => (
                  <Cell key={r.name} fill={colorFor(palette, r.key)} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  )
}

'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { Coverage, LibraryEntry, NormalizedEvent, SIEMAlert, SIEMStats } from '@/types'

export function useSIEMAlerts(params?: Record<string, string>) {
  return useApiList<SIEMAlert>('siem', ROUTES.siem.alerts, params, {
    refreshInterval: 15_000, // live feed
  })
}

export function useSIEMStats() {
  return useApiGet<SIEMStats>('siem', ROUTES.siem.alertStats, undefined, {
    refreshInterval: 30_000,
  })
}

// ─── The detection library ────────────────────────────────────
// The catalogue read through one tenant's eyes: every entry, whether they run
// it, and how their copy differs from the version they adopted.
export function useRuleLibrary() {
  return useApiList<LibraryEntry>('siem', ROUTES.siem.ruleLibrary)
}

// What the tenant detects by ATT&CK technique, against what the library offers.
export function useRuleCoverage() {
  return useApiGet<Coverage>('siem', ROUTES.siem.ruleCoverage)
}

// ─── La recherche d'événements ────────────────────────────────
// Ce que l'analyste fait juste après une alerte : regarder autour.
//
// Pas de refreshInterval : une recherche n'est pas un flux. Rafraîchir sous
// les yeux de quelqu'un qui lit une ligne la lui fait perdre, et chaque appel
// est un balayage sur ClickHouse. L'analyste relance quand il le décide.
export function useEventSearch(params: Record<string, string>) {
  return useApiList<NormalizedEvent>('siem', ROUTES.siem.events, params, {
    revalidateOnFocus: false,
    keepPreviousData: true,
  })
}

'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { Vulnerability, VulnStats } from '@/types'

export function useVulnerabilities(params?: Record<string, string>) {
  return useApiList<Vulnerability>('vuln', ROUTES.vuln.vulnerabilities, params)
}

export function useVulnStats() {
  return useApiGet<VulnStats>('vuln', ROUTES.vuln.stats)
}

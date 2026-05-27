'use client'
import { useApiGet, useApiList } from './useApi'
import type { Vulnerability, VulnStats } from '@/types'

export function useVulnerabilities(params?: Record<string, string>) {
  return useApiList<Vulnerability>('vuln', '/api/v1/vulnerabilities', params)
}

export function useVulnStats() {
  return useApiGet<VulnStats>('vuln', '/api/v1/vulnerabilities/stats')
}

'use client'
import { useApiGet, useApiList } from './useApi'
import { ROUTES } from '@/lib/api'
import type { APIKey, Webhook, WebhookDelivery, APIFWStats } from '@/types'

export function useAPIKeys(params?: Record<string, string>) {
  return useApiList<APIKey>('apifw', ROUTES.apifw.keys, params, { refreshInterval: 30_000 })
}

export function useWebhooks(params?: Record<string, string>) {
  return useApiList<Webhook>('apifw', ROUTES.apifw.webhooks, params, { refreshInterval: 30_000 })
}

export function useWebhookDeliveries(webhookID: string, params?: Record<string, string>) {
  return useApiList<WebhookDelivery>(
    'apifw',
    `${ROUTES.apifw.webhooks}/${webhookID}/deliveries`,
    params,
    { refreshInterval: 15_000 },
  )
}

export function useAPIFWStats() {
  return useApiGet<APIFWStats>('apifw', ROUTES.apifw.stats, undefined, { refreshInterval: 60_000 })
}

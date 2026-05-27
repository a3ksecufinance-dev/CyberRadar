'use client'
import { useApiGet, useApiList } from './useApi'
import type { APIKey, Webhook, WebhookDelivery, APIFWStats } from '@/types'

export function useAPIKeys(params?: Record<string, string>) {
  return useApiList<APIKey>('apifw', '/api/v1/apifw/keys', params, {
    refreshInterval: 30_000,
  })
}

export function useWebhooks(params?: Record<string, string>) {
  return useApiList<Webhook>('apifw', '/api/v1/apifw/webhooks', params, {
    refreshInterval: 30_000,
  })
}

export function useWebhookDeliveries(webhookID: string, params?: Record<string, string>) {
  return useApiList<WebhookDelivery>(
    'apifw',
    `/api/v1/apifw/webhooks/${webhookID}/deliveries`,
    params,
    { refreshInterval: 15_000 },
  )
}

export function useAPIFWStats() {
  return useApiGet<APIFWStats>('apifw', '/api/v1/apifw/stats', undefined, {
    refreshInterval: 60_000,
  })
}

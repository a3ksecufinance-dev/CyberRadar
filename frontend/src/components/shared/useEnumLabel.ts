'use client'
import { useTranslations } from 'next-intl'

/** The reader's word for a value a service defines.
 *
 * Thirty services store their taxonomies as snake_case identifiers —
 * `account_compromise`, `object_storage`, `engineering_workstation` — and the
 * tables printed them raw, so a French screen listed its incidents by English
 * column values. They are not free text and they are not many, so they are
 * translated from one catalogue rather than page by page.
 *
 * A value the catalogue does not know is humanised rather than hidden: new
 * taxonomies arrive with new features, and a customer must never meet a
 * missing-key marker on a screen. */
export function useEnumLabel() {
  const t = useTranslations('enum')
  return (value?: string | null): string => {
    if (!value) return '—'
    const key = value.toLowerCase()
    return t.has(key) ? t(key) : value.replace(/_/g, ' ')
  }
}

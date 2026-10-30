import { createContext, useContext, useMemo, type ReactNode } from 'react'
import { useAuth } from '@/auth/AuthProvider'
import { translate, type MessageKey } from './messages'

interface I18n {
  locale: string
  timeZone: string
  t: (key: MessageKey | (string & {}), params?: Record<string, string | number>) => string
  /** "28 Oct 2026, 14:32" in the user's timezone. Storage is always UTC. */
  formatDateTime: (iso: string | null | undefined) => string
  formatDate: (iso: string | null | undefined) => string
  formatRelative: (iso: string | null | undefined) => string
  formatNumber: (n: number) => string
}

const Ctx = createContext<I18n | null>(null)

function validTimeZone(tz: string | null | undefined): string | null {
  if (!tz) return null
  try {
    new Intl.DateTimeFormat('en', { timeZone: tz })
    return tz
  } catch {
    return null
  }
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const { me } = useAuth()
  const value = useMemo<I18n>(() => {
    // Preference order: the user's setting, then the organization default, then the browser.
    const locale = me?.user.locale || me?.organization.default_locale || navigator.language || 'en'
    const timeZone = validTimeZone(me?.user.timezone) ?? validTimeZone(me?.organization.default_timezone) ?? Intl.DateTimeFormat().resolvedOptions().timeZone ?? 'UTC'
    const parse = (iso: string | null | undefined) => {
      if (!iso) return null
      // The API sends UTC; SQLite-backed dev data may omit the zone suffix.
      const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso}Z`)
      return Number.isNaN(d.getTime()) ? null : d
    }
    const dt = new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short', timeZone })
    const d = new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeZone })
    const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' })
    const nf = new Intl.NumberFormat(locale)
    return {
      locale, timeZone,
      t: (key, params) => translate(locale, key, params),
      formatDateTime: (iso) => { const x = parse(iso); return x ? dt.format(x) : '—' },
      formatDate: (iso) => { const x = parse(iso); return x ? d.format(x) : '—' },
      formatRelative: (iso) => {
        const x = parse(iso)
        if (!x) return '—'
        const seconds = Math.round((x.getTime() - Date.now()) / 1000)
        const abs = Math.abs(seconds)
        if (abs < 60) return rtf.format(seconds, 'second')
        if (abs < 3600) return rtf.format(Math.round(seconds / 60), 'minute')
        if (abs < 86400) return rtf.format(Math.round(seconds / 3600), 'hour')
        return rtf.format(Math.round(seconds / 86400), 'day')
      },
      formatNumber: (n) => nf.format(n),
    }
  }, [me?.user.locale, me?.user.timezone, me?.organization.default_locale, me?.organization.default_timezone])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useI18n(): I18n {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useI18n must be used inside I18nProvider')
  return ctx
}

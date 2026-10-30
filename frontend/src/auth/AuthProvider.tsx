import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, SESSION_EXPIRED_EVENT } from '@/lib/api'
import type { Me } from '@/lib/schemas'

interface Auth {
  me: Me | null
  status: 'loading' | 'authenticated' | 'anonymous' | 'error'
  error: ApiError | null
  /** Capability checks mirror the server's; the server still enforces every one. */
  can: (permission: string) => boolean
  /** True after the server rejected our session; the sign-in page then explains why. */
  sessionExpired: boolean
  setMe: (me: Me) => void
  signOut: () => Promise<void>
}

const Ctx = createContext<Auth | null>(null)
export const ME_KEY = ['me'] as const

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const [sessionExpired, setSessionExpired] = useState(false)
  const query = useQuery({
    queryKey: ME_KEY,
    queryFn: ({ signal }) => api.auth.me(signal).catch((err) => {
      if (err instanceof ApiError && err.isUnauthenticated) return null
      throw err
    }),
    retry: (count, err) => !(err instanceof ApiError && err.status > 0 && err.status < 500) && count < 2,
    staleTime: 60_000,
  })

  const clear = useCallback(() => {
    qc.setQueryData(ME_KEY, null)
    qc.removeQueries({ predicate: (q) => q.queryKey[0] !== 'me' })
  }, [qc])

  useEffect(() => {
    // Clearing the cached user makes the route guard redirect to sign-in; the flag lets it say why.
    const onExpired = () => { setSessionExpired(true); clear() }
    window.addEventListener(SESSION_EXPIRED_EVENT, onExpired)
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, onExpired)
  }, [clear])

  const value = useMemo<Auth>(() => {
    const me = query.data ?? null
    return {
      me,
      status: query.isLoading ? 'loading' : query.isError && !me ? 'error' : me ? 'authenticated' : 'anonymous',
      error: query.error instanceof ApiError ? query.error : null,
      can: (permission) => !!me?.capabilities.includes(permission),
      sessionExpired,
      setMe: (next) => { setSessionExpired(false); qc.setQueryData(ME_KEY, next) },
      signOut: async () => {
        try { await api.auth.logout() } finally { clear() }
      },
    }
  }, [query.data, query.isLoading, query.isError, query.error, qc, clear, sessionExpired])

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuth(): Auth {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}

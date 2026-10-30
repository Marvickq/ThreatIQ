import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { useAuth } from '@/auth/AuthProvider'
import { EVENTS_URL } from '@/lib/api'

export type LiveState = 'connecting' | 'live' | 'reconnecting' | 'off'

/**
 * Server-Sent Events: new alerts and job progress, scoped by the server to the caller's organization.
 * Events only invalidate cached queries (the API stays the source of truth), so a missed event
 * costs at most one refetch. The browser reconnects automatically after a drop.
 */
export function useLiveEvents(): LiveState {
  const { me } = useAuth()
  const qc = useQueryClient()
  const [state, setState] = useState<LiveState>('off')
  const lastToast = useRef(0)
  const orgId = me?.organization.id

  useEffect(() => {
    if (!orgId) return
    setState('connecting')
    const source = new EventSource(EVENTS_URL, { withCredentials: true })
    source.onopen = () => setState('live')
    source.onerror = () => setState(source.readyState === EventSource.CLOSED ? 'off' : 'reconnecting')

    source.addEventListener('alert.created', (e) => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
      // Avoid a toast storm during bulk ingestion.
      if (Date.now() - lastToast.current > 5000) {
        lastToast.current = Date.now()
        try {
          const d = JSON.parse((e as MessageEvent).data)
          toast.info(`New ${d.severity ?? ''} alert`, { description: d.title })
        } catch { /* ignore malformed event */ }
      }
    })
    source.addEventListener('alert.updated', (e) => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
      try {
        const d = JSON.parse((e as MessageEvent).data)
        qc.invalidateQueries({ queryKey: ['alert', d.id] })
      } catch { /* ignore */ }
    })
    source.addEventListener('job.updated', (e) => {
      try {
        const d = JSON.parse((e as MessageEvent).data)
        qc.setQueryData(['job', d.id], (old: unknown) => (old ? { ...(old as object), ...d } : old))
        qc.invalidateQueries({ queryKey: ['jobs'] })
        if (d.status === 'succeeded' || d.status === 'failed') {
          qc.invalidateQueries({ queryKey: ['dashboard'] })
          qc.invalidateQueries({ queryKey: ['job', d.id] })
          if (d.subject_id) {
            qc.invalidateQueries({ queryKey: ['alert', d.subject_id] })
          }
          qc.invalidateQueries({ queryKey: ['integrations'] })
        }
      } catch { /* ignore */ }
    })
    return () => source.close()
  }, [orgId, qc])

  return state
}

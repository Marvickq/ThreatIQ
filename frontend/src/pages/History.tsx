import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { EmptyState, ErrorState, LoadingBlock, PageHeader, SectionCard } from '@/components/common'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n/I18nProvider'
import { api, ApiError } from '@/lib/api'
import NotFoundPage from './NotFound'

const ACTORS: Record<string, string> = { system: 'System', ai: 'AI', human: 'Analyst' }

export default function HistoryPage() {
  const { alertId = '' } = useParams()
  const { t, formatDateTime } = useI18n()
  const alert = useQuery({ queryKey: ['alert', alertId], queryFn: () => api.alerts.get(alertId) })
  const history = useQuery({ queryKey: ['alert', alertId, 'history'], queryFn: () => api.alerts.history(alertId) })

  if (alert.isLoading || history.isLoading) return <LoadingBlock rows={5} />
  if ((alert.error instanceof ApiError && alert.error.isNotFound) || (history.error instanceof ApiError && history.error.isNotFound)) return <NotFoundPage what="alert" />
  if (alert.isError || history.isError) return <ErrorState error={alert.error ?? history.error} onRetry={() => { alert.refetch(); history.refetch() }} />
  const a = alert.data!
  const h = history.data!

  return (
    <div>
      <PageHeader title={a.title} description={`Investigation history for ${a.id}`} actions={<Button asChild variant="outline" size="sm"><Link to={`/alerts/${encodeURIComponent(a.id)}`}>← Back to investigation</Link></Button>} />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="min-w-0 lg:col-span-2">
          <SectionCard title="Audit timeline" id="timeline" description="Recorded by ThreatIQ. Append-only in the application, but not a tamper-proof forensic log.">
            {h.events.length === 0 ? <EmptyState title="No history yet" description="Events appear as the alert is analyzed and reviewed." /> : (
              <ol className="border-l border-input">
                {h.events.map((e) => (
                  <li key={e.id} className="relative pb-6 pl-6 last:pb-0">
                    <span aria-hidden="true" className="absolute -left-[5px] top-1.5 size-2.5 bg-primary" />
                    <p className="font-mono text-xs text-muted-foreground"><time dateTime={e.created_at}>{formatDateTime(e.created_at)}</time> · {ACTORS[e.actor_type] ?? e.actor_type}</p>
                    <p className="mt-0.5 font-medium">{t(`event.${e.event_type}`)}</p>
                    {Object.keys(e.details).length > 0 && <pre className="mt-2 overflow-x-auto border bg-card p-2 font-mono text-xs text-muted-foreground">{JSON.stringify(e.details, null, 2)}</pre>}
                  </li>
                ))}
              </ol>
            )}
          </SectionCard>
        </div>
        <div className="space-y-6">
          <SectionCard title={`AI assessments (${h.assessments.length})`} id="assessments">
            {h.assessments.length === 0 ? <p className="text-sm text-muted-foreground">None recorded.</p> : (
              <ul className="space-y-2 text-sm">{[...h.assessments].reverse().map((x) => (
                <li key={x.id} className="border p-2.5"><p className="font-medium">#{x.version} · {t(`classification.${x.suggested_classification}`)}</p>
                  <p className="font-mono text-xs text-muted-foreground">{formatDateTime(x.created_at)} · {x.model_name}</p></li>))}</ul>
            )}
          </SectionCard>
          <SectionCard title={`Human decisions (${h.decisions.length})`} id="decisions">
            {h.decisions.length === 0 ? <p className="text-sm text-muted-foreground">None recorded.</p> : (
              <ul className="space-y-2 text-sm">{[...h.decisions].reverse().map((d, i) => (
                <li key={d.id} className="border p-2.5"><p className="font-medium">{t(`decision.${d.decision}`)}{i === 0 && <span className="ml-2 font-mono text-[10px] font-normal text-muted-foreground">LATEST</span>}</p>
                  <p className="font-mono text-xs text-muted-foreground">{d.reviewer_name ?? 'Unknown reviewer'} · {formatDateTime(d.created_at)}</p>
                  {d.reviewer_note && <p className="mt-1 whitespace-pre-wrap text-muted-foreground">{d.reviewer_note}</p>}</li>))}</ul>
            )}
          </SectionCard>
        </div>
      </div>
    </div>
  )
}

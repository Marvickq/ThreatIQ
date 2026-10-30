import { useMemo, type ReactNode } from 'react'
import { useIsFetching, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { Link, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useAuth } from '@/auth/AuthProvider'
import { DemoBadge, EmptyState, ErrorState, LoadingBlock, PageHeader, SectionCard, SeverityBadge, Spinner, StaleBanner, StatusBadge } from '@/components/common'
import { Button } from '@/components/ui/button'
import { NativeSelect } from '@/components/ui/native-select'
import { useI18n } from '@/i18n/I18nProvider'
import { api, type DashboardFilterQuery } from '@/lib/api'

const SEVERITY_COLORS: Record<string, string> = { critical: '#ff5a5f', high: '#e9b65b', medium: '#80b7ff', low: '#65c58b' }
const SCOPES = ['real', 'demo', 'all'] as const
type Scope = (typeof SCOPES)[number]

function Metric({ label, value, to, className = '' }: { label: string; value: number; to?: string; className?: string }) {
  const { formatNumber } = useI18n()
  const body = (
    <div className="border-r p-4 last:border-r-0">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="mt-1 font-mono text-3xl">{formatNumber(value)}</dd>
    </div>
  )
  return to ? <Link to={to} className={`block hover:bg-accent focus-visible:bg-accent ${className}`}>{body}</Link> : <div className={className}>{body}</div>
}

interface SectionQuery<T> { data?: T; isLoading: boolean; isError: boolean; error: unknown; dataUpdatedAt: number; refetch: () => unknown }

/** One section's query state: skeleton while loading, an error with retry, or a stale banner over cached data. */
function Section<T>({ query, children }: { query: SectionQuery<T>; children: (data: T) => ReactNode }) {
  if (query.isLoading) return <LoadingBlock rows={3} />
  if (query.isError && !query.data) return <ErrorState compact error={query.error} onRetry={() => query.refetch()} />
  if (!query.data) return null
  return (
    <>
      {query.isError && <StaleBanner updatedAt={query.dataUpdatedAt} onRetry={() => query.refetch()} />}
      {children(query.data)}
    </>
  )
}

export default function DashboardPage() {
  const { t, formatDate, formatRelative } = useI18n()
  const { can, me } = useAuth()
  const qc = useQueryClient()
  const [params, setParams] = useSearchParams()

  const scopeParam = params.get('data_scope')
  const scope: Scope = (SCOPES as readonly string[]).includes(scopeParam ?? '') ? (scopeParam as Scope) : 'real'
  const filters = useMemo<DashboardFilterQuery>(() => ({
    data_scope: scope, severity: params.get('severity') ?? undefined, status: params.get('status') ?? undefined,
    assigned_to: params.get('assigned_to') ?? undefined, review_state: params.get('review_state') ?? undefined,
  }), [params, scope])
  const hasFilters = !!(filters.severity || filters.status || filters.assigned_to || filters.review_state)
  const set = (patch: Record<string, string>) => setParams((prev) => {
    const next = new URLSearchParams(prev)
    for (const [k, v] of Object.entries(patch)) { if (v) next.set(k, v); else next.delete(k) }
    return next
  }, { replace: true })

  // The organization is part of every key so a switch can never show another organization's cached numbers.
  const key = (name: string) => ['dashboard', name, me?.organization.id, filters] as const
  const common = { refetchInterval: 60_000 }
  const summary = useQuery({ queryKey: key('summary'), queryFn: ({ signal }) => api.dashboard.summary(filters, signal), ...common })
  const severity = useQuery({ queryKey: key('severity'), queryFn: ({ signal }) => api.dashboard.severity(filters, signal), ...common })
  const daily = useQuery({ queryKey: key('daily'), queryFn: ({ signal }) => api.dashboard.daily(filters, signal), ...common })
  const queues = useQuery({ queryKey: key('queues'), queryFn: ({ signal }) => api.dashboard.queues(filters, signal), ...common })
  const fetching = useIsFetching({ queryKey: ['dashboard'] }) > 0
  const refreshAll = () => qc.invalidateQueries({ queryKey: ['dashboard'] })

  const demo = useMutation({
    mutationFn: api.org.loadDemoData,
    onSuccess: (r) => { toast.success(`Loaded ${r.created} demo alerts`); qc.invalidateQueries(); set({ data_scope: 'demo' }) },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not load demo data'),
  })

  const alertsLink = (extra: Record<string, string> = {}) => {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries({ ...filters, ...extra })) if (v) q.set(k, v)
    return `/alerts?${q}`
  }
  const d = summary.data
  const sources = d?.sources
  const clearFilters = () => set({ severity: '', status: '', assigned_to: '', review_state: '' })

  return (
    <div>
      <PageHeader
        title="Security overview"
        description="Review alerts. Investigate evidence. Make informed decisions."
        actions={<Button variant="outline" size="sm" onClick={refreshAll} disabled={fetching}>{fetching ? <Spinner /> : <RefreshCw className="size-3.5" />}{t('common.refresh')}</Button>}
      />

      <form role="search" aria-label="Dashboard filters" className="mb-4 flex flex-wrap items-end gap-3" onSubmit={(e) => e.preventDefault()}>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Data
          <NativeSelect value={scope} onChange={(e) => set({ data_scope: e.target.value === 'real' ? '' : e.target.value })}>
            <option value="real">Real alerts</option><option value="demo">Demo data (synthetic)</option><option value="all">Real + demo (mixed)</option>
          </NativeSelect></label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Severity
          <NativeSelect value={filters.severity ?? ''} onChange={(e) => set({ severity: e.target.value })}>
            <option value="">All severities</option>{['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{t(`severity.${s}`)}</option>)}
          </NativeSelect></label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Status
          <NativeSelect value={filters.status ?? ''} onChange={(e) => set({ status: e.target.value })}>
            <option value="">All statuses</option>{['new', 'investigating', 'awaiting_review', 'resolved'].map((s) => <option key={s} value={s}>{t(`status.${s}`)}</option>)}
          </NativeSelect></label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Assignment
          <NativeSelect value={filters.assigned_to ?? ''} onChange={(e) => set({ assigned_to: e.target.value })}>
            <option value="">Anyone</option><option value="unassigned">Unassigned</option><option value="me">Assigned to me</option>
          </NativeSelect></label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Review
          <NativeSelect value={filters.review_state ?? ''} onChange={(e) => set({ review_state: e.target.value })}>
            <option value="">Any review state</option><option value="unreviewed">No decision yet</option><option value="reviewed">Has a decision</option>
            <option value="true_positive">Latest: {t('decision.true_positive')}</option><option value="false_positive">Latest: {t('decision.false_positive')}</option>
            <option value="needs_further_review">Latest: {t('decision.needs_further_review')}</option>
          </NativeSelect></label>
        {hasFilters && <Button type="button" variant="ghost" size="sm" onClick={clearFilters}>{t('common.clearFilters')}</Button>}
      </form>

      {/* Synthetic and real data are never mixed silently: the scope is always stated. */}
      {scope === 'demo' && <p role="note" className="mb-4 flex items-center gap-2 border border-dashed px-3 py-2 text-sm text-muted-foreground"><DemoBadge /> Showing synthetic demo data only. None of it is a real incident.</p>}
      {scope === 'all' && <p role="note" className="mb-4 flex items-center gap-2 border border-warning/50 bg-warning/5 px-3 py-2 text-sm"><DemoBadge /> Real and synthetic demo alerts are combined in these numbers.</p>}
      {scope === 'real' && sources && sources.demo > 0 && (
        <p role="note" className="mb-4 flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
          <DemoBadge /> {sources.demo} synthetic demo {sources.demo === 1 ? 'alert is' : 'alerts are'} excluded from these numbers.
          <Button variant="link" size="sm" className="h-auto p-0" onClick={() => set({ data_scope: 'demo' })}>View demo data</Button>
        </p>
      )}

      <div className="min-w-0 space-y-6">
        <Section query={summary}>
          {(s) => s.total === 0 && !hasFilters ? (
            <EmptyState
              title={scope === 'real' ? 'No ingested alerts yet' : scope === 'demo' ? 'No demo data loaded' : 'No alerts yet'}
              description="Alerts appear here when a source sends them. Create an API key and post to the webhook, or connect Wazuh or Elastic Security."
              action={
                <div className="flex flex-wrap justify-center gap-2">
                  {can('integrations:manage') && <Button asChild><Link to="/settings/integrations">Connect a source</Link></Button>}
                  {can('apikeys:manage') && <Button asChild variant="outline"><Link to="/settings/api-keys">Create an API key</Link></Button>}
                  {scope === 'real' && s.sources.demo > 0 && <Button variant="outline" onClick={() => set({ data_scope: 'demo' })}>View demo data</Button>}
                  {s.sources.demo === 0 && me?.demo_data_allowed && can('org:manage') && (
                    <Button variant="outline" onClick={() => demo.mutate()} disabled={demo.isPending}>{demo.isPending && <Spinner />}Load labelled demo data</Button>
                  )}
                </div>
              }
            />
          ) : (
            <>
              <dl className="grid grid-cols-2 border bg-card md:grid-cols-5">
                <Metric label="Total alerts" value={s.total} to={alertsLink()} />
                <Metric label="Unresolved" value={s.unresolved} to={alertsLink({ unresolved: 'true' })} />
                <Metric label="High / Critical" value={s.high_or_critical} />
                <Metric label="Awaiting review" value={s.awaiting_review} to={alertsLink({ status: 'awaiting_review' })} />
                <Metric label="No decision yet" value={s.unreviewed} to={alertsLink({ review_state: 'unreviewed' })} className="col-span-2 md:col-span-1" />
              </dl>
              {s.total === 0 && (
                <div className="mt-6"><EmptyState title="No alerts match these filters" description="Try a different combination, or clear the filters." action={<Button onClick={clearFilters}>{t('common.clearFilters')}</Button>} /></div>
              )}
            </>
          )}
        </Section>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <SectionCard title="Alerts by severity" id="by-severity">
            <Section query={severity}>
              {(v) => v.total === 0 ? <p className="py-16 text-center text-sm text-muted-foreground">No alerts to chart.</p> : (
                <div role="img" aria-label={`Alerts by severity: ${v.items.map((i) => `${i.count} ${i.severity}`).join(', ')}`} className="h-52">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={v.items.map((i) => ({ name: t(`severity.${i.severity}`), key: i.severity, count: i.count }))} margin={{ left: -20, right: 8, top: 8 }}>
                      <CartesianGrid stroke="#292929" vertical={false} />
                      <XAxis dataKey="name" tick={{ fill: '#9a9a9a', fontSize: 12 }} axisLine={false} tickLine={false} />
                      <YAxis allowDecimals={false} tick={{ fill: '#9a9a9a', fontSize: 12 }} axisLine={false} tickLine={false} />
                      <Tooltip cursor={{ fill: '#191919' }} contentStyle={{ background: '#0f0f0f', border: '1px solid #292929', borderRadius: 2 }} />
                      <Bar dataKey="count" name="Alerts" radius={0}>
                        {v.items.map((i) => <Cell key={i.severity} fill={SEVERITY_COLORS[i.severity]} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Section>
          </SectionCard>

          <SectionCard title="Alerts per day (14 days, UTC)" id="per-day">
            <Section query={daily}>
              {(v) => v.total === 0 ? <p className="py-16 text-center text-sm text-muted-foreground">No alerts were created in the last {v.days} days.</p> : (
                <div role="img" aria-label={`Alerts created per day over the last ${v.days} days; ${v.total} in total`} className="h-52">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={v.items} margin={{ left: -20, right: 8, top: 8 }}>
                      <CartesianGrid stroke="#292929" vertical={false} />
                      <XAxis dataKey="date" tickFormatter={(x: string) => x.slice(5)} tick={{ fill: '#9a9a9a', fontSize: 11 }} axisLine={false} tickLine={false} interval={2} />
                      <YAxis allowDecimals={false} tick={{ fill: '#9a9a9a', fontSize: 12 }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{ background: '#0f0f0f', border: '1px solid #292929', borderRadius: 2 }} />
                      <Area type="monotone" dataKey="count" name="Alerts" stroke="#c81b1c" fill="#c81b1c" fillOpacity={0.2} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Section>
          </SectionCard>

          <SectionCard title="Investigation queues" id="queues">
            <Section query={queues}>
              {(v) => (
                <ul className="divide-y text-sm">
                  {v.items.map((item) => {
                    const row = <><span>{item.label}</span><span className="font-mono">{item.count}</span></>
                    return (
                      <li key={item.key}>
                        {item.query
                          ? <Link to={`/alerts?${new URLSearchParams(item.query)}`} className="flex items-center justify-between py-2.5 hover:text-primary">{row}</Link>
                          : <div className="flex items-center justify-between py-2.5 text-muted-foreground" title="The active filters exclude this queue">{row}</div>}
                      </li>
                    )
                  })}
                </ul>
              )}
            </Section>
          </SectionCard>
        </div>

        {d && d.total > 0 && (
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <SectionCard title="Recent alerts" id="recent" actions={<Button asChild variant="ghost" size="sm"><Link to={alertsLink()}>View all</Link></Button>}>
              <ul className="divide-y">
                {d.recent_alerts.map((a) => (
                  <li key={a.id}>
                    <Link to={`/alerts/${encodeURIComponent(a.id)}`} className="flex items-center gap-3 py-2.5 hover:text-primary">
                      <SeverityBadge severity={a.severity} />
                      <span className="min-w-0 flex-1 truncate text-sm">{a.title}</span>
                      {a.is_demo && <DemoBadge />}
                      <StatusBadge status={a.status} />
                      <span className="hidden font-mono text-[11px] text-muted-foreground sm:inline">{formatRelative(a.created_at)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </SectionCard>

            <SectionCard title="Recent activity" id="activity">
              {d.activity.length === 0 ? <p className="text-sm text-muted-foreground">No activity recorded yet.</p> : (
                <ul className="divide-y">
                  {d.activity.map((e) => (
                    <li key={e.id} className="flex items-center justify-between gap-3 py-2.5 text-sm">
                      <span><span className="font-medium">{t(`event.${e.event_type}`)}</span>{e.alert_id && <> · <Link className="font-mono text-xs text-muted-foreground underline underline-offset-4 hover:text-foreground" to={`/alerts/${encodeURIComponent(e.alert_id)}`}>{e.alert_id.slice(0, 8)}</Link></>}</span>
                      <span className="font-mono text-[11px] text-muted-foreground" title={formatDate(e.created_at)}>{formatRelative(e.created_at)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </SectionCard>
          </div>
        )}
        {d && <p className="font-mono text-[11px] text-muted-foreground">Updated {formatRelative(d.generated_at)}</p>}
      </div>
    </div>
  )
}

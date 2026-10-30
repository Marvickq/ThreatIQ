import { useCallback, useEffect, useMemo, useState } from 'react'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowDown, ArrowUp, ArrowUpDown, RefreshCw, Search } from 'lucide-react'
import { Link, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { useAuth } from '@/auth/AuthProvider'
import { ConfirmDialog, DemoBadge, EmptyState, ErrorState, LoadingBlock, PageHeader, SeverityBadge, Spinner, StaleBanner, StatusBadge } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { NativeSelect } from '@/components/ui/native-select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useI18n } from '@/i18n/I18nProvider'
import { api, type AlertQuery } from '@/lib/api'

const PAGE_SIZES = [10, 25, 50, 100]
const SORTABLE: Array<[string, string]> = [['title', 'Alert'], ['severity', 'Severity'], ['source', 'Source'], ['status', 'Status'], ['last_seen_at', 'Last seen']]

export default function AlertsPage() {
  const { t, formatDateTime, formatNumber } = useI18n()
  const { can } = useAuth()
  const qc = useQueryClient()
  const [params, setParams] = useSearchParams()
  const get = (k: string, d = '') => params.get(k) ?? d

  const [search, setSearch] = useState(get('q'))

  // Functional update: always applies to the *current* URL, never to a stale snapshot, so a delayed
  // (debounced) write cannot overwrite a filter the user changed in the meantime.
  const update = useCallback((patch: Record<string, string | undefined>, keepPage = false) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev)
      for (const [k, v] of Object.entries(patch)) { if (v) next.set(k, v); else next.delete(k) }
      if (!keepPage) next.delete('page')
      return next
    }, { replace: true })
  }, [setParams])

  useEffect(() => {
    const timer = setTimeout(() => { if (search !== (new URLSearchParams(window.location.search).get('q') ?? '')) update({ q: search }) }, 300)
    return () => clearTimeout(timer)
  }, [search, update])

  const limit = Number(get('size', '25')) || 25
  const page = Math.max(0, Number(get('page', '0')) || 0)
  const sort = get('sort', 'last_seen_at')
  const order = (get('order', 'desc') === 'asc' ? 'asc' : 'desc') as 'asc' | 'desc'
  const query: AlertQuery = useMemo(() => ({
    q: get('q'), severity: get('severity'), status: get('status'), assigned_to: get('assigned_to'), source: get('source'),
    review_state: get('review_state'), data_scope: get('data_scope'), unresolved: get('unresolved'),
    sort, order, limit, offset: page * limit,
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [params])

  const list = useQuery({ queryKey: ['alerts', query], queryFn: ({ signal }) => api.alerts.list(query, signal), placeholderData: keepPreviousData })
  const items = list.data?.items ?? []
  const total = list.data?.total ?? 0

  // Selection (bulk actions) is per page and cleared when the page changes.
  const [selected, setSelected] = useState<Set<string>>(new Set())
  useEffect(() => setSelected(new Set()), [params])
  const allOnPage = items.length > 0 && items.every((a) => selected.has(a.id))
  const [bulkStatus, setBulkStatus] = useState('investigating')
  const [confirm, setConfirm] = useState(false)

  const bulk = useMutation({
    mutationFn: () => api.alerts.bulkStatus([...selected], bulkStatus),
    onSuccess: (r) => {
      toast.success(`${r.updated} updated${r.unchanged ? `, ${r.unchanged} already ${t(`status.${bulkStatus}`).toLowerCase()}` : ''}`)
      setConfirm(false); setSelected(new Set())
      qc.invalidateQueries({ queryKey: ['alerts'] }); qc.invalidateQueries({ queryKey: ['dashboard'] })
    },
    onError: (e) => { setConfirm(false); toast.error(e instanceof Error ? e.message : 'Bulk update failed') },
  })

  const hasFilters = !!(get('q') || get('severity') || get('status') || get('assigned_to') || get('source') || get('review_state') || get('data_scope') || get('unresolved'))
  const pages = Math.max(1, Math.ceil(total / limit))

  function sortBy(col: string) {
    if (sort === col) update({ order: order === 'asc' ? 'desc' : 'asc' }, true)
    else update({ sort: col, order: col === 'title' || col === 'source' ? 'asc' : 'desc' }, true)
  }

  return (
    <div>
      <PageHeader
        title="Alerts"
        description="Server-side search, filters, sorting and pagination over every alert in this organization."
        actions={<Button variant="outline" size="sm" onClick={() => list.refetch()} disabled={list.isFetching}>{list.isFetching ? <Spinner /> : <RefreshCw className="size-3.5" />}{t('common.refresh')}</Button>}
      />

      <form role="search" className="mb-4 flex flex-wrap items-end gap-3" onSubmit={(e) => e.preventDefault()}>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Search
          <span className="relative"><Search className="pointer-events-none absolute left-2.5 top-2.5 size-4 text-muted-foreground" aria-hidden="true" />
            <Input type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Title, ID or entity" className="w-64 pl-8" /></span>
        </label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Severity
          <NativeSelect value={get('severity')} onChange={(e) => update({ severity: e.target.value })}>
            <option value="">All severities</option>{['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{t(`severity.${s}`)}</option>)}
          </NativeSelect></label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Status
          <NativeSelect value={get('status')} onChange={(e) => update({ status: e.target.value })}>
            <option value="">All statuses</option>{['new', 'investigating', 'awaiting_review', 'resolved'].map((s) => <option key={s} value={s}>{t(`status.${s}`)}</option>)}
          </NativeSelect></label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Assignment
          <NativeSelect value={get('assigned_to')} onChange={(e) => update({ assigned_to: e.target.value })}>
            <option value="">Anyone</option><option value="unassigned">Unassigned</option><option value="me">Assigned to me</option>
          </NativeSelect></label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Review
          <NativeSelect value={get('review_state')} onChange={(e) => update({ review_state: e.target.value })}>
            <option value="">Any review state</option><option value="unreviewed">No decision yet</option><option value="reviewed">Has a decision</option>
            <option value="true_positive">Latest: {t('decision.true_positive')}</option><option value="false_positive">Latest: {t('decision.false_positive')}</option>
            <option value="needs_further_review">Latest: {t('decision.needs_further_review')}</option>
          </NativeSelect></label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Data
          <NativeSelect value={get('data_scope')} onChange={(e) => update({ data_scope: e.target.value })}>
            <option value="">Real + demo</option><option value="real">Real alerts only</option><option value="demo">Demo data only</option>
          </NativeSelect></label>
        {get('unresolved') && <Button type="button" variant="outline" size="sm" onClick={() => update({ unresolved: undefined })}>Unresolved only ✕</Button>}
        {hasFilters && <Button type="button" variant="ghost" size="sm" onClick={() => { setSearch(''); setParams({}, { replace: true }) }}>{t('common.clearFilters')}</Button>}
      </form>

      {list.isError && list.data && <StaleBanner updatedAt={list.dataUpdatedAt} onRetry={() => list.refetch()} />}

      {can('alerts:write') && selected.size > 0 && (
        <div role="region" aria-label="Bulk actions" className="mb-3 flex flex-wrap items-center gap-3 border border-primary/50 bg-primary/5 px-3 py-2 text-sm">
          <span>{selected.size} selected</span>
          <NativeSelect value={bulkStatus} onChange={(e) => setBulkStatus(e.target.value)} aria-label="New status for selected alerts">
            {['new', 'investigating', 'awaiting_review', 'resolved'].map((s) => <option key={s} value={s}>Set to {t(`status.${s}`).toLowerCase()}</option>)}
          </NativeSelect>
          <Button size="sm" onClick={() => (bulkStatus === 'resolved' ? setConfirm(true) : bulk.mutate())} disabled={bulk.isPending}>{bulk.isPending && <Spinner />}Apply</Button>
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>Clear selection</Button>
        </div>
      )}

      {list.isLoading && <LoadingBlock rows={6} />}
      {list.isError && !list.data && <ErrorState error={list.error} onRetry={() => list.refetch()} />}
      {list.data && items.length === 0 && (
        <EmptyState
          title={hasFilters ? 'No alerts match your filters' : 'No alerts yet'}
          description={hasFilters ? 'Try removing a filter or searching for something else.' : 'Alerts appear when a source sends them. See Settings → Integrations and API keys.'}
          action={hasFilters ? <Button onClick={() => { setSearch(''); setParams({}, { replace: true }) }}>{t('common.clearFilters')}</Button> : undefined}
        />
      )}

      {items.length > 0 && (
        <div className={list.isPlaceholderData ? 'opacity-60 transition-opacity' : undefined} aria-busy={list.isFetching}>
          <div className="relative overflow-x-auto border bg-card">
            <Table className="min-w-[860px]">
              <TableHeader>
                <TableRow>
                  {can('alerts:write') && (
                    <TableHead className="w-10"><Checkbox aria-label="Select all alerts on this page" checked={allOnPage} onCheckedChange={(v) => setSelected(v ? new Set(items.map((a) => a.id)) : new Set())} /></TableHead>
                  )}
                  {SORTABLE.map(([col, label]) => (
                    <TableHead key={col} aria-sort={sort === col ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}>
                      <button type="button" onClick={() => sortBy(col)} className="inline-flex items-center gap-1 font-mono text-xs uppercase hover:text-foreground">
                        {label}{sort === col ? (order === 'asc' ? <ArrowUp className="size-3" /> : <ArrowDown className="size-3" />) : <ArrowUpDown className="size-3 opacity-40" />}
                      </button>
                    </TableHead>
                  ))}
                  <TableHead className="font-mono text-xs uppercase">Entity</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((a) => (
                  <TableRow key={a.id} data-state={selected.has(a.id) ? 'selected' : undefined}>
                    {can('alerts:write') && (
                      <TableCell><Checkbox aria-label={`Select ${a.title}`} checked={selected.has(a.id)} onCheckedChange={(v) => setSelected((s) => { const n = new Set(s); if (v) n.add(a.id); else n.delete(a.id); return n })} /></TableCell>
                    )}
                    <TableCell className="max-w-md">
                      <Link to={`/alerts/${encodeURIComponent(a.id)}`} className="font-medium hover:text-primary">{a.title}</Link>
                      <div className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
                        <span className="truncate">{a.id.length > 14 ? a.id.slice(0, 8) : a.id}</span>
                        {a.occurrence_count > 1 && <span title="Times this alert fired">×{a.occurrence_count}</span>}
                        {a.is_demo && <DemoBadge />}
                      </div>
                    </TableCell>
                    <TableCell><SeverityBadge severity={a.severity} /></TableCell>
                    <TableCell className="font-mono text-xs">{a.source}</TableCell>
                    <TableCell><StatusBadge status={a.status} /></TableCell>
                    <TableCell className="whitespace-nowrap font-mono text-xs">{formatDateTime(a.last_seen_at ?? a.created_at)}</TableCell>
                    <TableCell className="font-mono text-xs">{a.affected_entity ?? '—'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          <nav aria-label="Pagination" className="mt-3 flex flex-wrap items-center justify-between gap-3">
            <p className="font-mono text-xs text-muted-foreground" aria-live="polite">
              {formatNumber(page * limit + 1)}–{formatNumber(page * limit + items.length)} of {formatNumber(total)}
            </p>
            <div className="flex items-center gap-2">
              <label className="flex items-center gap-2 text-xs text-muted-foreground">Rows
                <NativeSelect value={limit} onChange={(e) => update({ size: e.target.value })} className="h-8">{PAGE_SIZES.map((n) => <option key={n} value={n}>{n}</option>)}</NativeSelect></label>
              <span className="font-mono text-xs text-muted-foreground">Page {page + 1} of {pages}</span>
              <Button size="sm" variant="outline" onClick={() => update({ page: String(page - 1) }, true)} disabled={page === 0}>Previous</Button>
              <Button size="sm" variant="outline" onClick={() => update({ page: String(page + 1) }, true)} disabled={(page + 1) * limit >= total}>Next</Button>
            </div>
          </nav>
        </div>
      )}

      <ConfirmDialog
        open={confirm} onOpenChange={setConfirm} busy={bulk.isPending} confirmLabel={`Resolve ${selected.size} alert${selected.size === 1 ? '' : 's'}`}
        title="Mark these alerts as resolved?"
        description={<p>This changes workflow status only and is recorded in each alert&apos;s audit history under your name. It does not record a true/false-positive decision.</p>}
        onConfirm={() => bulk.mutate()}
      />
    </div>
  )
}

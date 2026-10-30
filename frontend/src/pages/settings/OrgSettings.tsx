import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { z } from 'zod'
import { useAuth } from '@/auth/AuthProvider'
import { ConfirmDialog, EmptyState, ErrorState, LoadingBlock, SectionCard, Spinner } from '@/components/common'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { NativeSelect } from '@/components/ui/native-select'
import { Switch } from '@/components/ui/switch'
import { useI18n } from '@/i18n/I18nProvider'
import { api, ApiError } from '@/lib/api'
import type { Role } from '@/lib/schemas'
import { timeZones } from './AccountSettings'

const ROLE_ORDER: Role[] = ['viewer', 'analyst', 'admin', 'owner']

export function OrganizationSettings() {
  const { me, setMe, can } = useAuth()
  const qc = useQueryClient()
  const { t } = useI18n()
  const org = useQuery({ queryKey: ['organization'], queryFn: api.org.get })
  const [name, setName] = useState<string | null>(null)
  const [locale, setLocale] = useState<string | null>(null)
  const [tz, setTz] = useState<string | null>(null)
  const [retention, setRetention] = useState<string | null>(null)
  const [confirmExternal, setConfirmExternal] = useState(false)
  const update = useMutation({
    mutationFn: (b: Record<string, unknown>) => api.org.update(b),
    onSuccess: async (next) => {
      qc.setQueryData(['organization'], next)
      qc.invalidateQueries({ queryKey: ['intel-status'] })
      setConfirmExternal(false); toast.success('Organization updated')
      setMe({ ...me!, organization: next })
    },
    onError: (e) => { setConfirmExternal(false); toast.error(e instanceof Error ? e.message : 'Could not update') },
  })
  const demo = useMutation({
    mutationFn: api.org.loadDemoData,
    onSuccess: (r) => { toast.success(`Loaded ${r.created} labelled demo alerts`); qc.invalidateQueries() },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : 'Could not load demo data'),
  })
  if (org.isLoading) return <LoadingBlock rows={4} />
  if (org.isError) return <ErrorState error={org.error} onRetry={() => org.refetch()} />
  const o = org.data!
  const submit = (e: FormEvent) => {
    e.preventDefault()
    const body: Record<string, unknown> = {}
    if (name !== null && name !== o.name) body.name = name.trim()
    if (locale !== null && locale !== o.default_locale) body.default_locale = locale
    if (tz !== null && tz !== o.default_timezone) body.default_timezone = tz
    if (retention !== null && Number(retention) !== o.retention_days) {
      const n = z.coerce.number().int().min(0).max(36500).safeParse(retention)
      if (!n.success) return toast.error('Retention must be 0 (keep forever) to 36500 days.')
      body.retention_days = n.data
    }
    if (Object.keys(body).length === 0) return toast.info('Nothing to save')
    update.mutate(body)
  }
  return (
    <div className="space-y-6">
      <form onSubmit={submit}><SectionCard title="Organization" id="org">
        <div className="grid max-w-xl gap-4">
          <div className="space-y-1.5"><Label htmlFor="oname">Name</Label><Input id="oname" value={name ?? o.name} onChange={(e) => setName(e.target.value)} maxLength={100} /></div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5"><Label htmlFor="oloc">Default locale</Label><Input id="oloc" value={locale ?? o.default_locale} onChange={(e) => setLocale(e.target.value)} placeholder="en" /></div>
            <div className="space-y-1.5"><Label htmlFor="otz">Default time zone</Label>
              <NativeSelect id="otz" value={tz ?? o.default_timezone} onChange={(e) => setTz(e.target.value)} className="w-full">{timeZones().map((z) => <option key={z} value={z}>{z}</option>)}</NativeSelect></div>
          </div>
          <div className="space-y-1.5"><Label htmlFor="ret">Retention (days)</Label>
            <Input id="ret" inputMode="numeric" value={retention ?? String(o.retention_days)} onChange={(e) => setRetention(e.target.value)} className="w-40" />
            <p className="text-xs text-muted-foreground">0 keeps security records indefinitely. This setting records your policy; ThreatIQ never deletes alerts, assessments, decisions or audit events automatically.</p></div>
          <div><Button type="submit" disabled={update.isPending}>{update.isPending && <Spinner />}Save</Button></div>
        </div>
      </SectionCard></form>

      <SectionCard title="External enrichment" id="external" description="Controls what may leave this system.">
        <label className="flex max-w-xl items-start justify-between gap-4 text-sm">
          <span><span className="font-medium">Allow lookups with external providers</span>
            <span className="mt-1 block text-muted-foreground">When on, CVE IDs are sent to NIST NVD and, if configured, indicator values (IPs, domains, URLs, file hashes) to VirusTotal. Alert titles, descriptions and entities are never sent. CISA KEV needs no data sent and is always available.</span></span>
          <Switch checked={o.allow_external_enrichment} aria-label="Allow external enrichment" onCheckedChange={(v) => (v ? setConfirmExternal(true) : update.mutate({ allow_external_enrichment: false }))} />
        </label>
      </SectionCard>

      {me?.demo_data_allowed && can('org:manage') && (
        <SectionCard title="Demo data" id="demo" description="This server allows demo data (development only).">
          <Button variant="outline" onClick={() => demo.mutate()} disabled={demo.isPending}>{demo.isPending && <Spinner />}Load labelled demo alerts</Button>
          <p className="mt-2 text-xs text-muted-foreground">Only works if this organization has no alerts. Demo alerts are flagged and labelled everywhere.</p>
        </SectionCard>
      )}
      <p className="font-mono text-xs text-muted-foreground">Organization ID {o.id} · your role: {t(`role.${me!.role}`)}</p>
      <ConfirmDialog open={confirmExternal} onOpenChange={setConfirmExternal} busy={update.isPending} confirmLabel="Allow external lookups"
        title="Allow lookups with external providers?" description={<p>CVE IDs found in your alerts will be sent to NIST NVD. If a VirusTotal key is configured, indicator values will be sent to VirusTotal under its terms. Alert text is never sent. You can turn this off at any time.</p>}
        onConfirm={() => update.mutate({ allow_external_enrichment: true })} />
    </div>
  )
}

export function MembersSettings() {
  const { me } = useAuth()
  const { t, formatDate } = useI18n()
  const qc = useQueryClient()
  const members = useQuery({ queryKey: ['members'], queryFn: api.org.members })
  const sso = useQuery({ queryKey: ['sso-config'], queryFn: api.auth.ssoConfig, staleTime: 5 * 60_000, retry: false })
  const [email, setEmail] = useState(''); const [role, setRole] = useState<Role>('analyst'); const [formErr, setFormErr] = useState<string | null>(null)
  const [removing, setRemoving] = useState<{ id: string; name: string } | null>(null)
  const myRank = ROLE_ORDER.indexOf(me!.role)
  const grantable = ROLE_ORDER.filter((r) => ROLE_ORDER.indexOf(r) <= myRank)
  const refresh = () => qc.invalidateQueries({ queryKey: ['members'] })
  const add = useMutation({
    mutationFn: () => api.org.addMember(email.trim(), role),
    onSuccess: () => { setEmail(''); setFormErr(null); refresh(); toast.success('Member added') },
    onError: (e) => setFormErr(e instanceof ApiError ? e.message : 'Could not add the member'),
  })
  const setRoleFor = useMutation({
    mutationFn: ({ id, r }: { id: string; r: string }) => api.org.setRole(id, r),
    onSuccess: () => { refresh(); toast.success('Role updated') }, onError: (e) => { refresh(); toast.error(e instanceof Error ? e.message : 'Could not update the role') },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.org.removeMember(id),
    onSuccess: () => { setRemoving(null); refresh(); toast.success('Member removed') }, onError: (e) => { setRemoving(null); toast.error(e instanceof Error ? e.message : 'Could not remove') },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!z.email().safeParse(email.trim()).success) return setFormErr('Enter a valid email address.')
    setFormErr(null); add.mutate()
  }
  return (
    <div className="space-y-6">
      <SectionCard title="Add a member" id="add" description="Email invitations are not available (no email delivery is configured). The person must first register their own account; then add them here by email.">
        <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
          <div className="space-y-1.5"><Label htmlFor="memail">Email</Label><Input id="memail" type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="w-72" /></div>
          <div className="space-y-1.5"><Label htmlFor="mrole">Role</Label><NativeSelect id="mrole" value={role} onChange={(e) => setRole(e.target.value as Role)}>{grantable.map((r) => <option key={r} value={r}>{t(`role.${r}`)}</option>)}</NativeSelect></div>
          <Button type="submit" disabled={add.isPending}>{add.isPending && <Spinner />}Add member</Button>
        </form>
        {formErr && <p role="alert" className="mt-2 text-sm text-danger">{formErr}</p>}
      </SectionCard>
      <SectionCard title="Members" id="members" description={sso.data?.entra_enabled ? 'Members who sign in with Microsoft get their role from their Entra app role at every sign-in, which overwrites a role set here. Removing someone here does not remove their Entra assignment.' : undefined}>
        {members.isLoading && <LoadingBlock rows={3} />}
        {members.isError && <ErrorState error={members.error} onRetry={() => members.refetch()} compact />}
        {members.data?.length === 0 && <EmptyState title="No members" />}
        {members.data && members.data.length > 0 && (
          <ul className="divide-y">{members.data.map((m) => {
            const editable = ROLE_ORDER.indexOf(m.role) <= myRank && m.user_id !== me!.user.id
            return (
              <li key={m.user_id} className="flex flex-wrap items-center justify-between gap-3 py-3 text-sm">
                <div><p className="font-medium">{m.display_name}{m.user_id === me!.user.id && <Badge variant="outline" className="ml-2 font-mono text-[10px]">you</Badge>}</p>
                  <p className="text-xs text-muted-foreground">{m.email} · joined {formatDate(m.joined_at)}</p></div>
                <div className="flex items-center gap-2">
                  {editable ? (
                    <NativeSelect value={m.role} aria-label={`Role for ${m.display_name}`} disabled={setRoleFor.isPending} onChange={(e) => setRoleFor.mutate({ id: m.user_id, r: e.target.value })}>
                      {grantable.map((r) => <option key={r} value={r}>{t(`role.${r}`)}</option>)}</NativeSelect>
                  ) : <Badge variant="outline" className="font-mono text-[11px] uppercase">{t(`role.${m.role}`)}</Badge>}
                  {editable && <Button size="sm" variant="outline" onClick={() => setRemoving({ id: m.user_id, name: m.display_name })}>Remove</Button>}
                </div>
              </li>)
          })}</ul>
        )}
      </SectionCard>
      <ConfirmDialog open={!!removing} onOpenChange={(o) => !o && setRemoving(null)} busy={remove.isPending} destructive confirmLabel="Remove member"
        title={`Remove ${removing?.name}?`} description="They lose access to this organization immediately. Their past decisions stay in the audit history." onConfirm={() => removing && remove.mutate(removing.id)} />
    </div>
  )
}

export function AuditSettings() {
  const { t, formatDateTime } = useI18n()
  const [page, setPage] = useState(0)
  const [type, setType] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const limit = 25
  // Day boundaries are UTC, matching how events are stored and shown elsewhere.
  const since = from ? `${from}T00:00:00Z` : undefined
  const until = to ? new Date(Date.parse(`${to}T00:00:00Z`) + 86_400_000).toISOString() : undefined
  const log = useQuery({ queryKey: ['audit-log', page, type, since, until], queryFn: () => api.org.auditLog({ limit, offset: page * limit, event_type: type || undefined, since, until }), placeholderData: keepPreviousData })
  const filtered = Boolean(type || from || to)
  return (
    <SectionCard title="Audit log" id="audit" description="Security-relevant actions in this organization (sign-ins, member and API-key changes, integration changes, decisions). Append-only in the application.">
      <div className="mb-3 flex flex-wrap items-end gap-3 text-xs text-muted-foreground">
        <label className="flex items-center gap-2">Event type
          <NativeSelect value={type} onChange={(e) => { setType(e.target.value); setPage(0) }} className="h-8">
            <option value="">All events</option>{(log.data?.event_types ?? (type ? [type] : [])).map((e) => <option key={e} value={e}>{e}</option>)}
          </NativeSelect></label>
        <label className="flex items-center gap-2">From (UTC)
          <input type="date" value={from} max={to || undefined} onChange={(e) => { setFrom(e.target.value); setPage(0) }} className="h-8 rounded-md border border-input bg-background px-2 text-xs" /></label>
        <label className="flex items-center gap-2">To (UTC)
          <input type="date" value={to} min={from || undefined} onChange={(e) => { setTo(e.target.value); setPage(0) }} className="h-8 rounded-md border border-input bg-background px-2 text-xs" /></label>
        {filtered && <Button size="sm" variant="ghost" onClick={() => { setType(''); setFrom(''); setTo(''); setPage(0) }}>Clear filters</Button>}
      </div>
      {log.isLoading && <LoadingBlock rows={5} />}
      {log.isError && !log.data && <ErrorState error={log.error} onRetry={() => log.refetch()} compact />}
      {log.data && log.data.items.length === 0 && <EmptyState title={filtered ? 'No events match these filters' : 'No events recorded yet'} />}
      {log.data && log.data.items.length > 0 && (
        <>
          <ul className="divide-y text-sm">{log.data.items.map((e) => (
            <li key={e.id} className="py-2.5"><div className="flex flex-wrap items-center justify-between gap-2"><span className="font-medium">{t(`event.${e.event_type}`) === `event.${e.event_type}` ? e.event_type : t(`event.${e.event_type}`)}</span>
              <span className="font-mono text-[11px] text-muted-foreground">{formatDateTime(e.created_at)}</span></div>
              <p className="font-mono text-[11px] text-muted-foreground">{e.actor_name ?? (e.actor_type === 'system' ? 'System' : e.actor_type)}{e.alert_id && <> · <Link className="underline underline-offset-4 hover:text-foreground" to={`/alerts/${encodeURIComponent(e.alert_id)}`}>alert {e.alert_id.slice(0, 8)}</Link></>}</p>
              {Object.keys(e.details).length > 0 && <p className="mt-0.5 break-all font-mono text-[11px] text-muted-foreground">{JSON.stringify(e.details)}</p>}</li>))}</ul>
          <div className="mt-3 flex items-center justify-between"><span className="font-mono text-xs text-muted-foreground">{page * limit + 1}–{page * limit + log.data.items.length} of {log.data.total}</span>
            <div className="flex gap-2"><Button size="sm" variant="outline" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>Previous</Button>
              <Button size="sm" variant="outline" disabled={(page + 1) * limit >= log.data.total} onClick={() => setPage((p) => p + 1)}>Next</Button></div></div>
        </>
      )}
    </SectionCard>
  )
}

export function SystemSettings() {
  const status = useQuery({ queryKey: ['system-status'], queryFn: api.org.systemStatus, refetchInterval: 30_000 })
  const intel = useQuery({ queryKey: ['intel-status'], queryFn: api.intel.status })
  const qc = useQueryClient()
  const refresh = useMutation({
    mutationFn: api.intel.refresh,
    onSuccess: () => { toast.success('Refresh queued. Provider status below updates when it finishes.'); setTimeout(() => qc.invalidateQueries({ queryKey: ['intel-status'] }), 4000) },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not start the refresh'),
  })
  if (status.isLoading) return <LoadingBlock rows={4} />
  if (status.isError) return <ErrorState error={status.error} onRetry={() => status.refetch()} />
  const s = status.data!
  const db = s.database
  const rows: Array<[string, string, boolean?]> = [
    ['Version', s.version], ['Environment', s.environment],
    ['Database', `${db.engine} · ${db.reachable ? 'reachable' : 'UNREACHABLE'}`, !db.reachable],
    ['Schema', db.up_to_date ? `revision ${db.revision} (latest)` : `revision ${db.revision ?? 'unknown'}, latest is ${db.head ?? 'unknown'}: migrations pending`, !db.up_to_date],
    ['Redis', s.redis === 'ok' ? 'reachable' : s.redis === 'unreachable' ? 'UNREACHABLE' : 'not configured', s.redis === 'unreachable'],
    ['Artifact storage', s.artifact_storage],
    ['AI model', s.ai.configured ? `${s.ai.model ?? 'configured'} (configured; not live-checked here)` : 'not configured'],
    ['Microsoft sign-in', s.sso.entra_configured ? (s.sso.organization_bound ? 'configured; this organization has a bound tenant' : 'configured; this organization has NO bound tenant') : 'not configured'],
    ['Job backend', s.jobs.backend], ['Jobs (this org)', `${s.jobs.queued} queued · ${s.jobs.running} running · ${s.jobs.workers} workers`],
    ['Sentry', s.sentry ? 'enabled' : 'off'], ['OpenTelemetry', s.opentelemetry ? 'enabled' : 'off'],
  ]
  return (
    <div className="space-y-6">
      <SectionCard title="System status" id="system" description="Database and Redis are probed live on each refresh. Everything else is configuration state. Secret values are never shown.">
        <dl className="grid max-w-2xl grid-cols-[11rem_1fr] gap-y-2 font-mono text-sm">{rows.map(([k, v, bad]) => <div key={k} className="contents"><dt className="text-muted-foreground">{k}</dt><dd className={bad ? 'text-danger' : undefined}>{v}</dd></div>)}</dl>
      </SectionCard>
      <SectionCard title="Threat-intelligence providers" id="providers" actions={<Button size="sm" variant="outline" onClick={() => refresh.mutate()} disabled={refresh.isPending}>Refresh CISA KEV</Button>}>
        {intel.isLoading && <LoadingBlock rows={2} />}
        {intel.isError && <ErrorState error={intel.error} onRetry={() => intel.refetch()} compact />}
        {intel.data && <ul className="space-y-2 text-sm">{intel.data.map((p) => <li key={p.provider} className="border p-3"><p className="font-mono text-xs uppercase">{p.provider} <span className="text-muted-foreground">— {p.available ? 'available' : p.configured ? 'disabled' : 'not configured'}</span></p><p className="mt-1 text-muted-foreground">{p.detail}</p></li>)}</ul>}
      </SectionCard>
    </div>
  )
}

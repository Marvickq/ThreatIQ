import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, KeyRound } from 'lucide-react'
import { toast } from 'sonner'
import { z } from 'zod'
import { ConfirmDialog, EmptyState, ErrorState, LoadingBlock, SectionCard, Spinner } from '@/components/common'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { NativeSelect } from '@/components/ui/native-select'
import { useI18n } from '@/i18n/I18nProvider'
import { api, ApiError } from '@/lib/api'

const STATUS_LABEL: Record<string, { text: string; cls: string }> = {
  connected: { text: 'Connected', cls: 'border-success/60 text-success' },
  error: { text: 'Error', cls: 'border-danger/60 text-danger' },
  unconfigured: { text: 'Not configured', cls: 'text-muted-foreground' },
  never_synced: { text: 'Configured, never synced', cls: 'text-warning border-warning/60' },
  awaiting_events: { text: 'Waiting for first event', cls: 'text-warning border-warning/60' },
}

const createSchema = z.object({
  name: z.string().trim().min(1, 'Enter a name.').max(100),
  endpoint: z.string().trim().url('Enter a full URL, e.g. https://wazuh.example.com:9200').optional().or(z.literal('')),
})

function CreateIntegration({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient()
  const [kind, setKind] = useState('wazuh'); const [name, setName] = useState(''); const [endpoint, setEndpoint] = useState('')
  const [username, setUsername] = useState(''); const [password, setPassword] = useState(''); const [apiKey, setApiKey] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const create = useMutation({
    mutationFn: () => api.integrations.create({
      kind, name: name.trim(), config: kind === 'webhook' ? {} : { endpoint: endpoint.trim() },
      credentials: kind === 'wazuh' ? { username, password } : kind === 'elastic' ? { api_key: apiKey } : {},
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['integrations'] }); onOpenChange(false); toast.success('Integration created'); setName(''); setEndpoint(''); setUsername(''); setPassword(''); setApiKey('') },
    onError: (e) => setErr(e instanceof ApiError ? e.message : 'Could not create the integration'),
  })
  const submit = (e: FormEvent) => {
    e.preventDefault(); setErr(null)
    const parsed = createSchema.safeParse({ name, endpoint })
    if (!parsed.success) return setErr(parsed.error.issues[0].message)
    if (kind !== 'webhook' && !endpoint) return setErr('The endpoint URL is required.')
    create.mutate()
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader><DialogTitle>Add an integration</DialogTitle><DialogDescription>Credentials are encrypted at rest and never shown again.</DialogDescription></DialogHeader>
          <div className="space-y-1.5"><Label htmlFor="ikind">Type</Label>
            <NativeSelect id="ikind" value={kind} onChange={(e) => setKind(e.target.value)} className="w-full"><option value="wazuh">Wazuh (indexer)</option><option value="elastic">Elastic Security</option><option value="webhook">Generic JSON webhook</option></NativeSelect></div>
          <div className="space-y-1.5"><Label htmlFor="iname">Name</Label><Input id="iname" value={name} onChange={(e) => setName(e.target.value)} /></div>
          {kind !== 'webhook' && <div className="space-y-1.5"><Label htmlFor="iend">Endpoint URL</Label><Input id="iend" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder={kind === 'wazuh' ? 'https://wazuh-indexer:9200' : 'https://elasticsearch:9200'} />
            <p className="text-xs text-muted-foreground">Loopback and cloud-metadata addresses are always blocked. Private networks are allowed only if the server permits them.</p></div>}
          {kind === 'wazuh' && <div className="grid gap-3 sm:grid-cols-2"><div className="space-y-1.5"><Label htmlFor="iuser">Indexer username</Label><Input id="iuser" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" /></div>
            <div className="space-y-1.5"><Label htmlFor="ipw">Indexer password</Label><Input id="ipw" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" /></div></div>}
          {kind === 'elastic' && <div className="space-y-1.5"><Label htmlFor="ikey">API key (base64 id:key)</Label><Input id="ikey" type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} autoComplete="new-password" /></div>}
          {kind === 'webhook' && <p className="text-sm text-muted-foreground">Create an API key with the <span className="font-mono">ingest:write</span> scope, then POST events to <span className="font-mono">/api/v1/ingest/webhook</span>. Add <span className="font-mono">?integration=&lt;id&gt;</span> to attribute events to this integration.</p>}
          {err && <p role="alert" className="text-sm text-danger">{err}</p>}
          <DialogFooter><Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button><Button type="submit" disabled={create.isPending}>{create.isPending && <Spinner />}Create</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export function IntegrationsSettings() {
  const { formatDateTime, formatRelative } = useI18n()
  const qc = useQueryClient()
  const [adding, setAdding] = useState(false)
  const list = useQuery({ queryKey: ['integrations'], queryFn: api.integrations.list, refetchInterval: 15_000 })
  const refresh = () => qc.invalidateQueries({ queryKey: ['integrations'] })
  const test = useMutation({ mutationFn: (id: string) => api.integrations.test(id), onSuccess: (r) => (r.ok ? toast.success(`${r.message} This only tests the connection; the status becomes Connected after a sync succeeds.`) : toast.error(r.message)), onError: (e) => toast.error(e instanceof Error ? e.message : 'Test failed') })
  const sync = useMutation({ mutationFn: (id: string) => api.integrations.sync(id), onSuccess: () => { toast.success('Sync started'); setTimeout(refresh, 3000) }, onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not start the sync') })
  const toggle = useMutation({ mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.integrations.update(id, { enabled }), onSuccess: (_r, v) => { refresh(); toast.success(v.enabled ? 'Integration enabled' : 'Integration disabled') }, onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not update') })

  return (
    <div className="space-y-6">
      <SectionCard title="Alert sources" id="integrations" description="An integration is only 'Connected' after a sync or ingest has actually succeeded. Saving credentials does not make it connected. Editing and deleting integrations is not implemented yet: disable one to stop it." actions={<Button size="sm" onClick={() => setAdding(true)}>Add integration</Button>}>
        {list.isLoading && <LoadingBlock rows={2} />}
        {list.isError && <ErrorState error={list.error} onRetry={() => list.refetch()} compact />}
        {list.data?.length === 0 && <EmptyState title="No integrations yet" description="Add Wazuh or Elastic Security to pull alerts, or use the generic webhook to push them." />}
        {list.data && list.data.length > 0 && (
          <ul className="space-y-3">{list.data.map((i) => {
            const st = STATUS_LABEL[i.status] ?? { text: i.status, cls: '' }
            const pull = i.kind !== 'webhook'
            return (
              <li key={i.id} className="border p-4 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2"><span className="font-medium">{i.name}</span><Badge variant="outline" className="font-mono text-[10px] uppercase">{i.kind}</Badge>
                    <Badge variant="outline" className={`font-mono text-[10px] uppercase ${st.cls}`}>{st.text}</Badge>{!i.enabled && <Badge variant="outline" className="font-mono text-[10px] uppercase">Disabled</Badge>}</div>
                  <div className="flex flex-wrap items-center gap-2">
                    {pull && <Button size="sm" variant="outline" disabled={test.isPending || i.status === 'unconfigured'} onClick={() => test.mutate(i.id)}>{test.isPending && test.variables === i.id && <Spinner />}Test connection</Button>}
                    {pull && <Button size="sm" variant="outline" disabled={sync.isPending || i.status === 'unconfigured' || !i.enabled} onClick={() => sync.mutate(i.id)}>Sync now</Button>}
                    <Button size="sm" variant="ghost" onClick={() => toggle.mutate({ id: i.id, enabled: !i.enabled })}>{i.enabled ? 'Disable' : 'Enable'}</Button>
                  </div>
                </div>
                <dl className="mt-3 grid grid-cols-[9rem_1fr] gap-y-1 font-mono text-xs text-muted-foreground">
                  {i.config.endpoint ? <><dt>Endpoint</dt><dd className="break-all">{String(i.config.endpoint)}</dd></> : null}
                  <dt>Credentials</dt><dd>{i.has_credentials ? 'stored (encrypted)' : 'none'}</dd>
                  <dt>Last sync</dt><dd>{i.last_sync_at ? `${formatDateTime(i.last_sync_at)} (${formatRelative(i.last_sync_at)})` : 'never'}</dd>
                  <dt>Last success</dt><dd>{i.last_success_at ? formatDateTime(i.last_success_at) : 'never'}</dd>
                </dl>
                {i.status === 'unconfigured' && <p className="mt-2 text-xs text-warning">Setup incomplete: {i.kind === 'wazuh' ? 'set the indexer endpoint and a username and password' : 'set the Elasticsearch endpoint and an API key'}. The UI cannot edit an existing integration yet: add a new one with the full details and disable this one.</p>}
                {i.last_error && <p role="alert" className="mt-2 text-xs text-danger">Last error: {i.last_error}</p>}
              </li>)
          })}</ul>
        )}
      </SectionCard>
      <SectionCard title="Generic JSON webhook" id="webhook-docs" description="For any SIEM or tool that can POST JSON.">
        <pre className="overflow-x-auto border bg-background p-3 font-mono text-xs text-muted-foreground">{`curl -X POST ${window.location.origin}/api/v1/ingest/webhook \\
  -H "Authorization: Bearer tiq_xxxxxxxx_..." \\
  -H "Content-Type: application/json" \\
  -H "Idempotency-Key: <unique per delivery>" \\
  -d '{"source":"my-siem","external_id":"evt-123","title":"Suspicious login",
       "severity":"high","event_time":"2026-10-28T09:00:00Z",
       "affected_entity":"web-01","description":"…","indicators":[{"type":"ip","value":"203.0.113.9"}]}'`}</pre>
        <p className="mt-2 text-xs text-muted-foreground">Returns 201 for a new alert, 200 for a duplicate or update. Retrying is safe. Batches (up to 500) go to <span className="font-mono">/ingest/webhook/batch</span> and are processed in the background.</p>
      </SectionCard>
      <CreateIntegration open={adding} onOpenChange={setAdding} />
    </div>
  )
}

export function ApiKeysSettings() {
  const { formatDateTime, formatRelative } = useI18n()
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [name, setName] = useState(''); const [scopes, setScopes] = useState<string[]>(['ingest:write']); const [days, setDays] = useState('90'); const [err, setErr] = useState<string | null>(null)
  const [created, setCreated] = useState<string | null>(null); const [copied, setCopied] = useState(false)
  const [revoking, setRevoking] = useState<{ id: string; name: string } | null>(null)
  const [rotating, setRotating] = useState<{ id: string; name: string } | null>(null)
  const keys = useQuery({ queryKey: ['api-keys'], queryFn: api.keys.list })
  const create = useMutation({
    mutationFn: () => api.keys.create({ name: name.trim(), scopes, expires_in_days: days === 'never' ? null : Number(days) }),
    onSuccess: (k) => { setCreated(k.key); setCreating(false); setName(''); qc.invalidateQueries({ queryKey: ['api-keys'] }) },
    onError: (e) => setErr(e instanceof ApiError ? e.message : 'Could not create the key'),
  })
  const revoke = useMutation({
    mutationFn: (id: string) => api.keys.revoke(id),
    onSuccess: () => { setRevoking(null); qc.invalidateQueries({ queryKey: ['api-keys'] }); toast.success('Key revoked') },
    onError: () => { setRevoking(null); toast.error('Could not revoke the key') },
  })
  const rotate = useMutation({
    mutationFn: (id: string) => api.keys.rotate(id),
    onSuccess: (k) => { setRotating(null); setCreated(k.key); qc.invalidateQueries({ queryKey: ['api-keys'] }) },
    onError: (e) => { setRotating(null); toast.error(e instanceof Error ? e.message : 'Could not rotate the key') },
  })
  const SCOPES: Array<[string, string]> = [['ingest:write', 'Send alerts to the webhook'], ['alerts:read', 'Read alerts via the API'], ['alerts:write', 'Change alert status and assignment via the API']]
  const submit = (e: FormEvent) => {
    e.preventDefault(); setErr(null)
    if (!z.string().trim().min(1).safeParse(name).success) return setErr('Give the key a name.')
    if (scopes.length === 0) return setErr('Choose at least one scope.')
    create.mutate()
  }
  const copy = async () => { try { await navigator.clipboard.writeText(created!); setCopied(true); setTimeout(() => setCopied(false), 2000) } catch { toast.error('Copy failed. Select the key and copy it manually.') } }
  const state = (k: { revoked_at: string | null; expires_at: string | null }) => k.revoked_at ? 'Revoked' : k.expires_at && new Date(k.expires_at.endsWith('Z') ? k.expires_at : `${k.expires_at}Z`) < new Date() ? 'Expired' : 'Active'

  return (
    <div className="space-y-6">
      <SectionCard title="API keys" id="keys" description="Keys are stored hashed and shown only once. They authenticate webhooks and API calls, and can never make human review decisions." actions={<Button size="sm" onClick={() => { setErr(null); setCreating(true) }}><KeyRound className="size-3.5" />Create key</Button>}>
        {keys.isLoading && <LoadingBlock rows={2} />}
        {keys.isError && <ErrorState error={keys.error} onRetry={() => keys.refetch()} compact />}
        {keys.data?.length === 0 && <EmptyState title="No API keys" description="Create a key with the ingest:write scope to send alerts to the webhook." />}
        {keys.data && keys.data.length > 0 && (
          <ul className="divide-y">{keys.data.map((k) => {
            const s = state(k)
            return (
              <li key={k.id} className="flex flex-wrap items-center justify-between gap-3 py-3 text-sm">
                <div><p className="font-medium">{k.name} <Badge variant="outline" className={`ml-1 font-mono text-[10px] uppercase ${s === 'Active' ? 'border-success/60 text-success' : 'text-muted-foreground'}`}>{s}</Badge></p>
                  <p className="font-mono text-xs text-muted-foreground">{k.prefix}_… · {k.scopes.join(', ')}</p>
                  <p className="font-mono text-[11px] text-muted-foreground">Created {formatDateTime(k.created_at)} · {k.expires_at ? `expires ${formatDateTime(k.expires_at)}` : 'no expiry'} · {k.last_used_at ? `last used ${formatRelative(k.last_used_at)} (${k.use_count} requests)` : 'never used'}</p></div>
                {s === 'Active' && <div className="flex gap-2"><Button size="sm" variant="outline" onClick={() => setRotating({ id: k.id, name: k.name })}>Rotate</Button><Button size="sm" variant="outline" onClick={() => setRevoking({ id: k.id, name: k.name })}>Revoke</Button></div>}
              </li>)
          })}</ul>
        )}
      </SectionCard>

      <Dialog open={creating} onOpenChange={setCreating}>
        <DialogContent><form onSubmit={submit} className="space-y-4">
          <DialogHeader><DialogTitle>Create an API key</DialogTitle><DialogDescription>Grant only the scopes this integration needs.</DialogDescription></DialogHeader>
          <div className="space-y-1.5"><Label htmlFor="kname">Name</Label><Input id="kname" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Acme SIEM webhook" /></div>
          <fieldset className="space-y-2"><legend className="text-sm font-medium">Scopes</legend>
            {SCOPES.map(([v, label]) => (<label key={v} className="flex items-center gap-2 text-sm"><Checkbox checked={scopes.includes(v)} onCheckedChange={(c) => setScopes((s) => (c ? [...s, v] : s.filter((x) => x !== v)))} />{label} <span className="font-mono text-xs text-muted-foreground">{v}</span></label>))}</fieldset>
          <div className="space-y-1.5"><Label htmlFor="kexp">Expires after</Label><NativeSelect id="kexp" value={days} onChange={(e) => setDays(e.target.value)}><option value="30">30 days</option><option value="90">90 days</option><option value="365">1 year</option><option value="730">2 years</option></NativeSelect></div>
          {err && <p role="alert" className="text-sm text-danger">{err}</p>}
          <DialogFooter><Button type="button" variant="ghost" onClick={() => setCreating(false)}>Cancel</Button><Button type="submit" disabled={create.isPending}>{create.isPending && <Spinner />}Create key</Button></DialogFooter>
        </form></DialogContent>
      </Dialog>

      <Dialog open={!!created} onOpenChange={(o) => !o && setCreated(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>Copy your API key now</DialogTitle><DialogDescription>This is the only time it is shown. If you lose it, revoke it and create a new one.</DialogDescription></DialogHeader>
          <div className="flex items-center gap-2"><code className="min-w-0 flex-1 select-all break-all border bg-background p-3 font-mono text-xs">{created}</code>
            <Button type="button" variant="outline" size="icon" onClick={copy} aria-label="Copy key">{copied ? <Check className="size-4 text-success" /> : <Copy className="size-4" />}</Button></div>
          <DialogFooter><Button onClick={() => setCreated(null)}>I have saved it</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog open={!!rotating} onOpenChange={(o) => !o && setRotating(null)} busy={rotate.isPending} confirmLabel="Rotate key"
        title={`Rotate “${rotating?.name}”?`} description="A replacement with the same scopes and lifetime is created and shown once. The current key stops working immediately, so update whatever uses it." onConfirm={() => rotating && rotate.mutate(rotating.id)} />
      <ConfirmDialog open={!!revoking} onOpenChange={(o) => !o && setRevoking(null)} busy={revoke.isPending} destructive confirmLabel="Revoke key"
        title={`Revoke “${revoking?.name}”?`} description="Anything using this key stops working immediately. This cannot be undone." onConfirm={() => revoking && revoke.mutate(revoking.id)} />
    </div>
  )
}

import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
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

const LOCALES = [['', 'Organization default'], ['en', 'English'], ['en-GB', 'English (UK)'], ['en-US', 'English (US)'], ['de', 'Deutsch'], ['fr', 'Français'], ['es', 'Español'], ['ja', '日本語']]
const FALLBACK_ZONES = ['UTC', 'Europe/London', 'Europe/Berlin', 'America/New_York', 'America/Los_Angeles', 'Asia/Kolkata', 'Asia/Tokyo', 'Australia/Sydney']

export function timeZones(): string[] {
  const fn = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf
  return fn ? ['UTC', ...fn('timeZone').filter((z) => z !== 'UTC')] : FALLBACK_ZONES
}

function Profile() {
  const { me, setMe } = useAuth()
  const { formatDateTime, locale, timeZone } = useI18n()
  const qc = useQueryClient()
  const [name, setName] = useState(me!.user.display_name)
  const [loc, setLoc] = useState(me!.user.locale ?? '')
  const [tz, setTz] = useState(me!.user.timezone ?? '')
  const prefs = me!.user.notification_prefs as { in_app?: boolean; min_severity?: string; on_assignment?: boolean; on_job_failure?: boolean }
  const [inApp, setInApp] = useState(prefs.in_app ?? true)
  const [onFail, setOnFail] = useState(prefs.on_job_failure ?? true)
  const save = useMutation({
    mutationFn: () => api.auth.updateProfile({ display_name: name.trim(), locale: loc || null, timezone: tz || null, notification_prefs: { in_app: inApp, on_job_failure: onFail, min_severity: prefs.min_severity ?? 'high', on_assignment: prefs.on_assignment ?? true } }),
    onSuccess: (next) => { setMe(next); qc.invalidateQueries({ queryKey: ['organization'] }); toast.success('Profile saved') },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not save'),
  })
  const dirty = name.trim() !== me!.user.display_name || loc !== (me!.user.locale ?? '') || tz !== (me!.user.timezone ?? '') || inApp !== (prefs.in_app ?? true) || onFail !== (prefs.on_job_failure ?? true)
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!z.string().trim().min(1).max(100).safeParse(name).success) return toast.error('Enter your name.')
    save.mutate()
  }
  return (
    <form onSubmit={submit} className="space-y-6">
      <SectionCard title="Profile" id="profile">
        <div className="grid max-w-xl gap-4">
          <div className="space-y-1.5"><Label htmlFor="email">Email</Label><Input id="email" value={me!.user.email} disabled /></div>
          <div className="space-y-1.5"><Label htmlFor="name">Display name</Label><Input id="name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} /></div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5"><Label htmlFor="locale">Language &amp; number format</Label>
              <NativeSelect id="locale" value={loc} onChange={(e) => setLoc(e.target.value)} className="w-full">{LOCALES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</NativeSelect>
              <p className="text-xs text-muted-foreground">Dates and numbers follow this locale. Only English interface text ships today (translations: docs/ai-retrieval-i18n-observability.md).</p></div>
            <div className="space-y-1.5"><Label htmlFor="tz">Time zone</Label>
              <NativeSelect id="tz" value={tz} onChange={(e) => setTz(e.target.value)} className="w-full"><option value="">Organization default</option>{timeZones().map((z) => <option key={z} value={z}>{z}</option>)}</NativeSelect>
              <p className="text-xs text-muted-foreground">Everything is stored in UTC and shown in this zone. Now: {formatDateTime(new Date().toISOString())} ({timeZone}, {locale}).</p></div>
          </div>
        </div>
      </SectionCard>
      <SectionCard title="Notifications" id="notifications" description="In-app notifications only. Email, chat and push delivery are not implemented.">
        <div className="max-w-xl space-y-4">
          <label className="flex items-center justify-between gap-4 text-sm"><span>Show in-app notifications</span><Switch checked={inApp} onCheckedChange={setInApp} aria-label="In-app notifications" /></label>
          <label className="flex items-center justify-between gap-4 text-sm"><span>Notify me when a background job I started fails <span className="block text-xs text-muted-foreground">The only event ThreatIQ currently creates notifications for.</span></span><Switch checked={onFail} onCheckedChange={setOnFail} aria-label="Notify on job failure" /></label>
          <div className="flex items-center justify-between gap-4 text-sm"><span>Notify on new alerts by severity, and on assignment <span className="block text-xs text-muted-foreground">No notifications are created for alerts or assignments yet, so there is nothing to configure.</span></span>
            <Badge variant="outline" className="font-mono text-[10px] uppercase text-muted-foreground">Not implemented</Badge></div>
        </div>
      </SectionCard>
      <Button type="submit" disabled={save.isPending || !dirty}>{save.isPending && <Spinner />}Save changes</Button>
    </form>
  )
}

function Security() {
  const qc = useQueryClient()
  const { me } = useAuth()
  const policy = me!.security
  const [cur, setCur] = useState(''); const [next, setNext] = useState(''); const [confirmPw, setConfirmPw] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [revoke, setRevoke] = useState<string | null>(null)
  const { formatDateTime } = useI18n()
  const sessions = useQuery({ queryKey: ['sessions'], queryFn: api.auth.sessions })
  const change = useMutation({
    mutationFn: () => api.auth.changePassword(cur, next),
    onSuccess: () => { toast.success('Password changed. Other devices were signed out.'); setCur(''); setNext(''); setConfirmPw(''); qc.invalidateQueries({ queryKey: ['sessions'] }) },
    onError: (e) => setErr(e instanceof ApiError ? e.message : 'Could not change the password.'),
  })
  const kill = useMutation({
    mutationFn: (id: string) => api.auth.revokeSession(id),
    onSuccess: () => { setRevoke(null); qc.invalidateQueries({ queryKey: ['sessions'] }); toast.success('Session revoked') },
    onError: () => { setRevoke(null); toast.error('Could not revoke that session') },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault(); setErr(null)
    if (next.length < policy.password_min_length) return setErr(`Use at least ${policy.password_min_length} characters.`)
    if (next !== confirmPw) return setErr('The new passwords do not match.')
    change.mutate()
  }
  return (
    <div className="space-y-6">
      <SectionCard title="Sign-in policy" id="policy" description="Values enforced by this server.">
        <dl className="grid max-w-xl grid-cols-[14rem_1fr] gap-y-2 font-mono text-sm">
          <dt className="text-muted-foreground">Minimum password length</dt><dd>{policy.password_min_length} characters</dd>
          <dt className="text-muted-foreground">Session lifetime</dt><dd>{policy.session_ttl_hours} hours</dd>
          <dt className="text-muted-foreground">Account lockout</dt><dd>after {policy.login_max_failures} failed sign-ins, for {policy.login_lockout_minutes} min</dd>
          <dt className="text-muted-foreground">Microsoft sign-in</dt><dd>{policy.sso_user ? 'you sign in with Microsoft' : policy.sso_available ? 'available on this server' : 'not configured on this server'}</dd>
          <dt className="text-muted-foreground">Multi-factor authentication</dt><dd>Not implemented in ThreatIQ{policy.sso_available ? ' (enforce it in Microsoft Entra for SSO users)' : ''}</dd>
        </dl>
      </SectionCard>
      <SectionCard title="Change password" id="password" description={policy.sso_user ? undefined : "Passwords are stored with Argon2id. Changing yours signs out your other sessions."}>
        {policy.sso_user ? <p className="max-w-xl text-sm text-muted-foreground">Your account signs in with Microsoft and has no ThreatIQ password. Manage your password and MFA in your Microsoft account.</p> : <form onSubmit={submit} className="max-w-md space-y-3">
          <div className="space-y-1.5"><Label htmlFor="cur">Current password</Label><Input id="cur" type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} /></div>
          <div className="space-y-1.5"><Label htmlFor="new">New password</Label><Input id="new" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} /></div>
          <div className="space-y-1.5"><Label htmlFor="confirm">Confirm new password</Label><Input id="confirm" type="password" autoComplete="new-password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} /></div>
          {err && <p role="alert" className="text-sm text-danger">{err}</p>}
          <Button type="submit" disabled={change.isPending || !cur || !next}>{change.isPending && <Spinner />}Change password</Button>
        </form>}
      </SectionCard>
      <SectionCard title="Active sessions" id="sessions" description="Every browser currently signed in as you.">
        {sessions.isLoading && <LoadingBlock rows={2} />}
        {sessions.isError && <ErrorState error={sessions.error} onRetry={() => sessions.refetch()} compact />}
        {sessions.data?.length === 0 && <EmptyState title="No active sessions" />}
        {sessions.data && sessions.data.length > 0 && (
          <ul className="divide-y">{sessions.data.map((s) => (
            <li key={s.id} className="flex flex-wrap items-center justify-between gap-3 py-3 text-sm">
              <div className="min-w-0 flex-1"><p className="font-medium">{s.current ? 'This session' : 'Another session'} <span className="font-mono text-xs font-normal text-muted-foreground">{s.ip ?? 'unknown IP'}</span></p>
                <p className="truncate text-xs text-muted-foreground" title={s.user_agent ?? undefined}>{s.user_agent ?? 'Unknown browser'}</p>
                <p className="font-mono text-[11px] text-muted-foreground">Started {formatDateTime(s.created_at)} · expires {formatDateTime(s.expires_at)}</p></div>
              {!s.current && <Button size="sm" variant="outline" onClick={() => setRevoke(s.id)}>Sign out</Button>}
            </li>))}</ul>
        )}
      </SectionCard>
      <SectionCard title="Account recovery" id="recovery">
        <p className="text-sm text-muted-foreground">ThreatIQ has no email delivery configured, so there is no self-service password reset. If you lose access, an administrator with server access runs <code className="font-mono text-foreground">python -m app.cli reset-password you@example.com</code>, which sets a temporary password and signs out every session (docs/security.md, Account recovery).</p>
      </SectionCard>
      <ConfirmDialog open={!!revoke} onOpenChange={(o) => !o && setRevoke(null)} title="Sign out that session?" description="That browser will need to sign in again." confirmLabel="Sign out" onConfirm={() => revoke && kill.mutate(revoke)} busy={kill.isPending} />
    </div>
  )
}

export default function AccountSettings({ section }: { section: 'profile' | 'security' }) {
  return section === 'profile' ? <Profile /> : <Security />
}

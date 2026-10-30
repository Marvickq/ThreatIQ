import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bell, Building2, LayoutDashboard, LogOut, Menu, Settings, ShieldAlert, X } from 'lucide-react'
import { NavLink, Outlet, useLocation, useNavigate, Link } from 'react-router-dom'
import { toast } from 'sonner'
import { ME_KEY, useAuth } from '@/auth/AuthProvider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { OfflineBanner } from '@/components/common'
import { useI18n } from '@/i18n/I18nProvider'
import { useLiveEvents } from '@/hooks/useLiveEvents'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'

function NavItems({ onNavigate }: { onNavigate?: () => void }) {
  const { t } = useI18n()
  const items = [
    { to: '/', label: t('nav.dashboard'), icon: LayoutDashboard, end: true },
    { to: '/alerts', label: t('nav.alerts'), icon: ShieldAlert, end: false },
    { to: '/settings', label: t('nav.settings'), icon: Settings, end: false },
  ]
  return (
    <nav aria-label="Primary" className="flex-1 py-3">
      {items.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to} to={to} end={end} onClick={onNavigate}
          className={({ isActive }) => cn(
            'flex items-center gap-3 border-l-2 px-5 py-2.5 text-sm font-medium transition-colors',
            isActive ? 'border-primary bg-primary/10 text-foreground' : 'border-transparent text-muted-foreground hover:bg-accent hover:text-foreground',
          )}
        >
          <Icon className="size-4" aria-hidden="true" />{label}
        </NavLink>
      ))}
    </nav>
  )
}

function Brand({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <Link to="/" onClick={onNavigate} className="flex items-center gap-2 border-b px-5 py-5 text-xl font-bold tracking-tight">
      <span aria-hidden="true" className="inline-block size-3 bg-primary" />ThreatIQ
    </Link>
  )
}

function Notifications() {
  const qc = useQueryClient()
  const { formatRelative } = useI18n()
  const { data = [] } = useQuery({ queryKey: ['notifications'], queryFn: api.notifications.list, refetchInterval: 60_000 })
  const unread = data.filter((n) => !n.read_at).length
  const markRead = useMutation({
    mutationFn: api.notifications.readAll,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['notifications'] }),
    onError: () => toast.error('Could not mark notifications as read.'),
  })
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="icon" aria-label={`Notifications${unread ? `, ${unread} unread` : ''}`} className="relative">
          <Bell className="size-4" />
          {unread > 0 && <span className="absolute right-1.5 top-1.5 size-2 bg-primary" aria-hidden="true" />}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 p-0">
        <div className="flex items-center justify-between border-b px-3 py-2">
          <span className="text-sm font-medium">Notifications</span>
          {unread > 0 && <Button size="sm" variant="ghost" onClick={() => markRead.mutate()}>Mark all read</Button>}
        </div>
        {data.length === 0 ? (
          <p className="px-3 py-6 text-center text-sm text-muted-foreground">No notifications yet.</p>
        ) : (
          <ul className="max-h-80 divide-y overflow-y-auto">
            {data.map((n) => (
              <li key={n.id} className={cn('px-3 py-2 text-sm', !n.read_at && 'bg-accent/40')}>
                <p className="font-medium">{n.title}</p>
                {n.body && <p className="text-xs text-muted-foreground">{n.body}</p>}
                <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">{formatRelative(n.created_at)}</p>
              </li>
            ))}
          </ul>
        )}
      </PopoverContent>
    </Popover>
  )
}

function OrgSwitcher() {
  const { me, setMe } = useAuth()
  const qc = useQueryClient()
  const switchOrg = useMutation({
    mutationFn: (id: string) => api.auth.switchOrganization(id),
    onSuccess: (next) => { setMe(next); qc.removeQueries({ predicate: (q) => q.queryKey[0] !== 'me' }); toast.success(`Switched to ${next.organization.name}`) },
    onError: () => toast.error('Could not switch organization.'),
  })
  if (!me) return null
  const many = me.memberships.length > 1
  return (
    // Memberships can change while the page is open (an admin adds you elsewhere), so re-read them on open.
    <DropdownMenu onOpenChange={(open) => open && qc.invalidateQueries({ queryKey: ME_KEY })}>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="max-w-32 gap-2 sm:max-w-56" aria-label={`Organization: ${me.organization.name}`}>
          <Building2 className="size-3.5 shrink-0" /><span className="truncate">{me.organization.name}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuLabel className="text-xs text-muted-foreground">{many ? 'Switch organization' : 'Organization'}</DropdownMenuLabel>
        {me.memberships.map((m) => (
          <DropdownMenuItem key={m.organization_id} disabled={m.organization_id === me.organization.id || switchOrg.isPending} onSelect={() => switchOrg.mutate(m.organization_id)}>
            <span className="flex-1 truncate">{m.organization_name}</span>
            <span className="font-mono text-[10px] uppercase text-muted-foreground">{m.role}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export function AppShell() {
  const { me, signOut } = useAuth()
  const { t } = useI18n()
  const live = useLiveEvents()
  const [open, setOpen] = useState(false)
  const { pathname } = useLocation()
  void pathname
  const navigate = useNavigate()

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open])

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[15rem_1fr]">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:bg-primary focus:px-3 focus:py-2">Skip to content</a>
      <aside className="sticky top-0 hidden h-screen flex-col border-r bg-card lg:flex">
        <Brand />
        <NavItems />
        <div className="border-t px-5 py-4 font-mono text-[11px] text-muted-foreground">
          <span className={cn(live === 'live' ? 'text-success' : live === 'reconnecting' ? 'text-warning' : '')}>
            <span aria-hidden="true">{live === 'live' ? '●' : live === 'reconnecting' ? '◐' : '○'}</span>{' '}
            {live === 'live' ? 'Live updates on' : live === 'reconnecting' ? 'Reconnecting…' : 'Live updates off'}
          </span>
        </div>
      </aside>

      {open && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation menu" onKeyDown={(e) => e.key === 'Escape' && setOpen(false)}>
          <div className="absolute inset-0 bg-black/70" onClick={() => setOpen(false)} />
          <aside className="relative flex h-full w-72 max-w-[85vw] flex-col border-r bg-card">
            <Brand onNavigate={() => setOpen(false)} />
            <NavItems onNavigate={() => setOpen(false)} />
          </aside>
        </div>
      )}

      <div className="min-w-0">
        <header className="flex items-center gap-2 border-b px-4 py-2.5 sm:px-8">
          <Button variant="ghost" size="icon" className="lg:hidden" aria-label={open ? 'Close menu' : t('nav.menu')} aria-expanded={open} onClick={() => setOpen((o) => !o)}>
            {open ? <X className="size-4" /> : <Menu className="size-4" />}
          </Button>
          <OrgSwitcher />
          {me && me.organization && <Badge variant="outline" className="hidden font-mono text-[10px] uppercase sm:inline-flex">{t(`role.${me.role}`)}</Badge>}
          <div className="ml-auto flex min-w-0 items-center gap-1">
            <Notifications />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" aria-label="Account menu" className="max-w-24 sm:max-w-40"><span className="truncate">{me?.user.display_name}</span></Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56">
                <DropdownMenuLabel className="font-normal"><span className="block truncate text-sm">{me?.user.display_name}</span><span className="block truncate text-xs text-muted-foreground">{me?.user.email}</span></DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild><Link to="/settings/security">Account &amp; security</Link></DropdownMenuItem>
                <DropdownMenuItem onSelect={() => void signOut().then(() => navigate('/login', { replace: true }))}><LogOut className="size-4" />{t('nav.signOut')}</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>
        <OfflineBanner />
        <main id="main" className="min-w-0 px-4 py-8 sm:px-8 lg:px-9"><Outlet /></main>
      </div>
    </div>
  )
}

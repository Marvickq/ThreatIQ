import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle, Ban, CloudOff, Inbox, Loader2, RefreshCw, WifiOff } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { ApiError } from '@/lib/api'
import { useI18n } from '@/i18n/I18nProvider'
import { useOnline } from '@/hooks/useOnline'
import { cn } from '@/lib/utils'

// ------------------------------------------------------------------ badges (text + glyph, never color alone)
const SEVERITY_STYLE: Record<string, { glyph: string; cls: string }> = {
  critical: { glyph: '▲▲▲', cls: 'text-danger border-danger/60' },
  high: { glyph: '▲▲', cls: 'text-warning border-warning/60' },
  medium: { glyph: '▲', cls: 'text-info border-info/60' },
  low: { glyph: '▽', cls: 'text-success border-success/60' },
}

export function SeverityBadge({ severity }: { severity: string }) {
  const { t } = useI18n()
  const s = SEVERITY_STYLE[severity] ?? SEVERITY_STYLE.low
  return (
    <Badge variant="outline" className={cn('gap-1.5 font-mono text-[11px] uppercase', s.cls)}>
      <span aria-hidden="true">{s.glyph}</span>
      {t(`severity.${severity}`)}
    </Badge>
  )
}

export function StatusBadge({ status }: { status: string }) {
  const { t } = useI18n()
  return <Badge variant="outline" className="font-mono text-[11px] uppercase text-foreground/80">{t(`status.${status}`)}</Badge>
}

export function DemoBadge() {
  const { t } = useI18n()
  return <Badge variant="outline" className="border-dashed font-mono text-[10px] uppercase text-muted-foreground">{t('common.demo')}</Badge>
}

// ------------------------------------------------------------------ page chrome
export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-3xl font-bold tracking-tight">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function SectionCard({ title, description, children, actions, id }: { title: string; description?: string; children: ReactNode; actions?: ReactNode; id?: string }) {
  return (
    <section aria-labelledby={id} className="min-w-0 border bg-card p-5">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h2 id={id} className="font-mono text-xs uppercase tracking-wider text-muted-foreground">{title}</h2>
          {description && <p className="mt-1 text-xs text-muted-foreground">{description}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  )
}

// ------------------------------------------------------------------ states
export function LoadingBlock({ label, rows = 3 }: { label?: string; rows?: number }) {
  const { t } = useI18n()
  return (
    <div role="status" aria-live="polite" className="space-y-3">
      <span className="sr-only">{label ?? t('common.loading')}</span>
      {Array.from({ length: rows }, (_, i) => <Skeleton key={i} className="h-10 w-full" />)}
    </div>
  )
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn('size-4 animate-spin', className)} aria-hidden="true" />
}

export function EmptyState({ title, description, action, icon }: { title: string; description?: string; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 border border-dashed px-6 py-12 text-center">
      <div className="text-muted-foreground">{icon ?? <Inbox className="size-8" aria-hidden="true" />}</div>
      <p className="font-medium">{title}</p>
      {description && <p className="max-w-md text-sm text-muted-foreground">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}

export function PermissionDenied({ what }: { what?: string }) {
  const { t } = useI18n()
  return (
    <div role="alert" className="flex flex-col items-center gap-2 border px-6 py-12 text-center">
      <Ban className="size-8 text-warning" aria-hidden="true" />
      <p className="font-medium">{t('error.forbidden')}</p>
      <p className="max-w-md text-sm text-muted-foreground">
        {what ?? 'Your role does not include access to this area.'} Ask an organization administrator if you need it.
      </p>
      <Button asChild variant="outline" size="sm" className="mt-2"><Link to="/">Back to dashboard</Link></Button>
    </div>
  )
}

export function ErrorState({ error, onRetry, compact }: { error: unknown; onRetry?: () => void; compact?: boolean }) {
  const { t } = useI18n()
  const api = error instanceof ApiError ? error : null
  if (api?.isForbidden) return <PermissionDenied />
  const offline = api?.isNetwork
  return (
    <div role="alert" className={cn('flex flex-col items-start gap-2 border border-danger/40 p-4', !compact && 'py-8')}>
      <div className="flex items-center gap-2 font-medium">
        {offline ? <CloudOff className="size-4 text-danger" aria-hidden="true" /> : <AlertTriangle className="size-4 text-danger" aria-hidden="true" />}
        {offline ? 'Cannot reach the server' : t('error.generic')}
      </div>
      <p className="text-sm text-muted-foreground">{api?.message ?? (error instanceof Error ? error.message : t('error.generic'))}</p>
      {api?.requestId && <p className="font-mono text-xs text-muted-foreground">Request ID: {api.requestId}</p>}
      {onRetry && <Button size="sm" variant="outline" onClick={onRetry}><RefreshCw className="size-3.5" />{t('common.retry')}</Button>}
    </div>
  )
}

/** Shown when a background refresh failed but cached data is still on screen. */
export function StaleBanner({ updatedAt, onRetry }: { updatedAt: number; onRetry: () => void }) {
  const { t, formatDateTime } = useI18n()
  return (
    <div role="status" className="mb-4 flex flex-wrap items-center justify-between gap-2 border border-warning/50 bg-warning/5 px-3 py-2 text-sm">
      <span>{t('error.stale', { time: formatDateTime(new Date(updatedAt).toISOString()) })}</span>
      <Button size="sm" variant="ghost" onClick={onRetry}><RefreshCw className="size-3.5" />{t('common.retry')}</Button>
    </div>
  )
}

export function OfflineBanner() {
  const online = useOnline()
  const { t } = useI18n()
  if (online) return null
  return (
    <div role="status" className="flex items-center gap-2 border-b border-warning/50 bg-warning/10 px-4 py-2 text-sm">
      <WifiOff className="size-4" aria-hidden="true" />{t('error.offline')}
    </div>
  )
}

// ------------------------------------------------------------------ dialogs
export function ConfirmDialog({
  open, onOpenChange, title, description, confirmLabel, destructive, onConfirm, busy,
}: {
  open: boolean; onOpenChange: (open: boolean) => void; title: string; description: ReactNode
  confirmLabel: string; destructive?: boolean; onConfirm: () => void; busy?: boolean
}) {
  const { t } = useI18n()
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription asChild><div>{description}</div></AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>{t('common.cancel')}</AlertDialogCancel>
          <AlertDialogAction
            disabled={busy}
            onClick={(e) => { e.preventDefault(); onConfirm() }}
            className={destructive ? 'bg-destructive text-black hover:bg-destructive/90' : undefined}
          >
            {busy ? <Spinner /> : null}{confirmLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

// ------------------------------------------------------------------ error boundary
interface BoundaryState { error: Error | null }
export class ErrorBoundary extends Component<{ children: ReactNode }, BoundaryState> {
  state: BoundaryState = { error: null }
  static getDerivedStateFromError(error: Error): BoundaryState { return { error } }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error('Render error', error, info.componentStack) }
  render() {
    if (!this.state.error) return this.props.children
    return (
      <div role="alert" className="mx-auto mt-16 max-w-lg border p-8 text-center">
        <AlertTriangle className="mx-auto mb-3 size-8 text-danger" aria-hidden="true" />
        <h1 className="text-xl font-bold">This page failed to display</h1>
        <p className="mt-2 text-sm text-muted-foreground">The problem has been logged in your browser console. Your data is unaffected.</p>
        <div className="mt-4 flex justify-center gap-2">
          <Button variant="outline" onClick={() => this.setState({ error: null })}>Try again</Button>
          <Button onClick={() => window.location.assign('/')}>Go to dashboard</Button>
        </div>
      </div>
    )
  }
}

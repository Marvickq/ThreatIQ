import { lazy, Suspense, type ReactNode } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { useAuth } from '@/auth/AuthProvider'
import { AppShell } from '@/components/AppShell'
import { ErrorState, LoadingBlock, PermissionDenied } from '@/components/common'
import { Button } from '@/components/ui/button'

import LoginPage from '@/pages/Login'
import NotFoundPage from '@/pages/NotFound'

// Heavier, less frequently visited screens load on demand.
const DashboardPage = lazy(() => import('@/pages/Dashboard'))
const AlertsPage = lazy(() => import('@/pages/Alerts'))
const AlertDetailPage = lazy(() => import('@/pages/AlertDetail'))
const HistoryPage = lazy(() => import('@/pages/History'))
const SettingsPage = lazy(() => import('@/pages/settings/SettingsLayout'))

function Splash() {
  return <div className="mx-auto mt-24 max-w-sm p-6"><LoadingBlock label="Loading ThreatIQ" rows={2} /></div>
}

/** Route protection. Real authorization is enforced by the API on every request; this only shapes the UI. */
function RequireAuth({ children }: { children: ReactNode }) {
  const { status, error, sessionExpired } = useAuth()
  const location = useLocation()
  if (status === 'loading') return <Splash />
  if (status === 'error') {
    return (
      <div className="mx-auto mt-24 max-w-md p-6">
        <ErrorState error={error} />
        <Button className="mt-4" variant="outline" onClick={() => window.location.reload()}>Reload</Button>
      </div>
    )
  }
  if (status === 'anonymous') return <Navigate to={`/login?next=${encodeURIComponent(location.pathname + location.search)}${sessionExpired ? '&expired=1' : ''}`} replace />
  return <>{children}</>
}

export function RequireCapability({ capability, children }: { capability: string; children: ReactNode }) {
  const { can } = useAuth()
  return can(capability) ? <>{children}</> : <PermissionDenied />
}

export default function App() {
  return (
    <Suspense fallback={<Splash />}>
      <Routes>
        <Route path="/login" element={<LoginPage mode="login" />} />
        <Route path="/register" element={<LoginPage mode="register" />} />
        <Route element={<RequireAuth><AppShell /></RequireAuth>}>
          <Route index element={<DashboardPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="alerts/:alertId" element={<AlertDetailPage />} />
          <Route path="alerts/:alertId/history" element={<HistoryPage />} />
          <Route path="settings/*" element={<SettingsPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </Suspense>
  )
}

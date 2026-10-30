import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from '@/auth/AuthProvider'
import { PageHeader, PermissionDenied } from '@/components/common'
import { cn } from '@/lib/utils'
import AccountSettings from './AccountSettings'
import { ApiKeysSettings, IntegrationsSettings } from './IntegrationSettings'
import { AuditSettings, MembersSettings, OrganizationSettings, SystemSettings } from './OrgSettings'
import type { ReactNode } from 'react'

function Guard({ cap, children }: { cap: string; children: ReactNode }) {
  const { can } = useAuth()
  return can(cap) ? <>{children}</> : <PermissionDenied />
}

/** Canonical, absolute section routes. Links must be absolute: this component renders inside the `settings/*` splat
 * route, where a relative `to="security"` resolves against the current URL and appends (/settings/security/account). */
export const SETTINGS_BASE = '/settings'
export const SETTINGS_DEFAULT = `${SETTINGS_BASE}/account`
export const SETTINGS_SECTIONS = ['account', 'security', 'organization', 'members', 'integrations', 'api-keys', 'audit', 'system'] as const

export default function SettingsLayout() {
  const { can } = useAuth()
  const tabs = [
    { to: `${SETTINGS_BASE}/account`, label: 'Profile & notifications', show: true },
    { to: `${SETTINGS_BASE}/security`, label: 'Security', show: true },
    { to: `${SETTINGS_BASE}/organization`, label: 'Organization', show: can('org:manage') },
    { to: `${SETTINGS_BASE}/members`, label: 'Members', show: can('members:manage') },
    { to: `${SETTINGS_BASE}/integrations`, label: 'Integrations', show: can('integrations:manage') },
    { to: `${SETTINGS_BASE}/api-keys`, label: 'API keys', show: can('apikeys:manage') },
    { to: `${SETTINGS_BASE}/audit`, label: 'Audit log', show: can('org:manage') },
    { to: `${SETTINGS_BASE}/system`, label: 'System', show: can('org:manage') },
  ].filter((t) => t.show)

  return (
    <div>
      <PageHeader title="Settings" description="Your account, and — for administrators — this organization." />
      <div className="grid grid-cols-1 gap-8 lg:grid-cols-[13rem_minmax(0,1fr)]">
        <nav aria-label="Settings" className="flex flex-row flex-wrap gap-1 lg:flex-col">
          {tabs.map((t) => (
            <NavLink key={t.to} to={t.to} end className={({ isActive }) => cn('border-l-2 px-3 py-2 text-sm', isActive ? 'border-primary bg-primary/10 font-medium' : 'border-transparent text-muted-foreground hover:bg-accent hover:text-foreground')}>
              {t.label}
            </NavLink>
          ))}
        </nav>
        <div className="min-w-0">
          <Routes>
            <Route index element={<Navigate to={SETTINGS_DEFAULT} replace />} />
            <Route path="account" element={<AccountSettings section="profile" />} />
            <Route path="security" element={<AccountSettings section="security" />} />
            <Route path="organization" element={<Guard cap="org:manage"><OrganizationSettings /></Guard>} />
            <Route path="members" element={<Guard cap="members:manage"><MembersSettings /></Guard>} />
            <Route path="integrations" element={<Guard cap="integrations:manage"><IntegrationsSettings /></Guard>} />
            <Route path="api-keys" element={<Guard cap="apikeys:manage"><ApiKeysSettings /></Guard>} />
            <Route path="audit" element={<Guard cap="org:manage"><AuditSettings /></Guard>} />
            <Route path="system" element={<Guard cap="org:manage"><SystemSettings /></Guard>} />
            <Route path="*" element={<Navigate to={SETTINGS_DEFAULT} replace />} />
          </Routes>
        </div>
      </div>
    </div>
  )
}

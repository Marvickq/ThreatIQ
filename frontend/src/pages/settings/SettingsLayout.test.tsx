// Routing tests for the Settings sidebar. Rendered on the server (no DOM) with a memory router; the pages themselves
// are stubbed because only link targets, active state and permission gating are under test here.
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '@/i18n/I18nProvider'

let caps = new Set<string>()
vi.mock('@/auth/AuthProvider', () => ({ useAuth: () => ({ me: null, can: (c: string) => caps.has(c) }) }))
vi.mock('./AccountSettings', () => ({ default: ({ section }: { section: string }) => <p>account-page:{section}</p> }))
vi.mock('./IntegrationSettings', () => ({ ApiKeysSettings: () => <p>api-keys-page</p>, IntegrationsSettings: () => <p>integrations-page</p> }))
vi.mock('./OrgSettings', () => ({
  AuditSettings: () => <p>audit-page</p>, MembersSettings: () => <p>members-page</p>,
  OrganizationSettings: () => <p>organization-page</p>, SystemSettings: () => <p>system-page</p>,
}))

import SettingsLayout, { SETTINGS_DEFAULT, SETTINGS_SECTIONS } from './SettingsLayout'

const ALL = ['org:manage', 'members:manage', 'integrations:manage', 'apikeys:manage']

function render(path: string, granted: string[]) {
  caps = new Set(granted)
  return renderToStaticMarkup(
    <I18nProvider><MemoryRouter initialEntries={[path]}><Routes><Route path="settings/*" element={<SettingsLayout />} /></Routes></MemoryRouter></I18nProvider>,
  )
}
const hrefs = (html: string) => [...html.matchAll(/<a [^>]*href="([^"]+)"/g)].map((m) => m[1])

describe('Settings sidebar links', () => {
  it('has a stable absolute route for each of the 8 sections', () => {
    expect(hrefs(render('/settings/account', ALL))).toEqual(SETTINGS_SECTIONS.map((s) => `/settings/${s}`))
  })

  it.each([
    '/settings/security', '/settings/security/', '/settings/account', '/settings/audit', '/settings/api-keys',
  ])('never appends a section to the current URL (regression: /settings/security/account) at %s', (path) => {
    const links = hrefs(render(path, ALL))
    expect(links).toHaveLength(8)
    for (const href of links) {
      expect(href).toMatch(/^\/settings\/[a-z-]+$/)  // exactly one section segment
      expect(href.split('/').filter(Boolean)).toHaveLength(2)
    }
  })

  it('marks only the current section as active', () => {
    const html = render('/settings/security', ALL)
    const active = [...html.matchAll(/<a [^>]*aria-current="page"[^>]*href="([^"]+)"|<a [^>]*href="([^"]+)"[^>]*aria-current="page"/g)].map((m) => m[1] ?? m[2])
    expect(active).toEqual(['/settings/security'])
  })

  it('default route is the profile section', () => {
    expect(SETTINGS_DEFAULT).toBe('/settings/account')
  })
})

describe('Settings permission gating', () => {
  it('shows every section to an administrator', () => {
    const html = render('/settings/system', ALL)
    expect(html).toContain('system-page')
  })

  it('hides admin sections from a user without capabilities, keeping Profile and Security', () => {
    expect(hrefs(render('/settings/account', []))).toEqual(['/settings/account', '/settings/security'])
  })

  it.each([['organization', 'organization-page'], ['members', 'members-page'], ['integrations', 'integrations-page'], ['api-keys', 'api-keys-page'], ['audit', 'audit-page'], ['system', 'system-page']])(
    'direct navigation to /settings/%s shows permission-denied, not the page, without the capability', (section, marker) => {
      const html = render(`/settings/${section}`, [])
      expect(html).not.toContain(marker)
      expect(html).toContain('Your role does not include access to this area.')
    })

  it('renders profile and security for any signed-in user on direct navigation', () => {
    expect(render('/settings/account', [])).toContain('account-page:profile')
    expect(render('/settings/security', [])).toContain('account-page:security')
  })
})

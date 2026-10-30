/**
 * Message catalogs. To add a language: create a catalog with the same keys, register it in CATALOGS,
 * and set the user's or organization's locale. Missing keys fall back to English, then to the key.
 */
export const en = {
  'app.name': 'ThreatIQ',
  'nav.dashboard': 'Dashboard',
  'nav.alerts': 'Alerts',
  'nav.settings': 'Settings',
  'nav.signOut': 'Sign out',
  'nav.menu': 'Menu',
  'common.loading': 'Loading…',
  'common.retry': 'Retry',
  'common.cancel': 'Cancel',
  'common.save': 'Save',
  'common.refresh': 'Refresh',
  'common.search': 'Search',
  'common.clearFilters': 'Clear filters',
  'common.none': 'None',
  'common.demo': 'Demo',
  'status.new': 'New',
  'status.investigating': 'Investigating',
  'status.awaiting_review': 'Awaiting review',
  'status.resolved': 'Resolved',
  'severity.critical': 'Critical',
  'severity.high': 'High',
  'severity.medium': 'Medium',
  'severity.low': 'Low',
  'classification.likely_true_positive': 'Likely true positive',
  'classification.likely_false_positive': 'Likely false positive',
  'classification.needs_review': 'Needs review',
  'decision.true_positive': 'True positive',
  'decision.false_positive': 'False positive',
  'decision.needs_further_review': 'Needs further review',
  'role.owner': 'Owner',
  'role.admin': 'Administrator',
  'role.analyst': 'Analyst',
  'role.viewer': 'Read-only viewer',
  'error.offline': 'You are offline. Showing the last data received.',
  'error.stale': 'Could not refresh. Showing data from {time}.',
  'error.forbidden': 'You do not have permission to view this.',
  'error.generic': 'Something went wrong.',
  'event.alert_created': 'Alert created',
  'event.alert_occurrence_recorded': 'Repeat occurrence recorded',
  'event.assessment_started': 'Assessment started',
  'event.assessment_completed': 'Assessment completed',
  'event.assessment_failed': 'Assessment failed',
  'event.decision_recorded': 'Decision recorded',
  'event.status_changed': 'Status changed',
  'event.severity_changed': 'Severity changed',
  'event.alert_assigned': 'Alert assigned',
  'event.enrichment_completed': 'Enrichment completed',
} as const

export type MessageKey = keyof typeof en
export type Catalog = Partial<Record<MessageKey, string>>

export const CATALOGS: Record<string, Catalog> = { en }

export function translate(locale: string, key: MessageKey | string, params?: Record<string, string | number>): string {
  const lang = locale.split(/[-_]/)[0].toLowerCase()
  const template = (CATALOGS[lang] as Record<string, string> | undefined)?.[key] ?? (en as Record<string, string>)[key] ?? key
  return params ? template.replace(/\{(\w+)\}/g, (_, k) => String(params[k] ?? `{${k}}`)) : template
}

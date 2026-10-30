/** Zod schemas for API responses. A response that does not match is rejected, never half-rendered. */
import { z } from 'zod'

const iso = z.string()
const role = z.enum(['viewer', 'analyst', 'admin', 'owner'])
export type Role = z.infer<typeof role>

export const severity = z.enum(['low', 'medium', 'high', 'critical'])
export type Severity = z.infer<typeof severity>
export const alertStatus = z.enum(['new', 'investigating', 'awaiting_review', 'resolved'])
export type AlertStatus = z.infer<typeof alertStatus>

// ---------------------------------------------------------------- account
export const user = z.object({
  id: z.string(), email: z.string(), display_name: z.string(), locale: z.string().nullable(), timezone: z.string().nullable(),
  notification_prefs: z.record(z.string(), z.unknown()), created_at: iso, last_login_at: iso.nullable(),
})
export type User = z.infer<typeof user>

export const organization = z.object({
  id: z.string(), name: z.string(), slug: z.string(), default_locale: z.string(), default_timezone: z.string(),
  retention_days: z.number(), allow_external_enrichment: z.boolean(), created_at: iso,
})
export type Organization = z.infer<typeof organization>

export const me = z.object({
  user, organization, role,
  memberships: z.array(z.object({ organization_id: z.string(), organization_name: z.string(), role })),
  csrf_token: z.string(), capabilities: z.array(z.string()), demo_data_allowed: z.boolean(),
  security: z.object({
    password_min_length: z.number(), session_ttl_hours: z.number(), login_max_failures: z.number(), login_lockout_minutes: z.number(),
    sso_user: z.boolean(), sso_available: z.boolean(),
  }),
})
export type Me = z.infer<typeof me>

export const sessionInfo = z.object({
  id: z.string(), created_at: iso, last_seen_at: iso, expires_at: iso, ip: z.string().nullable(), user_agent: z.string().nullable(), current: z.boolean(),
})
export type SessionInfo = z.infer<typeof sessionInfo>

export const member = z.object({ user_id: z.string(), email: z.string(), display_name: z.string(), role, joined_at: iso, last_login_at: iso.nullable() })
export type Member = z.infer<typeof member>

export const apiKey = z.object({
  id: z.string(), name: z.string(), prefix: z.string(), scopes: z.array(z.string()), created_at: iso, expires_at: iso.nullable(),
  revoked_at: iso.nullable(), last_used_at: iso.nullable(), use_count: z.number(),
})
export type ApiKey = z.infer<typeof apiKey>
export const apiKeyCreated = apiKey.extend({ key: z.string() })

export const notification = z.object({
  id: z.string(), kind: z.string(), title: z.string(), body: z.string().nullable(), severity: z.string().nullable(),
  link: z.string().nullable(), read_at: iso.nullable(), created_at: iso,
})
export type Notification = z.infer<typeof notification>

// ---------------------------------------------------------------- alerts
export const alertSummary = z.object({
  id: z.string(), title: z.string(), severity, source: z.string(), affected_entity: z.string().nullable(), status: alertStatus,
  is_demo: z.boolean(), occurrence_count: z.number(), assigned_to: z.string().nullable(), created_at: iso, last_seen_at: iso.nullable(),
})
export type AlertSummary = z.infer<typeof alertSummary>
export const alertList = z.object({ items: z.array(alertSummary), total: z.number(), limit: z.number(), offset: z.number() })
export const alertDetail = alertSummary.extend({
  description: z.string(), updated_at: iso, first_seen_at: iso.nullable(), external_id: z.string().nullable(), assigned_to_name: z.string().nullable().optional(),
})
export type AlertDetail = z.infer<typeof alertDetail>

const dashboardFilters = z.object({
  data_scope: z.enum(['real', 'demo', 'all']), severity: z.string().nullable(), status: z.string().nullable(),
  assigned_to: z.string().nullable(), review_state: z.string().nullable(),
})
export const dashboard = z.object({
  generated_at: iso, filters: dashboardFilters, sources: z.object({ real: z.number(), demo: z.number() }),
  total: z.number(), unresolved: z.number(), high_or_critical: z.number(), awaiting_review: z.number(), unreviewed: z.number(),
  recent_alerts: z.array(z.object({ id: z.string(), title: z.string(), severity: z.string(), status: z.string(), source: z.string(), created_at: iso, is_demo: z.boolean() })),
  activity: z.array(z.object({ id: z.string(), event_type: z.string(), actor_type: z.string(), alert_id: z.string().nullable(), created_at: iso })),
})
export type Dashboard = z.infer<typeof dashboard>
export type DashboardFilters = z.infer<typeof dashboardFilters>

export const severityDistribution = z.object({
  generated_at: iso, filters: dashboardFilters, total: z.number(), items: z.array(z.object({ severity: z.string(), count: z.number() })),
})
export const dailyCounts = z.object({
  generated_at: iso, filters: dashboardFilters, timezone: z.literal('UTC'), days: z.number(), total: z.number(),
  items: z.array(z.object({ date: z.string(), count: z.number() })),
})
export const investigationQueues = z.object({
  generated_at: iso, filters: dashboardFilters,
  items: z.array(z.object({ key: z.string(), label: z.string(), count: z.number(), query: z.record(z.string(), z.string()).nullable() })),
})

export const evidenceRef = z.object({ source_type: z.string(), source_id: z.string(), claim: z.string(), evidence: z.string() })
export const assessment = z.object({
  id: z.string(), model_name: z.string(), suggested_classification: z.enum(['likely_true_positive', 'likely_false_positive', 'needs_review']),
  summary: z.string(), observed_facts: z.array(z.string()).default([]), interpretation: z.string().nullable().optional(),
  evidence: z.array(evidenceRef), missing_information: z.array(z.string()), recommended_steps: z.array(z.string()),
  version: z.number(), prompt_version: z.string().nullable(), model_params: z.record(z.string(), z.unknown()),
  evidence_ids: z.array(z.record(z.string(), z.unknown())), created_at: iso,
})
export type Assessment = z.infer<typeof assessment>

export const decision = z.object({
  id: z.string(), assessment_id: z.string().nullable(), decision: z.enum(['true_positive', 'false_positive', 'needs_further_review']),
  reviewer_note: z.string().nullable(), reviewer_id: z.string().nullable(), reviewer_name: z.string().nullable().optional(), created_at: iso,
})
export type Decision = z.infer<typeof decision>

export const auditEvent = z.object({
  id: z.string(), event_type: z.string(), actor_type: z.string(), actor_id: z.string().nullable(), details: z.record(z.string(), z.unknown()), created_at: iso,
})
export const history = z.object({ alert_id: z.string(), events: z.array(auditEvent), assessments: z.array(assessment), decisions: z.array(decision) })
export type History = z.infer<typeof history>

export const relatedIncidents = z.object({
  enabled: z.boolean(),
  items: z.array(z.object({
    id: z.string(), kind: z.enum(['historical_alert', 'demo_incident']), description: z.string(), outcome: z.string(), details: z.string(),
    matched_terms: z.array(z.string()), score: z.number(),
  })),
})

export const evidenceItem = z.object({
  id: z.string(), alert_id: z.string(), source_type: z.string(), source_id: z.string(), title: z.string(), url: z.string().nullable(),
  provider_status: z.string(), content: z.record(z.string(), z.unknown()), content_hash: z.string(), confidence: z.number().nullable(),
  retrieved_at: iso, expires_at: iso.nullable(), stale: z.boolean(),
})
export type EvidenceItem = z.infer<typeof evidenceItem>
export const evidenceList = z.object({ items: z.array(evidenceItem) })

export const indicator = z.object({ type: z.string(), value: z.string() })

export const job = z.object({
  id: z.string(), kind: z.string(), status: z.string(), progress: z.number(), message: z.string().nullable(), subject_id: z.string().nullable(),
  result: z.record(z.string(), z.unknown()), error: z.string().nullable(), attempts: z.number(), created_at: iso, started_at: iso.nullable(), finished_at: iso.nullable(),
})
export type Job = z.infer<typeof job>
export const jobList = z.object({ items: z.array(job), total: z.number() })

export const providerStatus = z.object({
  provider: z.string(), configured: z.boolean(), available: z.boolean(), detail: z.string(), last_refreshed_at: iso.nullable().optional(),
})
export type ProviderStatus = z.infer<typeof providerStatus>

export const integration = z.object({
  id: z.string(), kind: z.string(), name: z.string(), enabled: z.boolean(), config: z.record(z.string(), z.unknown()), status: z.string(),
  has_credentials: z.boolean(), last_sync_at: iso.nullable(), last_success_at: iso.nullable(), last_error: z.string().nullable(), created_at: iso,
})
export type Integration = z.infer<typeof integration>

export const auditLog = z.object({
  total: z.number(), event_types: z.array(z.string()),
  items: z.array(z.object({
    id: z.string(), event_type: z.string(), actor_type: z.string(), actor_id: z.string().nullable(), actor_name: z.string().nullable(), alert_id: z.string().nullable(),
    details: z.record(z.string(), z.unknown()), created_at: iso,
  })),
})

export const systemStatus = z.object({
  version: z.string(), environment: z.string(), redis: z.string(), artifact_storage: z.string(),
  database: z.object({ engine: z.string(), reachable: z.boolean(), revision: z.string().nullable(), head: z.string().nullable(), up_to_date: z.boolean() }),
  sso: z.object({ entra_configured: z.boolean(), organization_bound: z.boolean() }),
  ai: z.object({ configured: z.boolean(), model: z.string().nullable() }),
  jobs: z.object({ queued: z.number(), running: z.number(), workers: z.number(), backend: z.string() }),
  sentry: z.boolean(), opentelemetry: z.boolean(),
})

export const bulkResult = z.object({ updated: z.number(), unchanged: z.number(), not_found: z.array(z.string()) })
export const testResult = z.object({ ok: z.boolean(), message: z.string() })

// ---------------------------------------------------------------- investigation reports
export const REPORT_CLASSIFICATIONS = ['Public', 'Internal', 'Confidential', 'Restricted'] as const
export const report = z.object({
  id: z.string(), alert_id: z.string(), report_number: z.string(), status: z.enum(['generated', 'failed']), classification: z.string(),
  generated_by: z.string().nullable(), generated_by_name: z.string().nullable().optional(), assessment_id: z.string().nullable(), decision_id: z.string().nullable(),
  evidence_count: z.number(), error_code: z.string().nullable(), size_bytes: z.number().nullable(), sha256: z.string().nullable(), created_at: iso,
})
export type Report = z.infer<typeof report>

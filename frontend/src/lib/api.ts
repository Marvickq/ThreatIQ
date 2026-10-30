import { z } from 'zod'
import * as S from './schemas'

const BASE = (import.meta.env.VITE_API_URL as string | undefined) ?? '/api/v1'
const DEFAULT_TIMEOUT_MS = 20_000
const CSRF_COOKIE = 'tiq_csrf'

export class ApiError extends Error {
  readonly code: string
  readonly status: number
  readonly requestId: string | null
  readonly details: unknown

  constructor(code: string, message: string, status: number, requestId: string | null = null, details?: unknown) {
    super(message)
    this.code = code
    this.status = status
    this.requestId = requestId
    this.details = details
  }

  get isNetwork() { return this.code === 'NETWORK' }
  get isForbidden() { return this.status === 403 }
  get isUnauthenticated() { return this.status === 401 }
  get isNotFound() { return this.status === 404 }
}

/** Fired when the server says the session is gone, so the app can send the user to sign-in. */
export const SESSION_EXPIRED_EVENT = 'threatiq:session-expired'

function csrfToken(): string {
  const match = document.cookie.split('; ').find((c) => c.startsWith(`${CSRF_COOKIE}=`))
  return match ? decodeURIComponent(match.slice(CSRF_COOKIE.length + 1)) : ''
}

type Query = Record<string, string | number | boolean | null | undefined>
interface Options {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  body?: unknown
  query?: Query
  signal?: AbortSignal
  timeoutMs?: number
  headers?: Record<string, string>
}

async function request<T>(path: string, schema: z.ZodType<T> | null, opts: Options = {}): Promise<T> {
  const method = opts.method ?? 'GET'
  const url = new URL(`${BASE}${path}`, window.location.origin)
  for (const [k, v] of Object.entries(opts.query ?? {})) {
    if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v))
  }
  const timeout = AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS)
  const signal = opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout

  const headers: Record<string, string> = { Accept: 'application/json', ...opts.headers }
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken()

  let response: Response
  try {
    response = await fetch(url, { method, headers, credentials: 'include', signal, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined })
  } catch (err) {
    if (opts.signal?.aborted) throw err
    if (timeout.aborted) throw new ApiError('TIMEOUT', 'The request took too long. Try again.', 0)
    throw new ApiError('NETWORK', navigator.onLine ? 'Cannot reach the ThreatIQ server.' : 'You appear to be offline.', 0)
  }

  if (!response.ok) {
    const body = await response.json().catch(() => null)
    const e = body?.error
    if (response.status === 401 && path !== '/auth/login' && path !== '/auth/me') window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT))
    throw new ApiError(e?.code ?? 'REQUEST_FAILED', e?.message ?? `Request failed (${response.status}).`, response.status, e?.request_id ?? null, e?.details)
  }
  if (response.status === 204 || schema === null) return undefined as T
  const json = await response.json().catch(() => {
    throw new ApiError('INVALID_RESPONSE', 'The server sent an unreadable response.', response.status)
  })
  const parsed = schema.safeParse(json)
  if (!parsed.success) {
    console.error('Response validation failed', path, parsed.error.issues.slice(0, 3))
    throw new ApiError('INVALID_RESPONSE', 'The server response did not match what this app expects. Reload, or contact support.', response.status)
  }
  return parsed.data
}

/** Fetches a binary file with the session cookie. Errors are reported exactly like JSON requests. */
async function download(path: string): Promise<{ blob: Blob; filename: string }> {
  const url = new URL(`${BASE}${path}`, window.location.origin)
  let response: Response
  try {
    response = await fetch(url, { credentials: 'include', signal: AbortSignal.timeout(60_000) })
  } catch {
    throw new ApiError('NETWORK', navigator.onLine ? 'Cannot reach the ThreatIQ server.' : 'You appear to be offline.', 0)
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    const e = body?.error
    if (response.status === 401) window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT))
    throw new ApiError(e?.code ?? 'REQUEST_FAILED', e?.message ?? `Request failed (${response.status}).`, response.status, e?.request_id ?? null)
  }
  const filename = /filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') ?? '')?.[1] ?? 'report.pdf'
  return { blob: await response.blob(), filename }
}

export interface AlertQuery {
  q?: string; severity?: string; status?: string; source?: string; assigned_to?: string
  review_state?: string; data_scope?: string; unresolved?: string
  sort?: string; order?: 'asc' | 'desc'; limit?: number; offset?: number
}

export interface DashboardFilterQuery { data_scope?: string; severity?: string; status?: string; assigned_to?: string; review_state?: string }

export const api = {
  auth: {
    me: (signal?: AbortSignal) => request('/auth/me', S.me, { signal }),
    login: (email: string, password: string) => request('/auth/login', S.me, { method: 'POST', body: { email, password } }),
    register: (b: { email: string; password: string; display_name: string; organization_name: string }) => request('/auth/register', S.me, { method: 'POST', body: b }),
    logout: () => request('/auth/logout', null, { method: 'POST' }),
    ssoConfig: () => request('/auth/sso/config', z.object({ entra_enabled: z.boolean() })),
    updateProfile: (b: Record<string, unknown>) => request('/auth/me', S.me, { method: 'PATCH', body: b }),
    switchOrganization: (organization_id: string) => request('/auth/switch-organization', S.me, { method: 'POST', body: { organization_id } }),
    changePassword: (current_password: string, new_password: string) => request('/auth/change-password', null, { method: 'POST', body: { current_password, new_password } }),
    sessions: () => request('/auth/sessions', z.array(S.sessionInfo)),
    revokeSession: (id: string) => request(`/auth/sessions/${encodeURIComponent(id)}`, null, { method: 'DELETE' }),
  },
  org: {
    get: () => request('/organization', S.organization),
    update: (b: Record<string, unknown>) => request('/organization', S.organization, { method: 'PATCH', body: b }),
    members: () => request('/organization/members', z.array(S.member)),
    addMember: (email: string, role: string) => request('/organization/members', S.member, { method: 'POST', body: { email, role } }),
    setRole: (userId: string, role: string) => request(`/organization/members/${encodeURIComponent(userId)}`, S.member, { method: 'PATCH', body: { role } }),
    removeMember: (userId: string) => request(`/organization/members/${encodeURIComponent(userId)}`, null, { method: 'DELETE' }),
    loadDemoData: () => request('/organization/demo-data', z.object({ created: z.number() }), { method: 'POST' }),
    auditLog: (q: { limit?: number; offset?: number; event_type?: string; since?: string; until?: string }) => request('/audit-events', S.auditLog, { query: q }),
    systemStatus: () => request('/system/status', S.systemStatus),
  },
  keys: {
    list: () => request('/api-keys', z.array(S.apiKey)),
    create: (b: { name: string; scopes: string[]; expires_in_days: number | null }) => request('/api-keys', S.apiKeyCreated, { method: 'POST', body: b }),
    revoke: (id: string) => request(`/api-keys/${encodeURIComponent(id)}`, S.apiKey, { method: 'DELETE' }),
    rotate: (id: string) => request(`/api-keys/${encodeURIComponent(id)}/rotate`, S.apiKeyCreated, { method: 'POST' }),
  },
  alerts: {
    list: (q: AlertQuery, signal?: AbortSignal) => request('/alerts', S.alertList, { query: q as Query, signal }),
    get: (id: string) => request(`/alerts/${encodeURIComponent(id)}`, S.alertDetail),
    history: (id: string) => request(`/alerts/${encodeURIComponent(id)}/history`, S.history),
    related: (id: string) => request(`/alerts/${encodeURIComponent(id)}/related-incidents`, S.relatedIncidents),
    evidence: (id: string) => request(`/alerts/${encodeURIComponent(id)}/evidence`, S.evidenceList),
    indicators: (id: string) => request(`/alerts/${encodeURIComponent(id)}/indicators`, z.array(S.indicator)),
    bulkStatus: (alert_ids: string[], status: string) => request('/alerts/bulk-status', S.bulkResult, { method: 'POST', body: { alert_ids, status } }),
    assign: (id: string, user_id: string | null) => request(`/alerts/${encodeURIComponent(id)}/assignee`, S.alertDetail, { method: 'PUT', body: { user_id } }),
    decide: (id: string, b: { decision: string; reviewer_note: string | null; assessment_id: string | null }) =>
      request(`/alerts/${encodeURIComponent(id)}/decisions`, S.decision, { method: 'POST', body: b }),
    analyze: (id: string) => request(`/alerts/${encodeURIComponent(id)}/analyze`, S.job, { method: 'POST' }),
    enrich: (id: string, force = false) => request(`/alerts/${encodeURIComponent(id)}/enrich`, S.job, { method: 'POST', query: { force } }),
    reports: {
      list: (id: string) => request(`/alerts/${encodeURIComponent(id)}/reports`, z.array(S.report)),
      generate: (id: string, classification: string) =>
        request(`/alerts/${encodeURIComponent(id)}/reports`, S.report, { method: 'POST', body: { classification }, timeoutMs: 60_000 }),
      download: (id: string, reportId: string) => download(`/alerts/${encodeURIComponent(id)}/reports/${encodeURIComponent(reportId)}/download`),
    },
  },
  dashboard: {
    summary: (f: DashboardFilterQuery, signal?: AbortSignal) => request('/dashboard/summary', S.dashboard, { query: f as Query, signal }),
    severity: (f: DashboardFilterQuery, signal?: AbortSignal) => request('/dashboard/severity', S.severityDistribution, { query: f as Query, signal }),
    daily: (f: DashboardFilterQuery, signal?: AbortSignal) => request('/dashboard/daily', S.dailyCounts, { query: f as Query, signal }),
    queues: (f: DashboardFilterQuery, signal?: AbortSignal) => request('/dashboard/queues', S.investigationQueues, { query: f as Query, signal }),
  },
  jobs: {
    list: (q: { status?: string; kind?: string; subject_id?: string; limit?: number }) => request('/jobs', S.jobList, { query: q }),
    get: (id: string) => request(`/jobs/${encodeURIComponent(id)}`, S.job),
    retry: (id: string) => request(`/jobs/${encodeURIComponent(id)}/retry`, S.job, { method: 'POST' }),
  },
  intel: {
    status: () => request('/intel/status', z.array(S.providerStatus)),
    refresh: () => request('/intel/refresh', S.job, { method: 'POST' }),
  },
  integrations: {
    list: () => request('/integrations', z.array(S.integration)),
    create: (b: { kind: string; name: string; config: Record<string, unknown>; credentials: Record<string, unknown> }) =>
      request('/integrations', S.integration, { method: 'POST', body: b }),
    update: (id: string, b: Record<string, unknown>) => request(`/integrations/${encodeURIComponent(id)}`, S.integration, { method: 'PATCH', body: b }),
    test: (id: string) => request(`/integrations/${encodeURIComponent(id)}/test`, S.testResult, { method: 'POST', timeoutMs: 40_000 }),
    sync: (id: string) => request(`/integrations/${encodeURIComponent(id)}/sync`, S.job, { method: 'POST' }),
  },
  notifications: {
    list: () => request('/notifications', z.array(S.notification)),
    readAll: () => request('/notifications/read-all', null, { method: 'POST' }),
  },
}

/** Full-page navigation target: the backend runs the Microsoft sign-in and sets the session cookie itself. */
export const entraLoginUrl = (next: string) => `${BASE}/auth/sso/entra/login?next=${encodeURIComponent(next)}`

export const EVENTS_URL =`${BASE}/events/stream`

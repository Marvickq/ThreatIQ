import { useEffect, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, ExternalLink, FileText, History as HistoryIcon, RefreshCw, ShieldCheck } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { useAuth } from '@/auth/AuthProvider'
import { DemoBadge, EmptyState, ErrorState, LoadingBlock, SectionCard, SeverityBadge, Spinner, StaleBanner, StatusBadge } from '@/components/common'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { NativeSelect } from '@/components/ui/native-select'
import { Textarea } from '@/components/ui/textarea'
import { useI18n } from '@/i18n/I18nProvider'
import { api, ApiError } from '@/lib/api'
import { REPORT_CLASSIFICATIONS, type Assessment, type Decision, type EvidenceItem, type Job, type Report } from '@/lib/schemas'
import NotFoundPage from './NotFound'

const SOURCE_LABEL: Record<string, string> = {
  alert: 'Original alert', historical_alert: 'Historical alert', demo_incident: 'Demo incident',
  cisa_kev: 'CISA KEV', nvd: 'NIST NVD', virustotal: 'VirusTotal',
}
const DECISIONS = ['true_positive', 'false_positive', 'needs_further_review'] as const

const active = (j?: Job | null) => !!j && (j.status === 'queued' || j.status === 'running')

// ---------------------------------------------------------------- job tracking
/** Tracks one background job: polls as a fallback; live SSE events update the same cache entry. */
function useJob(jobId: string | null) {
  return useQuery({
    queryKey: ['job', jobId],
    queryFn: () => api.jobs.get(jobId!),
    enabled: !!jobId,
    refetchInterval: (q) => (active(q.state.data) || !q.state.data ? 2500 : false),
  })
}

function JobProgress({ job, label }: { job: Job; label: string }) {
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    const start = new Date(job.created_at.endsWith('Z') ? job.created_at : `${job.created_at}Z`).getTime()
    const tick = () => setElapsed(Math.max(0, Math.round((Date.now() - start) / 1000)))
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [job.created_at])
  return (
    <div role="status" aria-live="polite" className="border p-3 text-sm">
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-2"><Spinner />{label}</span>
        <span className="font-mono text-xs text-muted-foreground">{elapsed}s</span>
      </div>
      <div className="mt-2 h-1.5 w-full bg-accent" aria-hidden="true"><div className="h-full bg-primary transition-all" style={{ width: `${Math.max(5, job.progress)}%` }} /></div>
      <p className="mt-2 text-xs text-muted-foreground">{job.message ?? 'Working…'} · You can leave this page; the work continues on the server.</p>
    </div>
  )
}

// ---------------------------------------------------------------- AI assessment
function AssessmentView({ a, evidenceById }: { a: Assessment; evidenceById: Map<string, EvidenceItem> }) {
  const { t, formatDateTime } = useI18n()
  return (
    <div className="space-y-5">
      <div>
        <Badge variant="outline" className="border-warning/60 font-mono text-[11px] uppercase text-warning">AI recommendation · not yet verified</Badge>
        <p className="mt-3 text-xs text-muted-foreground">Suggested classification</p>
        <p className="text-2xl font-bold">{t(`classification.${a.suggested_classification}`)}</p>
      </div>
      <div><h3 className="text-sm font-medium">Summary</h3><p className="mt-1 leading-relaxed text-foreground/90">{a.summary}</p></div>

      {a.observed_facts.length > 0 && (
        <div><h3 className="text-sm font-medium">Observed facts <span className="font-normal text-muted-foreground">(taken from the evidence)</span></h3>
          <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-foreground/90">{a.observed_facts.map((f, i) => <li key={i}>{f}</li>)}</ul></div>
      )}
      {a.interpretation && (
        <div><h3 className="text-sm font-medium">Interpretation <span className="font-normal text-muted-foreground">(the model&apos;s reasoning, not fact)</span></h3>
          <p className="mt-1 text-sm text-foreground/90">{a.interpretation}</p></div>
      )}

      <div>
        <h3 className="text-sm font-medium">Evidence cited</h3>
        {a.evidence.length === 0 ? <p className="mt-1 text-sm text-muted-foreground">No supporting evidence was cited. Additional investigation is required.</p> : (
          <ul className="mt-2 space-y-2">
            {a.evidence.map((e, i) => {
              const stored = [...evidenceById.values()].find((x) => x.source_type === e.source_type && x.source_id === e.source_id)
              return (
                <li key={i} className="border p-3">
                  <p className="font-mono text-[11px] text-muted-foreground">{SOURCE_LABEL[e.source_type] ?? e.source_type} · {e.source_id.length > 20 ? e.source_id.slice(0, 8) : e.source_id}{stored?.retrieved_at && <> · retrieved {formatDateTime(stored.retrieved_at)}</>}</p>
                  <p className="mt-1 text-sm font-medium">{e.claim}</p>
                  <p className="mt-1 text-sm text-muted-foreground">{e.evidence}</p>
                </li>
              )
            })}
          </ul>
        )}
        <p className="mt-2 text-xs text-muted-foreground">Every citation was checked against the stored evidence sent to the model. The wording is the model&apos;s and is not independently verified.</p>
      </div>

      <div><h3 className="text-sm font-medium">Missing or conflicting information</h3>
        {a.missing_information.length === 0 ? <p className="mt-1 text-sm text-muted-foreground">None identified.</p> :
          <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-foreground/90">{a.missing_information.map((m, i) => <li key={i}>{m}</li>)}</ul>}</div>

      <div><h3 className="text-sm font-medium">Recommended next steps</h3><p className="text-xs text-muted-foreground">Guidance for the analyst. Nothing is executed automatically.</p>
        <ol className="mt-1 list-decimal space-y-1 pl-5 text-sm text-foreground/90">{a.recommended_steps.map((s, i) => <li key={i}>{s}</li>)}</ol></div>

      <details className="border p-3 text-xs">
        <summary className="cursor-pointer font-mono uppercase text-muted-foreground">How this assessment was produced</summary>
        <dl className="mt-2 grid grid-cols-[9rem_1fr] gap-y-1 font-mono">
          <dt className="text-muted-foreground">Model</dt><dd className="break-all">{a.model_name}</dd>
          <dt className="text-muted-foreground">Prompt version</dt><dd>{a.prompt_version ?? '—'}</dd>
          <dt className="text-muted-foreground">Version</dt><dd>#{a.version}</dd>
          <dt className="text-muted-foreground">Settings</dt><dd className="break-all">{JSON.stringify(a.model_params)}</dd>
          <dt className="text-muted-foreground">Evidence sent</dt><dd>{a.evidence_ids.length} item(s)</dd>
          <dt className="text-muted-foreground">Created</dt><dd>{formatDateTime(a.created_at)}</dd>
        </dl>
      </details>
    </div>
  )
}

function AssessmentPanel({ alertId, assessments, evidenceById, canWrite }: { alertId: string; assessments: Assessment[]; evidenceById: Map<string, EvidenceItem>; canWrite: boolean }) {
  const qc = useQueryClient()
  const [jobId, setJobId] = useState<string | null>(null)
  const [viewing, setViewing] = useState<string | null>(null)
  const { t, formatDateTime } = useI18n()

  // Resume tracking if an analysis is already running (e.g. started from another tab or before a reload).
  const recent = useQuery({ queryKey: ['jobs', 'analyze', alertId], queryFn: () => api.jobs.list({ subject_id: alertId, kind: 'analyze', limit: 3 }), refetchInterval: 10_000 })
  const running = recent.data?.items.find(active)
  const trackedId = jobId ?? running?.id ?? null
  const job = useJob(trackedId)

  const start = useMutation({
    mutationFn: () => api.alerts.analyze(alertId),
    onSuccess: (j) => { setJobId(j.id); qc.setQueryData(['job', j.id], j) },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : 'Could not start the analysis'),
  })
  const done = job.data?.status
  useEffect(() => {
    if (done === 'succeeded') { qc.invalidateQueries({ queryKey: ['alert', alertId] }); qc.invalidateQueries({ queryKey: ['alerts'] }); setViewing(null) }
  }, [done, alertId, qc])

  const latest = assessments[assessments.length - 1]
  const shown = assessments.find((a) => a.id === viewing) ?? latest
  const busy = active(job.data) || start.isPending
  const failed = job.data?.status === 'failed'

  return (
    <div className="space-y-4">
      {busy && job.data && <JobProgress job={job.data} label="Generating the investigation assessment" />}
      {busy && !job.data && <div role="status" className="flex items-center gap-2 text-sm"><Spinner />Starting analysis…</div>}
      {failed && (
        <div role="alert" className="border border-danger/40 p-3 text-sm">
          <p className="font-medium text-danger">The analysis did not complete</p>
          <p className="mt-1 text-muted-foreground">{job.data?.error ?? 'Unknown error.'}</p>
          {latest && <p className="mt-1 text-xs text-muted-foreground">The previous assessment is unchanged.</p>}
        </div>
      )}

      {shown ? <AssessmentView a={shown} evidenceById={evidenceById} /> : !busy && <p className="text-sm text-muted-foreground">No assessment has been generated for this alert yet.</p>}

      {assessments.length > 1 && (
        <label className="flex items-center gap-2 text-xs text-muted-foreground">Version
          <NativeSelect value={shown?.id} onChange={(e) => setViewing(e.target.value)} className="h-8">
            {[...assessments].reverse().map((a) => <option key={a.id} value={a.id}>#{a.version} · {formatDateTime(a.created_at)}{a.id === latest.id ? ' (latest)' : ''}</option>)}
          </NativeSelect></label>
      )}

      {canWrite ? (
        <Button onClick={() => start.mutate()} disabled={busy} variant={latest && !failed ? 'outline' : 'default'}>
          {busy ? <Spinner /> : <ShieldCheck className="size-4" />}{busy ? 'Analyzing…' : failed ? 'Retry analysis' : latest ? 'Reanalyze' : 'Analyze alert'}
        </Button>
      ) : <p className="text-xs text-muted-foreground">Your role can view assessments but not start them.</p>}
      <p className="text-xs text-muted-foreground">{t('classification.needs_review')} is the safe default when evidence is thin. The AI never closes or changes an alert.</p>
    </div>
  )
}

// ---------------------------------------------------------------- evidence
function EvidenceRow({ e }: { e: EvidenceItem }) {
  const { formatDateTime } = useI18n()
  const c = e.content as Record<string, unknown>
  const text = (v: unknown) => (v === null || v === undefined ? '' : String(v))
  const status = e.provider_status === 'found' ? 'Found' : e.provider_status === 'not_found' ? 'No record' : 'Provider error'
  const cvss = c.cvss as { score?: number; severity?: string; vector?: string; version?: string } | null | undefined
  return (
    <li className="border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{SOURCE_LABEL[e.source_type] ?? e.source_type}</span>
        <span className="font-mono text-xs">{e.source_id}</span>
        <Badge variant="outline" className={`font-mono text-[10px] uppercase ${e.provider_status === 'error' ? 'border-danger/60 text-danger' : e.provider_status === 'not_found' ? 'text-muted-foreground' : 'border-success/60 text-success'}`}>{status}</Badge>
        {e.stale && <Badge variant="outline" className="border-warning/60 font-mono text-[10px] uppercase text-warning">Stale</Badge>}
      </div>
      {e.provider_status === 'found' && (
        <div className="mt-2 space-y-1 text-muted-foreground">
          {e.source_type === 'cisa_kev' && <>
            <p>Listed in the CISA Known Exploited Vulnerabilities catalog: <span className="text-foreground">{text(c.name)}</span> ({text(c.vendor)} {text(c.product)}).</p>
            <p>Added {text(c.date_added)}{c.due_date ? ` · remediation due ${text(c.due_date)}` : ''}{c.known_ransomware_use ? ` · ransomware use: ${text(c.known_ransomware_use)}` : ''}</p>
            {c.required_action ? <p>Required action: {text(c.required_action)}</p> : null}
          </>}
          {e.source_type === 'nvd' && <>
            {cvss ? <p>CVSS {text(cvss.version)}: <span className="font-mono text-foreground">{text(cvss.score)}</span> {text(cvss.severity)} <span className="font-mono text-xs">{text(cvss.vector)}</span></p> : <p>No CVSS score published.</p>}
            <p>{text(c.description)}</p>
          </>}
          {e.source_type === 'virustotal' && <p className="font-mono text-xs">{JSON.stringify(c.last_analysis_stats)} · reputation {text(c.reputation)}</p>}
          {!['cisa_kev', 'nvd', 'virustotal'].includes(e.source_type) && <p>{text(c.description ?? c.title)}</p>}
        </div>
      )}
      {e.provider_status === 'not_found' && <p className="mt-2 text-muted-foreground">The provider has no record for this indicator. That is not evidence that it is safe.</p>}
      {e.provider_status === 'error' && <p className="mt-2 text-danger">The lookup failed: {text(c.error) || 'provider unavailable'}. This is not a negative result; refresh to retry.</p>}
      <p className="mt-2 flex flex-wrap items-center gap-x-3 font-mono text-[11px] text-muted-foreground">
        <span>Retrieved {formatDateTime(e.retrieved_at)}</span>
        {e.expires_at && <span>Fresh until {formatDateTime(e.expires_at)}</span>}
        <span title={e.content_hash}>sha256 {e.content_hash.slice(0, 10)}…</span>
        {e.url?.startsWith('https://') && <a href={e.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 underline underline-offset-4 hover:text-foreground">Source <ExternalLink className="size-3" /></a>}
      </p>
    </li>
  )
}

function EvidenceSection({ alertId, items, canWrite }: { alertId: string; items: EvidenceItem[]; canWrite: boolean }) {
  const qc = useQueryClient()
  const [jobId, setJobId] = useState<string | null>(null)
  const job = useJob(jobId)
  const intel = useQuery({ queryKey: ['intel-status'], queryFn: api.intel.status, staleTime: 60_000 })
  const refresh = useMutation({
    mutationFn: () => api.alerts.enrich(alertId, true),
    onSuccess: (j) => { setJobId(j.id); qc.setQueryData(['job', j.id], j) },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not start enrichment'),
  })
  const st = job.data?.status
  useEffect(() => {
    if (st === 'succeeded' || st === 'failed') qc.invalidateQueries({ queryKey: ['alert', alertId, 'evidence'] })
    if (st === 'failed') toast.error(job.data?.error ?? 'Enrichment failed')
  }, [st, alertId, qc, job.data?.error])
  const intelItems = items.filter((i) => ['cisa_kev', 'nvd', 'virustotal'].includes(i.source_type))
  const busy = active(job.data) || refresh.isPending

  return (
    <SectionCard
      title="Threat intelligence" id="intel" description="Distinguishes a confirmed result, no record, and a provider failure."
      actions={canWrite ? <Button size="sm" variant="outline" onClick={() => refresh.mutate()} disabled={busy}>{busy ? <Spinner /> : <RefreshCw className="size-3.5" />}Refresh</Button> : undefined}
    >
      {busy && job.data && <div className="mb-3"><JobProgress job={job.data} label="Looking up indicators" /></div>}
      {intelItems.length === 0 ? (
        <p className="text-sm text-muted-foreground">No lookups have been run. This alert has no CVE identifiers to look up, or enrichment has not been requested yet.</p>
      ) : <ul className="space-y-2">{intelItems.map((e) => <EvidenceRow key={e.id} e={e} />)}</ul>}
      {intel.data && (
        <ul className="mt-4 space-y-1 border-t pt-3 text-xs text-muted-foreground">
          {intel.data.map((p) => <li key={p.provider}><span className="font-mono uppercase">{p.provider}</span> — {p.available ? 'available' : p.configured ? 'disabled' : 'not configured'}. {p.detail}</li>)}
        </ul>
      )}
    </SectionCard>
  )
}

// ---------------------------------------------------------------- investigation report
const formatBytes = (n: number | null) => (n == null ? '—' : n < 1024 * 1024 ? `${Math.max(1, Math.round(n / 1024))} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`)

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

/** Generates and lists PDF investigation reports. Reports are built on the server from the stored records. */
function ReportsPanel({ alertId, canWrite }: { alertId: string; canWrite: boolean }) {
  const { formatDateTime } = useI18n()
  const qc = useQueryClient()
  const [classification, setClassification] = useState<string>('Confidential')
  const [downloading, setDownloading] = useState<string | null>(null)
  const reports = useQuery({ queryKey: ['alert', alertId, 'reports'], queryFn: () => api.alerts.reports.list(alertId) })
  const refreshLists = () => { for (const k of [['alert', alertId, 'reports'], ['alert', alertId, 'history']]) qc.invalidateQueries({ queryKey: k }) }

  const fetchPdf = async (r: Report) => {
    setDownloading(r.id)
    try {
      const file = await api.alerts.reports.download(alertId, r.id)
      saveBlob(file.blob, file.filename)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'The report could not be downloaded')
    } finally { setDownloading(null) }
  }
  const generate = useMutation({
    mutationFn: () => api.alerts.reports.generate(alertId, classification),
    onSuccess: (r) => { toast.success(`Report ${r.report_number} is ready`, { action: { label: 'Download', onClick: () => void fetchPdf(r) } }); refreshLists() },
    // A failed attempt is kept in the history, so refresh it too.
    onError: (e) => { toast.error(e instanceof Error ? e.message : 'The report could not be generated'); refreshLists() },
  })

  return (
    <SectionCard title="Investigation report" id="reports" description="A PDF snapshot built from this alert's stored evidence, AI assessment, analyst decision and audit history. Nothing is added or assumed.">
      {canWrite ? (
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">Classification
            <NativeSelect value={classification} onChange={(e) => setClassification(e.target.value)} disabled={generate.isPending}>
              {REPORT_CLASSIFICATIONS.map((c) => <option key={c} value={c}>{c}</option>)}
            </NativeSelect></label>
          <Button onClick={() => generate.mutate()} disabled={generate.isPending}>
            {generate.isPending ? <Spinner /> : <FileText className="size-3.5" />}{generate.isPending ? 'Generating report…' : 'Generate report'}
          </Button>
          {generate.isPending && <p role="status" aria-live="polite" className="text-sm text-muted-foreground">Building the PDF from stored records. This usually takes a few seconds.</p>}
        </div>
      ) : <p className="text-sm text-muted-foreground">Your role can download existing reports but not generate new ones.</p>}

      <div className="mt-5">
        <h3 className="mb-2 text-sm font-medium">Report history</h3>
        {reports.isLoading && <LoadingBlock rows={2} />}
        {reports.isError && <ErrorState error={reports.error} onRetry={() => reports.refetch()} compact />}
        {reports.data && reports.data.length === 0 && <p className="text-sm text-muted-foreground">No reports have been generated for this alert yet.</p>}
        {reports.data && reports.data.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                <tr><th className="py-1.5 pr-3">Report</th><th className="pr-3">Generated</th><th className="pr-3">By</th><th className="pr-3">Classification</th><th className="pr-3">Size</th><th className="sr-only">Actions</th></tr>
              </thead>
              <tbody>
                {reports.data.map((r) => (
                  <tr key={r.id} className="border-t">
                    <td className="py-2 pr-3 font-mono text-xs">{r.report_number}</td>
                    <td className="pr-3">{formatDateTime(r.created_at)}</td>
                    <td className="pr-3">{r.generated_by_name ?? '—'}</td>
                    <td className="pr-3">{r.classification}</td>
                    <td className="pr-3">{r.status === 'generated' ? formatBytes(r.size_bytes) : <Badge variant="outline" className="border-danger/40 text-danger" title={r.error_code ?? undefined}>Failed</Badge>}</td>
                    <td className="py-1 text-right">
                      {r.status === 'generated' && (
                        <Button size="sm" variant="outline" onClick={() => void fetchPdf(r)} disabled={downloading === r.id} aria-label={`Download report ${r.report_number}`}>
                          {downloading === r.id ? <Spinner /> : <Download className="size-3.5" />}Download PDF
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </SectionCard>
  )
}

// ---------------------------------------------------------------- human review
function ReviewPanel({ alertId, assessment, latest, canWrite }: { alertId: string; assessment?: Assessment; latest?: Decision; canWrite: boolean }) {
  const { t, formatDateTime } = useI18n()
  const qc = useQueryClient()
  const [decision, setDecision] = useState<string>('')
  const [note, setNote] = useState('')
  const save = useMutation({
    mutationFn: () => api.alerts.decide(alertId, { decision, reviewer_note: note.trim() || null, assessment_id: assessment?.id ?? null }),
    onSuccess: () => {
      toast.success('Decision saved'); setDecision(''); setNote('')
      for (const k of [['alert', alertId], ['alerts'], ['dashboard']]) qc.invalidateQueries({ queryKey: k })
    },
    // Selection and note are kept on failure so the analyst can retry.
    onError: (e) => toast.error(e instanceof Error ? e.message : 'The decision could not be saved'),
  })
  const submit = (e: FormEvent) => { e.preventDefault(); if (decision && !save.isPending) save.mutate() }

  return (
    <SectionCard title="Human review" id="review" description="Your decision is stored separately from the AI recommendation. It never triggers blocking, deletion or remediation.">
      <div className="grid gap-6 lg:grid-cols-2">
        <div className="space-y-4 text-sm">
          <div><h3 className="font-medium">AI recommendation</h3>
            <p className="mt-1 text-muted-foreground">{assessment ? <>{t(`classification.${assessment.suggested_classification}`)} <span className="font-mono text-xs">(not verified)</span></> : 'No AI assessment yet. You can still record a decision.'}</p></div>
          <div><h3 className="font-medium">Latest human decision</h3>
            {latest ? (
              <div className="mt-1 border p-3">
                <p className="font-medium">{t(`decision.${latest.decision}`)}</p>
                <p className="font-mono text-xs text-muted-foreground">{latest.reviewer_name ?? 'Unknown reviewer'} · {formatDateTime(latest.created_at)}</p>
                {latest.reviewer_note && <p className="mt-2 whitespace-pre-wrap text-muted-foreground">{latest.reviewer_note}</p>}
              </div>
            ) : <p className="mt-1 text-muted-foreground">No human decision has been recorded.</p>}</div>
        </div>
        {canWrite ? (
          <form onSubmit={submit}>
            <fieldset disabled={save.isPending} className="space-y-3">
              <legend className="text-sm font-medium">Record a decision</legend>
              {DECISIONS.map((d) => (
                <label key={d} className={`flex cursor-pointer items-center gap-3 border px-3 py-2 text-sm ${decision === d ? 'border-primary bg-primary/10' : 'hover:border-input'}`}>
                  <input type="radio" name="decision" value={d} checked={decision === d} onChange={() => setDecision(d)} className="accent-[#c81b1c]" />{t(`decision.${d}`)}
                </label>
              ))}
              <div className="space-y-1.5"><Label htmlFor="note">Reviewer note (optional)</Label>
                <Textarea id="note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} rows={3} placeholder="Explain the evidence or reasoning behind your decision…" /></div>
              <Button type="submit" disabled={!decision || save.isPending}>{save.isPending && <Spinner />}Submit decision</Button>
            </fieldset>
          </form>
        ) : <p className="text-sm text-muted-foreground">Your role can view alerts but not record decisions.</p>}
      </div>
    </SectionCard>
  )
}

// ---------------------------------------------------------------- page
export default function AlertDetailPage() {
  const { alertId = '' } = useParams()
  const { can, me } = useAuth()
  const { formatDateTime } = useI18n()
  const qc = useQueryClient()
  const canWrite = can('alerts:write')

  const alert = useQuery({ queryKey: ['alert', alertId], queryFn: () => api.alerts.get(alertId) })
  const history = useQuery({ queryKey: ['alert', alertId, 'history'], queryFn: () => api.alerts.history(alertId), enabled: alert.isSuccess })
  const evidence = useQuery({ queryKey: ['alert', alertId, 'evidence'], queryFn: () => api.alerts.evidence(alertId), enabled: alert.isSuccess })
  const related = useQuery({ queryKey: ['alert', alertId, 'related'], queryFn: () => api.alerts.related(alertId), enabled: alert.isSuccess })
  const indicators = useQuery({ queryKey: ['alert', alertId, 'indicators'], queryFn: () => api.alerts.indicators(alertId), enabled: alert.isSuccess })
  const assign = useMutation({
    mutationFn: (userId: string | null) => api.alerts.assign(alertId, userId),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alert', alertId] }); qc.invalidateQueries({ queryKey: ['alerts'] }); qc.invalidateQueries({ queryKey: ['dashboard'] }) },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not change the assignee'),
  })

  // History/audit data is refreshed whenever the alert changes (assessment, decision, enrichment, status).
  useEffect(() => { if (alert.dataUpdatedAt) qc.invalidateQueries({ queryKey: ['alert', alertId, 'history'] }) }, [alert.dataUpdatedAt, alertId, qc])

  if (alert.isLoading) return <LoadingBlock rows={5} />
  if (alert.error instanceof ApiError && alert.error.isNotFound) return <NotFoundPage what="alert" />
  if (alert.isError && !alert.data) return <ErrorState error={alert.error} onRetry={() => alert.refetch()} />
  const a = alert.data!
  const assessments = history.data?.assessments ?? []
  const decisions = history.data?.decisions ?? []
  const evidenceItems = evidence.data?.items ?? []
  const evidenceById = new Map(evidenceItems.map((e) => [e.id, e]))

  return (
    <div>
      {alert.isError && <StaleBanner updatedAt={alert.dataUpdatedAt} onRetry={() => alert.refetch()} />}
      <header className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <nav aria-label="Breadcrumb" className="mb-2 font-mono text-xs text-muted-foreground"><Link to="/alerts" className="hover:text-foreground">Alerts</Link> / <span className="text-foreground">{a.id.length > 14 ? a.id.slice(0, 8) : a.id}</span></nav>
          <h1 className="text-3xl font-bold tracking-tight">{a.title}</h1>
          <div className="mt-3 flex flex-wrap items-center gap-2"><SeverityBadge severity={a.severity} /><StatusBadge status={a.status} />{a.is_demo && <DemoBadge />}
            {a.occurrence_count > 1 && <Badge variant="outline" className="font-mono text-[11px]">fired ×{a.occurrence_count}</Badge>}</div>
          <p className="mt-2 font-mono text-xs text-muted-foreground">First seen {formatDateTime(a.first_seen_at ?? a.created_at)} · last seen {formatDateTime(a.last_seen_at ?? a.created_at)}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {canWrite && (a.assigned_to === me?.user.id
            ? <Button size="sm" variant="outline" onClick={() => assign.mutate(null)} disabled={assign.isPending}>Unassign me</Button>
            : <Button size="sm" variant="outline" onClick={() => assign.mutate(me!.user.id)} disabled={assign.isPending}>{a.assigned_to ? 'Take over' : 'Assign to me'}</Button>)}
          <Button asChild size="sm" variant="outline"><a href="#reports"><FileText className="size-3.5" />Report</a></Button>
          <Button asChild size="sm" variant="outline"><Link to={`/alerts/${encodeURIComponent(a.id)}/history`}><HistoryIcon className="size-3.5" />History</Link></Button>
        </div>
      </header>
      {a.assigned_to && <p className="-mt-3 mb-5 text-sm text-muted-foreground">Assigned to <span className="text-foreground">{a.assigned_to_name ?? 'a team member'}</span></p>}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="flex min-w-0 flex-col gap-6">
          <SectionCard title="Original alert" id="original" description="Source data as received. Not AI-generated. Displayed as plain text.">
            <p className="whitespace-pre-wrap break-words leading-relaxed text-foreground/90">{a.description}</p>
            <dl className="mt-5 grid grid-cols-[9rem_1fr] gap-y-2 font-mono text-sm">
              <dt className="text-muted-foreground">Alert ID</dt><dd className="break-all">{a.id}</dd>
              <dt className="text-muted-foreground">Source</dt><dd className="break-all">{a.source}</dd>
              <dt className="text-muted-foreground">External ID</dt><dd className="break-all">{a.external_id ?? '—'}</dd>
              <dt className="text-muted-foreground">Affected entity</dt><dd className="break-all">{a.affected_entity ?? '—'}</dd>
            </dl>
            {indicators.data && indicators.data.length > 0 && (
              <div className="mt-4"><h3 className="text-xs font-medium text-muted-foreground">Indicators extracted (deterministic, no AI)</h3>
                <ul className="mt-2 flex flex-wrap gap-1.5">{indicators.data.map((i) => <li key={`${i.type}:${i.value}`}><Badge variant="outline" className="max-w-full font-mono text-[11px]"><span className="text-muted-foreground">{i.type}</span><span className="truncate">{i.value}</span></Badge></li>)}</ul></div>
            )}
          </SectionCard>

          <EvidenceSection alertId={a.id} items={evidenceItems} canWrite={canWrite} />

          <SectionCard title="Related historical cases" id="related" description="Exact indicator matches against earlier alerts in this organization. Context, not proof of the same cause.">
            {related.isLoading && <LoadingBlock rows={2} />}
            {related.isError && <p className="text-sm text-muted-foreground">Historical cases could not be loaded. The rest of the investigation is unaffected.</p>}
            {related.data && !related.data.enabled && <p className="text-sm text-muted-foreground">Historical retrieval is disabled on this server.</p>}
            {related.data?.enabled && related.data.items.length === 0 && <EmptyState title="No related cases found" description="No earlier alert shares an indicator with this one." />}
            {related.data?.enabled && related.data.items.length > 0 && (
              <ul className="space-y-2">{related.data.items.map((r) => (
                <li key={r.id} className="border p-3 text-sm">
                  <p className="font-mono text-[11px] text-muted-foreground">{r.kind === 'demo_incident' ? 'Demo incident' : 'Earlier alert'} · {r.id.length > 14 ? r.id.slice(0, 8) : r.id} · recorded outcome: <span className="text-foreground">{r.outcome.replace(/_/g, ' ')}</span></p>
                  {r.kind === 'historical_alert' ? <Link className="mt-1 block font-medium hover:text-primary" to={`/alerts/${encodeURIComponent(r.id)}`}>{r.description}</Link> : <p className="mt-1 font-medium">{r.description}</p>}
                  <p className="mt-1 text-muted-foreground">{r.details}</p>
                  <p className="mt-1 break-all font-mono text-[11px] text-muted-foreground">Matched on: {r.matched_terms.join(', ')}</p>
                </li>))}</ul>
            )}
          </SectionCard>
        </div>

        <SectionCard title="AI assessment" id="assessment">
          {history.isLoading && <LoadingBlock rows={4} />}
          {history.isError && <ErrorState error={history.error} onRetry={() => history.refetch()} compact />}
          {history.data && <AssessmentPanel alertId={a.id} assessments={assessments} evidenceById={evidenceById} canWrite={canWrite} />}
        </SectionCard>
      </div>

      <div className="mt-6"><ReviewPanel alertId={a.id} assessment={assessments[assessments.length - 1]} latest={decisions[decisions.length - 1]} canWrite={canWrite} /></div>
      <div className="mt-6"><ReportsPanel alertId={a.id} canWrite={canWrite} /></div>
    </div>
  )
}

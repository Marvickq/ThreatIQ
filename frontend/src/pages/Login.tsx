import { useState, type FormEvent } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { z } from 'zod'
import { useAuth } from '@/auth/AuthProvider'
import { Spinner } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api, ApiError, entraLoginUrl } from '@/lib/api'

// The server redirects back with one of these fixed codes; raw identity-provider text is never shown.
const SSO_ERRORS: Record<string, string> = {
  denied: 'Microsoft sign-in was cancelled or not permitted.',
  expired: 'The Microsoft sign-in took too long or was opened in another browser. Try again.',
  tenant_not_allowed: 'Your Microsoft organization is not connected to ThreatIQ. Ask your administrator.',
  not_member: 'You are no longer a member of this organization. Ask an administrator to restore your access.',
  not_provisioned: 'Your account has not been set up in ThreatIQ yet. Ask an administrator.',
  no_email: 'Your Microsoft account did not share an email address, which ThreatIQ needs.',
  conflict: 'A ThreatIQ account with this email already exists. Sign in with your password, or ask an administrator to help move it to Microsoft sign-in.',
  disabled: 'This account is disabled.',
  not_configured: 'Microsoft sign-in is not configured on this server.',
  failed: 'Microsoft sign-in failed. Try again, or use your password.',
}

const loginSchema = z.object({ email: z.email('Enter a valid email address.'), password: z.string().min(1, 'Enter your password.') })
const registerSchema = loginSchema.extend({
  password: z.string().min(10, 'Use at least 10 characters.').max(256),
  display_name: z.string().trim().min(1, 'Enter your name.').max(100),
  organization_name: z.string().trim().min(2, 'Enter an organization name (2+ characters).').max(100),
})

type Errors = Partial<Record<'email' | 'password' | 'display_name' | 'organization_name' | 'form', string>>

export default function LoginPage({ mode }: { mode: 'login' | 'register' }) {
  const { status, setMe } = useAuth()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const next = params.get('next')
  const safeNext = next && next.startsWith('/') && !next.startsWith('//') ? next : '/'
  const [values, setValues] = useState({ email: '', password: '', display_name: '', organization_name: '' })
  const [errors, setErrors] = useState<Errors>({})
  const sso = useQuery({ queryKey: ['sso-config'], queryFn: api.auth.ssoConfig, enabled: mode === 'login', staleTime: 5 * 60_000, retry: false })
  const ssoError = params.get('sso_error')

  const submit = useMutation({
    mutationFn: () => (mode === 'login' ? api.auth.login(values.email, values.password) : api.auth.register(values)),
    onSuccess: (me) => { setMe(me); navigate(safeNext, { replace: true }) },
    onError: (err) => {
      const e = err instanceof ApiError ? err : null
      setErrors({ form: e ? (e.code === 'VALIDATION_ERROR' ? 'Check the highlighted fields and try again.' : e.message) : 'Something went wrong.' })
    },
  })

  if (status === 'authenticated') return <Navigate to={safeNext} replace />

  function onSubmit(e: FormEvent) {
    e.preventDefault()
    const parsed = (mode === 'login' ? loginSchema : registerSchema).safeParse(values)
    if (!parsed.success) {
      const next: Errors = {}
      for (const issue of parsed.error.issues) next[issue.path[0] as keyof Errors] ??= issue.message
      setErrors(next)
      return
    }
    setErrors({})
    submit.mutate()
  }

  const field = (name: keyof typeof values, label: string, type = 'text', autoComplete?: string) => (
    <div className="space-y-1.5">
      <Label htmlFor={name}>{label}</Label>
      <Input
        id={name} name={name} type={type} autoComplete={autoComplete} value={values[name]}
        onChange={(e) => setValues((v) => ({ ...v, [name]: e.target.value }))}
        aria-invalid={!!errors[name]} aria-describedby={errors[name] ? `${name}-error` : undefined}
      />
      {errors[name] && <p id={`${name}-error`} className="text-xs text-danger">{errors[name]}</p>}
    </div>
  )

  return (
    <main className="mx-auto flex min-h-screen max-w-md flex-col justify-center px-6 py-12">
      <div className="mb-8 flex items-center gap-2 text-2xl font-bold tracking-tight"><span aria-hidden="true" className="inline-block size-3.5 bg-primary" />ThreatIQ</div>
      <h1 className="text-2xl font-bold">{mode === 'login' ? 'Sign in' : 'Create your organization'}</h1>
      <p className="mt-1 text-sm text-muted-foreground">
        {mode === 'login' ? 'Investigate alerts with evidence, not guesswork.' : 'You will be the owner. You can add teammates who already have an account.'}
      </p>
      {params.get('expired') && mode === 'login' && <p role="status" className="mt-4 border border-warning/50 bg-warning/5 px-3 py-2 text-sm">Your session expired. Please sign in again.</p>}

      {ssoError && mode === 'login' && <p role="alert" className="mt-4 border border-danger/50 bg-danger/5 px-3 py-2 text-sm">{SSO_ERRORS[ssoError] ?? SSO_ERRORS.failed}</p>}
      {mode === 'login' && sso.data?.entra_enabled && (
        <div className="mt-6">
          <Button asChild variant="outline" className="w-full"><a href={entraLoginUrl(safeNext)}>Sign in with Microsoft</a></Button>
          <p className="my-4 text-center text-xs text-muted-foreground">or use your email and password</p>
        </div>
      )}

      <form onSubmit={onSubmit} noValidate className={sso.data?.entra_enabled && mode === 'login' ? 'space-y-4' : 'mt-6 space-y-4'}>
        {mode === 'register' && field('display_name', 'Your name', 'text', 'name')}
        {mode === 'register' && field('organization_name', 'Organization name', 'text', 'organization')}
        {field('email', 'Email', 'email', 'email')}
        {field('password', 'Password', 'password', mode === 'login' ? 'current-password' : 'new-password')}
        {errors.form && <p role="alert" className="text-sm text-danger">{errors.form}</p>}
        <Button type="submit" className="w-full" disabled={submit.isPending}>{submit.isPending && <Spinner />}{mode === 'login' ? 'Sign in' : 'Create account'}</Button>
      </form>

      <p className="mt-6 text-sm text-muted-foreground">
        {mode === 'login' ? (<>New here? <Link className="underline underline-offset-4 hover:text-foreground" to="/register">Create an organization</Link></>)
          : (<>Already registered? <Link className="underline underline-offset-4 hover:text-foreground" to="/login">Sign in</Link></>)}
      </p>
      {mode === 'login' && <p className="mt-2 text-xs text-muted-foreground">Forgot your password? Self-service reset is not available yet; an organization owner or your server administrator must reset it (see the account recovery guide in the documentation).</p>}
    </main>
  )
}

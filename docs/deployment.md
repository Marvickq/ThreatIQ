# Local development, deployment and rollback

## Local development (verified path)
```powershell
# backend
cd backend
py -3.13 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
copy .env.example .env.local          # set NEBIUS_* to use AI; set ALLOW_DEMO_DATA=true for sample alerts
.venv\Scripts\python -m uvicorn app.main:app --port 8000

# frontend (proxies /api to the backend, so cookies are same-origin)
cd frontend
npm install
npm run dev                            # http://localhost:5173  (VITE_BACKEND_URL overrides the proxy target)
```
Open the app, **Create an organization** (the first account adopts any pre-existing single-tenant data), then Settings.
SQLite is used locally. Background jobs run on an in-process thread pool; live updates are in-process.

## Supabase (PostgreSQL)
Use the connection string from Supabase → Connect. Both forms work (a trailing `?pgbouncer=true` is ignored, and server-side prepared statements are turned off automatically on the transaction pooler, port 6543):
```
DATABASE_URL=postgresql+psycopg://postgres.<project-ref>:<PASSWORD>@aws-0-<region>.pooler.supabase.com:6543/postgres
```
Prefer the **session pooler (port 5432)** or the direct connection for the first migration. Migrations run automatically at backend start, so check where `DATABASE_URL` points **before** starting the server: `backend/.env.local` overrides `backend/.env`. Read-only status check: `python -m alembic current` (prints the revision; changes nothing).

## Migrations
Run automatically at startup (`app/migrations.py`). A pre-Alembic database is stamped and upgraded, never reset.
```powershell
cd backend
.venv\Scripts\python -m alembic current
.venv\Scripts\python -m alembic upgrade head
.venv\Scripts\python -m alembic check        # models and migrations agree
```
`0001` baseline · `0002` `is_demo` · `0003` multi-tenancy (existing rows move into a "Default organization"; nothing is deleted) · `0004` assessment facts/interpretation.
**Downgrading past 0003 is intentionally unsupported** (it would discard tenant ownership): restore from backup. Always take a database backup/snapshot before upgrading production.

## Docker Compose (written, NOT run here)
```bash
cp .env.compose.example .env.compose      # set POSTGRES_PASSWORD and SECRET_KEY
docker compose --env-file .env.compose up --build
# optional metrics: docker compose --env-file .env.compose --profile observability up
```
Stack: PostgreSQL 16, Redis 7, API, Celery worker, nginx web on `:8080`. With Redis/Celery configured, jobs run in the worker and live events cross processes through Redis pub/sub.

## AWS with Terraform (written, NOT applied or validated here)
The `backend/terraform/` module creates ECS Fargate services (api, worker, a single dedicated scheduler, web), an ALB (HTTPS only; `/api/*` to the API), RDS PostgreSQL (encrypted, Multi-AZ, deletion-protected, 14-day backups), ElastiCache Redis (encrypted, TLS+auth), a private versioned S3 bucket with a least-privilege task role, Secrets Manager entries, CloudWatch logs, and ECS deployment circuit breakers with automatic rollback.
You provide: an existing VPC and subnets, pushed container images, an ACM certificate, and (optionally) Secrets Manager ARNs for the Nebius/NVD/VirusTotal keys.
```bash
cd backend/terraform
terraform init
terraform validate
terraform plan -var-file=prod.tfvars       # review carefully
terraform apply -var-file=prod.tfvars
```
Caveats: generated secrets live in Terraform state (use an encrypted remote backend); egress is open so the app can reach Nebius/NVD/CISA; this module does not create the VPC, DNS record, ECR repositories or Grafana/Prometheus. **Do not describe a deployment as complete until you have applied this and run the verification below.**

## Verifying a deployment
1. `GET /api/v1/ready` returns 200; `GET /api/v1/health` 200.
2. Register the first account; Settings → System shows `database: postgresql`, Redis `ok`, job backend `celery`, AI `configured`.
3. Post a webhook alert with an API key; it appears on an open dashboard without reload.
4. Run an analysis; confirm the job completes and the assessment cites stored evidence.
5. Restart/redeploy the API and worker; confirm data and sessions persist and no job is lost (queued jobs resume; running jobs requeue).

## Rollback
- **Application:** redeploy the previous image tag (ECS: update the service to the previous task definition revision; the circuit breaker does this automatically if a deployment fails health checks). Migrations are forward-only, so a rollback to an older image works only if the older code tolerates the newer schema (the 0001–0004 changes are additive).
- **Data:** restore the RDS snapshot taken before the upgrade into a new instance and repoint `DATABASE_URL`. Do not downgrade the schema in place.
- **Secrets:** `SECRET_KEY` must stay constant across rollbacks or stored integration credentials become unreadable.

## Graceful shutdown
SIGTERM stops the scheduler, lets running jobs finish (ECS `stopTimeout` 40–60 s), and leaves unstarted jobs `queued` in the database; they are picked up on next start. Jobs left `running` by a crash are requeued (until `JOB_MAX_ATTEMPTS`) or failed with "Interrupted by a restart".

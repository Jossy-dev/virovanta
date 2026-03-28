# Deployment Guide

This guide documents the production topology ViroVanta now expects.

## Recommended Topology

Run these as separate services:

1. API web service
2. Scan worker background service
3. Postgres
4. Redis
5. S3-compatible object storage

Why:

- the API stays responsive while scans run asynchronously
- workers can scale separately from the web tier
- BullMQ gives durable queueing across deploys and restarts
- object storage allows the API and workers to share scan inputs and report artifacts safely

## API Service

Required shape:

- `RUN_API_SERVER=true`
- `RUN_SCAN_WORKER=false`
- `DATA_STORE_DRIVER=postgres`
- `QUEUE_PROVIDER=bullmq`
- `OBJECT_STORAGE_PROVIDER=s3`
- `RATE_LIMIT_STORE=memory`

Recommended start command:

- `npm run start:api --prefix server`

Recommended health check:

- `GET /api/health/ready`
- `GET /ping` for simple external keep-warm or uptime pings

## Worker Service

Required shape:

- `RUN_API_SERVER=false`
- `RUN_SCAN_WORKER=true`
- `DATA_STORE_DRIVER=postgres`
- `QUEUE_PROVIDER=bullmq`
- `OBJECT_STORAGE_PROVIDER=s3`

Recommended start command:

- `npm run start:worker --prefix server`

Optional worker specialization:

- `npm run start:worker:file --prefix server`
- `npm run start:worker:link --prefix server`

## Core Production Environment

Set strong values for:

- `JWT_ACCESS_SECRET`
- `REPORT_SHARE_TOKEN_SECRET`
- `REPORT_INTEGRITY_SECRET`

Database and queue:

- `DATA_STORE_DRIVER=postgres`
- `DATABASE_URL=...`
- `DATABASE_SSL=true`
- `QUEUE_PROVIDER=bullmq`
- `REDIS_URL=...`
- `RATE_LIMIT_STORE=memory`

Important boundary:

- Redis is reserved for BullMQ queue and worker traffic only
- login, auth, public status, health checks, and request rate limiting must not depend on Redis
- guest quick scan stays in-process and does not touch BullMQ or Redis

Object storage:

- `OBJECT_STORAGE_PROVIDER=s3`
- `OBJECT_STORAGE_BUCKET=...`
- `OBJECT_STORAGE_ACCESS_KEY_ID=...`
- `OBJECT_STORAGE_SECRET_ACCESS_KEY=...`
- `OBJECT_STORAGE_REGION=...`

Supabase auth mode, when used:

- `AUTH_PROVIDER=supabase`
- `SUPABASE_URL=...`
- `SUPABASE_PUBLISHABLE_KEY=sb_publishable_...`
- do not use the legacy JWT anon key format

## Readiness And Alerts

Use these endpoints operationally:

- `/ping`
  lightweight plaintext ping for UptimeRobot and simple keep-warm checks
- `/api/health`
  basic heartbeat
- `/api/health/live`
  process liveness
- `/api/health/ready`
  store, queue, object storage, and in-process rate-limit readiness
- `/api/admin/metrics`
  admin business metrics plus runtime details

Trigger alerts when:

1. `/api/health/ready` returns `503`
2. queue runtime status becomes `degraded`
3. store readiness is false

Use `/ping` when you want a monitor that only verifies the process is awake and reachable.
Use `/api/health/ready` when you want a monitor that verifies the service is actually ready to handle production traffic.

## Database Hardening

For this architecture, the application tables should stay backend-owned.

Recommended stance:

1. do not query `virovanta_*` tables directly from the frontend
2. do not depend on Supabase `auth.uid()` defaults for these tables
3. revoke direct table privileges from `anon` and `authenticated`
4. keep authorization checks in backend service code

Example privilege lock-down after schema creation:

```sql
revoke all on table public.virovanta_users from anon, authenticated;
revoke all on table public.virovanta_jobs from anon, authenticated;
revoke all on table public.virovanta_reports from anon, authenticated;
revoke all on table public.virovanta_notifications from anon, authenticated;
revoke all on table public.virovanta_api_keys from anon, authenticated;
revoke all on table public.virovanta_refresh_tokens from anon, authenticated;
revoke all on table public.virovanta_password_reset_tokens from anon, authenticated;
revoke all on table public.virovanta_audit_events from anon, authenticated;
```

## Deployment Checklist

1. Build the client before starting the production API service if the API serves the frontend bundle
2. Run the API and worker as separate services
3. Point both services at the same Postgres, Redis, and object storage
4. Use `/api/health/ready` as the web-service health check
5. Verify admin metrics show `runtime.ready=true` after deploy
6. Run `npm run test:e2e --prefix server` before promoting changes

## Fallback Local Production-Like Mode

For a smaller environment or staging stack:

- `RUN_API_SERVER=true`
- `RUN_SCAN_WORKER=true`
- `DATA_STORE_DRIVER=postgres`
- `QUEUE_PROVIDER=local`

This works for staging, but it is not the recommended scale topology because the web and worker roles share one process.

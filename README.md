# ViroVanta

ViroVanta is a multi-user malware and threat analysis platform with guest quick scans, authenticated scan history, async job processing, signed reports, and operational controls for production deployment.

## Current Platform Shape

- React + Vite frontend
- Node.js + Express API
- Async scan orchestration with local queue or BullMQ
- Normalized Postgres persistence for users, jobs, reports, notifications, tokens, API keys, and audit events
- Guest quick scans plus authenticated file, URL, and website safety workflows
- Signed report integrity, PDF export, notifications, analytics, and admin metrics

## What Changed In This Hardening Pass

- Added focused end-to-end smoke coverage for guest quick scan, authenticated file scan, URL scan, website safety scan, history, analytics, and report PDF export
- Added runtime mode coverage for combined, API-only, and worker-only deployments
- Replaced embedded Postgres schema bootstrapping with a migration runner
- Added scale-oriented constraints and indexes for jobs, reports, notifications, and users
- Added readiness and liveness endpoints plus runtime health data in admin metrics
- Added runtime topology guards so bad production combinations fail fast
- Added server scripts and environment examples for clean API/worker separation

## Repository Layout

- `/Users/jossychidi/Documents/virovanta/client`
  Frontend app
- `/Users/jossychidi/Documents/virovanta/server`
  API, worker, storage, scanner orchestration, tests
- `/Users/jossychidi/Documents/virovanta/server/src/app/createApp.js`
  App composition, health endpoints, route wiring, service bootstrap
- `/Users/jossychidi/Documents/virovanta/server/src/services/scanQueueService.js`
  Queue orchestration, worker processing, analytics, job lifecycle
- `/Users/jossychidi/Documents/virovanta/server/src/store/persistentStore.js`
  File driver plus normalized Postgres store
- `/Users/jossychidi/Documents/virovanta/server/src/store/postgresMigrations.js`
  Migration definitions and runner
- `/Users/jossychidi/Documents/virovanta/server/DEPLOYMENT.md`
  Production topology, security, and deployment guidance

## Local Development

Install dependencies:

- `npm install --prefix server`
- `npm install --prefix client`

Create backend env:

- copy `/Users/jossychidi/Documents/virovanta/server/.env.example` to `/Users/jossychidi/Documents/virovanta/server/.env`

Start the default local stack:

- `npm run dev`

Useful variants:

- `npm run dev:client`
- `npm run dev:server`
- `npm run dev:api`
- `npm run dev:worker`

Local defaults:

- API: `http://localhost:3001`
- Client: `http://localhost:5173`
- Health: `http://localhost:3001/api/health`
- Readiness: `http://localhost:3001/api/health/ready`

## Runtime Modes

ViroVanta now supports three service modes:

1. Combined mode
   `RUN_API_SERVER=true`, `RUN_SCAN_WORKER=true`
2. API-only mode
   `RUN_API_SERVER=true`, `RUN_SCAN_WORKER=false`
3. Worker-only mode
   `RUN_API_SERVER=false`, `RUN_SCAN_WORKER=true`

Recommended production topology:

1. API-only web service
2. Worker-only background service
3. Postgres
4. Redis when `QUEUE_PROVIDER=bullmq`
5. S3-compatible object storage when API and workers are separated

## Storage And Migrations

The platform supports:

- `DATA_STORE_DRIVER=file`
  convenient for local development and tests
- `DATA_STORE_DRIVER=postgres`
  required for serious multi-user production deployment

Postgres schema management is migration-based:

- migrations table: `<table_base>_schema_migrations`
- current migrations:
  - `001_initial_schema`
  - `002_scale_hardening`

The normalized Postgres model includes:

- users
- jobs
- reports
- notifications
- API keys
- refresh tokens
- password reset tokens
- audit events

## Queueing

Queue modes:

- `QUEUE_PROVIDER=local`
  in-process queue, best for local development
- `QUEUE_PROVIDER=bullmq`
  Redis-backed async queue for production and split deployments

Production rule enforced by config:

- remote BullMQ workers require `OBJECT_STORAGE_PROVIDER=s3`

## Health And Monitoring

Health endpoints:

- `GET /api/health`
  basic service heartbeat
- `GET /api/health/live`
  liveness view with runtime mode
- `GET /api/health/ready`
  readiness view including store, queue, object storage, and rate-limit status

Admin operational visibility:

- `GET /api/admin/metrics`
  returns business metrics plus runtime health snapshot
- `GET /api/admin/audit`
  returns audit trail events

## Security Baseline

The backend now enforces or supports:

- strict startup validation for production secrets and runtime topology
- Supabase publishable-key validation when `AUTH_PROVIDER=supabase`
- signed report integrity payloads
- rate limiting with memory or Redis store
- Helmet, CORS allow-listing, request IDs, structured logging, and input validation
- backend-owned authorization for application tables

Do not expose the application tables directly to the frontend. The intended model is:

1. frontend uses Supabase for auth only
2. backend verifies the user identity
3. backend performs all reads and writes against `virovanta_*` tables

## Testing

Root scripts:

- `npm run test`
- `npm run test:e2e`
- `npm run build`

Server scripts:

- `npm run test --prefix server`
- `npm run test:e2e --prefix server`
- `npm run test:migrations --prefix server`

Client scripts:

- `npm run test --prefix client`
- `npm run build --prefix client`

## Next Recommended Operational Work

1. Add the readiness endpoint to your deployment health checks
2. Deploy the API and worker as separate services in production
3. Use Postgres, Redis, and S3-compatible object storage in production
4. Lock down database grants so only the backend role can access app tables
5. Add external alerting on `/api/health/ready` and queue degradation signals

For the production rollout guide, use `/Users/jossychidi/Documents/virovanta/server/DEPLOYMENT.md`.

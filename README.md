# ViroVanta

ViroVanta is now a **multi-user, authenticated, async file scanning platform** built with React + Node.js.

## What Is New in This Upgrade

- Account system with:
  - Registration + login
  - JWT access tokens
  - Rotating refresh tokens
  - API key lifecycle (create/list/revoke)
- Asynchronous scan job engine:
  - Queue-based processing (`queued -> processing -> completed/failed`)
  - Configurable worker concurrency
  - Per-user report ownership
- Stronger security posture:
  - Helmet hardening
  - CORS allow-list validation
  - Rate limiting and abuse controls
  - Strict request validation with `zod`
  - Correlation IDs and structured errors
  - Password policy enforcement
  - Audit trail events
- Persistent storage:
  - Atomic JSON datastore on disk
  - Users, jobs, reports, and audit events survive restart
- Free-tier enforcement:
  - Daily scan quota limits per user
  - Admin override support

## Stack

- Frontend: React + Vite
- Backend: Node.js + Express
- Security: Helmet, express-rate-limit, JWT, bcryptjs, zod
- Logging: pino + pino-http
- Uploads: multer
- Testing:
  - Backend: Vitest + Supertest integration tests
  - Frontend: Vitest + React Testing Library

## Architecture Summary

- `server/src/app/createApp.js`
  - App composition, middleware, security policy, route wiring
- `server/src/services/authService.js`
  - Auth/session/API-key/quota/business logic
- `server/src/services/scanQueueService.js`
  - Async job queue orchestration + report persistence
- `server/src/store/persistentStore.js`
  - Atomic file-backed datastore
- `server/src/scanner/fileScanner.js`
  - Heuristics + optional ClamAV + optional VirusTotal
- `client/src/App.jsx`
  - Auth UX, queue UX, report UX, API key management

## API Surface (v2)

### Auth
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/auth/api-keys`
- `POST /api/auth/api-keys`
- `DELETE /api/auth/api-keys/:keyId`

### Scans
- `POST /api/scans/jobs` (multipart file upload)
- `GET /api/scans/jobs`
- `GET /api/scans/jobs/:jobId`
- `GET /api/scans/reports`
- `GET /api/scans/reports/:reportId`

### Platform
- `GET /api/health`
- `GET /api/openapi.json`
- `GET /api/admin/metrics` (admin)
- `GET /api/admin/audit` (admin)

## Quick Start

1. Install dependencies:
   - `npm install --prefix server`
   - `npm install --prefix client`
2. Configure backend:
   - copy `server/.env.example` to `server/.env`
3. Start app:
   - `npm run dev`
4. Open:
   - UI: [http://localhost:5173](http://localhost:5173)
   - API health: [http://localhost:3001/api/health](http://localhost:3001/api/health)

## Environment Configuration

Use `server/.env.example` as baseline. Most important options:

- `JWT_ACCESS_SECRET`
- `ACCESS_TOKEN_TTL_MINUTES`
- `REFRESH_TOKEN_TTL_DAYS`
- `FREE_TIER_DAILY_SCAN_LIMIT`
- `SCAN_WORKER_CONCURRENCY`
- `MAX_UPLOAD_MB`
- `REQUESTS_PER_WINDOW`
- `REQUEST_WINDOW_MINUTES`
- `ENABLE_CLAMAV`
- `VIRUSTOTAL_API_KEY`

## Testing

- Full suite: `npm run test`
- Backend only: `npm run test --prefix server`
- Frontend only: `npm run test --prefix client`
- Frontend production build: `npm run build --prefix client`

## Cybersecurity Standards Alignment (Current)

As of **February 17, 2026**, this project is aligned to practical controls from:

- OWASP ASVS 5.0.0 (auth/session controls, API hardening, logging/auditability, input validation)
- OWASP API Security Top 10 (2023) (authz/authn, resource abuse controls, misconfiguration reduction, API inventory)
- NIST SSDF guidance trajectory (SP 800-218 Rev.1 IPD v1.2) through secure dev/test pipeline and control traceability


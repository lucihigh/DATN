# Secure Simulated E-Wallet Banking System (Monorepo Scaffold)

This repository is a pnpm-powered monorepo scaffold for a student project: **"Secure Simulated E-Wallet Banking System with Data Encryption & AI-based Anomalous Login Detection"**.

## Contract-first workflow
- Authoritative OpenAPI spec: `contracts/openapi.yaml`
- Validate: `pnpm contract:validate` (Redocly)
- Generate typed client: `pnpm contract:gen` (outputs to `packages/shared/api-client/types.ts`)
- Consumers: web and api import the generated client/types from `@secure-wallet/shared`
- After updating the spec, rerun generation and update implementations as needed.

## Structure
- apps/web – React (Vite) frontend for user + admin
- apps/api – Node.js + Express REST API with Prisma ORM
- apps/ai-service – Python FastAPI microservice for login anomaly scoring
- packages/shared – TypeScript shared types, Zod schemas, generated API client placeholder
- packages/config – Shared lint/format configs
- infra – docker-compose, Postgres, service wiring
- prisma – Prisma schema & migration entrypoint
- contracts – OpenAPI contract (single source of truth)

## Getting Started
1. Install pnpm (>=9) and Node.js >= 18.18, plus Python 3.10+.
2. Copy `.env.example` to `.env` and adjust secrets (never commit real secrets).
3. Install deps: `pnpm install` (workspace-wide).
4. Start stack (local, dev defaults): `pnpm dev` (runs web, api, ai-service in parallel).
5. Bring up Postgres via Docker: `docker compose -f infra/docker-compose.yml up -d`.
6. Run Prisma migrate: `pnpm --filter @secure-wallet/api prisma:migrate`.
7. Contract flow: edit `contracts/openapi.yaml` -> `pnpm contract:validate` -> `pnpm contract:gen`.

## Scripts (root)
- `pnpm dev` – runs all workspace `dev` scripts in parallel
- `pnpm lint` / `pnpm format` / `pnpm typecheck` / `pnpm test`
- `pnpm contract:validate` / `pnpm contract:gen`
- `pnpm --filter @secure-wallet/api db:init` – prepare Mongo collections/indexes (needs `MONGODB_URI`)
- `pnpm prepare` – installs husky hooks

## Branching strategy
- `main` – stable releases
- `dev` – integration branch
- Feature branches: `feature/frontend-ui`, `feature/backend-auth`, `feature/db-encrypt`, `feature/ai-service`, `feature/admin-audit`

## Code ownership (see CODEOWNERS)
- Frontend: apps/web
- Backend/Security: apps/api
- AI: apps/ai-service
- DB/Encryption: prisma/, encryption utils in api
- Admin/Audit: admin routes in web + api audit modules

## OpenAPI & Client
- Spec: `contracts/openapi.yaml`
- Generate client: `pnpm contract:gen` (into packages/shared/api-client)
- Database (MongoDB option): set `MONGODB_URI` (Atlas URI) and `MONGODB_DB`; run `pnpm --filter @secure-wallet/api db:init` once.

## Security & Compliance Notes
- Env-based key management only (no secrets committed).
- AES-256-GCM helper stubs under `apps/api/src/security/encryption.ts`.
- Rate-limit/lockout/headers middleware placeholders in `apps/api/src/middleware`.
- Audit logging and admin routes stubbed for extension.

## Testing / Quality
- Shared ESLint/Prettier configs from `packages/config`
- Husky pre-commit runs `pnpm lint && pnpm format && pnpm test` (opt-out by editing `.husky/pre-commit` if needed)

## Docker / Services
- Postgres exposed on 5432 (local only)
- API 4000, Web 5173, AI service 8000
- Update compose env if ports change.

Happy building!

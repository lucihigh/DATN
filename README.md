# FPIPay (Monorepo Scaffold)

This repository is a pnpm-powered monorepo scaffold for the **FPIPay** project: a secure digital payments platform with data encryption and anomalous login detection.

## Contract-first workflow
- Authoritative OpenAPI spec: `contracts/openapi.yaml`
- Validate: `pnpm contract:validate` (Redocly)
- Generate typed client: `pnpm contract:gen` (outputs to `packages/shared/api-client/types.ts`)
- Consumers: web and api import the generated client/types from `@secure-wallet/shared`
- After updating the spec, rerun generation and update implementations as needed.

## Structure
- apps/web - React (Vite) frontend for user + admin
- apps/api - Node.js + Express REST API with Prisma ORM
- apps/ai-service - Python FastAPI microservice for login anomaly scoring
- packages/shared - TypeScript shared types, Zod schemas, generated API client placeholder
- packages/config - Shared lint/format configs
- infra - docker-compose, Postgres, service wiring
- prisma - Prisma schema & migration entrypoint
- contracts - OpenAPI contract (single source of truth)

## Local Dev
- `pnpm dev` now starts `web`, `api`, and `ai-service` together.
- `apps/ai-service` uses `apps/ai-service/.venv` automatically when present, otherwise falls back to `py`/`python`.
- If `AI_SERVICE_URL` points to `localhost` or `127.0.0.1`, `apps/api` also auto-starts the local AI runtime when needed.

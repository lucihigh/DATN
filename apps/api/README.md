# API Service (Express + Prisma)

## Commands
- `pnpm dev` – start dev server with ts-node-dev
- `pnpm prisma:migrate` – run migrations
- `pnpm prisma:generate` – generate Prisma client
- Contract flow: `pnpm contract:validate` then `pnpm contract:gen` to refresh shared client types.
- `pnpm --filter @secure-wallet/api db:init` – ensure MongoDB collections/indexes (needs `MONGODB_URI`)

## Env
- `DATABASE_URL` – Postgres connection
- `JWT_SECRET` – signing key (placeholder currently unused)
- `ENCRYPTION_KEY` – base64 32-byte key for AES-256-GCM (e.g. `openssl rand -base64 32`)
- `AI_SERVICE_URL` – FastAPI anomaly scorer base URL
- `MONGODB_URI` – Mongo connection string
- `MONGODB_DB` – Mongo database name (default `ComputerResearchProject`)

## DB/Collections
- Schemas/types: `src/db/schemas.ts`
- Collections ensured by `db:init`: users, wallets, transactions, loginEvents, auditLogs, securityPolicies (indexes on email/userId/createdAt, etc.)

## Routes (contract-driven, stubbed)
See `contracts/openapi.yaml` for the authoritative contract covering auth, wallet, transfer, security, and admin routes.

Security middleware placeholders live in `src/middleware`.
Encryption helpers live in `src/security/encryption.ts`.
Audit logging stub in `src/services/audit.ts`.

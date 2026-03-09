# API Service (Express + Prisma)

## Commands
- `pnpm dev` - start dev server with ts-node-dev
- `pnpm prisma:migrate` - run migrations
- `pnpm prisma:generate` - generate Prisma client
- Contract flow: `pnpm contract:validate` then `pnpm contract:gen` to refresh shared client types.
- `pnpm --filter @secure-wallet/api db:migrate-mongo` - migrate MongoDB data into PostgreSQL (needs `MONGODB_URI` and `DATABASE_URL`)

## Env
- `DATABASE_URL` - Postgres connection
- `JWT_SECRET` - JWT signing key (required in production)
- `JWT_EXPIRES_IN` - optional JWT lifetime (default `7d`)
- `ENCRYPTION_KEY` - 32-byte AES key (base64 or hex; e.g. `openssl rand -base64 32`)
- `ENCRYPTION_KEY_ID` - optional key identifier for payload metadata (default `default`)
- `AI_SERVICE_URL` - FastAPI anomaly scorer base URL
- `MONGODB_URI` - Mongo connection string
- `MONGODB_DB` - Mongo database name (default `ComputerResearchProject`)

## DB (PostgreSQL via Prisma)
- Schema source: `prisma/schema.prisma`
- Prisma client: `src/db/prisma.ts`
- Repository layer: `src/db/repositories/*.ts`
- Migration path:
  - Run Prisma migrations first: `pnpm prisma:migrate`
  - Then import legacy Mongo data once: `pnpm --filter @secure-wallet/api db:migrate-mongo`
- Legacy Mongo helper files are kept only for reference/backward compatibility.

## Routes (contract-driven, stubbed)
See `contracts/openapi.yaml` for the authoritative contract covering auth, wallet, transfer, security, and admin routes.

Security middleware placeholders live in `src/middleware`.
Encryption helpers live in `src/security/encryption.ts`.
Use `encryptFields(...)` and `decryptFields(...)` for field-level encryption helpers.
Audit logging service in `src/services/audit.ts`.
Passwords are hashed with scrypt in `src/security/password.ts`.


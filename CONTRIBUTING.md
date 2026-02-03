# Contributing

## Branching
- `main`: stable releases
- `dev`: integration
- `feature/*`: one feature per branch (examples: `feature/backend-auth`, `feature/admin-audit`)

## Commit Messages
- Use Conventional Commits: `type(scope): subject`
  - types: feat, fix, docs, chore, refactor, test, ci
  - example: `feat(api): add login lockout hook`

## Collaboration Rules
- Stay in your workspace unless you have owner approval:
  - web: apps/web/** (owner @frontend-dev)
  - api/security: apps/api/** (owner @backend-dev)
  - ai service: apps/ai-service/** (owner @ai-dev)
  - db/encryption: prisma/** and apps/api/src/db/** and apps/api/src/security/encryption/** (owner @db-encrypt-dev)
  - admin/audit: apps/api/src/admin/**, apps/api/src/audit/**, apps/web/src/admin/** (owner @admin-audit-dev)
- Shared contracts go through `packages/shared` plus OpenAPI updates in `apps/api/openapi.yaml`; regenerate the client when schemas change.
- Database schema changes must include Prisma migrations and keep `prisma/schema.prisma` formatted.

## PR Expectations
- Feature branch naming enforced via PR template checklist.
- Run `pnpm lint`, `pnpm test` (or mark pending), and update docs before requesting review.
- Do not commit `.env` or secrets.

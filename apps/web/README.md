# Web App (React + Vite)

- User UI at `/`
- Admin UI at `/admin`
- Consumes the contract-generated client from `@secure-wallet/shared` (see `packages/shared/api-client`).

## Scripts
- `pnpm dev` – start Vite dev server
- `pnpm build` – production build
- `pnpm lint` / `pnpm format` / `pnpm typecheck` – quality gates

When the OpenAPI contract changes, rerun `pnpm contract:gen` at repo root and restart dev server.

#!/usr/bin/env bash
set -euo pipefail

cd /workspaces/DATN

if [ ! -f .env ] && [ -f .env.example ]; then
  cp .env.example .env
fi

pnpm install

python3 -m venv apps/ai-service/.venv
apps/ai-service/.venv/bin/pip install --upgrade pip
apps/ai-service/.venv/bin/pip install -r apps/ai-service/requirements.txt

pnpm --filter @secure-wallet/api prisma:generate

cat <<'EOF'

Dev container is ready.
Run `pnpm dev` to start web, api, and ai-service.
Postgres is already available at postgres:5432 inside the container.

EOF

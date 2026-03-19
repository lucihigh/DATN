FROM node:18-bullseye
WORKDIR /app
RUN corepack enable
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json tsconfig.base.json .env.example ./
COPY packages ./packages
COPY apps/api ./apps/api
COPY prisma ./prisma
RUN pnpm install --frozen-lockfile=false && pnpm --filter @secure-wallet/api prisma:generate
EXPOSE 4000
CMD ["pnpm", "--filter", "@secure-wallet/api", "dev"]

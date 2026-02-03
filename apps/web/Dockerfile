FROM node:18-bullseye
WORKDIR /app
RUN corepack enable
COPY pnpm-workspace.yaml package.json tsconfig.base.json .env.example ./
COPY packages ./packages
COPY apps/web ./apps/web
RUN pnpm install --frozen-lockfile=false
EXPOSE 5173
CMD ["pnpm", "--filter", "@secure-wallet/web", "dev", "--", "--host", "0.0.0.0"]

# Infra

Docker compose for the full local stack:

```powershell
docker compose -f infra/docker-compose.yml up --build -d
```

Stop everything:

```powershell
docker compose -f infra/docker-compose.yml down
```

Services:
- Postgres 15: `localhost:5432`
- API: `http://localhost:4000`
- Web: `http://localhost:5173`
- AI service: `http://localhost:8000`

Notes:
- `api` uses the internal Docker hostname `ai-service:8000` instead of `localhost`.
- `api` and `ai-service` use the internal Postgres URL `postgresql://postgres:postgres@postgres:5432/ewallet`.
- Other values still come from the repo root `.env` through `env_file`.

Init SQL runs from `infra/init-db.sql`.

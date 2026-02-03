# AI Service (FastAPI)

- POST /ai/score – returns dummy anomaly score
- GET /health – uptime check

## Run locally
`
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
`

Env vars: none required (defaults only).

from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime

app = FastAPI(title="AI Anomaly Scorer")

class LoginEvent(BaseModel):
    userId: str | None = None
    ipAddress: str
    userAgent: str | None = None
    timestamp: str | None = None

@app.get("/health")
def health():
    return {"status": "ok", "service": "ai", "timestamp": datetime.utcnow().isoformat()}

@app.post("/ai/score")
def score(event: LoginEvent):
    # Dummy scorer: higher score if no userAgent or ip private range heuristic could go here
    score_value = 0.2 if event.userAgent else 0.5
    reasons = ["stubbed-model"]
    return {"score": score_value, "reasons": reasons, "received": event.model_dump()}

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

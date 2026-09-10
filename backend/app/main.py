from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import models
from app.database import engine
from app.routes import analysis, events, stats, chat
from app.services.telemetry import start_telemetry_engine

models.Base.metadata.create_all(bind=engine)

# Start background shadow telemetry
start_telemetry_engine()

app = FastAPI(
    title="PhishTrace API",
    description="Backend for Phishing Detection & Behavioral Analytics",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analysis.router)
app.include_router(events.router)
app.include_router(stats.router)
app.include_router(chat.router)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

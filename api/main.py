from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routers import agents, metrics, rules, logs, attacks, settings
import logging
import os

# Setup Logging
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/system.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Multi-Agent SIEM Dashboard API",
    description="Backend API for controlling and monitoring SIEM agents",
    version="1.0.0"
)

# CORS Configuration
origins = [
    "http://localhost:3000",  # Next.js frontend
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(agents.router, prefix="/agents", tags=["Agents"])
app.include_router(metrics.router, prefix="/metrics", tags=["Metrics"])
app.include_router(rules.router, prefix="/rules", tags=["Rules"])
app.include_router(attacks.router, prefix="/attacks", tags=["Attacks"])
app.include_router(logs.router, prefix="/logs", tags=["Logs"])
app.include_router(settings.router, prefix="/settings", tags=["Settings"])

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)

"""FastAPI main application — ZAALIMA SOC Orchestrator."""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.db.database import create_tables, SessionLocal
from app.db.seed import seed_all
from app.api.routes import (
    auth, dashboard, threats, incidents, endpoints,
    playbooks, forensics, users, jira, audit_logs, reports,
    crowdstrike
)
from app.api import websocket

settings = get_settings()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("zaalima")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting ZAALIMA SOC Orchestrator...")
    create_tables()
    db = SessionLocal()
    try:
        seed_all(db)
        # Attempt real CrowdStrike sync if configured
        try:
            from app.services.crowdstrike_service import crowdstrike_service
            if crowdstrike_service.is_configured():
                cs_status = crowdstrike_service.get_connection_status()
                logger.info(f"CrowdStrike Falcon status: {cs_status.get('status')}")
                if cs_status.get("status") == "CONNECTED":
                    from app.api.routes.crowdstrike import sync_crowdstrike_data
                    # Run sync
                    from types import SimpleNamespace
                    dummy_admin = SimpleNamespace(username="system_auto_sync")
                    sync_res = await sync_crowdstrike_data(db=db, current_user=dummy_admin)
                    logger.info(f"CrowdStrike startup sync: {sync_res.get('message')}")
        except Exception as cs_err:
            logger.warning(f"CrowdStrike auto-sync bypassed: {cs_err}")
    finally:
        db.close()
    logger.info("ZAALIMA ready. Monitoring for threats.")
    yield
    logger.info("ZAALIMA shutting down.")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Enterprise Ransomware Containment & Incident Response Platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REST API routes
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(threats.router, prefix="/api/threats", tags=["Threat Detection"])
app.include_router(incidents.router, prefix="/api/incidents", tags=["Incident Management"])
app.include_router(endpoints.router, prefix="/api/endpoints", tags=["Endpoint Management"])
app.include_router(playbooks.router, prefix="/api/playbooks", tags=["Automated Playbooks"])
app.include_router(forensics.router, prefix="/api/forensics", tags=["Digital Forensics"])
app.include_router(users.router, prefix="/api/users", tags=["User Management"])
app.include_router(jira.router, prefix="/api/jira", tags=["Jira Integration"])
app.include_router(audit_logs.router, prefix="/api/audit", tags=["Audit Logs"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(crowdstrike.router, prefix="/api/crowdstrike", tags=["CrowdStrike Falcon"])

# WebSocket
app.include_router(websocket.router, tags=["WebSocket"])


@app.get("/", tags=["Health"])
async def root():
    return {"status": "operational", "app": settings.app_name, "version": settings.app_version}


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "zaalima-backend"}


# main.py
"""
FastAPI backend for the "Automated Ransomware Containment & Incident Response Orchestrator".

Endpoints:
  - GET  /health       : Health-check endpoint returning server operational status.
  - POST /alert        : Day 2 alert-intake endpoint (preserved for backwards compatibility).
  - POST /webhook/edr  : Day 4 secure webhook endpoint for receiving simulated EDR alerts.
  - GET  /docs         : OpenAPI / Swagger interactive documentation.
"""

import logging
import os
import secrets
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

# Setup logging
logger = logging.getLogger("orchestrator")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _load_env_file(filepath: str = ".env") -> None:
    """Load environment variables from a local .env file if present and not already set."""
    if not os.path.isfile(filepath):
        return
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                if key and key not in os.environ:
                    os.environ[key] = val
    except Exception as exc:
        logger.warning("Could not read .env file: %s", exc)


# Load local environment variables if available
_load_env_file()


app = FastAPI(
    title="Automated Ransomware Containment & Incident Response Orchestrator",
    description="Backend API and webhook intake for incident response orchestration.",
    version="0.4.0",
)


@app.get("/health")
def health_check() -> dict:
    """Health-check endpoint returning a simple JSON payload."""
    return {"status": "ok", "message": "Server is running"}


class Alert(BaseModel):
    """
    Alert data model representing incoming security detections.
    Supports both core required fields and optional contextual fields.
    """
    model_config = ConfigDict(extra="allow")

    alert_id: str = Field(..., description="Unique alert identifier")
    threat_type: str = Field(..., description="Classification of threat, e.g. ransomware")
    severity: int = Field(..., description="Severity level rating")
    description: str = Field(..., description="Detailed description of the alert")
    timestamp: str = Field(..., description="ISO 8601 timestamp of alert occurrence")

    # Optional fields for enriched endpoint context
    hostname: Optional[str] = Field(None, description="Host / computer affected")
    ip_address: Optional[str] = Field(None, description="IP address of endpoint")
    username: Optional[str] = Field(None, description="User account associated with the event")
    process_hash: Optional[str] = Field(None, description="Hash of offending process or file")


def verify_webhook_secret(
    x_webhook_secret: Optional[str] = Header(None, alias="X-Webhook-Secret"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """
    Validates incoming webhook request authentication.
    Checks the shared secret against the WEBHOOK_SECRET environment variable.
    Secrets are compared using constant-time comparison (secrets.compare_digest)
    to prevent timing attacks. Secrets are NEVER logged.
    """
    expected_secret = os.environ.get("WEBHOOK_SECRET", "").strip()
    if not expected_secret:
        logger.error("Webhook rejected: WEBHOOK_SECRET environment variable is not configured.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Webhook authentication not configured or unauthorized.",
        )

    provided_secret = x_webhook_secret
    if not provided_secret and authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            provided_secret = parts[1]
        elif len(parts) == 1:
            provided_secret = parts[0]

    if not provided_secret or not secrets.compare_digest(provided_secret, expected_secret):
        logger.warning("Unauthorized webhook request rejected: invalid or missing authentication secret.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing webhook secret.",
        )

    return provided_secret


@app.post("/alert")
def receive_alert(alert: Alert) -> dict:
    """
    Receive a simulated alert, validate it, and echo a confirmation JSON.
    (Preserved from Day 2 backend).
    """
    return {
        "status": "received",
        "alert_id": alert.alert_id,
        "message": f"Alert of type '{alert.threat_type}' recorded.",
    }


@app.post("/webhook/edr", status_code=status.HTTP_200_OK)
def receive_edr_webhook(
    alert: Alert,
    _auth: str = Depends(verify_webhook_secret),
) -> dict:
    """
    Secure webhook endpoint for receiving simulated EDR alerts.

    Workflow:
      1. Authenticates request via shared secret in headers (constant-time verification).
      2. Validates JSON payload against the Alert model (required & optional fields).
      3. Extracts essential fields and safely logs alert metadata (no secrets logged).
      4. Returns JSON confirmation acknowledgement.

    No destructive containment or automated endpoint actions are executed on Day 4.
    """
    # Safe logging of alert details without exposing sensitive auth tokens
    logger.info(
        "EDR Webhook alert received safely: alert_id=%s, threat_type=%s, severity=%d, hostname=%s, ip_address=%s",
        alert.alert_id,
        alert.threat_type,
        alert.severity,
        alert.hostname or "N/A",
        alert.ip_address or "N/A",
    )

    return {
        "status": "received",
        "alert_id": alert.alert_id,
        "message": f"EDR webhook alert '{alert.alert_id}' of type '{alert.threat_type}' processed successfully.",
        "threat_type": alert.threat_type,
        "severity": alert.severity,
    }


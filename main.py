# main.py
"""
FastAPI backend for the "Automated Ransomware Containment & Incident Response Orchestrator".

Endpoints:
  - GET   /health                  : Health-check endpoint returning server operational status.
  - POST  /alert                   : Day 2 alert-intake endpoint (preserved for backwards compatibility).
  - POST  /webhook/edr             : Day 4 secure webhook endpoint for receiving simulated EDR alerts.
  - POST  /incidents               : Week 5 Day 2 create a new incident record.
  - GET   /incidents               : Week 5 Day 2 list all incidents with optional filtering.
  - GET   /incidents/{alert_id}    : Week 5 Day 2 retrieve a single incident by alert_id.
  - PATCH /incidents/{alert_id}/status : Week 5 Day 2 update the lifecycle status of an incident.
  - GET   /docs                    : OpenAPI / Swagger interactive documentation.
"""

from contextlib import asynccontextmanager
import logging
import os
import secrets
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from incidents.database import init_db
from incidents.models import (
    IncidentAuditLogResponse,
    IncidentCreate,
    IncidentResponse,
    IncidentStatus,
    IncidentUpdateStatus,
)
from incidents.service import (
    IncidentDuplicateError,
    IncidentNotFoundError,
    create_incident,
    get_audit_logs_for_alert,
    get_incident_by_alert_id,
    list_incidents,
    update_incident_status,
)
from containment.identity_response import (
    execute_account_suspension,
    execute_session_revocation,
    process_coordinated_response_workflow,
)
from containment.network_containment import execute_network_containment
from integrations.alert_parser import AlertParsingError, parse_and_enrich_alert
from security.auth import (
    AuthenticatedIdentity,
    PERM_CONTAINMENT_COORDINATE,
    PERM_CONTAINMENT_EXECUTE,
    PERM_IDENTITY_REVOKE,
    PERM_IDENTITY_SUSPEND,
    PERM_INCIDENT_WRITE,
    require_permission,
)

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan managing database initialization."""
    init_db()
    yield


app = FastAPI(
    title="Automated Ransomware Containment & Incident Response Orchestrator",
    description="Backend API, webhook intake, and incident management for incident response orchestration.",
    version="0.5.0",
    lifespan=lifespan,
)


@app.get("/", include_in_schema=False)
def root():
    """Redirect root access directly to interactive Swagger API documentation."""
    return RedirectResponse(url="/docs")


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
    endpoint_id: Optional[str] = Field(None, description="Unique EDR endpoint / machine identifier")
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
    dry_run: Optional[bool] = None,
    _auth: str = Depends(verify_webhook_secret),
) -> dict:
    """
    Secure webhook endpoint for receiving simulated EDR alerts and coordinating
    automated containment workflows (Week 2 Day 3).

    Workflow:
      1. Authenticates request via shared secret in headers (constant-time verification).
      2. Validates JSON payload against the Alert model (required & optional fields).
      3. Extracts essential fields and safely logs alert metadata (no secrets logged).
      4. Stores the incoming alert as an incident record in SQLite (idempotent for retries).
      5. Passes normalized alert data to the containment decision and EDR execution coordinator.
      6. Enforces safe dry-run simulation mode by default.
      7. Transitions incident status in SQLite store based on containment outcome.
      8. Returns structured confirmation acknowledgement with containment telemetry.
    """
    # Safe logging of alert details without exposing sensitive auth tokens
    logger.info(
        "EDR Webhook alert received safely: alert_id=%s, threat_type=%s, severity=%d, hostname=%s, endpoint_id=%s, ip_address=%s",
        alert.alert_id,
        alert.threat_type,
        alert.severity,
        alert.hostname or "N/A",
        alert.endpoint_id or "N/A",
        alert.ip_address or "N/A",
    )

    # Parse, normalize, and enrich the incoming alert payload safely
    try:
        parsed_alert = parse_and_enrich_alert(alert)
    except AlertParsingError as parse_err:
        logger.warning("Webhook alert parsing error for alert_id=%s: %s", alert.alert_id, parse_err)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Malformed alert payload: {parse_err}",
        )

    # Check for existing incident (idempotency policy for webhooks)
    try:
        existing = get_incident_by_alert_id(parsed_alert.alert_id)
        if existing:
            logger.info("Webhook duplicate received for alert_id=%s. Idempotently acknowledging.", parsed_alert.alert_id)
            return {
                "status": "duplicate",
                "alert_id": parsed_alert.alert_id,
                "message": f"EDR webhook alert '{parsed_alert.alert_id}' has already been processed.",
                "threat_type": parsed_alert.threat_type,
                "severity": parsed_alert.severity,
                "incident_status": existing.status.value,
            }

        incident_create = IncidentCreate(
            alert_id=parsed_alert.alert_id,
            threat_type=parsed_alert.threat_type,
            severity=parsed_alert.severity,
            description=parsed_alert.description,
            timestamp=parsed_alert.timestamp,
            hostname=parsed_alert.hostname,
            ip_address=parsed_alert.ip_address,
            username=parsed_alert.username,
            process_hash=parsed_alert.process_hash,
            status=IncidentStatus.NEW,
        )
        stored = create_incident(incident_create)
    except IncidentDuplicateError:
        logger.info("Webhook alert_id=%s already recorded.", parsed_alert.alert_id)
        return {
            "status": "duplicate",
            "alert_id": parsed_alert.alert_id,
            "message": f"EDR webhook alert '{parsed_alert.alert_id}' has already been processed.",
            "threat_type": parsed_alert.threat_type,
            "severity": parsed_alert.severity,
        }
    except Exception as exc:
        logger.error("Failed to store incident for webhook %s: %s", parsed_alert.alert_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to store incident record securely.",
        )

    # Week 2 Day 3: Execute containment workflow for ingested alert
    containment_payload = parsed_alert.to_dict()
    if alert.endpoint_id:
        containment_payload["endpoint_id"] = alert.endpoint_id

    containment_res = execute_network_containment(containment_payload, dry_run=dry_run)

    # Refresh incident status from SQLite to reflect any transition (e.g. to CONTAINED or INVESTIGATING)
    refreshed = get_incident_by_alert_id(parsed_alert.alert_id)
    current_status = refreshed.status.value if refreshed else stored.status.value

    return {
        "status": "received",
        "alert_id": parsed_alert.alert_id,
        "message": f"EDR webhook alert '{parsed_alert.alert_id}' of type '{parsed_alert.threat_type}' processed successfully.",
        "threat_type": parsed_alert.threat_type,
        "severity": parsed_alert.severity,
        "incident_status": current_status,
        "containment": containment_res,
    }


# ── Week 5 Day 2 Incident Endpoints ──────────────────────────────────────────


@app.post("/incidents", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident_endpoint(incident_in: IncidentCreate) -> IncidentResponse:
    """Create a new security incident record."""
    try:
        return create_incident(incident_in)
    except IncidentDuplicateError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
    except Exception as exc:
        logger.error("Error creating incident %s: %s", incident_in.alert_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the incident record.",
        )


@app.get("/incidents", response_model=List[IncidentResponse], status_code=status.HTTP_200_OK)
def list_incidents_endpoint(
    status: Optional[str] = None,
    severity: Optional[int] = None,
    limit: int = 100,
) -> List[IncidentResponse]:
    """Retrieve all incidents with optional filtering by status and severity."""
    return list_incidents(status=status, severity=severity, limit=limit)


@app.get("/incidents/{alert_id}", response_model=IncidentResponse, status_code=status.HTTP_200_OK)
def get_incident_endpoint(alert_id: str) -> IncidentResponse:
    """Retrieve details for a specific incident by alert_id."""
    incident = get_incident_by_alert_id(alert_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with alert_id '{alert_id}' was not found.",
        )
    return incident


@app.patch("/incidents/{alert_id}/status", response_model=IncidentResponse, status_code=status.HTTP_200_OK)
def update_incident_status_endpoint(
    alert_id: str,
    update_data: IncidentUpdateStatus,
    _identity: AuthenticatedIdentity = Depends(require_permission(PERM_INCIDENT_WRITE)),
) -> IncidentResponse:
    """Update the lifecycle status of an existing incident."""
    try:
        return update_incident_status(alert_id, update_data.status)
    except IncidentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with alert_id '{alert_id}' was not found.",
        )


# ── Week 2 Day 2 Network Containment Endpoint ─────────────────────────────────


@app.post("/containment/isolate", status_code=status.HTTP_200_OK)
def trigger_network_containment_endpoint(
    alert: Alert,
    dry_run: Optional[bool] = None,
    _identity: AuthenticatedIdentity = Depends(require_permission(PERM_CONTAINMENT_EXECUTE)),
) -> dict:
    """
    Week 2 Day 2: Network Containment & EDR Isolation Endpoint.
    Evaluates incoming alert telemetry against containment policy and requests
    network isolation through the authorized EDR integration when recommended.
    Defaults to safe dry-run simulation mode.
    """
    return execute_network_containment(alert, dry_run=dry_run)


# ── Week 2 Day 4 Identity Provider & Account Suspension Endpoint ─────────────


@app.post("/identity/suspend", status_code=status.HTTP_200_OK)
def trigger_account_suspension_endpoint(
    alert: Alert,
    dry_run: Optional[bool] = None,
    _identity: AuthenticatedIdentity = Depends(require_permission(PERM_IDENTITY_SUSPEND)),
) -> dict:
    """
    Week 2 Day 4: Identity Provider Account Suspension Endpoint.
    Evaluates alert telemetry, identifies target compromised user, applies
    protection safeguards, and requests account suspension via configured IdP.
    Defaults to safe dry-run simulation mode.
    """
    return execute_account_suspension(alert, dry_run=dry_run)


# ── Week 2 Day 5 Session Revocation & Coordinated Response Endpoints ─────────


@app.post("/identity/revoke-sessions", status_code=status.HTTP_200_OK)
def trigger_session_revocation_endpoint(
    alert: Alert,
    dry_run: Optional[bool] = None,
    _identity: AuthenticatedIdentity = Depends(require_permission(PERM_IDENTITY_REVOKE)),
) -> dict:
    """
    Week 2 Day 5: User Sign-in Session Revocation Endpoint.
    Evaluates alert telemetry, resolves target user, applies protection safeguards,
    and invalidates active sign-in sessions via configured IdP (e.g. Entra ID Graph API).
    Defaults to safe dry-run simulation mode.
    """
    return execute_session_revocation(alert, dry_run=dry_run)


@app.post("/containment/coordinate", status_code=status.HTTP_200_OK)
def trigger_coordinated_response_endpoint(
    alert: Alert,
    dry_run: Optional[bool] = None,
    _identity: AuthenticatedIdentity = Depends(require_permission(PERM_CONTAINMENT_COORDINATE)),
) -> dict:
    """
    Week 2 Day 5: Coordinated Incident Response Orchestration Endpoint.
    Orchestrates EDR network containment, IdP account suspension, IdP session
    revocation, SQLite incident status progression, and granular audit logging.
    Defaults to safe dry-run simulation mode.
    """
    return process_coordinated_response_workflow(alert, dry_run=dry_run)


@app.get("/incidents/{alert_id}/audit-logs", response_model=List[IncidentAuditLogResponse], status_code=status.HTTP_200_OK)
def get_incident_audit_logs_endpoint(alert_id: str) -> List[IncidentAuditLogResponse]:
    """
    Week 2 Day 5: Audit Log Retrieval Endpoint.
    Retrieves the chronological audit trail of containment and identity actions
    recorded for the given alert_id.
    """
    return get_audit_logs_for_alert(alert_id)

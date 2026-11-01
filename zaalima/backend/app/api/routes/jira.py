"""Jira Integration API routes."""
from typing import Optional, List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.database import get_db
from app.core.security import get_current_user
from app.models.incident import Incident, IncidentStatus
from app.models.audit_log import AuditLog, AuditAction
from app.core.config import get_settings

router = APIRouter()
settings = get_settings()


class CreateJiraTicketRequest(BaseModel):
    incident_id: str
    summary: Optional[str] = None
    description: Optional[str] = None


@router.get("/status")
async def get_jira_status(current_user=Depends(get_current_user)):
    """Returns Jira Cloud integration connection status."""
    if not (settings.jira_api_token and settings.jira_base_url and settings.jira_email):
        return {
            "status": "DISCONNECTED",
            "real_jira": False,
            "message": "Jira Cloud credentials are not configured in .env"
        }

    try:
        import requests
        import base64
        credentials = base64.b64encode(
            f"{settings.jira_email}:{settings.jira_api_token}".encode()
        ).decode()
        resp = requests.get(
            f"{settings.jira_base_url}/rest/api/3/myself",
            headers={"Authorization": f"Basic {credentials}", "Accept": "application/json"},
            timeout=8
        )
        if resp.status_code == 200:
            user_data = resp.json()
            return {
                "status": "CONNECTED",
                "real_jira": True,
                "base_url": settings.jira_base_url,
                "user": user_data.get("displayName"),
                "email": user_data.get("emailAddress"),
                "project_key": settings.jira_project_key,
                "issue_type": settings.jira_issue_type,
                "message": f"Connected to Jira Cloud as {user_data.get('displayName')}"
            }
        else:
            return {
                "status": "AUTH_ERROR",
                "real_jira": False,
                "code": resp.status_code,
                "message": f"Jira Cloud authentication failed: HTTP {resp.status_code}"
            }
    except Exception as e:
        return {
            "status": "ERROR",
            "real_jira": False,
            "message": f"Connection error: {str(e)}"
        }


@router.post("/ticket")
async def create_jira_ticket(
    body: CreateJiraTicketRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    inc = db.query(Incident).filter(Incident.incident_id == body.incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if not settings.jira_api_token or not settings.jira_base_url:
        return {
            "status": "not_configured",
            "message": "Jira credentials not configured. Set JIRA_BASE_URL, JIRA_EMAIL, and JIRA_API_TOKEN in .env"
        }

    try:
        import requests
        import base64
        credentials = base64.b64encode(
            f"{settings.jira_email}:{settings.jira_api_token}".encode()
        ).decode()

        summary = body.summary or f"[{inc.severity.value.upper()}] {inc.title}"
        adf_description = {
            "version": 1, "type": "doc",
            "content": [{
                "type": "paragraph",
                "content": [{"type": "text", "text": f"""
Incident ID: {inc.incident_id}
Incident Type: {inc.threat_type}
Severity: {inc.severity.value.upper()}
Affected Host: {inc.hostname or 'N/A'}
IP Address: {inc.ip_address or 'N/A'}
Compromised User: {inc.affected_user or 'N/A'}
Description: {inc.description or 'N/A'}
Status: {inc.status.value}
""".strip()}]
            }]
        }

        payload = {
            "fields": {
                "project": {"key": settings.jira_project_key},
                "summary": summary,
                "description": adf_description,
                "issuetype": {"name": settings.jira_issue_type},
            }
        }

        response = requests.post(
            f"{settings.jira_base_url}/rest/api/3/issue",
            json=payload,
            headers={"Authorization": f"Basic {credentials}", "Content-Type": "application/json"},
            timeout=10, verify=True
        )

        if response.status_code == 201:
            data = response.json()
            ticket_id = data.get("id")
            ticket_key = data.get("key")
            ticket_url = f"{settings.jira_base_url}/browse/{ticket_key}"
            inc.jira_ticket_id = ticket_id
            inc.jira_ticket_key = ticket_key
            inc.jira_ticket_url = ticket_url
            db.add(AuditLog(action=AuditAction.jira_ticket_created, actor=current_user.username,
                            target=ticket_key, details=f"Real Jira Cloud ticket created: {ticket_key} (ID: {ticket_id}) for {inc.incident_id}", status="success"))
            db.commit()
            return {
                "ticket_id": ticket_id,
                "ticket_key": ticket_key,
                "ticket_url": ticket_url,
                "status": "created",
                "real_jira": True
            }
        else:
            raise HTTPException(status_code=502, detail=f"Jira API error: {response.status_code} {response.text[:200]}")

    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=503, detail="Cannot connect to Jira. Check JIRA_BASE_URL.")
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Jira API timeout.")


@router.post("/sync/{incident_id}")
async def sync_jira_ticket(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Synchronizes ticket status and issue ID directly from live Jira Cloud API."""
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if not inc.jira_ticket_key:
        raise HTTPException(status_code=400, detail="Incident does not have a linked Jira ticket")

    if not (settings.jira_api_token and settings.jira_base_url):
        raise HTTPException(status_code=400, detail="Jira credentials not configured")

    try:
        import requests
        import base64
        credentials = base64.b64encode(
            f"{settings.jira_email}:{settings.jira_api_token}".encode()
        ).decode()

        resp = requests.get(
            f"{settings.jira_base_url}/rest/api/3/issue/{inc.jira_ticket_key}",
            headers={"Authorization": f"Basic {credentials}", "Accept": "application/json"},
            timeout=10
        )

        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=f"Jira API error: {resp.text[:200]}")

        issue_data = resp.json()
        fields = issue_data.get("fields", {})
        jira_id = issue_data.get("id")
        jira_status_name = fields.get("status", {}).get("name", "Unknown")
        jira_status_category = fields.get("status", {}).get("statusCategory", {}).get("key", "")
        assignee_obj = fields.get("assignee")
        assignee_name = assignee_obj.get("displayName") if assignee_obj else None

        # Update local Incident record
        inc.jira_ticket_id = jira_id
        if assignee_name:
            inc.assigned_to = assignee_name

        # Map Jira status to Incident status
        old_status = inc.status.value if hasattr(inc.status, "value") else str(inc.status)
        if jira_status_category == "done" or jira_status_name.lower() in ["done", "resolved", "closed"]:
            inc.status = IncidentStatus.resolved
            inc.resolved_at = datetime.now(timezone.utc)
        elif jira_status_name.lower() in ["in progress", "investigating"]:
            inc.status = IncidentStatus.investigating

        db.add(AuditLog(
            action=AuditAction.incident_updated,
            actor=current_user.username,
            target=inc.jira_ticket_key,
            details=f"Jira synchronization complete: ID={jira_id}, Status='{jira_status_name}' (Mapped: {inc.status.value})",
            status="success"
        ))
        db.commit()

        return {
            "status": "synchronized",
            "incident_id": inc.incident_id,
            "jira_ticket_key": inc.jira_ticket_key,
            "jira_ticket_id": jira_id,
            "jira_status": jira_status_name,
            "incident_status": inc.status.value,
            "assignee": assignee_name,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Failed to communicate with Jira: {str(e)}")


@router.get("/tickets")
async def list_jira_tickets(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    incidents = db.query(Incident).filter(Incident.jira_ticket_key.isnot(None)).all()
    return [
        {
            "incident_id": i.incident_id,
            "title": i.title,
            "severity": i.severity.value,
            "status": i.status.value,
            "jira_ticket_id": i.jira_ticket_id,
            "jira_ticket_key": i.jira_ticket_key,
            "jira_ticket_url": i.jira_ticket_url,
            "assigned_to": i.assigned_to
        }
        for i in incidents
    ]

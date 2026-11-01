"""Incidents API routes."""
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_
from pydantic import BaseModel

from app.db.database import get_db
from app.core.security import get_current_user
from app.models.incident import Incident, IncidentStatus, IncidentSeverity
from app.models.audit_log import AuditLog, AuditAction

router = APIRouter()


class CreateIncidentRequest(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str
    threat_type: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    affected_user: Optional[str] = None
    assigned_to: Optional[str] = None


class UpdateIncidentRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None


@router.get("/")
async def list_incidents(
    skip: int = 0, limit: int = 50,
    search: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    q = db.query(Incident)
    if search:
        q = q.filter(or_(
            Incident.incident_id.ilike(f"%{search}%"),
            Incident.title.ilike(f"%{search}%"),
            Incident.hostname.ilike(f"%{search}%"),
        ))
    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)

    total = q.count()
    items = q.order_by(Incident.detected_at.desc()).offset(skip).limit(limit).all()

    return {
        "total": total,
        "items": [
            {"id": i.id, "incident_id": i.incident_id, "title": i.title,
             "severity": i.severity.value, "status": i.status.value,
             "threat_type": i.threat_type, "hostname": i.hostname,
             "ip_address": i.ip_address, "affected_user": i.affected_user,
             "assigned_to": i.assigned_to, "jira_ticket_key": i.jira_ticket_key,
             "jira_ticket_url": i.jira_ticket_url, "detected_at": i.detected_at,
             "resolved_at": i.resolved_at}
            for i in items
        ]
    }


@router.get("/{incident_id}")
async def get_incident(incident_id: str, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {
        "id": inc.id, "incident_id": inc.incident_id, "title": inc.title,
        "description": inc.description, "severity": inc.severity.value,
        "status": inc.status.value, "threat_type": inc.threat_type,
        "hostname": inc.hostname, "ip_address": inc.ip_address,
        "affected_user": inc.affected_user, "assigned_to": inc.assigned_to,
        "jira_ticket_key": inc.jira_ticket_key, "jira_ticket_url": inc.jira_ticket_url,
        "resolution_notes": inc.resolution_notes,
        "detected_at": inc.detected_at, "contained_at": inc.contained_at,
        "resolved_at": inc.resolved_at, "created_at": inc.created_at
    }


@router.post("/")
async def create_incident(
    body: CreateIncidentRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    from datetime import datetime, timezone
    import uuid
    inc_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
    inc = Incident(
        incident_id=inc_id, title=body.title, description=body.description,
        severity=body.severity, threat_type=body.threat_type,
        hostname=body.hostname, ip_address=body.ip_address,
        affected_user=body.affected_user, assigned_to=body.assigned_to,
        status=IncidentStatus.detected, detected_at=datetime.now(timezone.utc)
    )
    db.add(inc)
    db.add(AuditLog(action=AuditAction.incident_created, actor=current_user.username,
                    target=inc_id, details=f"Incident created: {body.title}", status="success"))
    db.commit()
    db.refresh(inc)
    return {"incident_id": inc.incident_id, "message": "Incident created successfully"}


@router.patch("/{incident_id}")
async def update_incident(
    incident_id: str,
    body: UpdateIncidentRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if body.status:
        inc.status = body.status
        if body.status == IncidentStatus.resolved.value:
            inc.resolved_at = datetime.now(timezone.utc)
        elif body.status == IncidentStatus.containing.value:
            inc.contained_at = datetime.now(timezone.utc)
    if body.assigned_to is not None:
        inc.assigned_to = body.assigned_to
    if body.resolution_notes is not None:
        inc.resolution_notes = body.resolution_notes
    db.add(AuditLog(action=AuditAction.incident_updated, actor=current_user.username,
                    target=incident_id, details=f"Updated: {body.dict(exclude_none=True)}", status="success"))
    db.commit()
    return {"message": "Incident updated", "incident_id": incident_id}


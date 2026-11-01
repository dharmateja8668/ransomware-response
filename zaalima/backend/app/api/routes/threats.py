"""Threats API routes."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.db.database import get_db
from app.core.security import get_current_user
from app.models.threat import Threat, ThreatSeverity, ThreatStatus

router = APIRouter()


@router.get("/")
async def list_threats(
    skip: int = 0,
    limit: int = 50,
    search: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    q = db.query(Threat)
    if search:
        q = q.filter(or_(
            Threat.threat_name.ilike(f"%{search}%"),
            Threat.hostname.ilike(f"%{search}%"),
            Threat.ip_address.ilike(f"%{search}%"),
            Threat.username.ilike(f"%{search}%"),
            Threat.threat_id.ilike(f"%{search}%"),
        ))
    if severity:
        q = q.filter(Threat.severity == severity)
    if status:
        q = q.filter(Threat.status == status)
    if source:
        q = q.filter(Threat.source == source.upper())

    total = q.count()
    threats = q.order_by(Threat.detected_at.desc()).offset(skip).limit(limit).all()

    return {
        "total": total,
        "items": [
            {"id": t.id, "threat_id": t.threat_id, "threat_name": t.threat_name,
             "hostname": t.hostname, "ip_address": t.ip_address, "username": t.username,
             "severity": t.severity.value, "status": t.status.value,
             "process_name": t.process_name, "process_hash": t.process_hash,
             "description": t.description, "source": t.source, "detected_at": t.detected_at}
            for t in threats
        ]
    }


@router.get("/{threat_id}")
async def get_threat(threat_id: str, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    threat = db.query(Threat).filter(Threat.threat_id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return {
        "id": threat.id, "threat_id": threat.threat_id, "threat_name": threat.threat_name,
        "hostname": threat.hostname, "ip_address": threat.ip_address, "username": threat.username,
        "severity": threat.severity.value, "status": threat.status.value,
        "process_name": threat.process_name, "process_hash": threat.process_hash,
        "file_path": threat.file_path, "description": threat.description,
        "source": threat.source, "detected_at": threat.detected_at, "created_at": threat.created_at
    }


@router.patch("/{threat_id}/status")
async def update_threat_status(
    threat_id: str,
    body: dict,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    threat = db.query(Threat).filter(Threat.threat_id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    new_status = body.get("status")
    if new_status not in [s.value for s in ThreatStatus]:
        raise HTTPException(status_code=400, detail="Invalid status")
    threat.status = new_status
    db.commit()
    return {"message": "Status updated", "threat_id": threat_id, "status": new_status}


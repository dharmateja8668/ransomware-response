"""Audit Logs API routes."""
from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.db.database import get_db
from app.core.security import get_current_user
from app.models.audit_log import AuditLog

router = APIRouter()


@router.get("/")
async def list_audit_logs(
    skip: int = 0, limit: int = 100,
    search: Optional[str] = None,
    action: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    q = db.query(AuditLog)
    if search:
        q = q.filter(or_(
            AuditLog.actor.ilike(f"%{search}%"),
            AuditLog.target.ilike(f"%{search}%"),
            AuditLog.details.ilike(f"%{search}%"),
        ))
    if action:
        q = q.filter(AuditLog.action == action)

    total = q.count()
    items = q.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit).all()

    return {
        "total": total,
        "items": [
            {"id": l.id, "action": l.action.value, "actor": l.actor,
             "target": l.target, "details": l.details,
             "status": l.status, "ip_address": l.ip_address,
             "created_at": l.created_at}
            for l in items
        ]
    }


"""User Management API routes."""
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.database import get_db
from app.core.security import get_current_user, require_admin, hash_password
from app.models.user import User, UserRole
from app.models.audit_log import AuditLog, AuditAction

router = APIRouter()


@router.get("/")
async def list_users(
    skip: int = 0, limit: int = 100,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    users = db.query(User).offset(skip).limit(limit).all()
    return [
        {"id": u.id, "username": u.username, "email": u.email,
         "role": u.role.value, "is_active": u.is_active, "last_login": u.last_login,
         "created_at": u.created_at}
        for u in users
    ]


@router.post("/{user_id}/suspend")
async def suspend_user(
    user_id: int,
    body: dict = {},
    db: Session = Depends(get_db),
    current_user=Depends(require_admin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot suspend your own account")
    user.is_active = False
    db.add(AuditLog(
        action=AuditAction.user_suspended, actor=current_user.username,
        target=user.username,
        details=f"[SIMULATED] Account suspended. Reason: {body.get('reason', 'Security incident')}",
        status="success"
    ))
    db.commit()
    return {"message": f"[SIMULATED] User {user.username} suspended", "simulated": True}


@router.post("/{user_id}/activate")
async def activate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = True
    db.add(AuditLog(action=AuditAction.user_activated, actor=current_user.username,
                    target=user.username, details="Account reactivated", status="success"))
    db.commit()
    return {"message": f"User {user.username} reactivated"}


@router.post("/{user_id}/revoke-sessions")
async def revoke_sessions(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.add(AuditLog(action=AuditAction.session_revoked, actor=current_user.username,
                    target=user.username,
                    details=f"[SIMULATED] All sessions revoked for {user.username}", status="success"))
    db.commit()
    return {"message": f"[SIMULATED] Sessions revoked for {user.username}", "simulated": True}


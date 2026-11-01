"""Authentication routes."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from app.db.database import get_db
from app.models.user import User
from app.models.audit_log import AuditLog, AuditAction
from app.core.security import verify_password, create_access_token, hash_password, get_current_user

router = APIRouter()


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "soc_analyst"


@router.post("/login", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(
        (User.email == form_data.username) | (User.username == form_data.username)
    ).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        db.add(AuditLog(action=AuditAction.login, actor=form_data.username,
                        target=form_data.username, details="Failed login attempt", status="failed"))
        db.commit()
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is suspended")

    token = create_access_token({"sub": str(user.id), "role": user.role.value})
    user.last_login = datetime.now(timezone.utc)
    db.add(AuditLog(action=AuditAction.login, actor=user.username,
                    target=user.username, details="Successful login", status="success"))
    db.commit()

    return TokenResponse(
        access_token=token,
        user={"id": user.id, "username": user.username, "email": user.email,
              "role": user.role.value, "is_active": user.is_active}
    )


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "username": current_user.username,
            "email": current_user.email, "role": current_user.role.value,
            "is_active": current_user.is_active, "last_login": current_user.last_login}


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.add(AuditLog(action=AuditAction.logout, actor=current_user.username,
                    target=current_user.username, details="User logged out", status="success"))
    db.commit()
    return {"message": "Logged out successfully"}


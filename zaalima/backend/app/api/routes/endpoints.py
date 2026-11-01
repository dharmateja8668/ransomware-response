"""Endpoints API routes."""
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.db.database import get_db
from app.core.security import get_current_user
from app.services.crowdstrike_service import crowdstrike_service
from app.models.endpoint import Endpoint, EndpointStatus
from app.models.audit_log import AuditLog, AuditAction

router = APIRouter()


@router.get("/")
async def list_endpoints(
    skip: int = 0, limit: int = 100,
    search: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    q = db.query(Endpoint)
    if search:
        q = q.filter(or_(
            Endpoint.hostname.ilike(f"%{search}%"),
            Endpoint.ip_address.ilike(f"%{search}%"),
            Endpoint.connected_user.ilike(f"%{search}%"),
        ))
    if status:
        q = q.filter(Endpoint.status == status)

    total = q.count()
    items = q.order_by(Endpoint.hostname).offset(skip).limit(limit).all()

    return {
        "total": total,
        "items": [
            {"id": e.id, "hostname": e.hostname, "ip_address": e.ip_address,
             "operating_system": e.operating_system, "connected_user": e.connected_user,
             "status": e.status.value, "is_isolated": e.is_isolated,
             "edr_agent_id": e.edr_agent_id,
             "edr_provider": e.edr_provider, "last_seen": e.last_seen}
            for e in items
        ]
    }


@router.get("/{hostname}")
async def get_endpoint(hostname: str, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    ep = db.query(Endpoint).filter(Endpoint.hostname == hostname).first()
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {
        "id": ep.id, "hostname": ep.hostname, "ip_address": ep.ip_address,
        "mac_address": ep.mac_address, "operating_system": ep.operating_system,
        "os_version": ep.os_version, "connected_user": ep.connected_user,
        "status": ep.status.value, "is_isolated": ep.is_isolated,
        "edr_agent_id": ep.edr_agent_id, "edr_provider": ep.edr_provider,
        "last_seen": ep.last_seen, "isolation_time": ep.isolation_time
    }


@router.post("/{hostname}/isolate")
async def isolate_endpoint(
    hostname: str,
    body: dict = {},
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    ep = db.query(Endpoint).filter(Endpoint.hostname == hostname).first()
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    if ep.is_isolated:
        raise HTTPException(status_code=400, detail="Endpoint is already isolated")

    # Real CrowdStrike containment if provider is CROWDSTRIKE
    if ep.edr_provider == "CROWDSTRIKE":
        if not body.get("authorized", False):
            raise HTTPException(
                status_code=400,
                detail="Explicit authorization required ('authorized: true') for real CrowdStrike containment."
            )
        try:
            res = crowdstrike_service.contain_endpoint(
                ep.edr_agent_id or ep.hostname,
                comment=body.get("reason"),
                confirm_dev_machine=body.get("confirm_dev_machine", False)
            )
            ep.is_isolated = True
            ep.status = EndpointStatus.isolated
            ep.isolation_time = datetime.now(timezone.utc)
            db.add(AuditLog(
                action=AuditAction.endpoint_isolated, actor=current_user.username,
                target=hostname,
                details=f"REAL CrowdStrike network containment applied to {hostname} (Device: {res.get('device_id')}). Reason: {body.get('reason', 'Security Incident')}",
                status="success"
            ))
            db.commit()
            return {
                "message": f"Real CrowdStrike containment successfully applied to {hostname}",
                "hostname": hostname,
                "device_id": res.get("device_id"),
                "status": "isolated",
                "simulated": False,
                "provider": "CROWDSTRIKE"
            }
        except Exception as e:
            db.add(AuditLog(
                action=AuditAction.endpoint_isolated, actor=current_user.username,
                target=hostname,
                details=f"REAL CrowdStrike containment FAILED for {hostname}: {str(e)}",
                status="failed"
            ))
            db.commit()
            raise HTTPException(status_code=502, detail=f"CrowdStrike containment failed: {str(e)}")

    # SIMULATED isolation for non-CrowdStrike/demo endpoints
    ep.is_isolated = True
    ep.status = EndpointStatus.isolated
    ep.isolation_time = datetime.now(timezone.utc)
    db.add(AuditLog(
        action=AuditAction.endpoint_isolated, actor=current_user.username,
        target=hostname,
        details=f"[SIMULATED] Endpoint {hostname} isolated. Reason: {body.get('reason', 'Security incident')}",
        status="success"
    ))
    db.commit()
    return {"message": f"[SIMULATED] Endpoint {hostname} isolated successfully",
            "hostname": hostname, "status": "isolated", "simulated": True, "provider": ep.edr_provider}


@router.post("/{hostname}/restore")
async def restore_endpoint(
    hostname: str,
    body: dict = {},
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    ep = db.query(Endpoint).filter(Endpoint.hostname == hostname).first()
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    if not ep.is_isolated:
        raise HTTPException(status_code=400, detail="Endpoint is not isolated")

    # Real CrowdStrike containment release
    if ep.edr_provider == "CROWDSTRIKE":
        if not body.get("authorized", False):
            raise HTTPException(
                status_code=400,
                detail="Explicit authorization required ('authorized: true') to lift real CrowdStrike containment."
            )
        try:
            res = crowdstrike_service.lift_containment(ep.edr_agent_id or ep.hostname, comment=body.get("reason"))
            ep.is_isolated = False
            ep.status = EndpointStatus.healthy
            ep.isolation_time = None
            db.add(AuditLog(
                action=AuditAction.endpoint_restored, actor=current_user.username,
                target=hostname,
                details=f"REAL CrowdStrike network containment lifted for {hostname} (Device: {res.get('device_id')})",
                status="success"
            ))
            db.commit()
            return {
                "message": f"Real CrowdStrike containment lifted for {hostname}",
                "hostname": hostname,
                "device_id": res.get("device_id"),
                "status": "healthy",
                "simulated": False,
                "provider": "CROWDSTRIKE"
            }
        except Exception as e:
            db.add(AuditLog(
                action=AuditAction.endpoint_restored, actor=current_user.username,
                target=hostname,
                details=f"REAL CrowdStrike lift containment FAILED for {hostname}: {str(e)}",
                status="failed"
            ))
            db.commit()
            raise HTTPException(status_code=502, detail=f"CrowdStrike lift containment failed: {str(e)}")

    # SIMULATED restore
    ep.is_isolated = False
    ep.status = EndpointStatus.healthy
    ep.isolation_time = None
    db.add(AuditLog(
        action=AuditAction.endpoint_restored, actor=current_user.username,
        target=hostname,
        details=f"[SIMULATED] Endpoint {hostname} connectivity restored",
        status="success"
    ))
    db.commit()
    return {"message": f"[SIMULATED] Endpoint {hostname} restored successfully",
            "hostname": hostname, "status": "healthy", "simulated": True, "provider": ep.edr_provider}


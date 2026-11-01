"""CrowdStrike Falcon Real Integration Routes.

Provides endpoints for live connection verification, device enumeration,
real alert ingestion, and authorized network containment.
"""

from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.database import get_db
from app.core.security import get_current_user, require_admin
from app.services.crowdstrike_service import crowdstrike_service
from app.models.endpoint import Endpoint, EndpointStatus
from app.models.threat import Threat, ThreatSeverity, ThreatStatus
from app.models.audit_log import AuditLog, AuditAction

router = APIRouter()


class ContainmentRequest(BaseModel):
    target: str  # device_id or hostname
    comment: Optional[str] = None
    authorized: bool = False  # Explicit authorization flag
    confirm_dev_machine: bool = False  # Explicit confirmation for primary development computer


@router.get("/devices/{target}/containment-status")
async def get_device_containment_status(target: str, current_user=Depends(get_current_user)):
    """Queries CrowdStrike directly to verify live device containment status."""
    try:
        return crowdstrike_service.get_device_containment_status(target)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to query CrowdStrike device status: {str(e)}")


@router.get("/status")
async def get_crowdstrike_status(current_user=Depends(get_current_user)):
    """Returns the live connection and permission status of CrowdStrike Falcon."""
    return crowdstrike_service.get_connection_status()


@router.get("/devices")
async def list_crowdstrike_devices(
    limit: int = 50,
    current_user=Depends(get_current_user)
):
    """Retrieves actual enrolled devices directly from CrowdStrike Falcon."""
    try:
        devices = crowdstrike_service.get_real_devices(limit=limit)
        return {
            "source": "CROWDSTRIKE",
            "count": len(devices),
            "devices": devices
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"CrowdStrike API error: {str(e)}")


@router.get("/alerts")
async def list_crowdstrike_alerts(
    limit: int = 50,
    current_user=Depends(get_current_user)
):
    """Retrieves actual security detections/alerts directly from CrowdStrike Falcon."""
    try:
        alerts = crowdstrike_service.get_real_alerts(limit=limit)
        return {
            "source": "CROWDSTRIKE",
            "count": len(alerts),
            "alerts": alerts
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"CrowdStrike API error: {str(e)}")


@router.post("/sync")
async def sync_crowdstrike_data(
    db: Session = Depends(get_db),
    current_user=Depends(require_admin)
):
    """Syncs real devices and alerts from CrowdStrike into the ZAALIMA database.

    All synced records are explicitly labeled with source='CROWDSTRIKE'.
    """
    try:
        # Sync devices
        devices = crowdstrike_service.get_real_devices(limit=100)
        synced_devices = 0
        for d in devices:
            existing = db.query(Endpoint).filter(
                (Endpoint.hostname == d["hostname"]) | (Endpoint.edr_agent_id == d["device_id"])
            ).first()

            if existing:
                existing.ip_address = d["ip_address"]
                existing.operating_system = d["operating_system"]
                existing.edr_agent_id = d["device_id"]
                existing.edr_provider = "CROWDSTRIKE"
                existing.status = EndpointStatus.isolated if d["is_isolated"] else EndpointStatus.healthy
                existing.is_isolated = d["is_isolated"]
            else:
                new_ep = Endpoint(
                    hostname=d["hostname"],
                    ip_address=d["ip_address"],
                    operating_system=d["operating_system"],
                    connected_user=d["connected_user"],
                    status=EndpointStatus.isolated if d["is_isolated"] else EndpointStatus.healthy,
                    is_isolated=d["is_isolated"],
                    edr_agent_id=d["device_id"],
                    edr_provider="CROWDSTRIKE"
                )
                db.add(new_ep)
            synced_devices += 1

        # Sync alerts
        alerts = crowdstrike_service.get_real_alerts(limit=50)
        synced_alerts = 0
        for a in alerts:
            existing_t = db.query(Threat).filter(Threat.threat_id == a["threat_id"]).first()
            if not existing_t:
                new_t = Threat(
                    threat_id=a["threat_id"],
                    threat_name=a["threat_name"],
                    hostname=a["hostname"],
                    ip_address=a["ip_address"],
                    username=a["username"],
                    severity=ThreatSeverity(a["severity"]),
                    status=ThreatStatus(a["status"]),
                    process_name=a["process_name"],
                    process_hash=a["process_hash"],
                    description=a["description"],
                    source="CROWDSTRIKE",
                    detected_at=datetime.now(timezone.utc)
                )
                db.add(new_t)
                synced_alerts += 1

        db.commit()
        return {
            "success": True,
            "message": f"Synced {synced_devices} device(s) and {synced_alerts} alert(s) from CrowdStrike Falcon.",
            "synced_devices": synced_devices,
            "synced_alerts": synced_alerts
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=502, detail=f"CrowdStrike sync error: {str(e)}")


@router.post("/contain")
async def contain_crowdstrike_device(
    body: ContainmentRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin)
):
    """Executes REAL network containment on an enrolled CrowdStrike endpoint.

    Requires explicit 'authorized: true' confirmation flag and admin role.
    """
    if not body.authorized:
        raise HTTPException(
            status_code=400,
            detail="Authorization required: 'authorized' must be explicitly set to True before executing real containment."
        )

    try:
        result = crowdstrike_service.contain_endpoint(
            body.target,
            comment=body.comment,
            confirm_dev_machine=body.confirm_dev_machine
        )

        # Update local database record if present
        ep = db.query(Endpoint).filter(
            (Endpoint.hostname == body.target) | (Endpoint.edr_agent_id == body.target)
        ).first()
        if ep:
            ep.is_isolated = True
            ep.status = EndpointStatus.isolated
            ep.isolation_time = datetime.now(timezone.utc)

        db.add(AuditLog(
            action=AuditAction.endpoint_isolated,
            actor=current_user.username,
            target=body.target,
            details=f"REAL CrowdStrike Falcon network containment applied to {body.target} (Device: {result.get('device_id')}). Reason: {body.comment or 'Security Incident'}",
            status="success"
        ))
        db.commit()

        return {
            "success": True,
            "real_edr_action": True,
            "provider": "CROWDSTRIKE",
            "target": body.target,
            "device_id": result.get("device_id"),
            "status": "contained",
            "message": result.get("message")
        }
    except Exception as e:
        db.add(AuditLog(
            action=AuditAction.endpoint_isolated,
            actor=current_user.username,
            target=body.target,
            details=f"REAL CrowdStrike Falcon network containment FAILED for {body.target}: {str(e)}",
            status="failed"
        ))
        db.commit()
        raise HTTPException(status_code=502, detail=f"CrowdStrike containment failed: {str(e)}")


@router.post("/lift")
async def lift_crowdstrike_containment(
    body: ContainmentRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin)
):
    """Lifts REAL network containment on an enrolled CrowdStrike endpoint."""
    if not body.authorized:
        raise HTTPException(
            status_code=400,
            detail="Authorization required: 'authorized' must be explicitly set to True before lifting containment."
        )

    try:
        result = crowdstrike_service.lift_containment(body.target, comment=body.comment)

        # Update local database record if present
        ep = db.query(Endpoint).filter(
            (Endpoint.hostname == body.target) | (Endpoint.edr_agent_id == body.target)
        ).first()
        if ep:
            ep.is_isolated = False
            ep.status = EndpointStatus.healthy
            ep.isolation_time = None

        db.add(AuditLog(
            action=AuditAction.endpoint_restored,
            actor=current_user.username,
            target=body.target,
            details=f"REAL CrowdStrike Falcon network containment LIFTED for {body.target} (Device: {result.get('device_id')})",
            status="success"
        ))
        db.commit()

        return {
            "success": True,
            "real_edr_action": True,
            "provider": "CROWDSTRIKE",
            "target": body.target,
            "device_id": result.get("device_id"),
            "status": "healthy",
            "message": result.get("message")
        }
    except Exception as e:
        db.add(AuditLog(
            action=AuditAction.endpoint_restored,
            actor=current_user.username,
            target=body.target,
            details=f"REAL CrowdStrike Falcon lift containment FAILED for {body.target}: {str(e)}",
            status="failed"
        ))
        db.commit()
        raise HTTPException(status_code=502, detail=f"CrowdStrike lift containment failed: {str(e)}")


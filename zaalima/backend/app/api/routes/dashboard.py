"""Dashboard statistics API."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.database import get_db
from app.core.security import get_current_user
from app.models.threat import Threat, ThreatStatus, ThreatSeverity
from app.models.incident import Incident, IncidentStatus
from app.models.endpoint import Endpoint, EndpointStatus
from app.models.audit_log import AuditLog

router = APIRouter()


@router.get("/stats")
async def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    total_alerts = db.query(Threat).count()
    critical_threats = db.query(Threat).filter(
        Threat.severity == ThreatSeverity.critical,
        Threat.status != ThreatStatus.resolved
    ).count()
    active_incidents = db.query(Incident).filter(
        Incident.status.notin_([IncidentStatus.resolved])
    ).count()
    infected_endpoints = db.query(Endpoint).filter(
        Endpoint.status == EndpointStatus.infected
    ).count()
    isolated_endpoints = db.query(Endpoint).filter(
        Endpoint.status == EndpointStatus.isolated
    ).count()
    resolved_incidents = db.query(Incident).filter(
        Incident.status == IncidentStatus.resolved
    ).count()

    return {
        "total_alerts": total_alerts,
        "critical_threats": critical_threats,
        "active_incidents": active_incidents,
        "infected_endpoints": infected_endpoints,
        "isolated_endpoints": isolated_endpoints,
        "resolved_incidents": resolved_incidents,
    }


@router.get("/threat-timeline")
async def get_threat_timeline(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """Returns last 7 days threat counts per day."""
    from datetime import datetime, timedelta, timezone
    days = []
    for i in range(6, -1, -1):
        day = datetime.now(timezone.utc) - timedelta(days=i)
        start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end = day.replace(hour=23, minute=59, second=59)
        count = db.query(Threat).filter(
            Threat.detected_at >= start,
            Threat.detected_at <= end
        ).count()
        days.append({"date": start.strftime("%b %d"), "threats": count})
    return days


@router.get("/severity-distribution")
async def get_severity_distribution(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    result = db.query(Threat.severity, func.count(Threat.id)).group_by(Threat.severity).all()
    return [{"severity": r[0].value, "count": r[1]} for r in result]


@router.get("/recent-alerts")
async def get_recent_alerts(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    threats = db.query(Threat).order_by(Threat.detected_at.desc()).limit(10).all()
    return [
        {"threat_id": t.threat_id, "threat_name": t.threat_name, "hostname": t.hostname,
         "severity": t.severity.value, "status": t.status.value, "detected_at": t.detected_at}
        for t in threats
    ]


@router.get("/endpoint-health")
async def get_endpoint_health(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    result = db.query(Endpoint.status, func.count(Endpoint.id)).group_by(Endpoint.status).all()
    return [{"status": r[0].value, "count": r[1]} for r in result]


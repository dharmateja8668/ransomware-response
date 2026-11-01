"""Reports API routes."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.database import get_db
from app.core.security import get_current_user
from app.models.threat import Threat, ThreatSeverity, ThreatStatus
from app.models.incident import Incident, IncidentStatus
from app.models.endpoint import Endpoint, EndpointStatus
from app.models.forensic import ForensicEvidence
from app.models.playbook import PlaybookExecution, PlaybookStatus

router = APIRouter()


@router.get("/summary")
async def get_report_summary(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    return {
        "threats": {
            "total": db.query(Threat).count(),
            "critical": db.query(Threat).filter(Threat.severity == ThreatSeverity.critical).count(),
            "high": db.query(Threat).filter(Threat.severity == ThreatSeverity.high).count(),
            "medium": db.query(Threat).filter(Threat.severity == ThreatSeverity.medium).count(),
            "low": db.query(Threat).filter(Threat.severity == ThreatSeverity.low).count(),
            "resolved": db.query(Threat).filter(Threat.status == ThreatStatus.resolved).count(),
        },
        "incidents": {
            "total": db.query(Incident).count(),
            "active": db.query(Incident).filter(Incident.status != IncidentStatus.resolved).count(),
            "resolved": db.query(Incident).filter(Incident.status == IncidentStatus.resolved).count(),
            "with_jira_ticket": db.query(Incident).filter(Incident.jira_ticket_key.isnot(None)).count(),
        },
        "endpoints": {
            "total": db.query(Endpoint).count(),
            "healthy": db.query(Endpoint).filter(Endpoint.status == EndpointStatus.healthy).count(),
            "isolated": db.query(Endpoint).filter(Endpoint.is_isolated == True).count(),
            "infected": db.query(Endpoint).filter(Endpoint.status == EndpointStatus.infected).count(),
        },
        "forensics": {
            "total_evidence": db.query(ForensicEvidence).count(),
        },
        "playbooks": {
            "total_executions": db.query(PlaybookExecution).count(),
            "completed": db.query(PlaybookExecution).filter(PlaybookExecution.status == PlaybookStatus.completed).count(),
            "failed": db.query(PlaybookExecution).filter(PlaybookExecution.status == PlaybookStatus.failed).count(),
        }
    }


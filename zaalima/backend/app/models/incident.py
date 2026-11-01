import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Enum, Text, ForeignKey
from app.db.database import Base


class IncidentStatus(str, enum.Enum):
    detected = "detected"
    investigating = "investigating"
    containing = "containing"
    evidence_collection = "evidence_collection"
    resolved = "resolved"


class IncidentSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(100), unique=True, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(IncidentSeverity), nullable=False)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.detected)
    threat_type = Column(String(100), nullable=False)
    hostname = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    affected_user = Column(String(100), nullable=True)
    assigned_to = Column(String(100), nullable=True)
    jira_ticket_id = Column(String(50), nullable=True)
    jira_ticket_key = Column(String(50), nullable=True)
    jira_ticket_url = Column(String(500), nullable=True)
    resolution_notes = Column(Text, nullable=True)
    detected_at = Column(DateTime(timezone=True), nullable=False)
    contained_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))


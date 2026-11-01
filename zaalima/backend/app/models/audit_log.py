import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Enum, Text
from app.db.database import Base


class AuditAction(str, enum.Enum):
    threat_detected = "threat_detected"
    incident_created = "incident_created"
    incident_updated = "incident_updated"
    endpoint_isolated = "endpoint_isolated"
    endpoint_restored = "endpoint_restored"
    user_suspended = "user_suspended"
    user_activated = "user_activated"
    session_revoked = "session_revoked"
    evidence_collected = "evidence_collected"
    playbook_executed = "playbook_executed"
    jira_ticket_created = "jira_ticket_created"
    login = "login"
    logout = "logout"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(Enum(AuditAction), nullable=False)
    actor = Column(String(100), nullable=True)  # who performed the action
    target = Column(String(255), nullable=True)  # what was acted upon
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    status = Column(String(20), default="success")  # success / failed
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


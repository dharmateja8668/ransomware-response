import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Enum, Text, JSON, ForeignKey
from app.db.database import Base


class PlaybookStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id = Column(Integer, primary_key=True, index=True)
    execution_id = Column(String(100), unique=True, nullable=False, index=True)
    playbook_name = Column(String(255), nullable=False)
    incident_id = Column(String(100), nullable=True)
    hostname = Column(String(255), nullable=True)
    triggered_by = Column(String(100), nullable=True)
    status = Column(Enum(PlaybookStatus), default=PlaybookStatus.pending)
    steps = Column(JSON, nullable=True)  # List of step results
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


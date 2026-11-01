import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Enum, Text, Float
from app.db.database import Base


class ThreatSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class ThreatStatus(str, enum.Enum):
    new = "new"
    investigating = "investigating"
    contained = "contained"
    resolved = "resolved"
    false_positive = "false_positive"


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(100), unique=True, nullable=False, index=True)
    threat_name = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=False)
    username = Column(String(100), nullable=True)
    severity = Column(Enum(ThreatSeverity), nullable=False)
    status = Column(Enum(ThreatStatus), default=ThreatStatus.new)
    process_name = Column(String(255), nullable=True)
    process_hash = Column(String(128), nullable=True)
    file_path = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    raw_alert = Column(Text, nullable=True)
    source = Column(String(100), default="SIMULATED")
    detected_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))


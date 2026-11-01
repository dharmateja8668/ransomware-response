import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Enum, Text, Boolean
from app.db.database import Base


class EndpointStatus(str, enum.Enum):
    healthy = "healthy"
    suspicious = "suspicious"
    infected = "infected"
    isolated = "isolated"
    offline = "offline"


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)
    mac_address = Column(String(17), nullable=True)
    operating_system = Column(String(255), nullable=True)
    os_version = Column(String(100), nullable=True)
    connected_user = Column(String(100), nullable=True)
    status = Column(Enum(EndpointStatus), default=EndpointStatus.healthy)
    is_isolated = Column(Boolean, default=False)
    edr_agent_id = Column(String(255), nullable=True)
    edr_provider = Column(String(50), default="SIMULATED")
    last_seen = Column(DateTime(timezone=True), nullable=True)
    isolation_time = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))


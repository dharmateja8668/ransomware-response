import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Enum, Text, Boolean
from app.db.database import Base


class EvidenceType(str, enum.Enum):
    memory_dump = "memory_dump"
    disk_image = "disk_image"
    kape_artifacts = "kape_artifacts"
    volatility_report = "volatility_report"
    network_capture = "network_capture"
    log_files = "log_files"
    registry_hive = "registry_hive"


class ForensicEvidence(Base):
    __tablename__ = "forensic_evidence"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String(100), unique=True, nullable=False, index=True)
    incident_id = Column(String(100), nullable=True, index=True)
    hostname = Column(String(255), nullable=False)
    evidence_type = Column(Enum(EvidenceType), nullable=False)
    file_name = Column(String(500), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    file_hash_md5 = Column(String(32), nullable=True)
    file_hash_sha256 = Column(String(64), nullable=True)
    s3_bucket = Column(String(255), nullable=True)
    s3_key = Column(String(1000), nullable=True)
    chain_of_custody = Column(Text, nullable=True)
    collection_status = Column(String(50), default="pending")
    collected_by = Column(String(100), nullable=True)
    notes = Column(Text, nullable=True)
    collected_at = Column(DateTime(timezone=True), nullable=True)
    uploaded_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


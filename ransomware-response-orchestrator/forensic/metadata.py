"""
forensic/metadata.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Forensic Evidence Metadata Module.
Automated Ransomware Containment & Incident Response Orchestrator - Day 2.

Defines the data models, collection states, and serialization logic for
forensic collection job records and evidence manifests.

Security Requirements:
  - Secrets, access tokens, and passwords must NEVER be saved in metadata.
  - Simulated collection runs must be explicitly flagged with simulation_indicator=True.
  - Artifact locations must only be recorded when verified by the acquisition system.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

logger = logging.getLogger("orchestrator.forensic.metadata")


class CollectionStatus(str, Enum):
    """Lifecycle states of a forensic evidence collection job."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class CollectionMethod(str, Enum):
    """Supported evidence collection mechanisms."""
    KAPE = "KAPE"
    RAM = "RAM"
    INVESTIGATION_PACKAGE = "INVESTIGATION_PACKAGE"


class KapeArtifactCategory(str, Enum):
    """Permitted KAPE Windows forensic artifact categories."""
    REGISTRY = "Registry"
    FILESYSTEM = "FileSystem"
    EVENTLOGS = "EventLogs"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    BROWSER = "Browser"
    NETWORK = "Network"


# Default permitted artifact categories for baseline ransomware triage
DEFAULT_KAPE_CATEGORIES: List[str] = [
    KapeArtifactCategory.REGISTRY.value,
    KapeArtifactCategory.FILESYSTEM.value,
    KapeArtifactCategory.EVENTLOGS.value,
    KapeArtifactCategory.EXECUTION.value,
    KapeArtifactCategory.PERSISTENCE.value,
]


@dataclass
class EvidenceMetadata:
    """
    Standardized forensic collection metadata record.
    Generated for every evidence collection job.
    """
    incident_id: str
    endpoint_id: str
    collection_job_id: str = field(
        default_factory=lambda: f"col-{uuid.uuid4().hex[:12]}"
    )
    collection_method: str = CollectionMethod.KAPE.value
    requested_artifacts: List[str] = field(default_factory=list)
    requested_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: Optional[str] = None
    status: str = CollectionStatus.PENDING.value
    hostname: Optional[str] = None
    artifact_location: Optional[str] = None
    error_details: Optional[str] = None
    simulation_indicator: bool = True
    containment_verified: bool = False
    file_hash_sha256: Optional[str] = None
    file_size_bytes: Optional[int] = None
    diagnostic_notes: Optional[str] = None
    # Day 3: AWS S3 Cloud Storage Manifest Fields
    s3_bucket: Optional[str] = None
    s3_object_key: Optional[str] = None
    s3_metadata_key: Optional[str] = None
    s3_upload_status: Optional[str] = None  # None, NOT_UPLOADED, UPLOADED, VERIFIED, FAILED
    s3_uploaded_at: Optional[str] = None
    s3_checksum_sha256: Optional[str] = None
    s3_checksum_verified: bool = False
    s3_simulation_indicator: bool = True
    s3_version_id: Optional[str] = None

    def __post_init__(self) -> None:
        # Normalize status to enum string if passed as enum
        if isinstance(self.status, CollectionStatus):
            self.status = self.status.value
        if isinstance(self.collection_method, CollectionMethod):
            self.collection_method = self.collection_method.value

    def mark_running(self) -> None:
        """Transitions job to RUNNING state."""
        self.status = CollectionStatus.RUNNING.value
        logger.info("Forensic job %s transitioned to RUNNING", self.collection_job_id)

    def mark_completed(
        self,
        artifact_location: Optional[str] = None,
        file_hash_sha256: Optional[str] = None,
        file_size_bytes: Optional[int] = None,
        diagnostic_notes: Optional[str] = None,
    ) -> None:
        """Transitions job to COMPLETED state and records completion telemetry."""
        self.status = CollectionStatus.COMPLETED.value
        self.completed_at = datetime.now(timezone.utc).isoformat()
        if artifact_location is not None:
            self.artifact_location = artifact_location
        if file_hash_sha256 is not None:
            self.file_hash_sha256 = file_hash_sha256
        if file_size_bytes is not None:
            self.file_size_bytes = file_size_bytes
        if diagnostic_notes is not None:
            self.diagnostic_notes = diagnostic_notes
        logger.info(
            "Forensic job %s COMPLETED (location=%s, simulation=%s)",
            self.collection_job_id,
            self.artifact_location or "N/A",
            self.simulation_indicator,
        )

    def mark_failed(self, error_details: str, diagnostic_notes: Optional[str] = None) -> None:
        """Transitions job to FAILED state and records error telemetry."""
        self.status = CollectionStatus.FAILED.value
        self.completed_at = datetime.now(timezone.utc).isoformat()
        self.error_details = str(error_details)
        if diagnostic_notes is not None:
            self.diagnostic_notes = diagnostic_notes
        logger.error(
            "Forensic job %s FAILED: %s",
            self.collection_job_id,
            self.error_details,
        )

    def record_s3_upload(
        self,
        bucket: str,
        object_key: str,
        checksum_sha256: str,
        checksum_verified: bool,
        metadata_key: Optional[str] = None,
        version_id: Optional[str] = None,
        simulation: bool = True,
    ) -> None:
        """Records verified AWS S3 archive telemetry in the evidence manifest."""
        self.s3_bucket = bucket
        self.s3_object_key = object_key
        self.s3_metadata_key = metadata_key
        self.s3_uploaded_at = datetime.now(timezone.utc).isoformat()
        self.s3_checksum_sha256 = checksum_sha256
        self.s3_checksum_verified = checksum_verified
        self.s3_version_id = version_id
        self.s3_simulation_indicator = simulation
        self.s3_upload_status = "VERIFIED" if checksum_verified else "UPLOADED"
        logger.info(
            "Recorded S3 archive for job %s: s3://%s/%s (Verified=%s, Simulation=%s)",
            self.collection_job_id,
            bucket,
            object_key,
            checksum_verified,
            simulation,
        )

    def record_s3_failure(self, error_details: str) -> None:
        """Records an S3 upload or checksum verification failure."""
        self.s3_upload_status = "FAILED"
        prefix = f"{self.error_details} | " if self.error_details else ""
        self.error_details = f"{prefix}S3 Upload Error: {error_details}"
        logger.error("S3 upload failed for job %s: %s", self.collection_job_id, error_details)

    def to_dict(self) -> Dict[str, Any]:
        """Converts metadata record to dictionary, ensuring no secrets are exposed."""
        data = asdict(self)
        # Ensure enum values are strings
        if isinstance(data.get("status"), Enum):
            data["status"] = data["status"].value
        if isinstance(data.get("collection_method"), Enum):
            data["collection_method"] = data["collection_method"].value
        return data

    def to_json(self, indent: int = 2) -> str:
        """Serializes metadata to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, evidence_dir: Path | str) -> Path:
        """
        Persists metadata to a JSON file in the configured evidence directory.
        File naming: <evidence_dir>/<collection_job_id>_metadata.json
        """
        target_dir = Path(evidence_dir).resolve()
        target_dir.mkdir(parents=True, exist_ok=True)
        file_path = target_dir / f"{self.collection_job_id}_metadata.json"

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(self.to_json(indent=2))

        logger.debug("Saved forensic metadata to %s", file_path)
        return file_path

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvidenceMetadata:
        """Reconstructs EvidenceMetadata from dictionary."""
        # Filter for known fields
        known_keys = {
            "incident_id",
            "endpoint_id",
            "collection_job_id",
            "collection_method",
            "requested_artifacts",
            "requested_at",
            "completed_at",
            "status",
            "hostname",
            "artifact_location",
            "error_details",
            "simulation_indicator",
            "containment_verified",
            "file_hash_sha256",
            "file_size_bytes",
            "diagnostic_notes",
            "s3_bucket",
            "s3_object_key",
            "s3_metadata_key",
            "s3_upload_status",
            "s3_uploaded_at",
            "s3_checksum_sha256",
            "s3_checksum_verified",
            "s3_simulation_indicator",
            "s3_version_id",
        }
        filtered = {k: v for k, v in data.items() if k in known_keys}
        return cls(**filtered)

    @classmethod
    def load(cls, file_path: Path | str) -> EvidenceMetadata:
        """Loads EvidenceMetadata from a saved JSON file."""
        path = Path(file_path).resolve()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

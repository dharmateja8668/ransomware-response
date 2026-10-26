"""
forensic package
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Automated Ransomware Containment & Incident Response Orchestrator - Day 2
Automated Forensic Evidence Collection Module.
"""

from forensic.metadata import (
    CollectionMethod,
    CollectionStatus,
    DEFAULT_KAPE_CATEGORIES,
    EvidenceMetadata,
    KapeArtifactCategory,
)
from forensic.evidence_collector import (
    CollectionJobError,
    DefenderInvestigationPackageAdapter,
    DuplicateJobError,
    EndpointMismatchError,
    EndpointNotContainedError,
    ForensicCollectorAdapter,
    ForensicError,
    KapeCollectionAdapter,
    RAMAcquisitionAdapter,
    SafetyCheckError,
    UnknownContainmentError,
    UnsupportedMethodError,
)
from forensic.collection_service import ForensicCollectionService
from storage.s3_storage import (
    S3ChecksumMismatchError,
    S3Config,
    S3ConfigError,
    S3FileNotFoundError,
    S3NetworkError,
    S3PermissionError,
    S3StorageError,
    S3StorageService,
    UploadResult,
)

__all__ = [
    # Status & Method Enums
    "CollectionStatus",
    "CollectionMethod",
    "KapeArtifactCategory",
    "DEFAULT_KAPE_CATEGORIES",
    # Metadata Record
    "EvidenceMetadata",
    # Exceptions
    "ForensicError",
    "SafetyCheckError",
    "EndpointNotContainedError",
    "UnknownContainmentError",
    "EndpointMismatchError",
    "UnsupportedMethodError",
    "DuplicateJobError",
    "CollectionJobError",
    # S3 Exceptions
    "S3StorageError",
    "S3ConfigError",
    "S3FileNotFoundError",
    "S3PermissionError",
    "S3NetworkError",
    "S3ChecksumMismatchError",
    # Adapters
    "ForensicCollectorAdapter",
    "KapeCollectionAdapter",
    "RAMAcquisitionAdapter",
    "DefenderInvestigationPackageAdapter",
    # Core Service
    "ForensicCollectionService",
    # S3 Storage
    "S3Config",
    "S3StorageService",
    "UploadResult",
]

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
    # Adapters
    "ForensicCollectorAdapter",
    "KapeCollectionAdapter",
    "RAMAcquisitionAdapter",
    "DefenderInvestigationPackageAdapter",
    # Core Service
    "ForensicCollectionService",
]

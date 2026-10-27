"""
Incident investigation and response orchestration services.
"""

from .incident_service import IncidentService, IncidentInvestigationReport, EndpointAssessment
from .evidence_catalog import (
    EvidenceCatalogService,
    CatalogRecord,
    IntegrityCheckResult,
    EvidenceCatalogError,
    EvidenceNotFoundError,
    EvidenceIntegrityError,
)

# NOTE: OrchestratorPipeline is intentionally NOT re-exported here to avoid a
# circular import.  alert_correlator imports from services.evidence_catalog,
# which triggers this __init__.  If orchestrator_pipeline were loaded here it
# would in turn import from analysis.alert_correlator before that module has
# finished initialising.  Import OrchestratorPipeline directly:
#   from services.orchestrator_pipeline import OrchestratorPipeline

__all__ = [
    "IncidentService",
    "IncidentInvestigationReport",
    "EndpointAssessment",
    "EvidenceCatalogService",
    "CatalogRecord",
    "IntegrityCheckResult",
    "EvidenceCatalogError",
    "EvidenceNotFoundError",
    "EvidenceIntegrityError",
]

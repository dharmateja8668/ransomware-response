# incidents/__init__.py
"""
Incidents package for the Automated Ransomware Containment & Incident Response Orchestrator.
Provides data models, SQLite storage, and incident lifecycle management.
"""

from incidents.models import (
    IncidentAuditLogResponse,
    IncidentCreate,
    IncidentResponse,
    IncidentStatus,
    IncidentUpdateStatus,
)
from incidents.service import (
    IncidentDuplicateError,
    IncidentNotFoundError,
    create_incident,
    get_audit_logs_for_alert,
    get_incident_by_alert_id,
    list_incidents,
    record_audit_log,
    update_incident_status,
)

__all__ = [
    "IncidentAuditLogResponse",
    "IncidentCreate",
    "IncidentResponse",
    "IncidentStatus",
    "IncidentUpdateStatus",
    "IncidentDuplicateError",
    "IncidentNotFoundError",
    "create_incident",
    "get_audit_logs_for_alert",
    "get_incident_by_alert_id",
    "list_incidents",
    "record_audit_log",
    "update_incident_status",
]

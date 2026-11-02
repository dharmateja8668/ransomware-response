"""
Root bridge for backend.jira_integration.
"""

import importlib.util
from pathlib import Path
import sys

_JIRA_PATH = Path(__file__).resolve().parent.parent / "ransomware-orchestrator" / "backend" / "jira_integration.py"
_spec = importlib.util.spec_from_file_location("_orchestrator_backend_jira", _JIRA_PATH)
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    for _name in dir(_mod):
        if not _name.startswith("__"):
            globals()[_name] = getattr(_mod, _name)

__all__ = [
    "IncidentData",
    "IncidentValidationError",
    "JiraAssignmentError",
    "JiraAuthenticationError",
    "JiraClient",
    "JiraConnectionError",
    "JiraIntegrationError",
    "JiraProjectNotFoundError",
    "JiraTicketCreationError",
    "create_incident_ticket",
    "format_ticket_description",
    "format_ticket_summary",
    "format_adf_description",
    "validate_incident_data",
]

"""
Root bridge for backend.jira_integration.
"""

from pathlib import Path
import sys

_ORCHESTRATOR_DIR = Path(__file__).resolve().parent.parent / "ransomware-orchestrator"
if str(_ORCHESTRATOR_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCHESTRATOR_DIR))

from backend.jira_integration import (
    IncidentData,
    IncidentValidationError,
    JiraAssignmentError,
    JiraAuthenticationError,
    JiraClient,
    JiraConnectionError,
    JiraIntegrationError,
    JiraProjectNotFoundError,
    JiraTicketCreationError,
    create_incident_ticket,
    format_ticket_description,
    format_ticket_summary,
    format_adf_description,
    validate_incident_data,
)

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


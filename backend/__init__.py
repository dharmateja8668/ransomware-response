"""
Root convenience package bridging to ransomware-orchestrator/backend.
"""

from pathlib import Path
import sys

_ORCHESTRATOR_DIR = Path(__file__).resolve().parent.parent / "ransomware-orchestrator"
if str(_ORCHESTRATOR_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCHESTRATOR_DIR))

from backend.config import JiraConfig, load_config
from backend.jira_integration import (
    JiraClient,
    create_incident_ticket,
    JiraIntegrationError,
    JiraAuthenticationError,
    JiraConnectionError,
    JiraProjectNotFoundError,
    JiraTicketCreationError,
    IncidentValidationError,
)

__all__ = [
    "JiraConfig",
    "load_config",
    "JiraClient",
    "create_incident_ticket",
    "JiraIntegrationError",
    "JiraAuthenticationError",
    "JiraConnectionError",
    "JiraProjectNotFoundError",
    "JiraTicketCreationError",
    "IncidentValidationError",
]


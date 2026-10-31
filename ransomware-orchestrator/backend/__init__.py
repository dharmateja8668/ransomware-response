"""
Backend package for Automated Ransomware Containment & Incident Response Orchestrator.
Day 1: Jira Cloud REST API Integration.
"""

from backend.config import JiraConfig, load_config
from backend.jira_integration import (
    JiraClient,
    create_incident_ticket,
    format_ticket_summary,
    format_ticket_description,
    format_adf_description,
    validate_incident_data,
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
    "format_ticket_summary",
    "format_ticket_description",
    "format_adf_description",
    "validate_incident_data",
    "JiraIntegrationError",
    "JiraAuthenticationError",
    "JiraConnectionError",
    "JiraProjectNotFoundError",
    "JiraTicketCreationError",
    "IncidentValidationError",
]


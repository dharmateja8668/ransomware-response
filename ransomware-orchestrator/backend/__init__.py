"""
Backend package for Automated Ransomware Containment & Incident Response Orchestrator.
Day 1: Jira Cloud REST API Integration.
"""

from backend.config import JiraConfig, SlackConfig, load_config, load_slack_config
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
from backend.slack_integration import (
    SlackClient,
    SlackIntegrationError,
    SlackConfigurationError,
    SlackConnectionError,
    SlackHTTPError,
    TEST_NOTIFICATION_TEXT,
    send_slack_notification,
)
from backend.incident_notifications import (
    IncidentNotificationService,
    NotificationServiceError,
    NotificationValidationError,
    SEVERITY_INDICATORS,
    DEFAULT_SEVERITY_ROLES,
)

__all__ = [
    "JiraConfig",
    "SlackConfig",
    "load_config",
    "load_slack_config",
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
    "SlackClient",
    "SlackIntegrationError",
    "SlackConfigurationError",
    "SlackConnectionError",
    "SlackHTTPError",
    "TEST_NOTIFICATION_TEXT",
    "send_slack_notification",
    "IncidentNotificationService",
    "NotificationServiceError",
    "NotificationValidationError",
    "SEVERITY_INDICATORS",
    "DEFAULT_SEVERITY_ROLES",
]


"""
Root convenience package bridging to ransomware-orchestrator/backend.
"""

from pathlib import Path
import sys

_ORCHESTRATOR_DIR = Path(__file__).resolve().parent.parent / "ransomware-orchestrator"
if str(_ORCHESTRATOR_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCHESTRATOR_DIR))

from backend.config import JiraConfig, SlackConfig, load_config, load_slack_config
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
from backend.ransomware_simulator import (
    RansomwareSimulator,
    SEVERITY_INCIDENT_TEMPLATES,
    mask_report_secrets,
    run_ransomware_simulation,
)

__all__ = [
    "JiraConfig",
    "SlackConfig",
    "load_config",
    "load_slack_config",
    "JiraClient",
    "create_incident_ticket",
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
    "RansomwareSimulator",
    "SEVERITY_INCIDENT_TEMPLATES",
    "mask_report_secrets",
    "run_ransomware_simulation",
]


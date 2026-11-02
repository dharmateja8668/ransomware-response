"""
Root bridge for backend.slack_integration.
"""

import importlib.util
from pathlib import Path
import sys

_SLACK_PATH = Path(__file__).resolve().parent.parent / "ransomware-orchestrator" / "backend" / "slack_integration.py"
_spec = importlib.util.spec_from_file_location("_orchestrator_backend_slack", _SLACK_PATH)
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    for _name in dir(_mod):
        if not _name.startswith("__"):
            globals()[_name] = getattr(_mod, _name)

__all__ = [
    "SlackClient",
    "SlackIntegrationError",
    "SlackConfigurationError",
    "SlackConnectionError",
    "SlackHTTPError",
    "TEST_NOTIFICATION_TEXT",
    "sanitize_error_message",
    "send_slack_notification",
]

"""
Root bridge for backend.incident_notifications.
"""

import importlib.util
from pathlib import Path
import sys

_NOTIF_PATH = Path(__file__).resolve().parent.parent / "ransomware-orchestrator" / "backend" / "incident_notifications.py"
_spec = importlib.util.spec_from_file_location("_orchestrator_backend_notif", _NOTIF_PATH)
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    for _name in dir(_mod):
        if not _name.startswith("__"):
            globals()[_name] = getattr(_mod, _name)

__all__ = [
    "IncidentNotificationService",
    "NotificationServiceError",
    "NotificationValidationError",
    "SEVERITY_INDICATORS",
    "DEFAULT_SEVERITY_ROLES",
]


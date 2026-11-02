"""
Root bridge for backend.config.
"""

import importlib.util
from pathlib import Path
import sys

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "ransomware-orchestrator" / "backend" / "config.py"
_spec = importlib.util.spec_from_file_location("_orchestrator_backend_config", _CONFIG_PATH)
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    for _name in dir(_mod):
        if not _name.startswith("__"):
            globals()[_name] = getattr(_mod, _name)

__all__ = [
    "JiraConfig",
    "SlackConfig",
    "load_config",
    "load_slack_config",
    "mask_secret",
    "mask_webhook_url",
    "load_env_file",
    "audit_configuration",
]

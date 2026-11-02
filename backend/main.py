"""
Root CLI bridge for backend.main.
"""

import importlib.util
from pathlib import Path
import sys

_MAIN_PATH = Path(__file__).resolve().parent.parent / "ransomware-orchestrator" / "backend" / "main.py"
_spec = importlib.util.spec_from_file_location("_orchestrator_backend_main", _MAIN_PATH)
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    main = getattr(_mod, "main")
    run_orchestrator = getattr(_mod, "run_orchestrator")
    run_slack_test = getattr(_mod, "run_slack_test")
    run_notification_workflow_test = getattr(_mod, "run_notification_workflow_test")

__all__ = ["main", "run_orchestrator", "run_slack_test", "run_notification_workflow_test"]

if __name__ == "__main__":
    main()

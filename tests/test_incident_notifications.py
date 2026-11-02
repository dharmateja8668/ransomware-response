"""
Root test runner for Incident Notification tests (Week 4 Day 3 Task 2).
Loads ransomware-orchestrator/tests/test_incident_notifications.py so that tests
can be executed from either the root repository or inside ransomware-orchestrator/.
"""

import importlib.util
from pathlib import Path
import sys

ORCHESTRATOR_DIR = Path(__file__).resolve().parent.parent / "ransomware-orchestrator"
if str(ORCHESTRATOR_DIR) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATOR_DIR))

test_file = ORCHESTRATOR_DIR / "tests" / "test_incident_notifications.py"
spec = importlib.util.spec_from_file_location("orchestrator_test_incident_notif", test_file)
if spec and spec.loader:
    notif_mod = importlib.util.module_from_spec(spec)
    sys.modules["orchestrator_test_incident_notif"] = notif_mod
    spec.loader.exec_module(notif_mod)
    for name in dir(notif_mod):
        if not name.startswith("__"):
            globals()[name] = getattr(notif_mod, name)


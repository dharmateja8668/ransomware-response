"""
Root test runner for Jira Integration tests.
Loads ransomware-orchestrator/tests/test_jira.py so that tests can be run from
either the root repository or inside ransomware-orchestrator/.
"""

import importlib.util
from pathlib import Path
import sys

ORCHESTRATOR_DIR = Path(__file__).resolve().parent.parent / "ransomware-orchestrator"
if str(ORCHESTRATOR_DIR) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATOR_DIR))

test_file = ORCHESTRATOR_DIR / "tests" / "test_jira.py"
spec = importlib.util.spec_from_file_location("orchestrator_test_jira", test_file)
if spec and spec.loader:
    jira_mod = importlib.util.module_from_spec(spec)
    sys.modules["orchestrator_test_jira"] = jira_mod
    spec.loader.exec_module(jira_mod)
    for name in dir(jira_mod):
        if not name.startswith("__"):
            globals()[name] = getattr(jira_mod, name)

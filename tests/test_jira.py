"""
Root test runner for Jira Integration tests (Day 1 & Day 2).
Loads ransomware-orchestrator/tests/test_jira.py and test_jira_day2.py so that tests can be run from
either the root repository or inside ransomware-orchestrator/.
"""

import importlib.util
from pathlib import Path
import sys

ORCHESTRATOR_DIR = Path(__file__).resolve().parent.parent / "ransomware-orchestrator"
if str(ORCHESTRATOR_DIR) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATOR_DIR))

# Load Day 1 tests
test_file_day1 = ORCHESTRATOR_DIR / "tests" / "test_jira.py"
spec1 = importlib.util.spec_from_file_location("orchestrator_test_jira", test_file_day1)
if spec1 and spec1.loader:
    jira_mod1 = importlib.util.module_from_spec(spec1)
    sys.modules["orchestrator_test_jira"] = jira_mod1
    spec1.loader.exec_module(jira_mod1)
    for name in dir(jira_mod1):
        if not name.startswith("__"):
            globals()[name] = getattr(jira_mod1, name)

# Load Day 2 tests
test_file_day2 = ORCHESTRATOR_DIR / "tests" / "test_jira_day2.py"
if test_file_day2.exists():
    spec2 = importlib.util.spec_from_file_location("orchestrator_test_jira_day2", test_file_day2)
    if spec2 and spec2.loader:
        jira_mod2 = importlib.util.module_from_spec(spec2)
        sys.modules["orchestrator_test_jira_day2"] = jira_mod2
        spec2.loader.exec_module(jira_mod2)
        for name in dir(jira_mod2):
            if not name.startswith("__"):
                globals()[name] = getattr(jira_mod2, name)


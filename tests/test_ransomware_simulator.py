"""
Root test runner for Ransomware Simulator tests (Week 4 Day 4).
Loads ransomware-orchestrator/tests/test_ransomware_simulator.py so that tests
can be executed from either the root repository or inside ransomware-orchestrator/.
"""

import importlib.util
from pathlib import Path
import sys

ORCHESTRATOR_DIR = Path(__file__).resolve().parent.parent / "ransomware-orchestrator"
if str(ORCHESTRATOR_DIR) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATOR_DIR))

test_file = ORCHESTRATOR_DIR / "tests" / "test_ransomware_simulator.py"
spec = importlib.util.spec_from_file_location("orchestrator_test_simulator", test_file)
if spec and spec.loader:
    sim_mod = importlib.util.module_from_spec(spec)
    sys.modules["orchestrator_test_simulator"] = sim_mod
    spec.loader.exec_module(sim_mod)
    for name in dir(sim_mod):
        if not name.startswith("__"):
            globals()[name] = getattr(sim_mod, name)


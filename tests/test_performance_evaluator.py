"""
Root test runner for Performance Evaluator tests (Week 4 Day 5).
Loads ransomware-orchestrator/tests/test_performance_evaluator.py so that tests
can be executed from either the root repository or inside ransomware-orchestrator/.
"""

import importlib.util
from pathlib import Path
import sys

ORCHESTRATOR_DIR = Path(__file__).resolve().parent.parent / "ransomware-orchestrator"
if str(ORCHESTRATOR_DIR) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATOR_DIR))

test_file = ORCHESTRATOR_DIR / "tests" / "test_performance_evaluator.py"
spec = importlib.util.spec_from_file_location("orchestrator_test_performance_evaluator", test_file)
if spec and spec.loader:
    perf_mod = importlib.util.module_from_spec(spec)
    sys.modules["orchestrator_test_performance_evaluator"] = perf_mod
    spec.loader.exec_module(perf_mod)
    for name in dir(perf_mod):
        if not name.startswith("__"):
            globals()[name] = getattr(perf_mod, name)


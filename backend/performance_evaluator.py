"""
Root bridge for backend.performance_evaluator.
"""

import importlib.util
from pathlib import Path
import sys

_EVAL_PATH = Path(__file__).resolve().parent.parent / "ransomware-orchestrator" / "backend" / "performance_evaluator.py"
_spec = importlib.util.spec_from_file_location("_orchestrator_backend_perf_eval", _EVAL_PATH)
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    for _name in dir(_mod):
        if not _name.startswith("__"):
            globals()[_name] = getattr(_mod, _name)

__all__ = [
    "PerformanceEvaluator",
    "calculate_statistics",
    "calculate_p95",
]

if __name__ == "__main__":
    evaluator = PerformanceEvaluator()
    evaluator.run_full_evaluation()


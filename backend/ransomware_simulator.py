"""
Root bridge for backend.ransomware_simulator.
"""

import importlib.util
from pathlib import Path
import sys

_SIM_PATH = Path(__file__).resolve().parent.parent / "ransomware-orchestrator" / "backend" / "ransomware_simulator.py"
_spec = importlib.util.spec_from_file_location("_orchestrator_backend_simulator", _SIM_PATH)
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    for _name in dir(_mod):
        if not _name.startswith("__"):
            globals()[_name] = getattr(_mod, _name)

__all__ = [
    "RansomwareSimulator",
    "SEVERITY_INCIDENT_TEMPLATES",
    "mask_report_secrets",
    "run_ransomware_simulation",
]


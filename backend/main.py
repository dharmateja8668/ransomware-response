"""
Root CLI bridge for backend.main.
"""

from pathlib import Path
import sys

_ORCHESTRATOR_DIR = Path(__file__).resolve().parent.parent / "ransomware-orchestrator"
if str(_ORCHESTRATOR_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCHESTRATOR_DIR))

from backend.main import main, run_orchestrator

if __name__ == "__main__":
    main()


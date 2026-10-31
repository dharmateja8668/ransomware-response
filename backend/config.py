"""
Root bridge for backend.config.
"""

from pathlib import Path
import sys

_ORCHESTRATOR_DIR = Path(__file__).resolve().parent.parent / "ransomware-orchestrator"
if str(_ORCHESTRATOR_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCHESTRATOR_DIR))

from backend.config import JiraConfig, load_config, mask_secret, load_env_file

__all__ = ["JiraConfig", "load_config", "mask_secret", "load_env_file"]


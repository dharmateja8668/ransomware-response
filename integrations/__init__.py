# integrations/__init__.py
"""
EDR integration package for the Automated Ransomware Containment &
Incident Response Orchestrator.
"""

from integrations.alert_parser import (
    AlertParsingError,
    ParsedAlert,
    normalize_severity,
    normalize_timestamp,
    parse_and_enrich_alert,
)
from integrations.edr_client import (
    BaseEDRClient,
    CrowdStrikeClient,
    DefenderClient,
    EDRAuthError,
    EDRConfig,
    EDRConfigError,
    EDRConnectionError,
    EDRProvider,
    EDRTimeoutError,
    SimulatedEDRClient,
    create_edr_client,
)

__all__ = [
    "AlertParsingError",
    "ParsedAlert",
    "normalize_severity",
    "normalize_timestamp",
    "parse_and_enrich_alert",
    "BaseEDRClient",
    "CrowdStrikeClient",
    "DefenderClient",
    "EDRAuthError",
    "EDRConfig",
    "EDRConfigError",
    "EDRConnectionError",
    "EDRProvider",
    "EDRTimeoutError",
    "SimulatedEDRClient",
    "create_edr_client",
]

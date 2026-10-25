"""
EDR and external security platform integration clients.
"""

from .defender_client import (
    DefenderClient,
    ContainmentStatus,
    EDRConfig,
    EDRAuthenticationError,
    EDRAPIError,
    EDRConnectionError,
    EDRTimeoutError,
    EDRConfigError,
)

__all__ = [
    "DefenderClient",
    "ContainmentStatus",
    "EDRConfig",
    "EDRAuthenticationError",
    "EDRAPIError",
    "EDRConnectionError",
    "EDRTimeoutError",
    "EDRConfigError",
]

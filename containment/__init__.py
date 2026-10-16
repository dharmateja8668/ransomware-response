# containment/__init__.py
"""
Network Containment Package
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Week    : 2
Day     : 1 -- Develop the Network Containment Logic

PURPOSE
-------
Evaluates incoming security alerts against configurable containment policies
to determine whether automated network containment should be initiated for
an affected endpoint.
"""

from containment.network_containment import (
    ContainmentDecision,
    ContainmentPolicy,
    ContainmentValidationError,
    build_containment_decision,
    evaluate_containment,
    evaluate_policy,
    validate_alert,
)

__all__ = [
    "ContainmentDecision",
    "ContainmentPolicy",
    "ContainmentValidationError",
    "build_containment_decision",
    "evaluate_containment",
    "evaluate_policy",
    "validate_alert",
]

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
    DECISION_CONTAINMENT_NOT_RECOMMENDED,
    DECISION_CONTAINMENT_RECOMMENDED,
    DECISION_CONTAINMENT_REJECTED,
    EXECUTION_MODE_DRY_RUN,
    EXECUTION_MODE_LIVE,
    STATUS_CONFIRMED,
    STATUS_FAILED,
    STATUS_NOT_RECOMMENDED,
    STATUS_REJECTED,
    STATUS_REQUESTED,
    STATUS_SIMULATED,
    STATUS_UNKNOWN,
    ContainmentDecision,
    ContainmentExecutionResult,
    ContainmentPolicy,
    ContainmentRegistry,
    ContainmentValidationError,
    build_containment_decision,
    clear_containment_registry,
    evaluate_containment,
    evaluate_policy,
    execute_network_containment,
    get_containment_registry,
    parse_edr_isolation_response,
    validate_alert,
)

__all__ = [
    "DECISION_CONTAINMENT_NOT_RECOMMENDED",
    "DECISION_CONTAINMENT_RECOMMENDED",
    "DECISION_CONTAINMENT_REJECTED",
    "EXECUTION_MODE_DRY_RUN",
    "EXECUTION_MODE_LIVE",
    "STATUS_CONFIRMED",
    "STATUS_FAILED",
    "STATUS_NOT_RECOMMENDED",
    "STATUS_REJECTED",
    "STATUS_REQUESTED",
    "STATUS_SIMULATED",
    "STATUS_UNKNOWN",
    "ContainmentDecision",
    "ContainmentExecutionResult",
    "ContainmentPolicy",
    "ContainmentRegistry",
    "ContainmentValidationError",
    "build_containment_decision",
    "clear_containment_registry",
    "evaluate_containment",
    "evaluate_policy",
    "execute_network_containment",
    "get_containment_registry",
    "parse_edr_isolation_response",
    "validate_alert",
]

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

from containment.identity_response import (
    IdentityActionRegistry,
    IdentityResponsePolicy,
    clear_identity_registry,
    evaluate_identity_policy,
    execute_account_suspension,
    execute_session_revocation,
    extract_user_identifier,
    get_identity_registry,
    is_account_protected,
    process_coordinated_response_workflow,
)
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
    process_containment_workflow,
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
    "process_containment_workflow",
    "validate_alert",
    "IdentityActionRegistry",
    "IdentityResponsePolicy",
    "clear_identity_registry",
    "evaluate_identity_policy",
    "execute_account_suspension",
    "execute_session_revocation",
    "extract_user_identifier",
    "get_identity_registry",
    "is_account_protected",
    "process_coordinated_response_workflow",
]

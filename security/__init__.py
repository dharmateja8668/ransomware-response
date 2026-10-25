# security/__init__.py
"""
Security module for the Automated Ransomware Containment Orchestrator.
Provides authentication, authorization (RBAC), and secret management.
"""

from security.auth import (
    AuthenticatedIdentity,
    get_current_identity,
    require_permission,
    require_role,
    require_any_permission,
    ROLE_PERMISSIONS,
    create_test_jwt,
)

__all__ = [
    "AuthenticatedIdentity",
    "get_current_identity",
    "require_permission",
    "require_role",
    "require_any_permission",
    "ROLE_PERMISSIONS",
    "create_test_jwt",
]

# security/auth.py
"""
Centralized Authentication & Role-Based Access Control (RBAC) Module.

Provides:
  - Multi-tier API Key authentication with rotation support (primary & secondary keys).
  - Multi-identity API Key mapping (ORCHESTRATOR_API_KEYS).
  - Validated HMAC-SHA256 JWT bearer token authentication (signature, issuer, aud, exp).
  - Fine-grained role and permission enforcement (RBAC).
  - Constant-time secret comparison (secrets.compare_digest) to prevent timing attacks.
  - Zero credential leakage in logs or responses.
  - Test helper utilities for generating cryptographically signed test tokens.
"""

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Callable, Dict, List, Optional, Set

from fastapi import Depends, Header, HTTPException, status

logger = logging.getLogger("orchestrator.security")

# ── Role & Permission Definitions ─────────────────────────────────────────────

PERM_ALL = "*"
PERM_INCIDENT_READ = "incident:read"
PERM_INCIDENT_WRITE = "incident:write"
PERM_CONTAINMENT_EXECUTE = "containment:execute"
PERM_IDENTITY_SUSPEND = "identity:suspend"
PERM_IDENTITY_REVOKE = "identity:revoke"
PERM_CONTAINMENT_COORDINATE = "containment:coordinate"

ALL_PERMISSIONS = {
    PERM_ALL,
    PERM_INCIDENT_READ,
    PERM_INCIDENT_WRITE,
    PERM_CONTAINMENT_EXECUTE,
    PERM_IDENTITY_SUSPEND,
    PERM_IDENTITY_REVOKE,
    PERM_CONTAINMENT_COORDINATE,
}

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "admin": {PERM_ALL},
    "secops_responder": {
        PERM_INCIDENT_READ,
        PERM_INCIDENT_WRITE,
        PERM_CONTAINMENT_EXECUTE,
        PERM_IDENTITY_SUSPEND,
        PERM_IDENTITY_REVOKE,
        PERM_CONTAINMENT_COORDINATE,
    },
    "containment_specialist": {
        PERM_INCIDENT_READ,
        PERM_CONTAINMENT_EXECUTE,
    },
    "identity_specialist": {
        PERM_INCIDENT_READ,
        PERM_IDENTITY_SUSPEND,
        PERM_IDENTITY_REVOKE,
    },
    "soc_analyst": {
        PERM_INCIDENT_READ,
    },
}


@dataclass
class AuthenticatedIdentity:
    """Represents an authenticated principal with roles and resolved permissions."""
    identity_id: str
    roles: Set[str] = field(default_factory=set)
    permissions: Set[str] = field(default_factory=set)
    auth_method: str = "api_key"

    def has_permission(self, permission: str) -> bool:
        """Check if principal holds the specified permission or wildcard admin."""
        if PERM_ALL in self.permissions or "admin" in self.roles:
            return True
        return permission in self.permissions

    def has_role(self, role: str) -> bool:
        """Check if principal holds the specified role or admin."""
        if "admin" in self.roles:
            return True
        return role in self.roles


# ── Secret Validation ─────────────────────────────────────────────────────────

MIN_SECRET_LENGTH = 16

DISALLOWED_WEAK_SECRETS = {
    "admin",
    "password",
    "12345678",
    "1234567890",
    "secret",
    "changeme",
    "default",
    "root",
    "guest",
    "secops-admin-key-change-me-in-production",
    "your-secure-webhook-secret-here",
    "your-32-byte-base64-or-hex-secret-key-for-hs256-signing",
}


def validate_api_secret_strength(secret: str) -> bool:
    """
    Validates that an API secret or token meets minimum enterprise strength requirements:
      - At least 16 characters in length
      - Not matching known placeholder, weak, or trivial defaults
    Returns True if valid; False otherwise. Never logs or echoes the secret value.
    """
    if not secret or not isinstance(secret, str):
        return False
    stripped = secret.strip()
    if len(stripped) < MIN_SECRET_LENGTH:
        return False
    if stripped.lower() in DISALLOWED_WEAK_SECRETS:
        return False
    return True


# ── Configuration Retrieval ───────────────────────────────────────────────────

def get_configured_api_keys() -> Dict[str, Dict]:
    """
    Returns configured API keys mapped to identity and roles.
    Only registers keys that meet strength requirements.
    Requires keys to be provided via environment variables:
      1. ORCHESTRATOR_API_KEYS (JSON string mapping key -> {identity, roles})
      2. ORCHESTRATOR_API_KEY (primary single key, defaults to role 'admin')
      3. ORCHESTRATOR_API_KEY_SECONDARY (rotation key, defaults to role 'admin')
    Fails safely with empty map if no valid keys are configured.
    """
    keys_map: Dict[str, Dict] = {}

    # 1. Parse JSON mapping if configured
    raw_json = os.environ.get("ORCHESTRATOR_API_KEYS", "").strip()
    if raw_json:
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    if not validate_api_secret_strength(k):
                        logger.warning(
                            "Configured API key in ORCHESTRATOR_API_KEYS does not meet security strength requirements (min %d chars, non-trivial). Skipping key.",
                            MIN_SECRET_LENGTH,
                        )
                        continue
                    if isinstance(v, dict):
                        keys_map[k] = {
                            "identity": v.get("identity", "service_account"),
                            "roles": set(v.get("roles", ["admin"])),
                            "permissions": set(v.get("permissions", [])),
                        }
                    elif isinstance(v, list):
                        keys_map[k] = {
                            "identity": "service_account",
                            "roles": set(v),
                            "permissions": set(),
                        }
        except Exception as exc:
            logger.warning("Failed to parse ORCHESTRATOR_API_KEYS JSON configuration: %s", exc)

    # 2. Primary API key (MUST be configured via environment variable -- no insecure hardcoded fallback)
    primary_key = os.environ.get("ORCHESTRATOR_API_KEY", "").strip()
    if primary_key:
        if validate_api_secret_strength(primary_key):
            if primary_key not in keys_map:
                keys_map[primary_key] = {
                    "identity": "primary_admin",
                    "roles": {"admin"},
                    "permissions": {PERM_ALL},
                }
        else:
            logger.warning(
                "Configured ORCHESTRATOR_API_KEY does not meet security strength requirements (min %d chars, non-trivial). It will not be registered.",
                MIN_SECRET_LENGTH,
            )

    # 3. Secondary API key (for rotation)
    secondary_key = os.environ.get("ORCHESTRATOR_API_KEY_SECONDARY", "").strip()
    if secondary_key:
        if validate_api_secret_strength(secondary_key):
            if secondary_key not in keys_map:
                keys_map[secondary_key] = {
                    "identity": "secondary_admin",
                    "roles": {"admin"},
                    "permissions": {PERM_ALL},
                }
        else:
            logger.warning(
                "Configured ORCHESTRATOR_API_KEY_SECONDARY does not meet security strength requirements (min %d chars, non-trivial). It will not be registered.",
                MIN_SECRET_LENGTH,
            )

    return keys_map


def _resolve_permissions(roles: Set[str], explicit_perms: Optional[Set[str]] = None) -> Set[str]:
    """Combines role-derived permissions with any explicit permissions."""
    perms = set(explicit_perms or [])
    for role in roles:
        role_perms = ROLE_PERMISSIONS.get(role, set())
        perms.update(role_perms)
    return perms


# ── JWT Validation (HMAC-SHA256) ──────────────────────────────────────────────

def _b64url_decode(payload_str: str) -> bytes:
    """Safely decodes base64url-encoded string with padding correction."""
    rem = len(payload_str) % 4
    if rem > 0:
        payload_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(payload_str.encode("utf-8"))


def _validate_jwt_token(token: str) -> AuthenticatedIdentity:
    """
    Validates a cryptographic JWT bearer token using HMAC-SHA256.
    Enforces:
      - 3-segment structure (header.payload.signature)
      - Algorithm HS256 (rejects 'none' and mismatched algorithms)
      - Valid HMAC-SHA256 signature using JWT_SECRET_KEY
      - Expiration timestamp ('exp') claim
      - Issuer ('iss') and Audience ('aud') claims if configured
      - Safe extraction of identity ('sub'), roles, and permissions
    """
    jwt_secret = os.environ.get("JWT_SECRET_KEY", "").strip()
    if not jwt_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT token validation not configured on server (JWT_SECRET_KEY missing).",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not validate_api_secret_strength(jwt_secret):
        logger.error("Configured JWT_SECRET_KEY does not meet minimum security strength requirements.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Server token validation misconfigured.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed bearer token format.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    header_b64, payload_b64, signature_b64 = parts

    # 1. Header validation
    try:
        header_bytes = _b64url_decode(header_b64)
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if header.get("alg") != "HS256":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unsupported token signing algorithm. Expected HS256.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Cryptographic signature verification using constant-time comparison
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_sig = hmac.new(jwt_secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        provided_sig = _b64url_decode(signature_b64)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token signature.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not secrets.compare_digest(expected_sig, provided_sig):
        logger.warning("Bearer token signature verification failed.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Payload validation
    try:
        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    now = int(time.time())

    # Expiry verification
    exp = payload.get("exp")
    if exp is not None:
        try:
            if int(exp) < now:
                logger.warning("Expired bearer token presented.")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        except (ValueError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 'exp' claim in token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Issuer verification
    expected_iss = os.environ.get("JWT_ISSUER", "").strip()
    if expected_iss:
        if payload.get("iss") != expected_iss:
            logger.warning("Bearer token issuer mismatch.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token issuer invalid.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Audience verification
    expected_aud = os.environ.get("JWT_AUDIENCE", "").strip()
    if expected_aud:
        token_aud = payload.get("aud")
        aud_match = False
        if isinstance(token_aud, list) and expected_aud in token_aud:
            aud_match = True
        elif isinstance(token_aud, str) and token_aud == expected_aud:
            aud_match = True
        if not aud_match:
            logger.warning("Bearer token audience mismatch.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token audience invalid.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    identity_id = payload.get("sub", "authenticated_jwt_principal")
    raw_roles = payload.get("roles", ["admin"] if "roles" not in payload else [])
    roles = set(raw_roles) if isinstance(raw_roles, list) else {str(raw_roles)}
    raw_perms = payload.get("permissions", [])
    perms = set(raw_perms) if isinstance(raw_perms, list) else {str(raw_perms)}
    resolved_perms = _resolve_permissions(roles, perms)

    return AuthenticatedIdentity(
        identity_id=identity_id,
        roles=roles,
        permissions=resolved_perms,
        auth_method="jwt_bearer",
    )


# ── Dependency: Get Current Identity ──────────────────────────────────────────

def get_current_identity(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> AuthenticatedIdentity:
    """
    FastAPI dependency that extracts and validates incoming credentials.
    Supports:
      1. X-API-Key header.
      2. Authorization: Bearer <API-Key> or <JWT>.
      3. Authorization: ApiKey <API-Key>.
    Uses constant-time comparison for all secret checks.
    Never logs credentials or leaks them in error responses.
    """
    token: Optional[str] = None
    auth_scheme: Optional[str] = None

    if x_api_key:
        token = x_api_key.strip()
        auth_scheme = "apikey"
    elif authorization:
        parts = authorization.strip().split(None, 1)
        if len(parts) == 2:
            scheme, value = parts
            auth_scheme = scheme.lower()
            token = value.strip()
        elif len(parts) == 1:
            token = parts[0].strip()
            auth_scheme = "bearer"

    if not token:
        logger.warning("Unauthorized request rejected: missing authentication credentials.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid API key or Bearer token.",
            headers={"WWW-Authenticate": 'Bearer realm="orchestrator", ApiKey realm="orchestrator"'},
        )

    # Case A: If 3-segment token and scheme is Bearer, attempt JWT validation
    if token.count(".") == 2 and auth_scheme in ("bearer", None):
        return _validate_jwt_token(token)

    # Case B: API Key matching using constant-time comparison against all configured keys
    configured_keys = get_configured_api_keys()

    if not configured_keys:
        logger.error("Authentication rejected: No valid API keys are configured on the server.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials are not configured on the server.",
            headers={"WWW-Authenticate": 'Bearer realm="orchestrator", ApiKey realm="orchestrator"'},
        )

    matched_identity_info: Optional[Dict] = None
    for configured_key, info in configured_keys.items():
        if secrets.compare_digest(token, configured_key):
            matched_identity_info = info
            break

    if matched_identity_info is None:
        logger.warning("Unauthorized request rejected: invalid API key or token presented.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
            headers={"WWW-Authenticate": 'Bearer realm="orchestrator", ApiKey realm="orchestrator"'},
        )

    roles = matched_identity_info.get("roles", set())
    perms = matched_identity_info.get("permissions", set())
    resolved = _resolve_permissions(roles, perms)

    return AuthenticatedIdentity(
        identity_id=matched_identity_info.get("identity", "api_key_principal"),
        roles=roles,
        permissions=resolved,
        auth_method="api_key",
    )


# ── Authorization Dependencies (RBAC) ─────────────────────────────────────────

def require_permission(required_permission: str) -> Callable[[AuthenticatedIdentity], AuthenticatedIdentity]:
    """
    Returns a FastAPI dependency that verifies the caller holds the specified permission.
    Rejects unauthorized callers with HTTP 403 Forbidden.
    """
    def _perm_dependency(identity: AuthenticatedIdentity = Depends(get_current_identity)) -> AuthenticatedIdentity:
        if not identity.has_permission(required_permission):
            logger.warning(
                "Access denied for principal '%s': lacks permission '%s'. Principal perms: %s",
                identity.identity_id,
                required_permission,
                list(identity.permissions),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: Insufficient permissions. Required: '{required_permission}'.",
            )
        return identity

    return _perm_dependency


def require_any_permission(*required_permissions: str) -> Callable[[AuthenticatedIdentity], AuthenticatedIdentity]:
    """
    Returns a FastAPI dependency verifying the caller holds at least one of the specified permissions.
    """
    def _any_perm_dependency(identity: AuthenticatedIdentity = Depends(get_current_identity)) -> AuthenticatedIdentity:
        has_any = any(identity.has_permission(p) for p in required_permissions)
        if not has_any:
            logger.warning(
                "Access denied for principal '%s': lacks any of required permissions %s",
                identity.identity_id,
                list(required_permissions),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: Requires at least one permission from: {list(required_permissions)}.",
            )
        return identity

    return _any_perm_dependency


def require_role(required_role: str) -> Callable[[AuthenticatedIdentity], AuthenticatedIdentity]:
    """
    Returns a FastAPI dependency that verifies the caller holds the specified role.
    """
    def _role_dependency(identity: AuthenticatedIdentity = Depends(get_current_identity)) -> AuthenticatedIdentity:
        if not identity.has_role(required_role):
            logger.warning(
                "Access denied for principal '%s': lacks role '%s'. Principal roles: %s",
                identity.identity_id,
                required_role,
                list(identity.roles),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: Requires role '{required_role}'.",
            )
        return identity

    return _role_dependency


# ── Test Utility: Create Test JWT ─────────────────────────────────────────────

def create_test_jwt(
    identity_id: str = "test-principal",
    roles: Optional[List[str]] = None,
    permissions: Optional[List[str]] = None,
    secret: str = "test-secret-key-for-jwt-signing-123",
    expires_in: int = 3600,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    header_alg: str = "HS256",
) -> str:
    """
    Generates a cryptographically signed HMAC-SHA256 JWT for unit testing.
    Never use default secrets in production.
    """
    now = int(time.time())
    header = {"alg": header_alg, "typ": "JWT"}
    payload = {
        "sub": identity_id,
        "iat": now,
        "exp": now + expires_in,
        "roles": roles or ["admin"],
        "permissions": permissions or [],
    }
    if issuer:
        payload["iss"] = issuer
    if audience:
        payload["aud"] = audience

    header_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    header_b64 = base64.urlsafe_b64encode(header_json).decode("utf-8").rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode("utf-8").rstrip("=")

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")

    return f"{header_b64}.{payload_b64}.{sig_b64}"

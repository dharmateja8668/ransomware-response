# integrations/identity_client.py
"""
Identity Provider Integration Module (Microsoft Entra ID & Microsoft Graph API)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Week    : 2
Day     : 4 -- Identity Provider Integration and Account Suspension
Day     : 5 -- Session Revocation and Coordinated Incident Response

PURPOSE
-------
Provides authenticated interaction with an enterprise Identity Provider (IdP)
such as Microsoft Entra ID (formerly Azure Active Directory) via Microsoft Graph API.

Supported Capabilities:
  1. OAuth 2.0 client-credentials authentication against Microsoft Entra ID.
  2. Resolving directory user accounts safely from incoming alert telemetry.
  3. Retrieving user directory IDs, UPNs, emails, and account status.
  4. Performing policy-controlled account suspension (PATCH /v1.0/users/{id} accountEnabled: false).
  5. Performing user session revocation (POST /v1.0/users/{id}/revokeSignInSessions).
  6. Enforcing safety controls (default dry-run simulation, credential protection,
     emergency administrator / break-glass / service-account protections).
  7. High-fidelity simulated / mock identity client for test and development without live credentials.

SECURITY NOTES
--------------
  - Credentials (client secrets, tokens, authorization headers) are NEVER logged.
  - Live execution is DISABLED by default (dry-run mode is default).
  - Dry-run mode never modifies real accounts or revokes real sessions.
  - API failures never silently fall back to simulated success.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import requests
from requests import Response
from requests.exceptions import ConnectionError, HTTPError, Timeout

logger = logging.getLogger("orchestrator.identity")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Enums and Constants
# ─────────────────────────────────────────────────────────────────────────────


class IdentityProvider(str, Enum):
    ENTRA_ID = "entra_id"
    AZURE_AD = "azure_ad"
    MOCK = "mock"
    SIMULATED = "simulated"


# Operation Action Names
ACTION_LOOKUP_USER = "LOOKUP_USER"
ACTION_SUSPEND_ACCOUNT = "SUSPEND_ACCOUNT"
ACTION_REVOKE_SESSIONS = "REVOKE_SESSIONS"

# Execution Modes
EXECUTION_MODE_DRY_RUN = "dry_run"
EXECUTION_MODE_LIVE = "live"

# Normalized Result Statuses
STATUS_SIMULATED = "SIMULATED"
STATUS_REQUESTED = "REQUESTED"
STATUS_CONFIRMED = "CONFIRMED"
STATUS_FAILED = "FAILED"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_REJECTED = "REJECTED"
STATUS_UNSUPPORTED = "UNSUPPORTED"
STATUS_NOT_RECOMMENDED = "NOT_RECOMMENDED"


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────


class IdentityConfigError(Exception):
    """Raised when identity provider configuration is missing, incomplete, or invalid."""


class IdentityAuthError(Exception):
    """Raised when authentication or authorization with the identity provider fails."""


class IdentityConnectionError(Exception):
    """Raised when network connectivity to the identity provider fails."""


class IdentityTimeoutError(Exception):
    """Raised when identity provider API calls exceed the configured timeout."""


class IdentityAPIError(Exception):
    """Raised when the identity provider API returns an unexpected error or malformed response."""


class UserNotFoundError(Exception):
    """Raised when the requested user identity cannot be resolved in the directory."""


class AmbiguousUserError(Exception):
    """Raised when a user search matches multiple directory identities."""


class ProtectedAccountError(Exception):
    """Raised when an action targets a protected emergency, break-glass, or service account."""


class IneligibleAccountError(Exception):
    """Raised when a target account is ineligible for the requested operation (e.g. already disabled)."""


class UnsupportedOperationError(Exception):
    """Raised when the identity provider does not support the requested operation."""


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────


class IdentityConfig:
    """
    Reads identity provider configuration from environment variables.
    Never exposes raw secrets in representations or logs.
    """

    DEFAULT_GRAPH_BASE_URL = "https://graph.microsoft.com"
    DEFAULT_TIMEOUT_SECONDS = 10
    DEFAULT_PROTECTED_ACCOUNTS = {
        "admin",
        "administrator",
        "breakglass",
        "break-glass",
        "emergency",
        "emergency-admin",
        "orchestrator",
        "svc-orchestrator",
        "orchestrator-svc",
        "root",
    }

    def __init__(self) -> None:
        raw_provider = os.environ.get("IDENTITY_PROVIDER", "mock").strip().lower()
        if raw_provider in ("entra_id", "azure_ad", "entra", "azure"):
            self.provider = IdentityProvider.ENTRA_ID
        elif raw_provider in ("mock", "simulated", "fake", ""):
            self.provider = IdentityProvider.MOCK
        else:
            raise IdentityConfigError(
                f"IDENTITY_PROVIDER='{raw_provider}' is not supported. "
                "Allowed values: 'entra_id' or 'mock'."
            )

        self.tenant_id: str = os.environ.get("IDENTITY_TENANT_ID", "").strip()
        self.client_id: str = os.environ.get("IDENTITY_CLIENT_ID", "").strip()
        self.client_secret: str = os.environ.get("IDENTITY_CLIENT_SECRET", "").strip()
        self.graph_base_url: str = (
            os.environ.get("IDENTITY_GRAPH_BASE_URL", self.DEFAULT_GRAPH_BASE_URL).strip()
            or self.DEFAULT_GRAPH_BASE_URL
        )

        try:
            self.timeout: int = int(
                os.environ.get("IDENTITY_TIMEOUT_SECONDS", str(self.DEFAULT_TIMEOUT_SECONDS))
            )
        except ValueError:
            raise IdentityConfigError("IDENTITY_TIMEOUT_SECONDS must be an integer (e.g. 10).")

        # Execution mode configuration
        env_mode = os.environ.get("IDENTITY_EXECUTION_MODE", "").strip().lower()
        env_dry = os.environ.get("IDENTITY_DRY_RUN", "").strip().lower()
        if env_mode == "live" or env_dry in ("false", "0", "no"):
            self.dry_run = False
        else:
            self.dry_run = True  # Mode A Dry-Run is enabled by default

        # Protected accounts configuration
        raw_protected = os.environ.get("IDENTITY_PROTECTED_ACCOUNTS", "").strip()
        self.protected_accounts: Set[str] = set(self.DEFAULT_PROTECTED_ACCOUNTS)
        if raw_protected:
            for item in raw_protected.split(","):
                clean_item = item.strip().lower()
                if clean_item:
                    self.protected_accounts.add(clean_item)

        # Optional test account allowlist
        raw_allowlist = os.environ.get("IDENTITY_TEST_ACCOUNT_ALLOWLIST", "").strip()
        self.allowed_test_accounts: Optional[Set[str]] = None
        if raw_allowlist:
            self.allowed_test_accounts = {
                acct.strip().lower() for acct in raw_allowlist.split(",") if acct.strip()
            }

        self._validate()

    def _validate(self) -> None:
        """Validates configuration if live execution against Entra ID is configured."""
        if not self.dry_run and self.provider == IdentityProvider.ENTRA_ID:
            missing: List[str] = []
            if not self.tenant_id:
                missing.append("IDENTITY_TENANT_ID")
            if not self.client_id:
                missing.append("IDENTITY_CLIENT_ID")
            if not self.client_secret:
                missing.append("IDENTITY_CLIENT_SECRET")
            if missing:
                raise IdentityConfigError(
                    f"Live Entra ID execution requires environment variable(s): {', '.join(missing)}."
                )

    def safe_repr(self) -> Dict[str, Any]:
        """Returns safe configuration metadata without exposing secret keys."""
        return {
            "provider": self.provider.value,
            "tenant_id_set": bool(self.tenant_id),
            "client_id_set": bool(self.client_id),
            "client_secret_set": bool(self.client_secret),
            "graph_base_url": self.graph_base_url,
            "timeout_seconds": self.timeout,
            "execution_mode": EXECUTION_MODE_DRY_RUN if self.dry_run else EXECUTION_MODE_LIVE,
            "dry_run": self.dry_run,
            "protected_account_count": len(self.protected_accounts),
            "has_test_allowlist": self.allowed_test_accounts is not None,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class UserIdentity:
    """Represents a resolved enterprise directory user identity."""

    user_id: str
    user_principal_name: str
    display_name: Optional[str] = None
    mail: Optional[str] = None
    account_enabled: bool = True
    department: Optional[str] = None
    job_title: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "user_principal_name": self.user_principal_name,
            "display_name": self.display_name,
            "mail": self.mail,
            "account_enabled": self.account_enabled,
            "department": self.department,
            "job_title": self.job_title,
        }


@dataclass
class IdentityActionResult:
    """
    Standardized result for an identity provider action.
    Adheres to Week 2 Day 4 & Day 5 result specifications.
    """

    alert_id: str
    user_id: Optional[str]
    identity_provider: str
    action: str
    execution_mode: str
    status: str
    message: str
    user_principal_name: Optional[str] = None
    action_id: Optional[str] = None
    timestamp: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the result matching the required JSON schema."""
        out: Dict[str, Any] = {
            "alert_id": self.alert_id,
            "user_id": self.user_id,
            "identity_provider": self.identity_provider,
            "action": self.action,
            "execution_mode": self.execution_mode,
            "status": self.status,
            "message": self.message,
        }
        if self.user_principal_name:
            out["user_principal_name"] = self.user_principal_name
        if self.action_id:
            out["action_id"] = self.action_id
        if self.timestamp:
            out["timestamp"] = self.timestamp
        else:
            out["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if self.details is not None:
            out["details"] = self.details
        return out


# ─────────────────────────────────────────────────────────────────────────────
# Base Identity Client
# ─────────────────────────────────────────────────────────────────────────────


class BaseIdentityClient:
    """Abstract base class for identity provider integrations."""

    PROVIDER_NAME = "base"

    def __init__(self, config: Optional[IdentityConfig] = None) -> None:
        self.config = config or IdentityConfig()

    def authenticate(self) -> None:
        """Authenticates with the identity provider (acquires access token)."""
        raise NotImplementedError("Subclasses must implement authenticate().")

    def resolve_user(self, identifier: str) -> Optional[UserIdentity]:
        """Resolves a user from identifier (user_id, UPN, email, or username)."""
        raise NotImplementedError("Subclasses must implement resolve_user().")

    def get_user(self, user_id: str) -> Optional[UserIdentity]:
        """Retrieves a user by stable directory user ID."""
        raise NotImplementedError("Subclasses must implement get_user().")

    def suspend_account(self, user_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
        """Requests account suspension (disabling sign-in)."""
        raise NotImplementedError("Subclasses must implement suspend_account().")

    def revoke_user_sessions(self, user_id: str) -> Dict[str, Any]:
        """Requests user sign-in session invalidation."""
        raise NotImplementedError("Subclasses must implement revoke_user_sessions().")


# ─────────────────────────────────────────────────────────────────────────────
# Microsoft Entra ID / Microsoft Graph API Client
# ─────────────────────────────────────────────────────────────────────────────


class EntraIDClient(BaseIdentityClient):
    """
    Microsoft Entra ID (Azure AD) client utilizing the Microsoft Graph API.

    API Operations:
      - Token Endpoint     : POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
      - User Query         : GET  https://graph.microsoft.com/v1.0/users/{id}
      - User Search Filter : GET  https://graph.microsoft.com/v1.0/users?$filter=...
      - Account Disable    : PATCH https://graph.microsoft.com/v1.0/users/{id} (body: {"accountEnabled": false})
      - Session Revocation : POST https://graph.microsoft.com/v1.0/users/{id}/revokeSignInSessions

    Required Permissions (Application scopes):
      - User.ReadWrite.All (for account suspension)
      - User.RevokeSessions.All or Directory.ReadWrite.All (for session revocation)
    """

    PROVIDER_NAME = "entra_id"
    TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    GRAPH_DEFAULT_SCOPE = "https://graph.microsoft.com/.default"

    def __init__(self, config: Optional[IdentityConfig] = None) -> None:
        super().__init__(config)
        self._session = requests.Session()
        self._access_token: Optional[str] = None
        logger.info("EntraIDClient initialized. Config: %s", self.config.safe_repr())

    def authenticate(self) -> None:
        """Acquires an OAuth 2.0 access token via Client Credentials Grant."""
        if not self.config.tenant_id or not self.config.client_id or not self.config.client_secret:
            raise IdentityConfigError(
                "Missing Entra ID credentials (IDENTITY_TENANT_ID, IDENTITY_CLIENT_ID, or IDENTITY_CLIENT_SECRET)."
            )

        token_url = self.TOKEN_URL_TEMPLATE.format(tenant_id=self.config.tenant_id)
        logger.info("Requesting Microsoft Entra ID access token from %s...", token_url)

        payload = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "scope": self.GRAPH_DEFAULT_SCOPE,
            "grant_type": "client_credentials",
        }

        try:
            resp = requests.post(token_url, data=payload, timeout=self.config.timeout)
        except Timeout:
            raise IdentityTimeoutError("Timed out while requesting Entra ID access token.")
        except ConnectionError as exc:
            raise IdentityConnectionError(f"Could not reach Entra ID token endpoint: {exc}")

        if resp.status_code == 401 or resp.status_code == 400:
            err_data = {}
            try:
                err_data = resp.json()
            except Exception:
                pass
            err_desc = err_data.get("error_description", resp.text)
            raise IdentityAuthError(f"Entra ID authentication failed ({resp.status_code}): {err_desc}")
        elif resp.status_code == 403:
            raise IdentityAuthError("Entra ID permission denied (HTTP 403). Verify application permissions.")

        try:
            resp.raise_for_status()
        except HTTPError as exc:
            raise IdentityAPIError(f"Entra ID token request failed: {resp.status_code} - {exc}")

        try:
            data = resp.json()
        except Exception as exc:
            raise IdentityAPIError(f"Entra ID returned non-JSON token response: {exc}")

        token = data.get("access_token")
        if not token:
            raise IdentityAuthError("Entra ID token response did not contain 'access_token'.")

        self._access_token = token
        self._session.headers.update({
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
            "ConsistencyLevel": "eventual",
        })
        logger.info("Entra ID authentication successful. Bearer token acquired.")

    def _ensure_authenticated(self) -> None:
        if not self._access_token:
            self.authenticate()

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._ensure_authenticated()
        url = self.config.graph_base_url.rstrip("/") + path
        try:
            resp = self._session.get(url, params=params, timeout=self.config.timeout)
            return self._handle_response(resp)
        except Timeout:
            raise IdentityTimeoutError(f"Microsoft Graph API request timed out ({self.config.timeout}s).")
        except ConnectionError as exc:
            raise IdentityConnectionError(f"Network error communicating with Microsoft Graph API: {exc}")

    def _patch(self, path: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_authenticated()
        url = self.config.graph_base_url.rstrip("/") + path
        try:
            resp = self._session.patch(url, json=json_data, timeout=self.config.timeout)
            return self._handle_response(resp, allow_no_content=True)
        except Timeout:
            raise IdentityTimeoutError(f"Microsoft Graph API request timed out ({self.config.timeout}s).")
        except ConnectionError as exc:
            raise IdentityConnectionError(f"Network error communicating with Microsoft Graph API: {exc}")

    def _post(self, path: str, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._ensure_authenticated()
        url = self.config.graph_base_url.rstrip("/") + path
        try:
            resp = self._session.post(url, json=json_data or {}, timeout=self.config.timeout)
            return self._handle_response(resp, allow_no_content=True)
        except Timeout:
            raise IdentityTimeoutError(f"Microsoft Graph API request timed out ({self.config.timeout}s).")
        except ConnectionError as exc:
            raise IdentityConnectionError(f"Network error communicating with Microsoft Graph API: {exc}")

    def _handle_response(self, resp: Response, allow_no_content: bool = False) -> Dict[str, Any]:
        if resp.status_code == 204 and allow_no_content:
            return {"status_code": 204, "complete": True}

        if resp.status_code == 401:
            raise IdentityAuthError("Microsoft Graph API authentication failed (HTTP 401). Token expired or invalid.")
        if resp.status_code == 403:
            raise IdentityAuthError("Microsoft Graph API authorization failed (HTTP 403). Insufficient Graph permissions.")
        if resp.status_code == 404:
            raise UserNotFoundError(f"Microsoft Graph entity was not found (HTTP 404): {resp.text}")

        try:
            resp.raise_for_status()
        except HTTPError as exc:
            raise IdentityAPIError(f"Microsoft Graph API returned HTTP error: {resp.status_code} - {exc}")

        try:
            return resp.json()
        except Exception as exc:
            raise IdentityAPIError(f"Microsoft Graph API returned malformed or non-JSON body: {exc}")

    def resolve_user(self, identifier: str) -> Optional[UserIdentity]:
        """
        Resolves a user account from an alert string identifier.
        Hierarchy:
          1. UUID directory user ID -> direct GET /v1.0/users/{id}
          2. UPN or Email with '@' -> direct GET /v1.0/users/{upn} or $filter
          3. Plain username -> search $filter across UPN, mail, onPremisesSamAccountName
        """
        if not identifier or not str(identifier).strip():
            return None

        clean_id = str(identifier).strip()

        # Check for UUID format (e.g. c0a80101-0000-0000-0000-000000000001)
        uuid_pattern = re.compile(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        )
        if uuid_pattern.match(clean_id):
            return self.get_user(clean_id)

        # Direct UPN / Email lookup attempt
        if "@" in clean_id:
            try:
                user_dict = self._get(f"/v1.0/users/{clean_id}")
                return self._parse_user_dict(user_dict)
            except UserNotFoundError:
                pass
            except Exception:
                raise

        # Fallback to search query using Graph $filter
        sanitized_query = clean_id.replace("'", "''")
        filter_expr = (
            f"userPrincipalName eq '{sanitized_query}' or "
            f"mail eq '{sanitized_query}' or "
            f"onPremisesSamAccountName eq '{sanitized_query}' or "
            f"displayName eq '{sanitized_query}'"
        )

        resp = self._get("/v1.0/users", params={"$filter": filter_expr, "$top": 5})
        value = resp.get("value")
        if not isinstance(value, list) or len(value) == 0:
            return None

        if len(value) > 1:
            raise AmbiguousUserError(
                f"Multiple user accounts ({len(value)}) matched identifier '{clean_id}' in directory."
            )

        return self._parse_user_dict(value[0])

    def get_user(self, user_id: str) -> Optional[UserIdentity]:
        """Retrieves user by directory UUID."""
        if not user_id or not str(user_id).strip():
            return None
        clean_id = str(user_id).strip()
        try:
            data = self._get(f"/v1.0/users/{clean_id}")
            return self._parse_user_dict(data)
        except UserNotFoundError:
            return None

    def suspend_account(self, user_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
        """
        Suspends a user account in Microsoft Entra ID.
        Operation: PATCH /v1.0/users/{user_id} with {"accountEnabled": false}
        """
        if not user_id or not str(user_id).strip():
            raise UserNotFoundError("Cannot suspend account: user_id is empty.")

        clean_id = str(user_id).strip()
        logger.info("Submitting Entra ID account suspension for user_id=%s...", clean_id)

        payload = {"accountEnabled": False}
        res = self._patch(f"/v1.0/users/{clean_id}", json_data=payload)

        # Graph API returns HTTP 204 (No Content) on success
        action_id = f"entra-susp-{clean_id}"
        return {
            "status": STATUS_CONFIRMED,
            "action": ACTION_SUSPEND_ACCOUNT,
            "user_id": clean_id,
            "complete": True,
            "action_id": action_id,
            "message": f"User account '{clean_id}' disabled successfully in Microsoft Entra ID.",
            "raw_response": res,
        }

    def revoke_user_sessions(self, user_id: str) -> Dict[str, Any]:
        """
        Invalidates all refresh tokens and sessions for the specified user.
        Operation: POST /v1.0/users/{user_id}/revokeSignInSessions
        Documented Response: {"value": true} with HTTP 200.
        """
        if not user_id or not str(user_id).strip():
            raise UserNotFoundError("Cannot revoke sessions: user_id is empty.")

        clean_id = str(user_id).strip()
        logger.info("Submitting Entra ID session revocation for user_id=%s...", clean_id)

        res = self._post(f"/v1.0/users/{clean_id}/revokeSignInSessions", json_data={})

        # Parse documented Graph API response: {"value": true}
        value = res.get("value")
        if value is True or res.get("status_code") == 204:
            return {
                "status": STATUS_CONFIRMED,
                "action": ACTION_REVOKE_SESSIONS,
                "user_id": clean_id,
                "complete": True,
                "value": True,
                "action_id": f"entra-revoke-{clean_id}",
                "message": f"Sign-in sessions revoked successfully for user '{clean_id}'.",
                "raw_response": res,
            }
        else:
            return {
                "status": STATUS_UNKNOWN,
                "action": ACTION_REVOKE_SESSIONS,
                "user_id": clean_id,
                "complete": False,
                "value": value,
                "action_id": None,
                "message": f"Ambiguous session revocation response for user '{clean_id}': {res}",
                "raw_response": res,
            }

    @staticmethod
    def _parse_user_dict(d: Dict[str, Any]) -> UserIdentity:
        return UserIdentity(
            user_id=str(d.get("id") or ""),
            user_principal_name=str(d.get("userPrincipalName") or ""),
            display_name=d.get("displayName"),
            mail=d.get("mail"),
            account_enabled=bool(d.get("accountEnabled", True)),
            department=d.get("department"),
            job_title=d.get("jobTitle"),
            raw_data=d,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Simulated / Mock Identity Client (Safe for Development and Tests)
# ─────────────────────────────────────────────────────────────────────────────


class SimulatedIdentityClient(BaseIdentityClient):
    """
    High-fidelity simulated identity provider client.
    Performs NO real network requests and modifies NO external accounts.
    Provides realistic mock responses conforming to Microsoft Graph API specifications.
    Supports failure injection hooks for comprehensive unit and integration testing.
    """

    PROVIDER_NAME = "simulated"

    def __init__(self, config: Optional[IdentityConfig] = None) -> None:
        super().__init__(config)
        logger.info("[SIMULATED] Identity client initialized (safe local mode).")

        # Test failure injection toggles
        self.simulate_auth_failure: bool = False
        self.simulate_authz_failure: bool = False
        self.simulate_timeout: bool = False
        self.simulate_server_error: bool = False
        self.simulate_malformed: bool = False
        self.simulate_ambiguous_result: bool = False
        self.simulate_unsupported: bool = False

        # In-memory mock directory
        self._directory: Dict[str, UserIdentity] = {}
        self._seed_mock_users()

    def _seed_mock_users(self) -> None:
        """Seeds realistic test identities into the local mock directory."""
        users = [
            UserIdentity(
                user_id="c0a80101-0001-0000-0000-000000000001",
                user_principal_name="testuser@example.com",
                display_name="Test User",
                mail="testuser@example.com",
                account_enabled=True,
                department="Engineering",
            ),
            UserIdentity(
                user_id="c0a80101-0002-0000-0000-000000000002",
                user_principal_name="compromised.user@contoso.com",
                display_name="Compromised User",
                mail="compromised.user@contoso.com",
                account_enabled=True,
                department="Finance",
            ),
            UserIdentity(
                user_id="c0a80101-0003-0000-0000-000000000003",
                user_principal_name="victim@contoso.com",
                display_name="Victim Employee",
                mail="victim@contoso.com",
                account_enabled=True,
                department="Operations",
            ),
            UserIdentity(
                user_id="c0a80101-0004-0000-0000-000000000004",
                user_principal_name="disabled.user@contoso.com",
                display_name="Disabled User",
                mail="disabled.user@contoso.com",
                account_enabled=False,
                department="Former Employees",
            ),
            # Emergency Administrator (Protected)
            UserIdentity(
                user_id="c0a80101-0005-0000-0000-000000000005",
                user_principal_name="breakglass-admin@contoso.com",
                display_name="Break-Glass Emergency Admin",
                mail="breakglass-admin@contoso.com",
                account_enabled=True,
                department="Security Operations",
            ),
            # Orchestrator Service Account (Protected)
            UserIdentity(
                user_id="c0a80101-0006-0000-0000-000000000006",
                user_principal_name="svc-orchestrator@contoso.com",
                display_name="Orchestrator Service Principal",
                mail="svc-orchestrator@contoso.com",
                account_enabled=True,
                department="IT Automation",
            ),
            # Ambiguous user 1
            UserIdentity(
                user_id="c0a80101-0007-0000-0000-000000000007",
                user_principal_name="ambiguous.one@contoso.com",
                display_name="Ambiguous User",
                mail="ambiguous@contoso.com",
                account_enabled=True,
            ),
            # Ambiguous user 2
            UserIdentity(
                user_id="c0a80101-0008-0000-0000-000000000008",
                user_principal_name="ambiguous.two@contoso.com",
                display_name="Ambiguous User",
                mail="ambiguous@contoso.com",
                account_enabled=True,
            ),
        ]
        for u in users:
            self._directory[u.user_id] = u

    def authenticate(self) -> Dict[str, Any]:
        if self.simulate_auth_failure:
            raise IdentityAuthError("Simulated authentication failure (HTTP 401). Invalid credentials.")
        if self.simulate_timeout:
            raise IdentityTimeoutError("Simulated token acquisition timeout.")
        logger.info("[SIMULATED] Authenticated successfully with simulated identity provider.")
        return {"status": "simulated", "token": "SIMULATED_IDENTITY_ACCESS_TOKEN"}

    def _check_injected_faults(self) -> None:
        if self.simulate_auth_failure:
            raise IdentityAuthError("Simulated IdP authentication failure (HTTP 401).")
        if self.simulate_authz_failure:
            raise IdentityAuthError("Simulated IdP authorization failure (HTTP 403). Insufficient permissions.")
        if self.simulate_timeout:
            raise IdentityTimeoutError("Simulated IdP API timeout.")
        if self.simulate_server_error:
            raise IdentityAPIError("Simulated IdP internal server error (HTTP 500).")

    def resolve_user(self, identifier: str) -> Optional[UserIdentity]:
        self._check_injected_faults()
        if not identifier or not str(identifier).strip():
            return None

        clean = str(identifier).strip().lower()

        # Check by user_id directly
        for u in self._directory.values():
            if u.user_id.lower() == clean:
                return u

        # Search matching UPN, mail, displayName, or local-part of UPN
        matches: List[UserIdentity] = []
        for u in self._directory.values():
            upn_clean = u.user_principal_name.lower()
            upn_user = upn_clean.split("@")[0]
            mail_clean = (u.mail or "").lower()
            disp_clean = (u.display_name or "").lower()

            if clean in (upn_clean, upn_user, mail_clean, disp_clean):
                matches.append(u)

        if not matches:
            return None

        if len(matches) > 1:
            raise AmbiguousUserError(
                f"Multiple directory user accounts ({len(matches)}) matched identifier '{identifier}'."
            )

        return matches[0]

    def get_user(self, user_id: str) -> Optional[UserIdentity]:
        self._check_injected_faults()
        if not user_id:
            return None
        return self._directory.get(str(user_id).strip())

    def suspend_account(self, user_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
        self._check_injected_faults()
        if not user_id or not str(user_id).strip():
            raise UserNotFoundError("Missing user identifier for account suspension.")

        clean_id = str(user_id).strip()
        user = self._directory.get(clean_id)
        if not user:
            # Fallback search by UPN
            for u in self._directory.values():
                if u.user_principal_name.lower() == clean_id.lower():
                    user = u
                    break
        if not user:
            raise UserNotFoundError(f"User '{clean_id}' was not found in simulated directory.")

        if self.simulate_malformed:
            return {"malformed_key": True, "status": None}
        if self.simulate_ambiguous_result:
            return {"status": "UNKNOWN", "complete": False, "message": "Simulated ambiguous suspension result."}

        # Update in-memory state
        user.account_enabled = False
        action_id = f"sim-susp-{user.user_id}"
        logger.info("[SIMULATED] Account '%s' (%s) suspended successfully.", user.user_principal_name, user.user_id)

        return {
            "status": STATUS_CONFIRMED,
            "action": ACTION_SUSPEND_ACCOUNT,
            "user_id": user.user_id,
            "user_principal_name": user.user_principal_name,
            "complete": True,
            "action_id": action_id,
            "message": f"Simulated account suspension confirmed for {user.user_principal_name}.",
        }

    def revoke_user_sessions(self, user_id: str) -> Dict[str, Any]:
        self._check_injected_faults()
        if self.simulate_unsupported:
            raise UnsupportedOperationError("Provider does not support session revocation.")
        if not user_id or not str(user_id).strip():
            raise UserNotFoundError("Missing user identifier for session revocation.")

        clean_id = str(user_id).strip()
        user = self._directory.get(clean_id)
        if not user:
            for u in self._directory.values():
                if u.user_principal_name.lower() == clean_id.lower():
                    user = u
                    break
        if not user:
            raise UserNotFoundError(f"User '{clean_id}' was not found in simulated directory.")

        if self.simulate_malformed:
            return "non-dict malformed response"  # type: ignore
        if self.simulate_ambiguous_result:
            return {"status": "UNKNOWN", "value": None, "message": "Simulated ambiguous revocation outcome."}

        action_id = f"sim-revoke-{user.user_id}"
        logger.info("[SIMULATED] Sign-in sessions revoked for user '%s'.", user.user_principal_name)

        return {
            "status": STATUS_CONFIRMED,
            "action": ACTION_REVOKE_SESSIONS,
            "user_id": user.user_id,
            "user_principal_name": user.user_principal_name,
            "complete": True,
            "value": True,
            "action_id": action_id,
            "message": f"Simulated session revocation confirmed for {user.user_principal_name}.",
        }


# Alias MockIdentityClient to SimulatedIdentityClient for convenience
MockIdentityClient = SimulatedIdentityClient


# ─────────────────────────────────────────────────────────────────────────────
# Factory Function
# ─────────────────────────────────────────────────────────────────────────────


def create_identity_client(
    simulated: bool = False,
    config: Optional[IdentityConfig] = None,
) -> BaseIdentityClient:
    """
    Factory function returning the configured Identity Provider client.

    Parameters:
      simulated: If True, returns SimulatedIdentityClient regardless of configuration.
      config: Optional pre-loaded IdentityConfig.

    Returns:
      BaseIdentityClient instance (EntraIDClient or SimulatedIdentityClient).
    """
    if simulated:
        logger.info("Simulated identity client requested directly.")
        return SimulatedIdentityClient(config)

    cfg = config or IdentityConfig()

    if cfg.provider in (IdentityProvider.MOCK, IdentityProvider.SIMULATED):
        return SimulatedIdentityClient(cfg)
    elif cfg.provider in (IdentityProvider.ENTRA_ID, IdentityProvider.AZURE_AD):
        return EntraIDClient(cfg)
    else:
        raise IdentityConfigError(f"Unsupported identity provider: {cfg.provider}")

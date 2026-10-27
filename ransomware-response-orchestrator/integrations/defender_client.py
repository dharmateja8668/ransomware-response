"""
integrations/defender_client.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Microsoft Defender for Endpoint (MDE) EDR Client Integration Module.
Part of the Automated Ransomware Containment & Incident Response Orchestrator.

Security Requirements:
  - Credentials and tokens are NEVER hardcoded or logged.
  - All operations are strictly READ-ONLY for Day 1.
  - Robust error handling for network timeouts, auth errors, and schema variations.
  - Built-in Mock Mode for offline and non-production testing.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import requests
from requests.exceptions import ConnectionError, HTTPError, RequestException, Timeout

logger = logging.getLogger("orchestrator.defender_client")


class ContainmentStatus(str, Enum):
    """Normalized containment/isolation state of an endpoint."""
    ISOLATED = "ISOLATED"
    NOT_ISOLATED = "NOT_ISOLATED"
    UNKNOWN = "UNKNOWN"


# ─────────────────────────────────────────────────────────────────────────────
# Custom Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class EDRError(Exception):
    """Base exception for all EDR integration errors."""


class EDRConfigError(EDRError):
    """Raised when configuration parameters are invalid or missing."""


class EDRAuthenticationError(EDRError):
    """Raised when OAuth2 authentication fails with Azure Active Directory."""


class EDRConnectionError(EDRError):
    """Raised when network connectivity to the EDR API fails."""


class EDRTimeoutError(EDRError):
    """Raised when an EDR API request exceeds the configured timeout."""


class EDRAPIError(EDRError):
    """Raised when the EDR API returns an unexpected HTTP response error."""

    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


# ─────────────────────────────────────────────────────────────────────────────
# Configuration Manager
# ─────────────────────────────────────────────────────────────────────────────

class EDRConfig:
    """
    Manages EDR connection parameters and Azure AD credentials.
    Reads securely from environment variables.
    """

    DEFAULT_BASE_URL = "https://api.securitycenter.microsoft.com"
    DEFAULT_TIMEOUT_SECONDS = 15

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        api_base_url: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        mock_mode: Optional[bool] = None,
    ) -> None:
        # Determine mock mode first
        env_mock = os.getenv("EDR_MOCK_MODE", "").strip().lower()
        if mock_mode is not None:
            self.mock_mode = mock_mode
        elif env_mock in ("true", "1", "yes"):
            self.mock_mode = True
        elif env_mock in ("false", "0", "no"):
            self.mock_mode = False
        else:
            # Auto-enable mock mode if credentials are unset in environment
            has_creds = bool(
                os.getenv("DEFENDER_TENANT_ID")
                and os.getenv("DEFENDER_CLIENT_ID")
                and os.getenv("DEFENDER_CLIENT_SECRET")
            )
            self.mock_mode = not has_creds

        self.tenant_id = (tenant_id or os.getenv("DEFENDER_TENANT_ID", "")).strip()
        self.client_id = (client_id or os.getenv("DEFENDER_CLIENT_ID", "")).strip()
        self.client_secret = (client_secret or os.getenv("DEFENDER_CLIENT_SECRET", "")).strip()
        self.api_base_url = (api_base_url or os.getenv("DEFENDER_API_BASE_URL", self.DEFAULT_BASE_URL)).strip().rstrip("/")

        raw_timeout = timeout_seconds or os.getenv("EDR_TIMEOUT_SECONDS", str(self.DEFAULT_TIMEOUT_SECONDS))
        try:
            self.timeout_seconds = int(raw_timeout)
            if self.timeout_seconds <= 0:
                raise ValueError
        except (ValueError, TypeError):
            logger.warning("Invalid EDR_TIMEOUT_SECONDS '%s'; defaulting to %s seconds.", raw_timeout, self.DEFAULT_TIMEOUT_SECONDS)
            self.timeout_seconds = self.DEFAULT_TIMEOUT_SECONDS

        # Validate credentials when not running in mock mode
        if not self.mock_mode:
            missing = []
            if not self.tenant_id:
                missing.append("DEFENDER_TENANT_ID")
            if not self.client_id:
                missing.append("DEFENDER_CLIENT_ID")
            if not self.client_secret:
                missing.append("DEFENDER_CLIENT_SECRET")

            if missing:
                raise EDRConfigError(
                    f"Live EDR mode enabled (EDR_MOCK_MODE=false) but required credentials are missing: {', '.join(missing)}. "
                    "Please configure them in .env or switch to EDR_MOCK_MODE=true."
                )

    def __repr__(self) -> str:
        """Mask credentials in string representations to prevent secret leakage."""
        masked_secret = "***REDACTED***" if self.client_secret else "None"
        return (
            f"<EDRConfig mock_mode={self.mock_mode} tenant_id={self.tenant_id or 'None'} "
            f"client_id={self.client_id or 'None'} client_secret={masked_secret} "
            f"base_url={self.api_base_url} timeout={self.timeout_seconds}s>"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Microsoft Defender for Endpoint Client
# ─────────────────────────────────────────────────────────────────────────────

class DefenderClient:
    """
    Client for interacting with the Microsoft Defender for Endpoint REST API.

    Features:
      - OAuth 2.0 Client Credentials authentication via Azure AD / Microsoft Entra ID.
      - Read-only retrieval of security incident details and alert telemetry.
      - Endpoint containment (machine isolation) verification.
      - Integrated Mock Mode for offline testing and continuous integration.
    """

    def __init__(self, config: Optional[EDRConfig] = None) -> None:
        self.config = config or EDRConfig()
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._session = requests.Session()
        self._mock_machine_actions: Dict[str, Dict[str, Any]] = {}
        logger.info("Initialized DefenderClient (Mock Mode: %s)", self.config.mock_mode)

    # ─────────────────────────────────────────────────────────────────────────
    # Task 2: Authentication
    # ─────────────────────────────────────────────────────────────────────────

    def authenticate(self, force_refresh: bool = False) -> str:
        """
        Retrieves or refreshes an OAuth 2.0 bearer token using Azure AD client credentials.

        Endpoint:
          POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token

        Returns:
          Valid access token string (never logged or exposed in raw output).
        """
        if self.config.mock_mode:
            logger.info("Mock Mode: Simulating successful Azure AD OAuth2 token generation.")
            self._access_token = "mock-defender-bearer-token-secops-day1"
            self._token_expires_at = datetime.now(timezone.utc).timestamp() + 3600
            return self._access_token

        # Check existing cached token validity
        now = datetime.now(timezone.utc).timestamp()
        if not force_refresh and self._access_token and now < (self._token_expires_at - 60):
            return self._access_token

        token_url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
        token_data = {
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "scope": f"{self.config.api_base_url}/.default",
        }

        logger.debug("Requesting OAuth2 access token from Azure AD token endpoint for client: %s", self.config.client_id)

        try:
            response = self._session.post(
                token_url,
                data=token_data,
                timeout=self.config.timeout_seconds,
            )
        except Timeout as err:
            logger.error("Authentication timed out after %d seconds contacting Azure AD.", self.config.timeout_seconds)
            raise EDRTimeoutError(f"Azure AD authentication request timed out: {err}") from err
        except ConnectionError as err:
            logger.error("Network connection failure contacting Azure AD token endpoint.")
            raise EDRConnectionError(f"Failed to connect to Azure AD: {err}") from err
        except RequestException as err:
            logger.error("Unexpected network error during authentication.")
            raise EDRAPIError(f"Network error during authentication: {err}") from err

        if response.status_code != 200:
            # Secure error extraction - do not leak secrets
            logger.error("Azure AD authentication rejected with HTTP %d.", response.status_code)
            try:
                err_data = response.json()
                err_desc = err_data.get("error_description", err_data.get("error", response.text))
            except Exception:
                err_desc = response.text
            raise EDRAuthenticationError(
                f"Azure AD authentication failed (HTTP {response.status_code}): {err_desc}"
            )

        try:
            token_json = response.json()
            access_token = token_json.get("access_token")
            expires_in = int(token_json.get("expires_in", 3599))
            if not access_token:
                raise EDRAuthenticationError("Azure AD response missing 'access_token' parameter.")
        except Exception as err:
            raise EDRAuthenticationError(f"Failed to parse Azure AD authentication response: {err}") from err

        self._access_token = access_token
        self._token_expires_at = now + expires_in
        logger.info("Successfully acquired Azure AD access token for Defender API (expires in %ds).", expires_in)
        return self._access_token

    def _get_auth_headers(self) -> Dict[str, str]:
        """Constructs secure request headers with authorization bearer token."""
        token = self.authenticate()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Task 3: Retrieve Incident Details
    # ─────────────────────────────────────────────────────────────────────────

    def get_incident(self, incident_id: str | int) -> Dict[str, Any]:
        """
        Retrieves incident details from Microsoft Defender for Endpoint.

        Official Endpoint:
          GET https://api.securitycenter.microsoft.com/api/incidents/{id}

        Returns normalized incident dictionary containing:
          - incident_id
          - incident_name / title
          - severity
          - status
          - affected_device_name
          - device_ip_address
          - alerts (list of associated alert objects)
          - raw_data (full API response)
        """
        incident_id_str = str(incident_id).strip()
        if not incident_id_str:
            raise ValueError("Incident ID cannot be empty.")

        logger.info("Retrieving incident details for incident ID: %s", incident_id_str)

        if self.config.mock_mode:
            return self._mock_get_incident(incident_id_str)

        url = f"{self.config.api_base_url}/api/incidents/{incident_id_str}"
        headers = self._get_auth_headers()

        try:
            response = self._session.get(url, headers=headers, timeout=self.config.timeout_seconds)
        except Timeout as err:
            logger.error("Timeout retrieving incident %s after %ds.", incident_id_str, self.config.timeout_seconds)
            raise EDRTimeoutError(f"Timeout while retrieving incident {incident_id_str}: {err}") from err
        except ConnectionError as err:
            logger.error("Connection failure retrieving incident %s.", incident_id_str)
            raise EDRConnectionError(f"Connection error while retrieving incident {incident_id_str}: {err}") from err
        except RequestException as err:
            raise EDRAPIError(f"Request failed for incident {incident_id_str}: {err}") from err

        if response.status_code == 404:
            logger.warning("Incident %s not found in Defender for Endpoint (HTTP 404).", incident_id_str)
            raise EDRAPIError(f"Incident '{incident_id_str}' not found.", status_code=404)

        if response.status_code == 401:
            logger.warning("Authentication token expired or rejected (HTTP 401). Retrying with refreshed token.")
            # Invalidate cached token and retry once
            self._access_token = None
            headers = self._get_auth_headers()
            response = self._session.get(url, headers=headers, timeout=self.config.timeout_seconds)

        if response.status_code != 200:
            logger.error("Defender API returned HTTP %d for incident %s.", response.status_code, incident_id_str)
            raise EDRAPIError(
                f"Failed to retrieve incident {incident_id_str} (HTTP {response.status_code}): {response.text}",
                status_code=response.status_code,
                response_body=response.text,
            )

        try:
            raw_incident = response.json()
        except Exception as err:
            raise EDRAPIError(f"Invalid JSON returned for incident {incident_id_str}: {err}") from err

        return self._normalize_incident_data(raw_incident)

    def list_incidents(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Lists recent incidents from Microsoft Defender for Endpoint.

        Official Endpoint:
          GET https://api.securitycenter.microsoft.com/api/incidents?$top={limit}
        """
        logger.info("Listing recent incidents (limit=%d)", limit)
        if self.config.mock_mode:
            return [
                self._mock_get_incident("1001"),
                self._mock_get_incident("1002"),
            ]

        url = f"{self.config.api_base_url}/api/incidents?$top={limit}"
        headers = self._get_auth_headers()

        try:
            response = self._session.get(url, headers=headers, timeout=self.config.timeout_seconds)
            if response.status_code != 200:
                raise EDRAPIError(f"Failed to list incidents (HTTP {response.status_code}): {response.text}", status_code=response.status_code)
            data = response.json()
            raw_list = data.get("value", []) if isinstance(data, dict) else data
            return [self._normalize_incident_data(item) for item in raw_list]
        except Timeout as err:
            raise EDRTimeoutError(f"Timeout listing incidents: {err}") from err
        except ConnectionError as err:
            raise EDRConnectionError(f"Connection failure listing incidents: {err}") from err
        except RequestException as err:
            raise EDRAPIError(f"Request failed listing incidents: {err}") from err

    def get_incident_alerts(self, incident_id: str | int) -> List[Dict[str, Any]]:
        """
        Retrieves alert telemetry associated with an incident for correlation analysis.

        In mock mode, returns the alerts embedded in the mock incident response.
        In live mode, queries Microsoft Defender for Endpoint alerts for the specified incident.

        Official Endpoints:
          GET https://api.securitycenter.microsoft.com/api/incidents/{id}/alerts
          or GET https://api.securitycenter.microsoft.com/api/alerts?$filter=incidentId eq {id}

        Args:
            incident_id: The incident identifier.

        Returns:
            List of alert dictionaries (may be empty if no alerts are found).
        """
        incident_id_str = str(incident_id).strip()
        if not incident_id_str:
            raise ValueError("Incident ID cannot be empty.")

        logger.info("Retrieving alert telemetry for incident ID: %s", incident_id_str)

        if self.config.mock_mode:
            incident_data = self.get_incident(incident_id_str)
            raw_alerts = incident_data.get("raw_data", {}).get("alerts")
            if raw_alerts is not None:
                alerts = raw_alerts
            else:
                alerts = incident_data.get("alerts", [])
            logger.debug(
                "Retrieved %d mock alerts for incident #%s",
                len(alerts),
                incident_id_str,
            )
            return alerts

        url = f"{self.config.api_base_url}/api/incidents/{incident_id_str}/alerts"
        headers = self._get_auth_headers()

        try:
            response = self._session.get(url, headers=headers, timeout=self.config.timeout_seconds)
            if response.status_code == 404:
                # Fallback to OData filter query on /api/alerts
                filter_url = f"{self.config.api_base_url}/api/alerts?$filter=incidentId eq {incident_id_str}"
                response = self._session.get(filter_url, headers=headers, timeout=self.config.timeout_seconds)
        except Timeout as err:
            logger.error("Timeout retrieving alerts for incident %s after %ds.", incident_id_str, self.config.timeout_seconds)
            raise EDRTimeoutError(f"Timeout while retrieving alerts for incident {incident_id_str}: {err}") from err
        except ConnectionError as err:
            logger.error("Connection failure retrieving alerts for incident %s.", incident_id_str)
            raise EDRConnectionError(f"Connection error while retrieving alerts for incident {incident_id_str}: {err}") from err
        except RequestException as err:
            raise EDRAPIError(f"Request failed for alerts of incident {incident_id_str}: {err}") from err

        if response.status_code == 404:
            logger.warning("No alerts found for incident %s in Defender API (HTTP 404).", incident_id_str)
            return []

        if response.status_code == 401:
            logger.warning("Authentication token expired or rejected (HTTP 401). Retrying with refreshed token.")
            self._access_token = None
            headers = self._get_auth_headers()
            try:
                response = self._session.get(url, headers=headers, timeout=self.config.timeout_seconds)
            except RequestException as err:
                raise EDRAPIError(f"Request retry failed for alerts of incident {incident_id_str}: {err}") from err

        if response.status_code != 200:
            logger.error("Defender API returned HTTP %d for incident %s alerts.", response.status_code, incident_id_str)
            raise EDRAPIError(
                f"Failed to retrieve alerts for incident {incident_id_str} (HTTP {response.status_code}): {response.text}",
                status_code=response.status_code,
                response_body=response.text,
            )

        try:
            data = response.json()
            raw_list = data.get("value", []) if isinstance(data, dict) else data
            return raw_list if isinstance(raw_list, list) else []
        except Exception as err:
            raise EDRAPIError(f"Invalid JSON returned for incident {incident_id_str} alerts: {err}") from err

    # ─────────────────────────────────────────────────────────────────────────
    # Task 4: Verify Endpoint Containment
    # ─────────────────────────────────────────────────────────────────────────


    def get_endpoint_containment_status(self, machine_id_or_name: str) -> Dict[str, Any]:
        """
        Checks the isolation or containment status of an endpoint.

        Official Defender Endpoint:
          GET https://api.securitycenter.microsoft.com/api/machines/{machine_id}

        Returns:
          Dictionary with:
            - device_id: Machine identifier
            - device_name: Computer DNS name
            - containment_status: ContainmentStatus (ISOLATED, NOT_ISOLATED, UNKNOWN)
            - isolation_details: Raw isolation status string or metadata
            - risk_score: Defender device risk score if available
            - health_status: Defender device health status
            - verified_at: ISO 8601 UTC timestamp of verification
        """
        target = str(machine_id_or_name).strip()
        if not target:
            raise ValueError("Endpoint identifier (machine ID or DNS name) cannot be empty.")

        logger.info("Verifying containment status for endpoint: %s", target)

        if self.config.mock_mode:
            return self._mock_get_endpoint_containment(target)

        url = f"{self.config.api_base_url}/api/machines/{target}"
        headers = self._get_auth_headers()

        try:
            response = self._session.get(url, headers=headers, timeout=self.config.timeout_seconds)
        except Timeout as err:
            logger.error("Timeout checking containment for endpoint %s after %ds.", target, self.config.timeout_seconds)
            raise EDRTimeoutError(f"Timeout checking containment for {target}: {err}") from err
        except ConnectionError as err:
            logger.error("Connection error checking containment for endpoint %s.", target)
            raise EDRConnectionError(f"Connection failure checking containment for {target}: {err}") from err
        except RequestException as err:
            raise EDRAPIError(f"API request failed for endpoint {target}: {err}") from err

        if response.status_code == 404:
            logger.warning("Endpoint '%s' was not found in Microsoft Defender inventory (HTTP 404).", target)
            return {
                "device_id": target,
                "device_name": target,
                "containment_status": ContainmentStatus.UNKNOWN.value,
                "isolation_details": "Device not found in EDR inventory (HTTP 404)",
                "risk_score": "Unknown",
                "health_status": "Unknown",
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }

        if response.status_code != 200:
            logger.error("Defender API returned HTTP %d checking endpoint %s.", response.status_code, target)
            raise EDRAPIError(
                f"Failed to check endpoint {target} (HTTP {response.status_code}): {response.text}",
                status_code=response.status_code,
            )

        try:
            machine_data = response.json()
        except Exception as err:
            raise EDRAPIError(f"Failed to parse machine data for {target}: {err}") from err

        return self._evaluate_containment_status(machine_data)

    # ─────────────────────────────────────────────────────────────────────────
    # Day 2: Live Response & Investigation Package Actions
    # ─────────────────────────────────────────────────────────────────────────

    def collect_investigation_package(
        self, machine_id: str, comment: str = "Forensic evidence collection initiated by IR orchestrator"
    ) -> Dict[str, Any]:
        """
        Initiates an investigation package collection on an endpoint via Defender for Endpoint API.

        Official Defender Endpoint:
          POST https://api.securitycenter.microsoft.com/api/machines/{machine_id}/collectInvestigationPackage

        Body:
          {"Comment": comment}

        Returns:
          Dictionary with action_id, status, creation_time, machine_id.
        """
        target = str(machine_id).strip()
        if not target:
            raise ValueError("Machine ID cannot be empty.")

        logger.info("Initiating investigation package collection for machine: %s", target)

        if self.config.mock_mode:
            return self._mock_collect_investigation_package(target, comment)

        url = f"{self.config.api_base_url}/api/machines/{target}/collectInvestigationPackage"
        headers = self._get_auth_headers()
        body = {"Comment": comment}

        try:
            response = self._session.post(url, json=body, headers=headers, timeout=self.config.timeout_seconds)
        except Timeout as err:
            logger.error("Timeout initiating investigation package for %s: %s", target, err)
            raise EDRTimeoutError(f"Timeout initiating investigation package for {target}: {err}") from err
        except ConnectionError as err:
            logger.error("Connection error initiating investigation package for %s: %s", target, err)
            raise EDRConnectionError(f"Connection failure initiating investigation package for {target}: {err}") from err
        except RequestException as err:
            raise EDRAPIError(f"API request failed initiating investigation package for {target}: {err}") from err

        if response.status_code == 404:
            raise EDRAPIError(f"Machine '{target}' not found in Defender inventory (HTTP 404).", status_code=404)
        if response.status_code not in (200, 201):
            raise EDRAPIError(
                f"Failed to initiate investigation package for {target} (HTTP {response.status_code}): {response.text}",
                status_code=response.status_code,
            )

        data = response.json()
        return self._normalize_machine_action(data)

    def get_machine_action(self, action_id: str) -> Dict[str, Any]:
        """
        Retrieves the status of a machine action (such as investigation package collection).

        Official Defender Endpoint:
          GET https://api.securitycenter.microsoft.com/api/machineactions/{action_id}
        """
        target = str(action_id).strip()
        if not target:
            raise ValueError("Action ID cannot be empty.")

        logger.info("Checking status for machine action: %s", target)

        if self.config.mock_mode:
            return self._mock_get_machine_action(target)

        url = f"{self.config.api_base_url}/api/machineactions/{target}"
        headers = self._get_auth_headers()

        try:
            response = self._session.get(url, headers=headers, timeout=self.config.timeout_seconds)
        except Timeout as err:
            raise EDRTimeoutError(f"Timeout checking machine action {target}: {err}") from err
        except ConnectionError as err:
            raise EDRConnectionError(f"Connection failure checking machine action {target}: {err}") from err
        except RequestException as err:
            raise EDRAPIError(f"API request failed checking machine action {target}: {err}") from err

        if response.status_code == 404:
            raise EDRAPIError(f"Machine action '{target}' not found (HTTP 404).", status_code=404)
        if response.status_code != 200:
            raise EDRAPIError(
                f"Failed to check machine action {target} (HTTP {response.status_code}): {response.text}",
                status_code=response.status_code,
            )

        data = response.json()
        return self._normalize_machine_action(data)

    def get_package_uri(self, action_id: str) -> Optional[str]:
        """
        Retrieves the secure SAS download URL for a completed investigation package.

        Official Defender Endpoint:
          GET https://api.securitycenter.microsoft.com/api/machineactions/{action_id}/GetPackageUri
        """
        target = str(action_id).strip()
        if not target:
            raise ValueError("Action ID cannot be empty.")

        logger.info("Retrieving package URI for machine action: %s", target)

        if self.config.mock_mode:
            return self._mock_get_package_uri(target)

        url = f"{self.config.api_base_url}/api/machineactions/{target}/GetPackageUri"
        headers = self._get_auth_headers()

        try:
            response = self._session.get(url, headers=headers, timeout=self.config.timeout_seconds)
        except Timeout as err:
            raise EDRTimeoutError(f"Timeout retrieving package URI for {target}: {err}") from err
        except ConnectionError as err:
            raise EDRConnectionError(f"Connection failure retrieving package URI for {target}: {err}") from err
        except RequestException as err:
            raise EDRAPIError(f"API request failed retrieving package URI for {target}: {err}") from err

        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise EDRAPIError(
                f"Failed to retrieve package URI for {target} (HTTP {response.status_code}): {response.text}",
                status_code=response.status_code,
            )

        data = response.json()
        return data.get("value")

    def check_live_response_capability(self, machine_id: str) -> Dict[str, Any]:
        """
        Checks whether Live Response capability is supported and enabled on the endpoint.
        """
        target = str(machine_id).strip()
        if not target:
            raise ValueError("Machine ID cannot be empty.")

        if self.config.mock_mode:
            return self._mock_check_live_response_capability(target)

        url = f"{self.config.api_base_url}/api/machines/{target}"
        headers = self._get_auth_headers()
        try:
            response = self._session.get(url, headers=headers, timeout=self.config.timeout_seconds)
            if response.status_code != 200:
                return {"supported": False, "reason": f"Machine query failed (HTTP {response.status_code})"}
            mach = response.json()
            os_plat = str(mach.get("osPlatform", "")).lower()
            supported = "windows" in os_plat or "linux" in os_plat or "macos" in os_plat
            return {
                "supported": supported,
                "os_platform": mach.get("osPlatform"),
                "os_version": mach.get("osVersion"),
                "live_response_configured": False,
                "reason": "Live Response requires library script registration",
            }
        except Exception as err:
            return {"supported": False, "reason": str(err)}

    # ─────────────────────────────────────────────────────────────────────────
    # Helper Methods: Normalization & Evaluation
    # ─────────────────────────────────────────────────────────────────────────

    def _normalize_incident_data(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes Defender incident fields into a standard SOC structure.
        Safely extracts required fields even if some telemetry is missing.
        """
        incident_id = str(raw.get("incidentId") or raw.get("id") or "").strip()
        incident_name = raw.get("incidentName") or raw.get("title") or "Unnamed Security Incident"
        severity = raw.get("severity", "Unknown")
        status = raw.get("status", "Unknown")

        # Extract alerts and affected machine telemetry
        raw_alerts = raw.get("alerts", [])
        normalized_alerts = []
        affected_devices: List[str] = []
        ip_addresses: List[str] = []
        machine_ids: List[str] = []

        for alert in raw_alerts:
            alert_id = str(alert.get("alertId") or alert.get("id") or "")
            alert_title = alert.get("title", "")
            alert_sev = alert.get("severity", "")
            alert_cat = alert.get("category", "")
            m_id = alert.get("machineId")
            dev_name = alert.get("computerDnsName") or alert.get("deviceName")
            ip = alert.get("lastIpAddress") or alert.get("ipAddress")

            if dev_name and dev_name not in affected_devices:
                affected_devices.append(dev_name)
            if m_id and m_id not in machine_ids:
                machine_ids.append(m_id)
            if ip and ip not in ip_addresses:
                ip_addresses.append(ip)

            normalized_alerts.append({
                "alert_id": alert_id,
                "title": alert_title,
                "severity": alert_sev,
                "category": alert_cat,
                "machine_id": m_id,
                "device_name": dev_name,
                "ip_address": ip,
            })

        # Top-level fallback for device name and IP if not in alerts array
        primary_device = (
            affected_devices[0]
            if affected_devices
            else raw.get("computerDnsName") or raw.get("deviceName") or "Unknown"
        )
        primary_ip = (
            ip_addresses[0]
            if ip_addresses
            else raw.get("lastIpAddress") or raw.get("ipAddress") or None
        )
        primary_machine_id = machine_ids[0] if machine_ids else raw.get("machineId")

        return {
            "incident_id": incident_id,
            "title": incident_name,
            "severity": severity,
            "status": status,
            "affected_device_name": primary_device,
            "device_ip_address": primary_ip,
            "machine_id": primary_machine_id,
            "all_affected_devices": affected_devices or ([primary_device] if primary_device != "Unknown" else []),
            "all_ip_addresses": ip_addresses or ([primary_ip] if primary_ip else []),
            "alerts_count": len(normalized_alerts),
            "alerts": normalized_alerts,
            "created_time": raw.get("createdTime"),
            "last_update_time": raw.get("lastUpdateTime"),
            "raw_data": raw,
        }

    def _evaluate_containment_status(self, machine_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates machine isolation status according to official Defender schema:
          - machineIsolationStatus == "Isolated" -> ISOLATED
          - machineIsolationStatus == "NotIsolated" -> NOT_ISOLATED
          - Any other value, missing field, or ambiguous state -> UNKNOWN
        """
        device_id = machine_data.get("id") or machine_data.get("machineId") or "Unknown"
        device_name = machine_data.get("computerDnsName") or machine_data.get("deviceName") or "Unknown"
        raw_status = machine_data.get("machineIsolationStatus") or machine_data.get("isolationStatus")

        if isinstance(raw_status, str):
            status_clean = raw_status.strip().lower()
            if status_clean == "isolated":
                containment = ContainmentStatus.ISOLATED
            elif status_clean in ("notisolated", "not_isolated", "none"):
                containment = ContainmentStatus.NOT_ISOLATED
            else:
                logger.warning("Unrecognized machineIsolationStatus '%s' for endpoint %s", raw_status, device_name)
                containment = ContainmentStatus.UNKNOWN
        else:
            logger.warning("Missing or non-string machineIsolationStatus for endpoint %s", device_name)
            containment = ContainmentStatus.UNKNOWN

        return {
            "device_id": device_id,
            "device_name": device_name,
            "containment_status": containment.value,
            "isolation_details": raw_status or "Field not provided in API response",
            "risk_score": machine_data.get("riskScore", "Unknown"),
            "health_status": machine_data.get("healthStatus", "Unknown"),
            "last_ip_address": machine_data.get("lastIpAddress"),
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Mock Data Generators (for offline testing & Day 1 demonstration)
    # ─────────────────────────────────────────────────────────────────────────

    def _mock_get_incident(self, incident_id: str) -> Dict[str, Any]:
        """Generates realistic Microsoft Defender incident responses for testing."""
        if incident_id == "404" or incident_id == "non_existent":
            raise EDRAPIError(f"Incident '{incident_id}' not found.", status_code=404)

        if incident_id == "500" or incident_id == "server_error":
            raise EDRAPIError("Internal Server Error in Defender API.", status_code=500)

        if incident_id in ("1002", "contained"):
            mock_raw = {
                "incidentId": 1002,
                "incidentName": "Contained Ransomware Outbreak (LockBit 3.0 Telemetry)",
                "createdTime": "2026-10-25T15:10:00Z",
                "lastUpdateTime": "2026-10-25T15:45:00Z",
                "status": "Active",
                "severity": "High",
                "classification": "TruePositive",
                "determination": "Ransomware",
                "alerts": [
                    {
                        "alertId": "da-99120-alert-01",
                        "title": "Ransomware payload execution contained via endpoint network isolation",
                        "category": "Ransomware",
                        "severity": "High",
                        "machineId": "mach-isolated-host",
                        "computerDnsName": "ISOLATED-HOST.corp.contoso.com",
                        "lastIpAddress": "10.0.8.22",
                    }
                ],
            }
            return self._normalize_incident_data(mock_raw)

        # High-severity ransomware incident mock (Incident 1001: unisolated active outbreak)
        mock_raw = {
            "incidentId": int(incident_id) if incident_id.isdigit() else 1001,
            "incidentName": "Multi-stage Ransomware Activity Detected (BlackCat/ALPHV Heuristics)",
            "createdTime": "2026-10-25T14:32:00Z",
            "lastUpdateTime": "2026-10-25T14:38:15Z",
            "status": "Active",
            "severity": "High",
            "classification": "TruePositive",
            "determination": "Ransomware",
            "alerts": [
                {
                    "alertId": "da-77821-alert-01",
                    "title": "Suspicious PowerShell command attempting shadow copy deletion (vssadmin)",
                    "category": "DefenseEvasion",
                    "severity": "High",
                    "machineId": "f489a71b-324e-4f01-92bb-187640df21a1",
                    "computerDnsName": "FINANCE-SRV-01.corp.contoso.com",
                    "lastIpAddress": "10.0.4.15",
                },
                {
                    "alertId": "da-77821-alert-02",
                    "title": "High volume of files rapidly renamed with .enc extension",
                    "category": "Ransomware",
                    "severity": "High",
                    "machineId": "f489a71b-324e-4f01-92bb-187640df21a1",
                    "computerDnsName": "FINANCE-SRV-01.corp.contoso.com",
                    "lastIpAddress": "10.0.4.15",
                },
            ],
        }
        return self._normalize_incident_data(mock_raw)

    def _mock_get_endpoint_containment(self, target: str) -> Dict[str, Any]:
        """Generates realistic containment verification responses."""
        target_lower = target.lower()

        if target_lower in ("isolated-host", "isolated-pc", "isolated") or "isolated" in target_lower:
            raw_status = "Isolated"
            risk = "High"
            health = "Active"
        elif target_lower in ("unknown-host", "ambiguous", "pending"):
            raw_status = "PendingAction"
            risk = "Medium"
            health = "Unknown"
        elif target_lower in ("not-found", "404"):
            return {
                "device_id": target,
                "device_name": target,
                "containment_status": ContainmentStatus.UNKNOWN.value,
                "isolation_details": "Device not found in EDR inventory (HTTP 404)",
                "risk_score": "Unknown",
                "health_status": "Unknown",
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }
        else:
            # Default mock is NotIsolated (typical active ransomware target requiring containment)
            raw_status = "NotIsolated"
            risk = "High"
            health = "Active"

        mock_machine = {
            "id": "f489a71b-324e-4f01-92bb-187640df21a1" if "srv" in target_lower or target == "1001" else f"mach-{target}",
            "computerDnsName": target if "." in target else f"{target}.corp.contoso.com",
            "machineIsolationStatus": raw_status,
            "lastIpAddress": "10.0.4.15",
            "healthStatus": health,
            "riskScore": risk,
        }
        return self._evaluate_containment_status(mock_machine)

    def _normalize_machine_action(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalizes Defender machine action telemetry."""
        return {
            "action_id": str(raw.get("id") or raw.get("action_id", "")),
            "action_type": raw.get("type") or raw.get("action_type", "Unknown"),
            "status": raw.get("status", "Pending"),
            "machine_id": raw.get("machineId") or raw.get("machine_id", ""),
            "creation_time": raw.get("creationDateTimeUtc") or raw.get("creation_time"),
            "last_update_time": raw.get("lastUpdateDateTimeUtc") or raw.get("last_update_time"),
            "error_code": raw.get("errorCode"),
            "raw_data": raw,
        }

    def _mock_collect_investigation_package(self, machine_id: str, comment: str) -> Dict[str, Any]:
        """Generates mock machine action for investigation package collection."""
        target_lower = machine_id.lower()
        if "not-found" in target_lower or "404" in target_lower:
            raise EDRAPIError(f"Machine '{machine_id}' not found (HTTP 404).", status_code=404)
        if "auth-fail" in target_lower:
            raise EDRAuthenticationError("Azure AD token expired or invalid.")
        if "timeout" in target_lower:
            raise EDRTimeoutError(f"Timeout communicating with Defender API for machine {machine_id}.")

        import uuid
        action_id = f"act-{uuid.uuid4().hex[:8]}"
        initial_status = "InProgress" if "running" in target_lower else ("Failed" if "fail" in target_lower else "Succeeded")

        action_data = {
            "id": action_id,
            "type": "CollectInvestigationPackage",
            "status": initial_status,
            "machineId": machine_id,
            "creationDateTimeUtc": datetime.now(timezone.utc).isoformat(),
            "lastUpdateDateTimeUtc": datetime.now(timezone.utc).isoformat(),
            "errorCode": "SimulatedCollectionFailure" if initial_status == "Failed" else None,
            "comment": comment,
        }
        self._mock_machine_actions[action_id] = action_data
        return self._normalize_machine_action(action_data)

    def _mock_get_machine_action(self, action_id: str) -> Dict[str, Any]:
        """Retrieves mock machine action."""
        if action_id == "404" or "not-found" in action_id.lower():
            raise EDRAPIError(f"Machine action '{action_id}' not found (HTTP 404).", status_code=404)
        if "timeout" in action_id.lower():
            raise EDRTimeoutError(f"Timeout querying action {action_id}.")

        if action_id in self._mock_machine_actions:
            return self._normalize_machine_action(self._mock_machine_actions[action_id])

        # Default fallback mock action
        action_data = {
            "id": action_id,
            "type": "CollectInvestigationPackage",
            "status": "Succeeded",
            "machineId": "f489a71b-324e-4f01-92bb-187640df21a1",
            "creationDateTimeUtc": datetime.now(timezone.utc).isoformat(),
            "lastUpdateDateTimeUtc": datetime.now(timezone.utc).isoformat(),
            "errorCode": None,
        }
        return self._normalize_machine_action(action_data)

    def _mock_get_package_uri(self, action_id: str) -> Optional[str]:
        """Retrieves mock package SAS download URI."""
        if "missing-uri" in action_id.lower() or "no-location" in action_id.lower():
            return None
        action = self._mock_machine_actions.get(action_id, {})
        if action.get("status") == "Failed":
            return None
        mach_id = action.get("machineId", "f489a71b-324e-4f01-92bb-187640df21a1")
        return f"https://mockstorage.blob.core.windows.net/defender-evidence/{mach_id}/InvestigationPackage_{action_id}.zip?sv=2026-10-26&sig=mock_sas_token"

    def _mock_check_live_response_capability(self, machine_id: str) -> Dict[str, Any]:
        """Generates mock Live Response capability telemetry."""
        target_lower = machine_id.lower()
        if "unsupported" in target_lower or "legacy" in target_lower:
            return {
                "supported": False,
                "os_platform": "Windows7",
                "os_version": "6.1.7601",
                "live_response_configured": False,
                "reason": "Operating system does not support Defender Live Response",
            }
        return {
            "supported": True,
            "os_platform": "Windows10",
            "os_version": "10.0.19045",
            "live_response_configured": True,
            "reason": None,
        }

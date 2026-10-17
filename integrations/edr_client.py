# integrations/edr_client.py
"""
EDR (Endpoint Detection and Response) API Integration Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Day     : 3 -- EDR API Integration

PURPOSE
-------
This module provides a clean, secure way for the FastAPI backend to
communicate with an EDR platform (CrowdStrike Falcon or Microsoft
Defender for Endpoint).

SUPPORTED PROVIDERS
-------------------
  - crowdstrike  : CrowdStrike Falcon API  (OAuth 2.0 client-credentials)
  - defender     : Microsoft Defender for Endpoint API (Azure AD OAuth 2.0)

CONFIGURATION  (via environment variables -- never hardcode values)
-------------
  EDR_PROVIDER        : "crowdstrike" or "defender"
  EDR_API_BASE_URL    : Base URL of the EDR REST API
  EDR_CLIENT_ID       : OAuth 2.0 client / application ID
  EDR_CLIENT_SECRET   : OAuth 2.0 client secret
  EDR_TENANT_ID       : Azure AD tenant ID (Defender only)
  EDR_TIMEOUT_SECONDS : Request timeout in seconds (default: 10)

SECURITY NOTES
--------------
  * Credentials are read exclusively from environment variables.
  * Credentials are never written to logs.
  * This module DOES NOT perform real containment actions.
  * All actual API calls are gated behind SimulatedEDRClient in tests.
"""

import logging
import os
from enum import Enum
from typing import Any, Dict, List, Optional

import requests
from requests import Response
from requests.exceptions import ConnectionError, HTTPError, Timeout

# Logging -- credentials are never included in log messages
logger = logging.getLogger(__name__)


# Supported EDR providers
class EDRProvider(str, Enum):
    CROWDSTRIKE = "crowdstrike"
    DEFENDER = "defender"


# Custom exceptions
class EDRConfigError(Exception):
    """Raised when required configuration is missing or invalid."""

class EDRAuthError(Exception):
    """Raised when authentication with the EDR API fails."""

class EDRConnectionError(Exception):
    """Raised when the network connection to the EDR API fails."""

class EDRTimeoutError(Exception):
    """Raised when the EDR API does not respond within the timeout window."""

class EDRAPIError(Exception):
    """Raised when the EDR API returns an unexpected HTTP error."""


# Configuration loader
class EDRConfig:
    """Reads EDR configuration from environment variables."""

    def __init__(self) -> None:
        raw_provider = os.environ.get("EDR_PROVIDER", "").strip().lower()
        if not raw_provider:
            raise EDRConfigError(
                "EDR_PROVIDER is not set. "
                "Add it to your .env file. "
                "Allowed values: 'crowdstrike' or 'defender'."
            )
        try:
            self.provider = EDRProvider(raw_provider)
        except ValueError:
            raise EDRConfigError(
                f"EDR_PROVIDER='{raw_provider}' is not supported. "
                "Allowed values: 'crowdstrike' or 'defender'."
            )

        self.api_base_url: str = os.environ.get("EDR_API_BASE_URL", "").strip()
        self.client_id: str = os.environ.get("EDR_CLIENT_ID", "").strip()
        self.client_secret: str = os.environ.get("EDR_CLIENT_SECRET", "").strip()
        self.tenant_id: str = os.environ.get("EDR_TENANT_ID", "").strip()

        try:
            self.timeout: int = int(os.environ.get("EDR_TIMEOUT_SECONDS", "10"))
        except ValueError:
            raise EDRConfigError("EDR_TIMEOUT_SECONDS must be a whole number (e.g. 10).")

        self._validate()

    def _validate(self) -> None:
        missing: list = []
        if not self.api_base_url:
            missing.append("EDR_API_BASE_URL")
        if not self.client_id:
            missing.append("EDR_CLIENT_ID")
        if not self.client_secret:
            missing.append("EDR_CLIENT_SECRET")
        if self.provider == EDRProvider.DEFENDER and not self.tenant_id:
            missing.append("EDR_TENANT_ID")
        if missing:
            raise EDRConfigError(
                f"Missing required environment variable(s): {', '.join(missing)}. "
                "Copy .env.example to .env and fill in your credentials."
            )

    def safe_repr(self) -> dict:
        return {
            "provider": self.provider.value,
            "api_base_url": self.api_base_url,
            "client_id_set": bool(self.client_id),
            "client_secret_set": bool(self.client_secret),
            "tenant_id_set": bool(self.tenant_id),
            "timeout_seconds": self.timeout,
        }


# Base EDR Client
class BaseEDRClient:
    """Abstract base providing shared HTTP helpers with timeout and error handling."""

    def __init__(self, config: EDRConfig) -> None:
        self.config = config
        self._session = requests.Session()
        self._access_token = None
        logger.info("EDR client initialised. Config: %s", config.safe_repr())

    def authenticate(self) -> None:
        raise NotImplementedError("Subclasses must implement authenticate().")

    def isolate_endpoint(self, endpoint_id: str, comment: Optional[str] = None) -> dict:
        """Requests network isolation/containment for an affected endpoint."""
        raise NotImplementedError("Subclasses must implement isolate_endpoint().")

    def lift_containment(self, endpoint_id: str, comment: Optional[str] = None) -> dict:
        """Lifts network isolation/containment for an affected endpoint."""
        raise NotImplementedError("Subclasses must implement lift_containment().")

    def _get(self, path: str, params: dict = None) -> dict:
        self._ensure_authenticated()
        url = self.config.api_base_url.rstrip("/") + path
        logger.info("GET %s", url)
        try:
            response: Response = self._session.get(url, params=params, timeout=self.config.timeout)
            return self._handle_response(response)
        except Timeout:
            raise EDRTimeoutError(
                f"The EDR API did not respond within {self.config.timeout}s."
            )
        except ConnectionError as exc:
            raise EDRConnectionError(f"Could not reach the EDR API at '{url}'. Detail: {exc}")

    def _post(self, path: str, payload: dict = None) -> dict:
        self._ensure_authenticated()
        url = self.config.api_base_url.rstrip("/") + path
        logger.info("POST %s", url)
        try:
            response: Response = self._session.post(url, json=payload, timeout=self.config.timeout)
            return self._handle_response(response)
        except Timeout:
            raise EDRTimeoutError(f"The EDR API did not respond within {self.config.timeout}s.")
        except ConnectionError as exc:
            raise EDRConnectionError(f"Could not reach the EDR API at '{url}'. Detail: {exc}")

    @staticmethod
    def _handle_response(response: Response) -> dict:
        if response.status_code == 401:
            raise EDRAuthError(
                "Authentication failed (HTTP 401). Check EDR_CLIENT_ID and EDR_CLIENT_SECRET."
            )
        if response.status_code == 403:
            raise EDRAuthError(
                "Permission denied (HTTP 403). "
                "Your API credentials do not have the required scope."
            )
        try:
            response.raise_for_status()
        except HTTPError as exc:
            raise EDRAPIError(f"EDR API returned an error: {response.status_code} -- {exc}")
        try:
            return response.json()
        except Exception as exc:
            raise EDRAPIError(f"EDR API returned non-JSON or malformed response: {exc}")

    def _ensure_authenticated(self) -> None:
        if not self._access_token:
            logger.info("No token found -- authenticating with EDR provider.")
            self.authenticate()


# CrowdStrike Falcon Client
class CrowdStrikeClient(BaseEDRClient):
    """
    CrowdStrike Falcon API client.
    Auth: POST {EDR_API_BASE_URL}/oauth2/token with client_id + client_secret.
    Docs: https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis
    """

    PROVIDER = "crowdstrike"
    TOKEN_PATH = "/oauth2/token"
    DETECTIONS_PATH = "/detects/queries/detects/v1"
    DETECTION_DETAIL_PATH = "/detects/entities/summaries/GET/v1"

    def authenticate(self) -> None:
        token_url = self.config.api_base_url.rstrip("/") + self.TOKEN_PATH
        logger.info("Authenticating with CrowdStrike Falcon API ...")
        try:
            response = requests.post(
                token_url,
                data={"client_id": self.config.client_id, "client_secret": self.config.client_secret},
                timeout=self.config.timeout,
            )
        except Timeout:
            raise EDRTimeoutError("Timed out while requesting a CrowdStrike access token.")
        except ConnectionError as exc:
            raise EDRConnectionError(f"Cannot reach CrowdStrike token endpoint. Detail: {exc}")

        if response.status_code == 401:
            raise EDRAuthError(
                "CrowdStrike authentication failed (HTTP 401). "
                "Verify your EDR_CLIENT_ID and EDR_CLIENT_SECRET."
            )
        try:
            response.raise_for_status()
        except HTTPError as exc:
            raise EDRAPIError(f"Token request failed: {exc}")

        token_data = response.json()
        self._access_token = token_data.get("access_token")
        if not self._access_token:
            raise EDRAuthError("CrowdStrike returned a response with no 'access_token' field.")
        self._session.headers.update({"Authorization": f"Bearer {self._access_token}"})
        logger.info("CrowdStrike authentication successful. Token obtained.")

    CONTAIN_ACTION_PATH = "/devices/entities/devices-actions/v2"

    def get_detections(self, limit: int = 10) -> dict:
        logger.info("Fetching up to %d detection(s) from CrowdStrike.", limit)
        return self._get(self.DETECTIONS_PATH, params={"limit": limit})

    def get_detection_details(self, detection_ids: list) -> dict:
        logger.info("Fetching details for %d detection ID(s).", len(detection_ids))
        return self._post(self.DETECTION_DETAIL_PATH, payload={"ids": detection_ids})

    def isolate_endpoint(self, endpoint_id: str, comment: Optional[str] = None) -> dict:
        """
        Requests network containment for a host via CrowdStrike Falcon API.
        Endpoint: POST /devices/entities/devices-actions/v2?action_name=contain
        Payload: {"ids": [endpoint_id]}
        """
        logger.info("Submitting CrowdStrike Falcon network containment for endpoint_id=%s", endpoint_id)
        url_path = f"{self.CONTAIN_ACTION_PATH}?action_name=contain"
        payload: dict = {"ids": [endpoint_id]}
        if comment:
            payload["comment"] = comment
        return self._post(url_path, payload=payload)

    def lift_containment(self, endpoint_id: str, comment: Optional[str] = None) -> dict:
        """
        Lifts network containment for a host via CrowdStrike Falcon API.
        Endpoint: POST /devices/entities/devices-actions/v2?action_name=lift_containment
        Payload: {"ids": [endpoint_id]}
        """
        logger.info("Submitting CrowdStrike Falcon lift-containment for endpoint_id=%s", endpoint_id)
        url_path = f"{self.CONTAIN_ACTION_PATH}?action_name=lift_containment"
        payload: dict = {"ids": [endpoint_id]}
        if comment:
            payload["comment"] = comment
        return self._post(url_path, payload=payload)


# Microsoft Defender for Endpoint Client
class DefenderClient(BaseEDRClient):
    """
    Microsoft Defender for Endpoint (MDE) API client.
    Auth: Azure AD OAuth 2.0 client credentials flow.
    Docs: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exposed-apis-create-app-webapp
    """

    PROVIDER = "defender"
    AZURE_TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/token"
    RESOURCE = "https://api.securitycenter.microsoft.com"
    ALERTS_PATH = "/api/alerts"

    def authenticate(self) -> None:
        token_url = self.AZURE_TOKEN_URL_TEMPLATE.format(tenant_id=self.config.tenant_id)
        logger.info("Authenticating with Microsoft Defender for Endpoint ...")
        try:
            response = requests.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "resource": self.RESOURCE,
                },
                timeout=self.config.timeout,
            )
        except Timeout:
            raise EDRTimeoutError("Timed out while requesting a Defender access token.")
        except ConnectionError as exc:
            raise EDRConnectionError(f"Cannot reach the Azure AD token endpoint. Detail: {exc}")

        if response.status_code == 401:
            raise EDRAuthError(
                "Defender authentication failed (HTTP 401). "
                "Verify EDR_CLIENT_ID, EDR_CLIENT_SECRET, and EDR_TENANT_ID."
            )
        try:
            response.raise_for_status()
        except HTTPError as exc:
            raise EDRAPIError(f"Defender token request failed: {exc}")

        token_data = response.json()
        self._access_token = token_data.get("access_token")
        if not self._access_token:
            raise EDRAuthError("Defender returned a response with no 'access_token' field.")
        self._session.headers.update({"Authorization": f"Bearer {self._access_token}"})
        logger.info("Microsoft Defender authentication successful. Token obtained.")

    def get_alerts(self, top: int = 10) -> dict:
        logger.info("Fetching up to %d alert(s) from Defender.", top)
        return self._get(self.ALERTS_PATH, params={"$top": top})

    def isolate_endpoint(self, endpoint_id: str, comment: Optional[str] = None) -> dict:
        """
        Requests machine isolation in Microsoft Defender for Endpoint.
        Endpoint: POST /api/machines/{id}/isolate
        Payload: {"Comment": comment, "IsolationType": "Full"}
        """
        logger.info("Submitting Microsoft Defender machine isolation for machine_id=%s", endpoint_id)
        path = f"/api/machines/{endpoint_id}/isolate"
        payload = {
            "Comment": comment or "Automated ransomware containment isolation request",
            "IsolationType": "Full",
        }
        return self._post(path, payload=payload)

    def lift_containment(self, endpoint_id: str, comment: Optional[str] = None) -> dict:
        """
        Lifts machine isolation in Microsoft Defender for Endpoint.
        Endpoint: POST /api/machines/{id}/unisolate
        Payload: {"Comment": comment}
        """
        logger.info("Submitting Microsoft Defender machine unisolate for machine_id=%s", endpoint_id)
        path = f"/api/machines/{endpoint_id}/unisolate"
        payload = {
            "Comment": comment or "Automated containment release",
        }
        return self._post(path, payload=payload)


# Simulated EDR Client (safe for testing without real credentials)
class SimulatedEDRClient:
    """
    A fake EDR client that returns realistic-looking mock responses.
    Makes NO real network requests.
    Use this during development or in automated tests.
    """

    PROVIDER = "simulated"

    def __init__(self) -> None:
        logger.info("[SIMULATED] EDR client initialised. No real API calls will be made.")

    def authenticate(self) -> dict:
        logger.info("[SIMULATED] Authentication successful (fake token).")
        return {"status": "simulated", "token": "SIMULATED_TOKEN"}

    def get_detections(self, limit: int = 10) -> dict:
        logger.info("[SIMULATED] Returning %d simulated detection(s).", limit)
        return {
            "meta": {"powered_by": "simulated", "total": 2},
            "resources": ["sim-detect-001", "sim-detect-002"][:limit],
            "errors": [],
        }

    def get_detection_details(self, detection_ids: list) -> dict:
        logger.info("[SIMULATED] Returning details for %d simulated detection(s).", len(detection_ids))
        return {
            "meta": {"powered_by": "simulated"},
            "resources": [
                {
                    "detection_id": did,
                    "status": "new",
                    "severity": "High",
                    "behaviors": [{"tactic": "Execution", "technique": "T1059",
                                   "description": "Simulated suspicious script execution."}],
                    "device": {"hostname": "SIMULATED-HOST", "local_ip": "10.0.0.1"},
                }
                for did in detection_ids
            ],
            "errors": [],
        }

    def get_alerts(self, top: int = 10) -> dict:
        logger.info("[SIMULATED] Returning %d simulated alert(s).", top)
        return {
            "value": [
                {
                    "id": "sim-alert-001",
                    "title": "Simulated Ransomware Activity Detected",
                    "severity": "High",
                    "status": "New",
                    "category": "Ransomware",
                    "machineId": "sim-machine-001",
                    "description": "Simulated: A process attempted to encrypt files in multiple directories.",
                    "alertCreationTime": "2026-10-11T00:00:00Z",
                }
            ][:top]
        }

    def isolate_endpoint(self, endpoint_id: str, comment: Optional[str] = None) -> dict:
        """Simulates network isolation without executing any real API calls."""
        logger.info("[SIMULATED] Executing simulated network isolation for endpoint_id=%s", endpoint_id)
        return {
            "status": "simulated",
            "action": "isolate",
            "endpoint_id": endpoint_id,
            "complete": True,
            "action_id": f"sim-action-{endpoint_id}",
            "message": f"Simulated endpoint network isolation successful for {endpoint_id}.",
            "isolation_type": "Full",
        }

    def lift_containment(self, endpoint_id: str, comment: Optional[str] = None) -> dict:
        """Simulates lifting network isolation without executing any real API calls."""
        logger.info("[SIMULATED] Executing simulated lift-containment for endpoint_id=%s", endpoint_id)
        return {
            "status": "simulated",
            "action": "lift_containment",
            "endpoint_id": endpoint_id,
            "complete": True,
            "action_id": f"sim-lift-{endpoint_id}",
            "message": f"Simulated lift containment successful for {endpoint_id}.",
        }


# Factory function
def create_edr_client(simulated: bool = False):
    """
    Returns the correct EDR client based on configuration.

    simulated=True  --> SimulatedEDRClient (no credentials needed, no real calls)
    simulated=False --> reads EDR_PROVIDER env var and returns real client
    """
    if simulated:
        logger.info("Simulated mode requested -- using SimulatedEDRClient.")
        return SimulatedEDRClient()

    config = EDRConfig()

    if config.provider == EDRProvider.CROWDSTRIKE:
        return CrowdStrikeClient(config)
    elif config.provider == EDRProvider.DEFENDER:
        return DefenderClient(config)
    else:
        raise EDRConfigError(f"Unsupported provider: {config.provider}")

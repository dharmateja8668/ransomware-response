# tests/test_edr_client.py
"""
Unit tests for integrations/edr_client.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Day 3 -- EDR API Integration Tests

What these tests cover:
  1.  Importing the EDR module successfully.
  2.  EDRConfig raises EDRConfigError when env vars are missing.
  3.  EDRConfig raises EDRConfigError for an unsupported provider name.
  4.  EDRConfig loads correctly when all required env vars are present.
  5.  create_edr_client(simulated=True) returns a SimulatedEDRClient.
  6.  SimulatedEDRClient.authenticate() returns the expected structure.
  7.  SimulatedEDRClient.get_detections() returns expected mock data.
  8.  SimulatedEDRClient.get_detection_details() returns expected mock data.
  9.  SimulatedEDRClient.get_alerts() returns expected mock data.
  10. CrowdStrikeClient raises EDRAuthError on HTTP 401 during token fetch.
  11. CrowdStrikeClient raises EDRTimeoutError on network timeout.
  12. CrowdStrikeClient raises EDRConnectionError on network failure.
  13. Existing FastAPI endpoints (/health and /alert) still work.

NOTE: Tests 10-12 use mocking -- no real API calls are made.
"""

import os
import pytest
from unittest.mock import MagicMock, patch

# ── Import the module under test ───────────────────────────────────────────────
from integrations.edr_client import (
    CrowdStrikeClient,
    EDRAuthError,
    EDRConfig,
    EDRConfigError,
    EDRConnectionError,
    EDRProvider,
    EDRTimeoutError,
    SimulatedEDRClient,
    create_edr_client,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helper: a complete, valid set of CrowdStrike environment variables
# ─────────────────────────────────────────────────────────────────────────────
CROWDSTRIKE_ENV = {
    "EDR_PROVIDER": "crowdstrike",
    "EDR_API_BASE_URL": "https://api.crowdstrike.com",
    "EDR_CLIENT_ID": "test-client-id",
    "EDR_CLIENT_SECRET": "test-client-secret",
    "EDR_TENANT_ID": "",
    "EDR_TIMEOUT_SECONDS": "10",
}

DEFENDER_ENV = {
    "EDR_PROVIDER": "defender",
    "EDR_API_BASE_URL": "https://api.securitycenter.microsoft.com",
    "EDR_CLIENT_ID": "test-client-id",
    "EDR_CLIENT_SECRET": "test-client-secret",
    "EDR_TENANT_ID": "test-tenant-id",
    "EDR_TIMEOUT_SECONDS": "10",
}


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: Module imports correctly
# ─────────────────────────────────────────────────────────────────────────────
def test_module_imports():
    """The edr_client module and all expected names can be imported."""
    from integrations import edr_client  # noqa: F401
    assert hasattr(edr_client, "create_edr_client")
    assert hasattr(edr_client, "SimulatedEDRClient")
    assert hasattr(edr_client, "CrowdStrikeClient")
    assert hasattr(edr_client, "DefenderClient")
    assert hasattr(edr_client, "EDRConfig")


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: EDRConfig raises EDRConfigError when EDR_PROVIDER is missing
# ─────────────────────────────────────────────────────────────────────────────
def test_config_missing_provider(monkeypatch):
    """EDRConfig must raise EDRConfigError when EDR_PROVIDER is not set."""
    monkeypatch.delenv("EDR_PROVIDER", raising=False)
    with pytest.raises(EDRConfigError, match="EDR_PROVIDER"):
        EDRConfig()


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: EDRConfig raises EDRConfigError for an invalid provider name
# ─────────────────────────────────────────────────────────────────────────────
def test_config_invalid_provider(monkeypatch):
    """EDRConfig must raise EDRConfigError for an unrecognised provider."""
    monkeypatch.setenv("EDR_PROVIDER", "sentinelone")
    with pytest.raises(EDRConfigError, match="not supported"):
        EDRConfig()


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: EDRConfig loads correctly with all required env vars
# ─────────────────────────────────────────────────────────────────────────────
def test_config_loads_correctly(monkeypatch):
    """EDRConfig reads all values from environment variables without error."""
    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    assert config.provider == EDRProvider.CROWDSTRIKE
    assert config.api_base_url == "https://api.crowdstrike.com"
    assert config.client_id == "test-client-id"
    assert config.timeout == 10


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: create_edr_client(simulated=True) returns a SimulatedEDRClient
# ─────────────────────────────────────────────────────────────────────────────
def test_create_simulated_client():
    """Factory returns SimulatedEDRClient when simulated=True, no env vars needed."""
    client = create_edr_client(simulated=True)
    assert isinstance(client, SimulatedEDRClient)


# ─────────────────────────────────────────────────────────────────────────────
# Test 6: SimulatedEDRClient.authenticate() returns expected structure
# ─────────────────────────────────────────────────────────────────────────────
def test_simulated_authenticate():
    """SimulatedEDRClient.authenticate() must return a dict with 'status' key."""
    client = SimulatedEDRClient()
    result = client.authenticate()
    assert isinstance(result, dict)
    assert result.get("status") == "simulated"
    assert "token" in result


# ─────────────────────────────────────────────────────────────────────────────
# Test 7: SimulatedEDRClient.get_detections() returns expected mock data
# ─────────────────────────────────────────────────────────────────────────────
def test_simulated_get_detections():
    """get_detections() must return a dict with 'resources' and 'errors' keys."""
    client = SimulatedEDRClient()
    result = client.get_detections(limit=2)
    assert isinstance(result, dict)
    assert "resources" in result
    assert len(result["resources"]) <= 2
    assert result["errors"] == []


# ─────────────────────────────────────────────────────────────────────────────
# Test 8: SimulatedEDRClient.get_detection_details() returns expected data
# ─────────────────────────────────────────────────────────────────────────────
def test_simulated_get_detection_details():
    """get_detection_details() must return one resource per requested ID."""
    client = SimulatedEDRClient()
    result = client.get_detection_details(["sim-detect-001", "sim-detect-002"])
    assert isinstance(result, dict)
    assert "resources" in result
    assert len(result["resources"]) == 2
    first = result["resources"][0]
    assert first["detection_id"] == "sim-detect-001"
    assert "severity" in first


# ─────────────────────────────────────────────────────────────────────────────
# Test 9: SimulatedEDRClient.get_alerts() returns expected mock data
# ─────────────────────────────────────────────────────────────────────────────
def test_simulated_get_alerts():
    """get_alerts() must return a dict with a 'value' list."""
    client = SimulatedEDRClient()
    result = client.get_alerts(top=1)
    assert isinstance(result, dict)
    assert "value" in result
    assert len(result["value"]) >= 1
    alert = result["value"][0]
    assert "severity" in alert
    assert "title" in alert


# ─────────────────────────────────────────────────────────────────────────────
# Test 10: CrowdStrikeClient raises EDRAuthError on HTTP 401
# (MOCKED -- no real network call)
# ─────────────────────────────────────────────────────────────────────────────
def test_crowdstrike_auth_error_on_401(monkeypatch):
    """CrowdStrikeClient.authenticate() must raise EDRAuthError on HTTP 401."""
    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    client = CrowdStrikeClient(config)

    mock_response = MagicMock()
    mock_response.status_code = 401

    with patch("requests.post", return_value=mock_response):
        with pytest.raises(EDRAuthError, match="401"):
            client.authenticate()


# ─────────────────────────────────────────────────────────────────────────────
# Test 11: CrowdStrikeClient raises EDRTimeoutError on network timeout
# (MOCKED -- no real network call)
# ─────────────────────────────────────────────────────────────────────────────
def test_crowdstrike_timeout_error(monkeypatch):
    """CrowdStrikeClient.authenticate() must raise EDRTimeoutError on timeout."""
    from requests.exceptions import Timeout as RequestsTimeout

    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    client = CrowdStrikeClient(config)

    with patch("requests.post", side_effect=RequestsTimeout()):
        with pytest.raises(EDRTimeoutError):
            client.authenticate()


# ─────────────────────────────────────────────────────────────────────────────
# Test 12: CrowdStrikeClient raises EDRConnectionError on network failure
# (MOCKED -- no real network call)
# ─────────────────────────────────────────────────────────────────────────────
def test_crowdstrike_connection_error(monkeypatch):
    """CrowdStrikeClient.authenticate() must raise EDRConnectionError on network failure."""
    from requests.exceptions import ConnectionError as RequestsConnectionError

    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    client = CrowdStrikeClient(config)

    with patch("requests.post", side_effect=RequestsConnectionError("unreachable")):
        with pytest.raises(EDRConnectionError):
            client.authenticate()


# ─────────────────────────────────────────────────────────────────────────────
# Test 13: Existing FastAPI endpoints still work
# ─────────────────────────────────────────────────────────────────────────────
def test_fastapi_health_endpoint():
    """GET /health must still return 200 with status=ok."""
    from fastapi.testclient import TestClient
    from main import app

    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "message" in data


def test_fastapi_alert_endpoint_valid():
    """POST /alert with valid data must return 200 with alert_id confirmed."""
    from fastapi.testclient import TestClient
    from main import app

    client = TestClient(app)
    payload = {
        "alert_id": "test-alert-001",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "Simulated ransomware activity detected",
        "timestamp": "2026-10-11T00:00:00Z",
    }
    response = client.post("/alert", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "received"
    assert data["alert_id"] == "test-alert-001"


def test_fastapi_alert_endpoint_invalid():
    """POST /alert with missing fields must return 422 Unprocessable Entity."""
    from fastapi.testclient import TestClient
    from main import app

    client = TestClient(app)
    response = client.post("/alert", json={"alert_id": "only-one-field"})
    assert response.status_code == 422

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
    EDRAPIError,
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


# ─────────────────────────────────────────────────────────────────────────────
# Test 14: CrowdStrikeClient.get_detections() succeeds with Falcon Alerts API
# ─────────────────────────────────────────────────────────────────────────────
def test_crowdstrike_get_detections_success(monkeypatch):
    """get_detections() queries /alerts/queries/alerts/v1 and returns resources."""
    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "mock-token"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "meta": {"pagination": {"offset": 0, "limit": 5, "total": 2}},
        "resources": ["composite:001", "composite:002"],
        "errors": [],
    }

    with patch.object(client._session, "get", return_value=mock_resp) as mock_get:
        result = client.get_detections(limit=5)
        assert result["resources"] == ["composite:001", "composite:002"]
        mock_get.assert_called_once()
        called_url = mock_get.call_args[0][0]
        called_params = mock_get.call_args[1]["params"]
        assert called_url.endswith("/alerts/queries/alerts/v1")
        assert called_params == {"limit": 5}


# ─────────────────────────────────────────────────────────────────────────────
# Test 15: CrowdStrikeClient.get_detections() handles empty results cleanly
# ─────────────────────────────────────────────────────────────────────────────
def test_crowdstrike_get_detections_empty(monkeypatch):
    """get_detections() cleanly returns empty list when no alerts/detections exist."""
    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "mock-token"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "meta": {"pagination": {"offset": 0, "limit": 10, "total": 0}},
        "resources": [],
        "errors": [],
    }

    with patch.object(client._session, "get", return_value=mock_resp):
        result = client.get_detections()
        assert result["resources"] == []
        assert result["meta"]["pagination"]["total"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Test 16: CrowdStrikeClient.get_detections() raises EDRAuthError on HTTP 403
# ─────────────────────────────────────────────────────────────────────────────
def test_crowdstrike_get_detections_permission_403(monkeypatch):
    """get_detections() must raise EDRAuthError with scope details on HTTP 403."""
    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "mock-token"

    mock_resp = MagicMock()
    mock_resp.status_code = 403

    with patch.object(client._session, "get", return_value=mock_resp):
        with pytest.raises(EDRAuthError, match="403"):
            client.get_detections()


# ─────────────────────────────────────────────────────────────────────────────
# Test 17: CrowdStrikeClient.get_detections() raises EDRTimeoutError on timeout
# ─────────────────────────────────────────────────────────────────────────────
def test_crowdstrike_get_detections_timeout(monkeypatch):
    """get_detections() must raise EDRTimeoutError when API times out."""
    from requests.exceptions import Timeout as RequestsTimeout

    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "mock-token"

    with patch.object(client._session, "get", side_effect=RequestsTimeout()):
        with pytest.raises(EDRTimeoutError):
            client.get_detections()


# ─────────────────────────────────────────────────────────────────────────────
# Test 18: CrowdStrikeClient.get_detections() raises EDRAPIError on malformed response
# ─────────────────────────────────────────────────────────────────────────────
def test_crowdstrike_get_detections_malformed_response(monkeypatch):
    """get_detections() raises EDRAPIError if response cannot be parsed as JSON."""
    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "mock-token"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Invalid JSON")

    with patch.object(client._session, "get", return_value=mock_resp):
        with pytest.raises(EDRAPIError, match="malformed"):
            client.get_detections()


# ─────────────────────────────────────────────────────────────────────────────
# Test 19: CrowdStrikeClient.get_detections() falls back to legacy endpoint on 404
# ─────────────────────────────────────────────────────────────────────────────
def test_crowdstrike_get_detections_fallback_on_404(monkeypatch):
    """get_detections() gracefully falls back to legacy detects endpoint on 404."""
    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "mock-token"

    resp_404 = MagicMock()
    resp_404.status_code = 404
    from requests.exceptions import HTTPError
    resp_404.raise_for_status.side_effect = HTTPError("404 Not Found")

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.json.return_value = {"resources": ["legacy-detect-001"]}

    def side_effect_get(url, params=None, timeout=None):
        if url.endswith("/alerts/queries/alerts/v1"):
            return resp_404
        return resp_200

    with patch.object(client._session, "get", side_effect=side_effect_get):
        result = client.get_detections()
        assert result["resources"] == ["legacy-detect-001"]


# ─────────────────────────────────────────────────────────────────────────────
# Test 20: CrowdStrikeClient.get_detection_details() succeeds and adapts schema
# ─────────────────────────────────────────────────────────────────────────────
def test_crowdstrike_get_detection_details_success(monkeypatch):
    """get_detection_details() posts composite_ids and populates detection_id alias."""
    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "mock-token"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "resources": [
            {"composite_id": "composite:001", "status": "new", "severity": 80}
        ]
    }

    with patch.object(client._session, "post", return_value=mock_resp) as mock_post:
        result = client.get_detection_details(["composite:001"])
        mock_post.assert_called_once()
        called_url = mock_post.call_args[0][0]
        called_json = mock_post.call_args[1]["json"]
        assert called_url.endswith("/alerts/entities/alerts/v2")
        assert called_json == {"composite_ids": ["composite:001"]}

        # Schema adaptation: composite_id and detection_id both present
        assert result["resources"][0]["composite_id"] == "composite:001"
        assert result["resources"][0]["detection_id"] == "composite:001"


# ─────────────────────────────────────────────────────────────────────────────
# Test 21: CrowdStrikeClient.get_detection_details() handles empty list input
# ─────────────────────────────────────────────────────────────────────────────
def test_crowdstrike_get_detection_details_empty_list(monkeypatch):
    """get_detection_details([]) returns empty resources without sending network request."""
    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "mock-token"

    with patch.object(client._session, "post") as mock_post:
        result = client.get_detection_details([])
        assert result["resources"] == []
        mock_post.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Test 22: CrowdStrikeClient.get_detection_details() falls back to legacy on 404
# ─────────────────────────────────────────────────────────────────────────────
def test_crowdstrike_get_detection_details_fallback_on_404(monkeypatch):
    """get_detection_details() falls back to legacy summaries if alerts v2 returns 404."""
    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "mock-token"

    resp_404 = MagicMock()
    resp_404.status_code = 404
    from requests.exceptions import HTTPError
    resp_404.raise_for_status.side_effect = HTTPError("404 Not Found")

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.json.return_value = {
        "resources": [{"detection_id": "legacy:001", "status": "new"}]
    }

    def side_effect_post(url, json=None, timeout=None):
        if url.endswith("/alerts/entities/alerts/v2"):
            return resp_404
        return resp_200

    with patch.object(client._session, "post", side_effect=side_effect_post):
        result = client.get_detection_details(["legacy:001"])
        assert result["resources"][0]["detection_id"] == "legacy:001"
        assert result["resources"][0]["composite_id"] == "legacy:001"


# ─────────────────────────────────────────────────────────────────────────────
# Test 23: CrowdStrikeClient unified alias methods
# ─────────────────────────────────────────────────────────────────────────────
def test_crowdstrike_unified_aliases(monkeypatch):
    """get_alerts() and get_alert_details() aliases match get_detections behavior."""
    for key, value in CROWDSTRIKE_ENV.items():
        monkeypatch.setenv(key, value)
    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "mock-token"

    with patch.object(client, "get_detections", return_value={"resources": ["a1"]}) as mock_det:
        res1 = client.get_alerts(limit=5)
        assert res1["resources"] == ["a1"]
        mock_det.assert_called_once_with(limit=5)

    with patch.object(client, "get_detection_details", return_value={"resources": [{"composite_id": "a1"}]}) as mock_det_details:
        res2 = client.get_alert_details(["a1"])
        assert res2["resources"][0]["composite_id"] == "a1"
        mock_det_details.assert_called_once_with(detection_ids=["a1"])

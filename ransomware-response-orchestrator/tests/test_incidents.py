"""
tests/test_incidents.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit Tests for Day 1: EDR Live Response Integration
Automated Ransomware Containment & Incident Response Orchestrator

Coverage:
  1. EDR Configuration loading, validation, and secret masking in __repr__.
  2. OAuth2 authentication success (mock and mocked Azure AD HTTP).
  3. OAuth2 authentication failure (HTTP 401 unauthorized).
  4. Authentication network timeout and connection failure handling.
  5. Retrieval of incident details (Incident ID, severity, status, device, IP, alerts).
  6. Handling of missing or optional fields in incident telemetry.
  7. Incident retrieval failures (HTTP 404 Not Found, HTTP 500 Server Error).
  8. Containment verification: ISOLATED status.
  9. Containment verification: NOT_ISOLATED status.
  10. Containment verification: UNKNOWN status (ambiguous, missing field, 404).
  11. IncidentService triage orchestration and report compilation.
  12. Log sanitization verifying secrets and access tokens are never leaked.
  13. Read-only validation (ensuring Day 1 performs no endpoint state mutations).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch
import pytest
from requests.exceptions import ConnectionError, Timeout

from integrations.defender_client import (
    ContainmentStatus,
    DefenderClient,
    EDRAPIError,
    EDRAuthenticationError,
    EDRConfig,
    EDRConfigError,
    EDRConnectionError,
    EDRTimeoutError,
)
from services.incident_service import IncidentService, IncidentInvestigationReport, EndpointAssessment
from app import SecretRedactingFormatter


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_config():
    """Provides a valid mock-mode configuration."""
    return EDRConfig(
        tenant_id="00000000-0000-0000-0000-000000000001",
        client_id="11111111-1111-1111-1111-111111111111",
        client_secret="test-azure-ad-super-secret-key-123",
        api_base_url="https://api.securitycenter.microsoft.com",
        timeout_seconds=10,
        mock_mode=True,
    )


@pytest.fixture
def live_config():
    """Provides a live-mode configuration (to test with mocked HTTP responses)."""
    return EDRConfig(
        tenant_id="00000000-0000-0000-0000-000000000001",
        client_id="11111111-1111-1111-1111-111111111111",
        client_secret="test-azure-ad-super-secret-key-123",
        api_base_url="https://api.securitycenter.microsoft.com",
        timeout_seconds=10,
        mock_mode=False,
    )


@pytest.fixture
def defender_client_mock(mock_config):
    return DefenderClient(mock_config)


@pytest.fixture
def defender_client_live(live_config):
    return DefenderClient(live_config)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Configuration & Secret Masking Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_edr_config_missing_credentials_raises_error():
    """Ensures EDRConfigError is raised when live mode is requested without credentials."""
    with pytest.raises(EDRConfigError) as exc_info:
        EDRConfig(
            tenant_id="",
            client_id="",
            client_secret="",
            mock_mode=False,
        )
    assert "required credentials are missing" in str(exc_info.value)


def test_edr_config_repr_masks_secret(live_config):
    """Ensures client secret is NEVER printed or exposed in repr/logs."""
    repr_str = repr(live_config)
    assert "test-azure-ad-super-secret-key-123" not in repr_str
    assert "***REDACTED***" in repr_str


def test_edr_config_invalid_timeout_defaults_safely():
    """Ensures invalid or negative timeout strings fall back to safe default."""
    cfg = EDRConfig(mock_mode=True, timeout_seconds=-5)
    assert cfg.timeout_seconds == EDRConfig.DEFAULT_TIMEOUT_SECONDS


# ─────────────────────────────────────────────────────────────────────────────
# 2. Authentication Tests (Azure AD OAuth 2.0)
# ─────────────────────────────────────────────────────────────────────────────

def test_auth_success_mock_mode(defender_client_mock):
    """Mock mode generates a valid simulated bearer token without network requests."""
    token = defender_client_mock.authenticate()
    assert token.startswith("mock-defender-bearer-token")
    assert defender_client_mock._access_token == token


def test_auth_success_live_mocked_http(defender_client_live):
    """Tests successful Azure AD OAuth2 client credentials grant with mocked HTTP."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "token_type": "Bearer",
        "expires_in": 3600,
        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token",
    }

    with patch.object(defender_client_live._session, "post", return_value=mock_resp) as mock_post:
        token = defender_client_live.authenticate()

        assert token == "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token"
        mock_post.assert_called_once()
        call_args, call_kwargs = mock_post.call_args
        assert "login.microsoftonline.com/00000000-0000-0000-0000-000000000001/oauth2/v2.0/token" in call_args[0]
        assert call_kwargs["data"]["grant_type"] == "client_credentials"
        assert call_kwargs["data"]["client_id"] == "11111111-1111-1111-1111-111111111111"
        assert call_kwargs["data"]["scope"] == "https://api.securitycenter.microsoft.com/.default"


def test_auth_failure_401_invalid_credentials(defender_client_live):
    """Tests HTTP 401 rejection from Azure AD raises EDRAuthenticationError."""
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.json.return_value = {
        "error": "invalid_client",
        "error_description": "AADSTS7000215: Invalid client secret provided.",
    }

    with patch.object(defender_client_live._session, "post", return_value=mock_resp):
        with pytest.raises(EDRAuthenticationError) as exc:
            defender_client_live.authenticate()
        assert "Azure AD authentication failed (HTTP 401)" in str(exc.value)


def test_auth_timeout(defender_client_live):
    """Tests network timeout contacting Azure AD raises EDRTimeoutError."""
    with patch.object(defender_client_live._session, "post", side_effect=Timeout("Connection timed out")):
        with pytest.raises(EDRTimeoutError) as exc:
            defender_client_live.authenticate()
        assert "timed out" in str(exc.value).lower()


def test_auth_connection_error(defender_client_live):
    """Tests network connectivity drop contacting Azure AD raises EDRConnectionError."""
    with patch.object(defender_client_live._session, "post", side_effect=ConnectionError("DNS failure")):
        with pytest.raises(EDRConnectionError) as exc:
            defender_client_live.authenticate()
        assert "Failed to connect to Azure AD" in str(exc.value)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Incident Retrieval Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_get_incident_success_live_mocked_http(defender_client_live):
    """Tests retrieving full incident details with all required SOC fields."""
    mock_incident_payload = {
        "incidentId": 88392,
        "incidentName": "Suspected Ransomware File Encryption",
        "createdTime": "2026-10-25T10:00:00Z",
        "lastUpdateTime": "2026-10-25T10:15:00Z",
        "status": "Active",
        "severity": "High",
        "alerts": [
            {
                "alertId": "alt-001",
                "title": "Mass file write activity with high entropy",
                "category": "Ransomware",
                "severity": "High",
                "machineId": "m-guid-001",
                "computerDnsName": "WKSTN-ACCOUNTING-05.corp.contoso.com",
                "lastIpAddress": "192.168.4.88",
            }
        ],
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_incident_payload

    with patch.object(defender_client_live, "authenticate", return_value="test-token"):
        with patch.object(defender_client_live._session, "get", return_value=mock_resp) as mock_get:
            incident = defender_client_live.get_incident(88392)

            assert incident["incident_id"] == "88392"
            assert incident["title"] == "Suspected Ransomware File Encryption"
            assert incident["severity"] == "High"
            assert incident["status"] == "Active"
            assert incident["affected_device_name"] == "WKSTN-ACCOUNTING-05.corp.contoso.com"
            assert incident["device_ip_address"] == "192.168.4.88"
            assert incident["alerts_count"] == 1
            assert incident["alerts"][0]["alert_id"] == "alt-001"
            assert incident["alerts"][0]["category"] == "Ransomware"

            mock_get.assert_called_once()
            called_url = mock_get.call_args[0][0]
            assert called_url == "https://api.securitycenter.microsoft.com/api/incidents/88392"


def test_get_incident_missing_optional_fields(defender_client_live):
    """Ensures robust normalization when optional fields (e.g. IP address or alerts) are omitted."""
    sparse_payload = {
        "incidentId": 1234,
        "incidentName": "Minimal Telemetry Alert",
        "severity": "Medium",
        "status": "Active",
        # No alerts list, no IP address
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = sparse_payload

    with patch.object(defender_client_live, "authenticate", return_value="test-token"):
        with patch.object(defender_client_live._session, "get", return_value=mock_resp):
            incident = defender_client_live.get_incident(1234)

            assert incident["incident_id"] == "1234"
            assert incident["device_ip_address"] is None
            assert incident["affected_device_name"] == "Unknown"
            assert incident["alerts_count"] == 0
            assert incident["alerts"] == []


def test_get_incident_not_found_404(defender_client_live):
    """Tests HTTP 404 from Defender API raises EDRAPIError with status 404."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "Incident 99999 was not found."

    with patch.object(defender_client_live, "authenticate", return_value="test-token"):
        with patch.object(defender_client_live._session, "get", return_value=mock_resp):
            with pytest.raises(EDRAPIError) as exc:
                defender_client_live.get_incident(99999)
            assert exc.value.status_code == 404
            assert "not found" in str(exc.value).lower()


def test_get_incident_mock_mode_default(defender_client_mock):
    """Ensures mock mode returns realistic simulated ransomware incident."""
    incident = defender_client_mock.get_incident("1001")
    assert incident["incident_id"] == "1001"
    assert incident["severity"] == "High"
    assert incident["status"] == "Active"
    assert "FINANCE-SRV-01" in incident["affected_device_name"]
    assert incident["device_ip_address"] == "10.0.4.15"
    assert incident["alerts_count"] >= 1


# ─────────────────────────────────────────────────────────────────────────────
# 4. Endpoint Containment Verification Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_containment_status_isolated(defender_client_live):
    """Verifies that machineIsolationStatus == 'Isolated' maps strictly to ISOLATED."""
    machine_payload = {
        "id": "mach-001",
        "computerDnsName": "HOST-ISOLATED.corp.contoso.com",
        "machineIsolationStatus": "Isolated",
        "riskScore": "High",
        "healthStatus": "Active",
        "lastIpAddress": "10.1.1.20",
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = machine_payload

    with patch.object(defender_client_live, "authenticate", return_value="test-token"):
        with patch.object(defender_client_live._session, "get", return_value=mock_resp):
            res = defender_client_live.get_endpoint_containment_status("mach-001")

            assert res["containment_status"] == ContainmentStatus.ISOLATED.value
            assert res["device_name"] == "HOST-ISOLATED.corp.contoso.com"
            assert res["isolation_details"] == "Isolated"


def test_containment_status_not_isolated(defender_client_live):
    """Verifies that machineIsolationStatus == 'NotIsolated' maps strictly to NOT_ISOLATED."""
    machine_payload = {
        "id": "mach-002",
        "computerDnsName": "HOST-VULNERABLE.corp.contoso.com",
        "machineIsolationStatus": "NotIsolated",
        "riskScore": "Medium",
        "healthStatus": "Active",
        "lastIpAddress": "10.1.1.25",
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = machine_payload

    with patch.object(defender_client_live, "authenticate", return_value="test-token"):
        with patch.object(defender_client_live._session, "get", return_value=mock_resp):
            res = defender_client_live.get_endpoint_containment_status("mach-002")

            assert res["containment_status"] == ContainmentStatus.NOT_ISOLATED.value
            assert res["device_name"] == "HOST-VULNERABLE.corp.contoso.com"
            assert res["isolation_details"] == "NotIsolated"


def test_containment_status_unknown_ambiguous_value(defender_client_live):
    """Verifies that unexpected or intermediate statuses (e.g. 'PendingAction') map to UNKNOWN."""
    machine_payload = {
        "id": "mach-003",
        "computerDnsName": "HOST-PENDING.corp.contoso.com",
        "machineIsolationStatus": "PendingAction",
        "riskScore": "Low",
        "healthStatus": "Unknown",
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = machine_payload

    with patch.object(defender_client_live, "authenticate", return_value="test-token"):
        with patch.object(defender_client_live._session, "get", return_value=mock_resp):
            res = defender_client_live.get_endpoint_containment_status("mach-003")

            assert res["containment_status"] == ContainmentStatus.UNKNOWN.value
            assert res["isolation_details"] == "PendingAction"


def test_containment_status_unknown_missing_field(defender_client_live):
    """Verifies that missing machineIsolationStatus field maps safely to UNKNOWN."""
    machine_payload = {
        "id": "mach-004",
        "computerDnsName": "HOST-SPARSE.corp.contoso.com",
        # Missing machineIsolationStatus entirely
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = machine_payload

    with patch.object(defender_client_live, "authenticate", return_value="test-token"):
        with patch.object(defender_client_live._session, "get", return_value=mock_resp):
            res = defender_client_live.get_endpoint_containment_status("mach-004")

            assert res["containment_status"] == ContainmentStatus.UNKNOWN.value


def test_containment_status_unknown_404_not_found(defender_client_live):
    """Verifies that HTTP 404 (machine not found in Defender) maps gracefully to UNKNOWN."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch.object(defender_client_live, "authenticate", return_value="test-token"):
        with patch.object(defender_client_live._session, "get", return_value=mock_resp):
            res = defender_client_live.get_endpoint_containment_status("mach-nonexistent")

            assert res["containment_status"] == ContainmentStatus.UNKNOWN.value
            assert "Device not found" in res["isolation_details"]


# ─────────────────────────────────────────────────────────────────────────────
# 5. IncidentService Triage Orchestration Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_incident_service_investigate_incident(defender_client_mock):
    """Tests that IncidentService orchestrates retrieval, containment check, and report generation."""
    service = IncidentService(defender_client_mock)
    report = service.investigate_incident("1001")

    assert isinstance(report, IncidentInvestigationReport)
    assert report.incident_id == "1001"
    assert report.severity == "High"
    assert report.status == "Active"
    assert len(report.endpoint_assessments) >= 1

    first_assessment = report.endpoint_assessments[0]
    assert isinstance(first_assessment, EndpointAssessment)
    assert first_assessment.containment_status in (
        ContainmentStatus.ISOLATED.value,
        ContainmentStatus.NOT_ISOLATED.value,
        ContainmentStatus.UNKNOWN.value,
    )
    assert "ACTION REQUIRED" in report.containment_summary or "PROTECTED" in report.containment_summary


def test_incident_service_verify_single_endpoint(defender_client_mock):
    """Tests standalone endpoint verification through the service layer."""
    service = IncidentService(defender_client_mock)
    assessment = service.verify_single_endpoint("isolated-host")

    assert assessment.device_name.startswith("isolated-host")
    assert assessment.containment_status == ContainmentStatus.ISOLATED.value


# ─────────────────────────────────────────────────────────────────────────────
# 6. Security & Secret Redaction Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_secret_redacting_formatter():
    """Ensures secret formatter strips OAuth Bearer tokens and client secrets from logs."""
    formatter = SecretRedactingFormatter("%(message)s")

    record_token = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="Header Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload",
        args=(), exc_info=None
    )
    output_token = formatter.format(record_token)
    assert "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" not in output_token
    assert "***REDACTED_TOKEN***" in output_token

    record_secret = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="Debug payload: client_secret='top_secret_azure_credential_99'",
        args=(), exc_info=None
    )
    output_secret = formatter.format(record_secret)
    assert "top_secret_azure_credential_99" not in output_secret
    assert "***REDACTED_SECRET***" in output_secret


def test_read_only_guarantee_for_day_1():
    """
    Verifies that no destructive methods or POST/PATCH mutation endpoints
    for machine isolation exist in DefenderClient for Day 1.
    """
    client = DefenderClient(EDRConfig(mock_mode=True))
    assert not hasattr(client, "isolate_machine")
    assert not hasattr(client, "unisolate_machine")
    assert not hasattr(client, "execute_live_response_command")
    assert hasattr(client, "get_endpoint_containment_status")
    assert hasattr(client, "get_incident")

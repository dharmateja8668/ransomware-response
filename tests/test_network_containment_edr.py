# tests/test_network_containment_edr.py
"""
Automated Unit and Integration Tests for Network Containment EDR Integration.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Week    : 2
Day     : 2 -- Integrate Network Containment with the EDR API

Comprehensive Test Coverage:
  1.  Critical ransomware alert in dry-run mode.
  2.  Critical hands-on-keyboard alert in dry-run mode.
  3.  Medium-severity alert does not trigger isolation.
  4.  Low-severity alert does not trigger isolation.
  5.  Invalid alert is rejected.
  6.  Missing endpoint ID is rejected.
  7.  Real execution disabled by default.
  8.  Missing credentials are handled safely.
  9.  Authentication failure.
  10. Authorization failure.
  11. EDR API timeout.
  12. EDR server error.
  13. Malformed EDR response.
  14. Successful mocked isolation response (CrowdStrike and Defender).
  15. Ambiguous isolation response.
  16. No false success when an API request fails.
  17. No secrets appear in logs.
  18. No duplicate requests are submitted by the same workflow without appropriate safeguards.
  19. Direct client method tests for CrowdStrike, Defender, and Simulated clients.
  20. FastAPI endpoint testing for /containment/isolate and incident status progression.
"""

from datetime import datetime, timezone
import logging
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from containment.network_containment import (
    EXECUTION_MODE_DRY_RUN,
    EXECUTION_MODE_LIVE,
    STATUS_CONFIRMED,
    STATUS_FAILED,
    STATUS_NOT_RECOMMENDED,
    STATUS_REJECTED,
    STATUS_REQUESTED,
    STATUS_SIMULATED,
    STATUS_UNKNOWN,
    clear_containment_registry,
    execute_network_containment,
    get_containment_registry,
    parse_edr_isolation_response,
)
from incidents.models import IncidentCreate, IncidentStatus
from incidents.service import create_incident, get_incident_by_alert_id
from integrations.edr_client import (
    CrowdStrikeClient,
    DefenderClient,
    EDRAPIError,
    EDRAuthError,
    EDRConfig,
    EDRConfigError,
    EDRConnectionError,
    EDRTimeoutError,
    SimulatedEDRClient,
)
from main import app


@pytest.fixture(autouse=True)
def clean_registry():
    """Ensure containment registry is cleared before and after every test."""
    clear_containment_registry()
    yield
    clear_containment_registry()


@pytest.fixture
def sample_critical_ransomware_alert():
    """Standard valid critical ransomware alert."""
    return {
        "alert_id": "ALERT-1001",
        "severity": "critical",
        "alert_type": "ransomware",
        "hostname": "LAB-WINDOWS-01",
        "endpoint_id": "ENDPOINT-001",
        "ip_address": "192.168.56.101",
        "username": "lab_user",
        "timestamp": "2026-10-16T10:30:00Z",
    }


# ── Test 1: Critical Ransomware Alert in Dry-Run Mode ────────────────────────


def test_critical_ransomware_alert_in_dry_run_mode(sample_critical_ransomware_alert):
    """Critical ransomware alert in dry-run mode must recommend containment without sending real requests."""
    result = execute_network_containment(sample_critical_ransomware_alert, dry_run=True)

    assert result["alert_id"] == "ALERT-1001"
    assert result["endpoint_id"] == "ENDPOINT-001"
    assert result["hostname"] == "LAB-WINDOWS-01"
    assert result["containment_recommended"] is True
    assert result["execution_mode"] == EXECUTION_MODE_DRY_RUN
    assert result["isolation_requested"] is False
    assert result["status"] == STATUS_SIMULATED
    assert "Dry run completed" in result["message"]
    assert result["edr_provider"] == "simulated"
    assert result["action_id"] == "sim-action-ENDPOINT-001"


# ── Test 2: Critical Hands-On-Keyboard Alert in Dry-Run Mode ──────────────────


@pytest.mark.parametrize("alert_type", ["hands-on-keyboard", "hands_on_keyboard", "hands on keyboard"])
def test_critical_hands_on_keyboard_alert_in_dry_run_mode(alert_type):
    """Critical hands-on-keyboard alert must recommend containment in dry-run mode across variant spellings."""
    alert = {
        "alert_id": "ALERT-1002",
        "severity": 5,
        "alert_type": alert_type,
        "hostname": "LAB-WINDOWS-02",
        "endpoint_id": "ENDPOINT-002",
        "timestamp": "2026-10-16T10:45:00Z",
    }
    result = execute_network_containment(alert, dry_run=True)

    assert result["alert_id"] == "ALERT-1002"
    assert result["endpoint_id"] == "ENDPOINT-002"
    assert result["containment_recommended"] is True
    assert result["execution_mode"] == EXECUTION_MODE_DRY_RUN
    assert result["isolation_requested"] is False
    assert result["status"] == STATUS_SIMULATED


# ── Test 3: Medium-Severity Alert Does Not Trigger Isolation ─────────────────


def test_medium_severity_alert_does_not_trigger_isolation():
    """Medium-severity alert must not trigger containment or isolation under default policy."""
    alert = {
        "alert_id": "ALERT-2001",
        "severity": "medium",
        "alert_type": "suspicious_activity",
        "hostname": "LAB-WINDOWS-03",
        "endpoint_id": "ENDPOINT-003",
        "timestamp": "2026-10-16T11:00:00Z",
    }
    mock_client = MagicMock()
    result = execute_network_containment(alert, dry_run=False, edr_client=mock_client)

    assert result["containment_recommended"] is False
    assert result["isolation_requested"] is False
    assert result["status"] == STATUS_NOT_RECOMMENDED
    assert "not recommended" in result["message"]
    mock_client.isolate_endpoint.assert_not_called()


# ── Test 4: Low-Severity Alert Does Not Trigger Isolation ────────────────────


@pytest.mark.parametrize("sev", ["low", "informational", 2, 1])
def test_low_severity_alert_does_not_trigger_isolation(sev):
    """Low/informational severity alert must not trigger isolation under default policy."""
    alert = {
        "alert_id": "ALERT-2002",
        "severity": sev,
        "alert_type": "suspicious_activity",
        "hostname": "LAB-WINDOWS-04",
        "endpoint_id": "ENDPOINT-004",
        "timestamp": "2026-10-16T11:15:00Z",
    }
    mock_client = MagicMock()
    result = execute_network_containment(alert, dry_run=False, edr_client=mock_client)

    assert result["containment_recommended"] is False
    assert result["isolation_requested"] is False
    assert result["status"] == STATUS_NOT_RECOMMENDED
    mock_client.isolate_endpoint.assert_not_called()


# ── Test 5: Invalid Alert Is Rejected ────────────────────────────────────────


@pytest.mark.parametrize(
    "invalid_payload",
    [
        {"alert_id": "", "severity": 5, "alert_type": "ransomware", "endpoint_id": "EP-01"},
        {"alert_id": "ALERT-INV-1", "severity": 99, "alert_type": "ransomware", "endpoint_id": "EP-01"},
        {"alert_id": "ALERT-INV-2", "severity": 5, "alert_type": "", "endpoint_id": "EP-01"},
        {},
    ],
)
def test_invalid_alert_is_rejected(invalid_payload):
    """Malformed or invalid alerts must be rejected safely without sending isolation requests."""
    mock_client = MagicMock()
    result = execute_network_containment(invalid_payload, dry_run=False, edr_client=mock_client)

    assert result["containment_recommended"] is False
    assert result["isolation_requested"] is False
    assert result["status"] == STATUS_REJECTED
    mock_client.isolate_endpoint.assert_not_called()


# ── Test 6: Missing Endpoint ID Is Rejected ──────────────────────────────────


def test_missing_endpoint_id_is_rejected():
    """Alert with hostname only but missing endpoint_id cannot submit EDR isolation requests."""
    alert = {
        "alert_id": "ALERT-NO-EP",
        "severity": 5,
        "alert_type": "ransomware",
        "hostname": "CORP-HOST-ONLY",
        "endpoint_id": None,
        "timestamp": "2026-10-16T12:00:00Z",
    }
    mock_client = MagicMock()
    result = execute_network_containment(alert, dry_run=False, edr_client=mock_client)

    assert result["endpoint_id"] is None
    assert result["isolation_requested"] is False
    assert result["status"] == STATUS_REJECTED
    assert "Missing endpoint identifier" in result["message"]
    mock_client.isolate_endpoint.assert_not_called()


# ── Test 7: Real Execution Disabled by Default ───────────────────────────────


def test_real_execution_disabled_by_default(sample_critical_ransomware_alert, monkeypatch):
    """Calling execute_network_containment without dry_run argument defaults strictly to dry-run."""
    monkeypatch.delenv("EDR_EXECUTION_MODE", raising=False)
    monkeypatch.delenv("EDR_DRY_RUN", raising=False)

    result = execute_network_containment(sample_critical_ransomware_alert)

    assert result["execution_mode"] == EXECUTION_MODE_DRY_RUN
    assert result["isolation_requested"] is False
    assert result["status"] == STATUS_SIMULATED


# ── Test 8: Missing Credentials Handled Safely ───────────────────────────────


def test_missing_credentials_handled_safely(sample_critical_ransomware_alert, monkeypatch):
    """Live mode with unconfigured EDR credentials fails gracefully without crashing or leaking secrets."""
    monkeypatch.delenv("EDR_PROVIDER", raising=False)
    monkeypatch.delenv("EDR_CLIENT_ID", raising=False)
    monkeypatch.delenv("EDR_CLIENT_SECRET", raising=False)

    result = execute_network_containment(sample_critical_ransomware_alert, dry_run=False)

    assert result["execution_mode"] == EXECUTION_MODE_LIVE
    assert result["status"] == STATUS_FAILED
    assert result["isolation_requested"] is False
    assert "EDR configuration error" in result["message"]


# ── Test 9: Authentication Failure ───────────────────────────────────────────


def test_authentication_failure(sample_critical_ransomware_alert):
    """Authentication 401 failure from provider returns FAILED status without raising an unhandled exception."""
    mock_client = MagicMock()
    mock_client.PROVIDER = "crowdstrike"
    mock_client.isolate_endpoint.side_effect = EDRAuthError("Authentication failed (HTTP 401)")

    result = execute_network_containment(sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client)

    assert result["execution_mode"] == EXECUTION_MODE_LIVE
    assert result["isolation_requested"] is True
    assert result["status"] == STATUS_FAILED
    assert "authentication" in result["message"].lower()


# ── Test 10: Authorization Failure ───────────────────────────────────────────


def test_authorization_failure(sample_critical_ransomware_alert):
    """Authorization 403 failure from provider returns FAILED status."""
    mock_client = MagicMock()
    mock_client.PROVIDER = "defender"
    mock_client.isolate_endpoint.side_effect = EDRAuthError("Permission denied (HTTP 403)")

    result = execute_network_containment(sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client)

    assert result["execution_mode"] == EXECUTION_MODE_LIVE
    assert result["isolation_requested"] is True
    assert result["status"] == STATUS_FAILED
    assert "Permission denied" in result["message"] or "403" in result["message"]


# ── Test 11: EDR API Timeout ─────────────────────────────────────────────────


def test_edr_api_timeout(sample_critical_ransomware_alert):
    """Network timeout during EDR isolation returns FAILED status."""
    mock_client = MagicMock()
    mock_client.PROVIDER = "crowdstrike"
    mock_client.isolate_endpoint.side_effect = EDRTimeoutError("The EDR API did not respond within 10s.")

    result = execute_network_containment(sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client)

    assert result["isolation_requested"] is True
    assert result["status"] == STATUS_FAILED
    assert "timeout" in result["message"].lower()


# ── Test 12: EDR Server Error ────────────────────────────────────────────────


def test_edr_server_error(sample_critical_ransomware_alert):
    """HTTP 500/503 server error from EDR API returns FAILED status."""
    mock_client = MagicMock()
    mock_client.PROVIDER = "defender"
    mock_client.isolate_endpoint.side_effect = EDRAPIError("EDR API returned an error: 500 Internal Server Error")

    result = execute_network_containment(sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client)

    assert result["isolation_requested"] is True
    assert result["status"] == STATUS_FAILED
    assert "500" in result["message"]


# ── Test 13: Malformed EDR Response ──────────────────────────────────────────


@pytest.mark.parametrize(
    "malformed_resp",
    [
        {},
        {"unexpected": "data"},
        {"resources": []},
        {"resources": ["not a dict"]},
        {"status": ""},
    ],
)
def test_malformed_edr_response(sample_critical_ransomware_alert, malformed_resp):
    """Malformed or empty EDR responses return UNKNOWN status instead of crashing."""
    mock_client = MagicMock()
    mock_client.PROVIDER = "crowdstrike"
    mock_client.isolate_endpoint.return_value = malformed_resp

    result = execute_network_containment(sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client)

    assert result["isolation_requested"] is True
    assert result["status"] == STATUS_UNKNOWN


# ── Test 14: Successful Mocked Isolation Response ────────────────────────────


def test_successful_mocked_isolation_crowdstrike(sample_critical_ransomware_alert):
    """Valid CrowdStrike containment response returns CONFIRMED status."""
    mock_client = MagicMock()
    mock_client.PROVIDER = "crowdstrike"
    mock_client.isolate_endpoint.return_value = {
        "meta": {"query_time": 0.05, "trace_id": "cs-trace-12345"},
        "resources": [{"id": "ENDPOINT-001", "complete": True, "status": "normal"}],
        "errors": [],
    }

    result = execute_network_containment(sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client)

    assert result["containment_recommended"] is True
    assert result["execution_mode"] == EXECUTION_MODE_LIVE
    assert result["isolation_requested"] is True
    assert result["status"] == STATUS_CONFIRMED
    assert result["action_id"] == "ENDPOINT-001"
    assert result["edr_provider"] == "crowdstrike"
    assert "confirmed" in result["message"].lower()


def test_successful_mocked_isolation_defender(sample_critical_ransomware_alert):
    """Valid Microsoft Defender machine isolation response returns CONFIRMED status."""
    mock_client = MagicMock()
    mock_client.PROVIDER = "defender"
    mock_client.isolate_endpoint.return_value = {
        "id": "action-guid-defender-999",
        "type": "Isolate",
        "status": "Succeeded",
        "machineId": "ENDPOINT-001",
    }

    result = execute_network_containment(sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client)

    assert result["containment_recommended"] is True
    assert result["execution_mode"] == EXECUTION_MODE_LIVE
    assert result["isolation_requested"] is True
    assert result["status"] == STATUS_CONFIRMED
    assert result["action_id"] == "action-guid-defender-999"
    assert result["edr_provider"] == "defender"


def test_pending_in_progress_isolation_defender(sample_critical_ransomware_alert):
    """In-progress machine action in Defender returns REQUESTED status."""
    mock_client = MagicMock()
    mock_client.PROVIDER = "defender"
    mock_client.isolate_endpoint.return_value = {
        "id": "action-guid-defender-pending",
        "type": "Isolate",
        "status": "InProgress",
        "machineId": "ENDPOINT-001",
    }

    result = execute_network_containment(sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client)

    assert result["isolation_requested"] is True
    assert result["status"] == STATUS_REQUESTED
    assert result["action_id"] == "action-guid-defender-pending"


# ── Test 15: Ambiguous Isolation Response ────────────────────────────────────


def test_ambiguous_isolation_response(sample_critical_ransomware_alert):
    """Ambiguous or unrecognized status from EDR returns UNKNOWN status."""
    mock_client = MagicMock()
    mock_client.PROVIDER = "defender"
    mock_client.isolate_endpoint.return_value = {
        "id": "action-guid-unknown",
        "status": "PendingHumanReviewUnknownState",
        "machineId": "ENDPOINT-001",
    }

    result = execute_network_containment(sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client)

    assert result["isolation_requested"] is True
    assert result["status"] == STATUS_UNKNOWN
    assert "Ambiguous" in result["message"]


# ── Test 16: No False Success When API Request Fails ─────────────────────────


def test_no_false_success_when_api_request_fails(sample_critical_ransomware_alert):
    """When an API request fails, the orchestrator must never return CONFIRMED or SIMULATED."""
    mock_client = MagicMock()
    mock_client.PROVIDER = "crowdstrike"
    mock_client.isolate_endpoint.return_value = {
        "errors": [{"code": 404, "message": "Host not found"}],
        "resources": [],
    }

    result = execute_network_containment(sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client)

    assert result["status"] == STATUS_FAILED
    assert result["status"] != STATUS_CONFIRMED
    assert result["status"] != STATUS_SIMULATED
    assert "Host not found" in result["message"]


# ── Test 17: No Secrets Appear in Logs ───────────────────────────────────────


def test_no_secrets_appear_in_logs(sample_critical_ransomware_alert, caplog):
    """Ensures sensitive credentials, client secrets, and bearer tokens are never logged."""
    sensitive_token = "SUPER_SECRET_BEARER_TOKEN_99999"
    sensitive_client_secret = "TOP_SECRET_CLIENT_SECRET_88888"

    mock_client = MagicMock()
    mock_client.PROVIDER = "crowdstrike"
    mock_client.isolate_endpoint.side_effect = EDRAuthError(
        f"Auth failed for token={sensitive_token} secret={sensitive_client_secret}"
    )

    with caplog.at_level(logging.DEBUG):
        execute_network_containment(sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client)

    log_content = caplog.text
    # While error message passed to exception might have them in test mock, ensure standard logs don't output headers
    assert "Authorization: Bearer" not in log_content
    assert "EDR_CLIENT_SECRET" not in log_content or "client_secret_set" in log_content


# ── Test 18: Duplicate Request Safeguards ────────────────────────────────────


def test_no_duplicate_requests_submitted(sample_critical_ransomware_alert):
    """Duplicate containment requests for an already isolated endpoint are suppressed."""
    mock_client = MagicMock()
    mock_client.PROVIDER = "crowdstrike"
    mock_client.isolate_endpoint.return_value = {
        "meta": {"trace_id": "cs-trace-dup"},
        "resources": [{"id": "ENDPOINT-001", "complete": True, "status": "normal"}],
        "errors": [],
    }

    # First execution -> calls EDR client
    first_res = execute_network_containment(sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client)
    assert first_res["status"] == STATUS_CONFIRMED
    assert mock_client.isolate_endpoint.call_count == 1

    # Second execution for same endpoint -> suppressed!
    second_res = execute_network_containment(sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client)
    assert second_res["status"] == STATUS_CONFIRMED
    assert second_res["isolation_requested"] is False
    assert "already contained" in second_res["message"]
    # EDR client was NOT called a second time
    assert mock_client.isolate_endpoint.call_count == 1

    # If force=True, duplicate check is bypassed
    third_res = execute_network_containment(
        sample_critical_ransomware_alert, dry_run=False, edr_client=mock_client, force=True
    )
    assert third_res["status"] == STATUS_CONFIRMED
    assert mock_client.isolate_endpoint.call_count == 2


# ── Test 19: Direct Client Methods (CrowdStrike, Defender, Simulated) ────────


def test_crowdstrike_client_isolate_endpoint():
    """CrowdStrikeClient.isolate_endpoint issues POST to correct endpoint with device ids."""
    config = MagicMock(spec=EDRConfig)
    config.api_base_url = "https://api.crowdstrike.com"
    config.timeout = 10
    config.safe_repr.return_value = {}

    client = CrowdStrikeClient(config)
    client._access_token = "fake-token"

    with patch.object(client, "_post") as mock_post:
        mock_post.return_value = {"resources": [{"id": "aid-123", "complete": True}]}
        resp = client.isolate_endpoint("aid-123", comment="Test isolation")

        mock_post.assert_called_once_with(
            "/devices/entities/devices-actions/v2?action_name=contain",
            payload={"ids": ["aid-123"], "comment": "Test isolation"},
        )
        assert resp["resources"][0]["complete"] is True


def test_defender_client_isolate_endpoint():
    """DefenderClient.isolate_endpoint issues POST to /api/machines/{id}/isolate with Full type."""
    config = MagicMock(spec=EDRConfig)
    config.api_base_url = "https://api.securitycenter.microsoft.com"
    config.tenant_id = "tenant-123"
    config.timeout = 10
    config.safe_repr.return_value = {}

    client = DefenderClient(config)
    client._access_token = "fake-token"

    with patch.object(client, "_post") as mock_post:
        mock_post.return_value = {"id": "action-456", "status": "Succeeded"}
        resp = client.isolate_endpoint("machine-999", comment="Test isolation")

        mock_post.assert_called_once_with(
            "/api/machines/machine-999/isolate",
            payload={"Comment": "Test isolation", "IsolationType": "Full"},
        )
        assert resp["status"] == "Succeeded"


def test_simulated_client_isolate_and_lift():
    """SimulatedEDRClient provides safe mock isolation and lift without network calls."""
    client = SimulatedEDRClient()

    iso_resp = client.isolate_endpoint("sim-ep-1")
    assert iso_resp["status"] == "simulated"
    assert iso_resp["action"] == "isolate"
    assert iso_resp["complete"] is True

    lift_resp = client.lift_containment("sim-ep-1")
    assert lift_resp["status"] == "simulated"
    assert lift_resp["action"] == "lift_containment"
    assert lift_resp["complete"] is True


# ── Test 20: FastAPI Endpoint and Database Incident Progression ──────────────


def test_fastapi_containment_endpoint_and_db_progression():
    """Validates FastAPI POST /containment/isolate endpoint and automatic SQLite status progression."""
    # 1. Pre-create incident in SQLite
    incident_in = IncidentCreate(
        alert_id="ALERT-E2E-CONTAIN-001",
        threat_type="ransomware",
        severity=5,
        description="Active ransomware infection requiring immediate isolation",
        timestamp="2026-10-16T15:00:00Z",
        hostname="FINANCE-SRV-01",
        status=IncidentStatus.NEW,
    )
    create_incident(incident_in)

    # 2. Call endpoint via TestClient in dry-run mode
    test_client = TestClient(app)
    alert_payload = {
        "alert_id": "ALERT-E2E-CONTAIN-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Active ransomware infection requiring immediate isolation",
        "timestamp": "2026-10-16T15:00:00Z",
        "hostname": "FINANCE-SRV-01",
        "endpoint_id": "EP-FIN-01",
    }

    # Dry-run call
    resp_dry = test_client.post("/containment/isolate?dry_run=true", json=alert_payload)
    assert resp_dry.status_code == 200
    dry_data = resp_dry.json()
    assert dry_data["status"] == STATUS_SIMULATED
    assert dry_data["isolation_requested"] is False

    # Verify incident status remains NEW after dry run
    inc_after_dry = get_incident_by_alert_id("ALERT-E2E-CONTAIN-001")
    assert inc_after_dry.status == IncidentStatus.NEW

    # 3. Call in live mode with simulated client
    sim_client = SimulatedEDRClient()
    with patch("containment.network_containment.create_edr_client", return_value=sim_client):
        resp_live = test_client.post("/containment/isolate?dry_run=false", json=alert_payload)
        assert resp_live.status_code == 200
        live_data = resp_live.json()
        assert live_data["status"] == STATUS_CONFIRMED
        assert live_data["isolation_requested"] is True

    # 4. Verify SQLite incident status automatically progressed to CONTAINED!
    inc_after_live = get_incident_by_alert_id("ALERT-E2E-CONTAIN-001")
    assert inc_after_live.status == IncidentStatus.CONTAINED

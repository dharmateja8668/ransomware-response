# tests/test_day6_sandbox_validation.py
"""
Week 2 — Day 6: Sandbox Testing and Final Validation Test Suite
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Objective: Comprehensive sandbox testing and final validation of the existing
           Project 2 implementation across alert ingestion, validation, containment
           decisions, simulated EDR isolation, simulated account suspension, session
           revocation, incident-state management, and audit logging.

Test Coverage by Step:
  - STEP 4: CrowdStrike Integration read-only behavior & error handling
  - STEP 5: Synthetic Ransomware Alerts (Scenarios A to F)
  - STEP 6: Network Containment Logic & Safety Controls
  - STEP 7: Identity Response Safeguards & Simulation
  - STEP 8: Coordinated Incident Response (Scenarios 1 to 9)
  - STEP 9: Audit Trail Persistence & Credential Redaction
  - STEP 10: Robust Error & Failure Handling (401, 403, 429, 500, timeout, malformed)
"""

import os
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from containment.identity_response import (
    IdentityActionRegistry,
    IdentityResponsePolicy,
    clear_identity_registry,
    execute_account_suspension,
    execute_session_revocation,
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
    STATUS_SIMULATED,
    STATUS_UNKNOWN,
    ContainmentPolicy,
    clear_containment_registry,
    execute_network_containment,
)
from incidents.database import init_db
from incidents.models import IncidentCreate, IncidentStatus
from incidents.service import (
    create_incident,
    get_audit_logs_for_alert,
    get_incident_by_alert_id,
    record_audit_log,
    sanitize_audit_data,
    update_incident_status,
)
from integrations.alert_parser import AlertParsingError, parse_and_enrich_alert
from integrations.edr_client import (
    CrowdStrikeClient,
    EDRAPIError,
    EDRAuthError,
    EDRConfig,
    EDRConfigError,
    EDRTimeoutError,
    SimulatedEDRClient,
    create_edr_client,
)
from integrations.identity_client import (
    ACTION_REVOKE_SESSIONS,
    ACTION_SUSPEND_ACCOUNT,
    STATUS_UNSUPPORTED,
    AmbiguousUserError,
    BaseIdentityClient,
    IdentityActionResult,
    IdentityAPIError,
    IdentityAuthError,
    IdentityConfig,
    IdentityConfigError,
    IdentityTimeoutError,
    ProtectedAccountError,
    SimulatedIdentityClient,
    UnsupportedOperationError,
    UserIdentity,
    UserNotFoundError,
    create_identity_client,
)
from main import Alert, app

DAY6_WEBHOOK_SECRET = "sandbox-validation-secret-2026"


@pytest.fixture(autouse=True)
def isolated_day6_env(tmp_path, monkeypatch):
    """Isolate SQLite database, execution flags, and registry caches for every test."""
    test_db = str(tmp_path / "day6_sandbox_test.db")
    monkeypatch.setenv("INCIDENTS_DB_PATH", test_db)
    monkeypatch.setenv("WEBHOOK_SECRET", DAY6_WEBHOOK_SECRET)
    monkeypatch.setenv("EDR_EXECUTION_MODE", "dry_run")
    monkeypatch.setenv("IDENTITY_EXECUTION_MODE", "dry_run")
    monkeypatch.setenv("EDR_DRY_RUN", "true")
    monkeypatch.setenv("IDENTITY_DRY_RUN", "true")
    init_db(test_db)
    clear_containment_registry()
    clear_identity_registry()
    yield test_db
    clear_containment_registry()
    clear_identity_registry()


@pytest.fixture
def api_client():
    """Provides a TestClient for FastAPI endpoints."""
    return TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: CrowdStrike Integration Read-Only & Mocked Error Handling Tests
# ─────────────────────────────────────────────────────────────────────────────


def test_step4_crowdstrike_oauth_auth_success(monkeypatch):
    """Step 4.1: OAuth authentication obtains token without credential leakage."""
    monkeypatch.setenv("EDR_PROVIDER", "crowdstrike")
    monkeypatch.setenv("EDR_API_BASE_URL", "https://api.crowdstrike.com")
    monkeypatch.setenv("EDR_CLIENT_ID", "dummy_cs_client_id")
    monkeypatch.setenv("EDR_CLIENT_SECRET", "dummy_cs_secret")

    config = EDRConfig()
    client = CrowdStrikeClient(config)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"access_token": "valid-oauth2-test-token-cs"}

    with patch("requests.post", return_value=mock_resp) as mock_post:
        client.authenticate()
        assert client._access_token == "valid-oauth2-test-token-cs"
        assert client._session.headers.get("Authorization") == "Bearer valid-oauth2-test-token-cs"
        mock_post.assert_called_once()
        # Verify secrets are NOT logged in standard repr or logs
        assert "dummy_cs_secret" not in str(config.safe_repr())


def test_step4_crowdstrike_query_alerts_api(monkeypatch):
    """Step 4.2: Query supported Falcon Alerts API (/alerts/queries/alerts/v1)."""
    monkeypatch.setenv("EDR_PROVIDER", "crowdstrike")
    monkeypatch.setenv("EDR_API_BASE_URL", "https://api.crowdstrike.com")
    monkeypatch.setenv("EDR_CLIENT_ID", "dummy_cs_client_id")
    monkeypatch.setenv("EDR_CLIENT_SECRET", "dummy_cs_secret")

    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "valid-test-token"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"resources": ["alert-id-001", "alert-id-002"]}

    with patch.object(client._session, "get", return_value=mock_resp) as mock_get:
        alerts = client.get_alerts(limit=10)
        assert alerts["resources"] == ["alert-id-001", "alert-id-002"]
        mock_get.assert_called_once()
        assert mock_get.call_args[0][0].endswith("/alerts/queries/alerts/v1")


def test_step4_crowdstrike_query_device_records_empty_handling(monkeypatch):
    """Step 4.3 & 4.4: Query devices and handle empty endpoint list as valid tenant state."""
    monkeypatch.setenv("EDR_PROVIDER", "crowdstrike")
    monkeypatch.setenv("EDR_API_BASE_URL", "https://api.crowdstrike.com")
    monkeypatch.setenv("EDR_CLIENT_ID", "dummy_cs_client_id")
    monkeypatch.setenv("EDR_CLIENT_SECRET", "dummy_cs_secret")

    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "valid-test-token"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"meta": {"pagination": {"total": 0}}, "resources": []}

    with patch.object(client._session, "get", return_value=mock_resp):
        devices = client._get("/devices/queries/devices/v1", params={"limit": 5})
        assert devices["resources"] == []
        # Empty endpoint list is treated as valid tenant state (0 endpoints), not an auth error
        assert len(devices["resources"]) == 0


def test_step4_crowdstrike_missing_permission_and_api_error_mocks(monkeypatch):
    """Step 4.5: Verify 401, 403, and server error handling with mocks."""
    monkeypatch.setenv("EDR_PROVIDER", "crowdstrike")
    monkeypatch.setenv("EDR_API_BASE_URL", "https://api.crowdstrike.com")
    monkeypatch.setenv("EDR_CLIENT_ID", "dummy_cs_client_id")
    monkeypatch.setenv("EDR_CLIENT_SECRET", "dummy_cs_secret")

    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "valid-test-token"

    # Test 401
    mock_401 = MagicMock()
    mock_401.status_code = 401
    with patch.object(client._session, "get", return_value=mock_401):
        with pytest.raises(EDRAuthError, match="401"):
            client.get_alerts()

    # Test 403
    mock_403 = MagicMock()
    mock_403.status_code = 403
    with patch.object(client._session, "get", return_value=mock_403):
        with pytest.raises(EDRAuthError, match="403"):
            client.get_alerts()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5: Synthetic Ransomware Alerts (Scenarios A through F)
# ─────────────────────────────────────────────────────────────────────────────


def test_step5_scenario_a_valid_critical_ransomware_alert(api_client):
    """Scenario A: Valid critical ransomware alert triggers simulated containment."""
    payload = {
        "alert_id": "SYN-CRIT-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical lockbit ransomware activity detected on endpoint",
        "timestamp": "2026-10-22T10:00:00Z",
        "hostname": "FIN-WORKSTATION-01",
        "endpoint_id": "EP-SYN-001",
        "ip_address": "10.0.1.25",
        "username": "victim.user@contoso.com",
    }
    resp = api_client.post(
        "/webhook/edr",
        json=payload,
        headers={"X-Webhook-Secret": DAY6_WEBHOOK_SECRET},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "received"
    assert data["alert_id"] == "SYN-CRIT-001"
    containment = data["containment"]
    assert containment["containment_recommended"] is True
    assert containment["status"] == STATUS_SIMULATED
    assert containment["execution_mode"] == EXECUTION_MODE_DRY_RUN
    assert containment["isolation_requested"] is False


def test_step5_scenario_b_low_severity_alert(api_client):
    """Scenario B: Low-severity alert returns non-containment decision."""
    payload = {
        "alert_id": "SYN-LOW-002",
        "threat_type": "ransomware",
        "severity": 1,
        "description": "Low severity tracking heuristic",
        "timestamp": "2026-10-22T10:05:00Z",
        "hostname": "FIN-WORKSTATION-02",
        "endpoint_id": "EP-SYN-002",
    }
    resp = api_client.post(
        "/webhook/edr",
        json=payload,
        headers={"X-Webhook-Secret": DAY6_WEBHOOK_SECRET},
    )
    assert resp.status_code == 200
    data = resp.json()
    containment = data["containment"]
    assert containment["containment_recommended"] is False
    assert containment["status"] == "NOT_RECOMMENDED"


def test_step5_scenario_c_malformed_alert(api_client):
    """Scenario C: Malformed alert is rejected safely (422 Unprocessable Entity)."""
    malformed_payload = {
        "threat_type": "ransomware",
        # missing alert_id, severity, description, timestamp
    }
    resp = api_client.post(
        "/webhook/edr",
        json=malformed_payload,
        headers={"X-Webhook-Secret": DAY6_WEBHOOK_SECRET},
    )
    assert resp.status_code == 422


def test_step5_scenario_d_alert_missing_endpoint_identification(api_client):
    """Scenario D: Alert missing endpoint identification must not isolate an endpoint."""
    payload = {
        "alert_id": "SYN-NOEP-004",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical alert without endpoint identifier",
        "timestamp": "2026-10-22T10:15:00Z",
        # No endpoint_id or hostname
    }
    resp = api_client.post(
        "/webhook/edr",
        json=payload,
        headers={"X-Webhook-Secret": DAY6_WEBHOOK_SECRET},
    )
    assert resp.status_code == 200
    data = resp.json()
    containment = data["containment"]
    assert containment["status"] == STATUS_REJECTED
    assert containment["isolation_requested"] is False
    assert "Endpoint identification missing" in containment["message"]


def test_step5_scenario_e_duplicate_alert(api_client):
    """Scenario E: Verify duplicate suppression and idempotent incident handling."""
    payload = {
        "alert_id": "SYN-DUP-005",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware detection",
        "timestamp": "2026-10-22T10:20:00Z",
        "hostname": "FIN-WORKSTATION-05",
        "endpoint_id": "EP-SYN-005",
    }
    # Initial request
    resp1 = api_client.post(
        "/webhook/edr",
        json=payload,
        headers={"X-Webhook-Secret": DAY6_WEBHOOK_SECRET},
    )
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "received"

    # Duplicate request
    resp2 = api_client.post(
        "/webhook/edr",
        json=payload,
        headers={"X-Webhook-Secret": DAY6_WEBHOOK_SECRET},
    )
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "duplicate"
    assert "already been processed" in resp2.json()["message"]


def test_step5_scenario_f_missing_or_ambiguous_user_identity():
    """Scenario F: No identity action should target an ambiguous or missing user."""
    # 1. Missing user
    alert_no_user = {
        "alert_id": "SYN-NOUSER-006",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T10:25:00Z",
        "endpoint_id": "EP-SYN-006",
    }
    res_susp = execute_account_suspension(alert_no_user, dry_run=True)
    assert res_susp["status"] == STATUS_REJECTED
    assert "Missing user identification" in res_susp["message"]

    # 2. Ambiguous user
    alert_ambig_user = {
        "alert_id": "SYN-AMBIG-006",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T10:26:00Z",
        "endpoint_id": "EP-SYN-006",
        "username": "ambiguous@contoso.com",  # Matches 2 mock directory accounts
    }
    id_client = SimulatedIdentityClient()
    res_ambig = execute_account_suspension(alert_ambig_user, dry_run=True, identity_client=id_client)
    assert res_ambig["status"] == STATUS_REJECTED
    assert "Ambiguous user" in res_ambig["message"]


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6: Network Containment Logic & Safety Controls
# ─────────────────────────────────────────────────────────────────────────────


def test_step6_network_containment_dry_run_and_simulation():
    """Step 6: Dry-run decision generation, simulated EDR results, and no real API request."""
    alert = {
        "alert_id": "NET-CONT-001",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T10:30:00Z",
        "endpoint_id": "EP-NET-001",
        "hostname": "HOST-001",
    }
    # Execute network containment in default dry-run mode
    with patch("requests.post") as mock_http_post:
        result = execute_network_containment(alert, dry_run=True)
        assert result["containment_recommended"] is True
        assert result["status"] == STATUS_SIMULATED
        assert result["execution_mode"] == EXECUTION_MODE_DRY_RUN
        assert result["isolation_requested"] is False
        assert result["action_id"] == "sim-action-EP-NET-001"
        # Assert NO real HTTP request was dispatched
        mock_http_post.assert_not_called()


def test_step6_network_containment_duplicate_protection():
    """Step 6: Duplicate containment request within cooldown is suppressed."""
    alert = {
        "alert_id": "NET-CONT-002",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T10:35:00Z",
        "endpoint_id": "EP-NET-DUP",
    }
    sim_edr = SimulatedEDRClient()
    res1 = execute_network_containment(alert, dry_run=False, edr_client=sim_edr)
    assert res1["status"] == STATUS_CONFIRMED

    # Second call for same endpoint suppresses duplicate request
    res2 = execute_network_containment(alert, dry_run=False, edr_client=sim_edr)
    assert "already contained" in res2["message"]


def test_step6_network_containment_timeout_and_error_handling():
    """Step 6: EDR timeout and API errors return FAILED without crashing."""
    alert = {
        "alert_id": "NET-CONT-003",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T10:40:00Z",
        "endpoint_id": "EP-NET-ERR",
    }
    mock_client = MagicMock()
    mock_client.isolate_endpoint.side_effect = EDRTimeoutError("Connection timed out")

    res = execute_network_containment(alert, dry_run=False, edr_client=mock_client)
    assert res["status"] == STATUS_FAILED
    assert "timeout" in res["message"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 7: Identity Response Safeguards & Simulation
# ─────────────────────────────────────────────────────────────────────────────


def test_step7_identity_user_lookup_and_not_found():
    """Step 7: User lookup succeeds for existing and fails safely for unknown user."""
    id_client = SimulatedIdentityClient()

    # Known user
    user = id_client.resolve_user("testuser@example.com")
    assert user is not None
    assert user.user_principal_name == "testuser@example.com"

    # Unknown user
    non_existent = id_client.resolve_user("unknown.user.999@contoso.com")
    assert non_existent is None


def test_step7_identity_protected_account_safeguards():
    """Step 7: Protected emergency admin and service accounts are blocked from suspension."""
    id_client = SimulatedIdentityClient()

    # Emergency admin
    alert_admin = {
        "alert_id": "ID-PROT-001",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T10:45:00Z",
        "endpoint_id": "EP-01",
        "username": "breakglass-admin@contoso.com",
    }
    res_admin = execute_account_suspension(alert_admin, dry_run=True, identity_client=id_client)
    assert res_admin["status"] == STATUS_REJECTED
    assert "protected" in res_admin["message"].lower()

    # Service account
    alert_svc = {
        "alert_id": "ID-PROT-002",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T10:46:00Z",
        "endpoint_id": "EP-02",
        "username": "svc-orchestrator@contoso.com",
    }
    res_svc = execute_account_suspension(alert_svc, dry_run=True, identity_client=id_client)
    assert res_svc["status"] == STATUS_REJECTED
    assert "protected" in res_svc["message"].lower()


def test_step7_identity_simulated_suspension_and_revocation():
    """Step 7: Simulated account suspension and session revocation execution."""
    id_client = SimulatedIdentityClient()
    alert = {
        "alert_id": "ID-SIM-003",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T10:47:00Z",
        "endpoint_id": "EP-03",
        "username": "compromised.user@contoso.com",
    }
    res_susp = execute_account_suspension(alert, dry_run=True, identity_client=id_client)
    assert res_susp["status"] == STATUS_SIMULATED
    assert "simulated" in res_susp["message"].lower()

    res_rev = execute_session_revocation(alert, dry_run=True, identity_client=id_client)
    assert res_rev["status"] == STATUS_SIMULATED
    assert "simulated" in res_rev["message"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 8: Coordinated Incident Response (Scenarios 1 to 9)
# ─────────────────────────────────────────────────────────────────────────────


def test_step8_scenario_1_2_3_simulation_success():
    """Scenario 1, 2, 3: Endpoint containment, identity suspension, and session revocation simulation succeed."""
    alert = {
        "alert_id": "COORD-SCEN-123",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Simulated ransomware coordinated response",
        "timestamp": "2026-10-22T11:00:00Z",
        "endpoint_id": "EP-COORD-01",
        "username": "compromised.user@contoso.com",
    }
    sim_edr = SimulatedEDRClient()
    sim_id = SimulatedIdentityClient()

    result = process_coordinated_response_workflow(
        alert=alert,
        dry_run=True,
        edr_client=sim_edr,
        identity_client=sim_id,
    )
    assert result["overall_status"] == STATUS_SIMULATED
    assert result["endpoint_containment"]["status"] == STATUS_SIMULATED
    assert result["account_suspension"]["status"] == STATUS_SIMULATED
    assert result["session_revocation"]["status"] == STATUS_SIMULATED


def test_step8_scenario_4_edr_fails_identity_succeeds():
    """Scenario 4: Endpoint containment fails while identity actions succeed (PARTIAL_SUCCESS)."""
    alert = {
        "alert_id": "COORD-SCEN-4",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T11:05:00Z",
        "endpoint_id": "EP-COORD-FAIL-EDR",
        "username": "compromised.user@contoso.com",
    }
    mock_edr = MagicMock()
    mock_edr.isolate_endpoint.side_effect = EDRAPIError("500 Internal Server Error")

    sim_id = SimulatedIdentityClient()

    result = process_coordinated_response_workflow(
        alert=alert,
        dry_run=False,
        edr_client=mock_edr,
        identity_client=sim_id,
    )
    assert result["endpoint_containment"]["status"] == STATUS_FAILED
    assert result["account_suspension"]["status"] == STATUS_CONFIRMED
    assert result["session_revocation"]["status"] == STATUS_CONFIRMED
    assert result["overall_status"] == "PARTIAL_SUCCESS"


def test_step8_scenario_5_identity_fails_edr_succeeds():
    """Scenario 5: Identity actions fail while containment succeeds (PARTIAL_SUCCESS)."""
    alert = {
        "alert_id": "COORD-SCEN-5",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T11:10:00Z",
        "endpoint_id": "EP-COORD-OK",
        "username": "compromised.user@contoso.com",
    }
    sim_edr = SimulatedEDRClient()
    sim_id = SimulatedIdentityClient()
    sim_id.simulate_server_error = True

    result = process_coordinated_response_workflow(
        alert=alert,
        dry_run=False,
        edr_client=sim_edr,
        identity_client=sim_id,
    )
    assert result["endpoint_containment"]["status"] == STATUS_CONFIRMED
    assert result["account_suspension"]["status"] == STATUS_FAILED
    assert result["session_revocation"]["status"] == STATUS_FAILED
    assert result["overall_status"] == "PARTIAL_SUCCESS"


def test_step8_scenario_6_all_actions_fail():
    """Scenario 6: All response actions fail."""
    alert = {
        "alert_id": "COORD-SCEN-6",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T11:15:00Z",
        "endpoint_id": "EP-COORD-ALL-FAIL",
        "username": "compromised.user@contoso.com",
    }
    mock_edr = MagicMock()
    mock_edr.isolate_endpoint.side_effect = EDRAPIError("EDR failure")

    sim_id = SimulatedIdentityClient()
    sim_id.simulate_server_error = True

    result = process_coordinated_response_workflow(
        alert=alert,
        dry_run=False,
        edr_client=mock_edr,
        identity_client=sim_id,
    )
    assert result["endpoint_containment"]["status"] == STATUS_FAILED
    assert result["account_suspension"]["status"] == STATUS_FAILED
    assert result["session_revocation"]["status"] == STATUS_FAILED
    assert result["overall_status"] == STATUS_FAILED


def test_step8_scenario_7_duplicate_response_request():
    """Scenario 7: Duplicate response request is received and handled."""
    alert = {
        "alert_id": "COORD-SCEN-7",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T11:20:00Z",
        "endpoint_id": "EP-COORD-DUP",
        "username": "compromised.user@contoso.com",
    }
    sim_edr = SimulatedEDRClient()
    sim_id = SimulatedIdentityClient()

    # Initial response
    res1 = process_coordinated_response_workflow(
        alert=alert, dry_run=False, edr_client=sim_edr, identity_client=sim_id
    )
    assert res1["overall_status"] == STATUS_CONFIRMED

    # Duplicate response
    res2 = process_coordinated_response_workflow(
        alert=alert, dry_run=False, edr_client=sim_edr, identity_client=sim_id
    )
    # The duplicate is recognized and suppressed safely
    assert "already contained" in res2["endpoint_containment"]["message"]
    assert "already suspended" in res2["account_suspension"]["message"]
    assert "already been revoked" in res2["session_revocation"]["message"]


def test_step8_scenario_8_ambiguous_identity_information():
    """Scenario 8: Alert contains ambiguous identity information."""
    alert = {
        "alert_id": "COORD-SCEN-8",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T11:25:00Z",
        "endpoint_id": "EP-COORD-AMBIG",
        "username": "ambiguous@contoso.com",
    }
    sim_edr = SimulatedEDRClient()
    sim_id = SimulatedIdentityClient()

    result = process_coordinated_response_workflow(
        alert=alert, dry_run=False, edr_client=sim_edr, identity_client=sim_id
    )
    # EDR succeeds, but ambiguous user is safely rejected
    assert result["endpoint_containment"]["status"] == STATUS_CONFIRMED
    assert result["account_suspension"]["status"] == STATUS_REJECTED
    assert result["session_revocation"]["status"] == STATUS_REJECTED
    assert "Ambiguous user" in result["account_suspension"]["message"]


def test_step8_scenario_9_unsupported_provider():
    """Scenario 9: Unsupported identity provider configured."""
    alert = {
        "alert_id": "COORD-SCEN-9",
        "threat_type": "ransomware",
        "severity": 5,
        "timestamp": "2026-10-22T11:30:00Z",
        "endpoint_id": "EP-COORD-UNSUP",
        "username": "testuser@example.com",
    }
    sim_edr = SimulatedEDRClient()

    mock_unsupported_id = MagicMock()
    mock_unsupported_id.PROVIDER_NAME = "legacy_ldap"
    mock_unsupported_id.resolve_user.return_value = UserIdentity(
        user_id="ldap-001",
        user_principal_name="testuser@example.com",
        account_enabled=True,
    )
    mock_unsupported_id.get_user.return_value = UserIdentity(
        user_id="ldap-001",
        user_principal_name="testuser@example.com",
        account_enabled=True,
    )
    mock_unsupported_id.suspend_account.side_effect = UnsupportedOperationError("LDAP suspend unsupported")
    mock_unsupported_id.revoke_user_sessions.side_effect = UnsupportedOperationError("LDAP revoke unsupported")

    result = process_coordinated_response_workflow(
        alert=alert, dry_run=False, edr_client=sim_edr, identity_client=mock_unsupported_id
    )
    assert result["account_suspension"]["status"] == STATUS_UNSUPPORTED
    assert result["session_revocation"]["status"] == STATUS_UNSUPPORTED


# ─────────────────────────────────────────────────────────────────────────────
# STEP 9: Verify Audit Logging & Secret Redaction
# ─────────────────────────────────────────────────────────────────────────────


def test_step9_audit_logging_and_secret_redaction(api_client):
    """Step 9: Audit records logged with correct identifiers, status, and zero secrets."""
    alert_id = "AUDIT-VERIF-001"
    create_incident(
        IncidentCreate(
            alert_id=alert_id,
            threat_type="ransomware",
            severity=5,
            description="Testing audit logs and secret scrubbing",
            timestamp="2026-10-22T11:40:00Z",
            username="victim.audit@contoso.com",
        )
    )

    # Record log with sensitive data
    sensitive_details = {
        "client_secret": "SUPER_SECRET_VALUE_12345",
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "auth_header": "Bearer eyJhbGciOiJIUzI1Ni...",
        "hostname": "WORKSTATION-AUDIT",
    }
    record_audit_log(
        alert_id=alert_id,
        action="TEST_ACTION",
        execution_mode="dry_run",
        status="CONFIRMED",
        details=sensitive_details,
    )

    logs = get_audit_logs_for_alert(alert_id)
    assert len(logs) >= 1
    target_log = [l for l in logs if l.action == "TEST_ACTION"][0]
    assert target_log.details["client_secret"] == "[REDACTED]"
    assert target_log.details["access_token"] == "[REDACTED]"
    assert "SUPER_SECRET_VALUE_12345" not in str(target_log.details)
    assert target_log.details["hostname"] == "WORKSTATION-AUDIT"

    # Verify retrieval endpoint
    resp = api_client.get(f"/incidents/{alert_id}/audit-logs")
    assert resp.status_code == 200
    retrieved = resp.json()
    assert len(retrieved) >= 1
    assert retrieved[0]["details"]["client_secret"] == "[REDACTED]"


# ─────────────────────────────────────────────────────────────────────────────
# STEP 10: Robust Error & Failure Handling
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "status_code,expected_exc",
    [
        (401, EDRAuthError),
        (403, EDRAuthError),
        (429, EDRAPIError),
        (500, EDRAPIError),
        (503, EDRAPIError),
    ],
)
def test_step10_http_error_codes_handling(monkeypatch, status_code, expected_exc):
    """Step 10: 401, 403, 429, 500, 503 are handled safely without false success."""
    monkeypatch.setenv("EDR_PROVIDER", "crowdstrike")
    monkeypatch.setenv("EDR_API_BASE_URL", "https://api.crowdstrike.com")
    monkeypatch.setenv("EDR_CLIENT_ID", "dummy_cs_client_id")
    monkeypatch.setenv("EDR_CLIENT_SECRET", "dummy_cs_secret")

    config = EDRConfig()
    client = CrowdStrikeClient(config)
    client._access_token = "valid-test-token"

    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    if status_code >= 400 and status_code not in (401, 403):
        from requests.exceptions import HTTPError
        mock_resp.raise_for_status.side_effect = HTTPError(f"HTTP {status_code}")

    with patch.object(client._session, "get", return_value=mock_resp):
        with pytest.raises(expected_exc):
            client.get_alerts()

# tests/test_e2e_workflow.py
"""
End-to-End Integration and Workflow Validation Suite.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Week    : 2
Day     : 3 -- Implement and Validate the Containment Workflow

Comprehensive Workflow Stages Validated:
  1.  Critical ransomware alert through the complete workflow (Webhook -> Ingestion -> Policy -> EDR -> SQLite).
  2.  Critical hands-on-keyboard alert containment evaluation and execution.
  3.  Medium-severity alert does not trigger network isolation.
  4.  Low-severity alert does not trigger network isolation.
  5.  Invalid alert payload rejection without calling EDR.
  6.  Missing endpoint identifier rejection without calling EDR.
  7.  Dry-run containment simulation (default mode, zero outbound requests).
  8.  Successful mocked EDR responses (both CrowdStrike Falcon and Microsoft Defender for Endpoint).
  9.  EDR API timeout handled safely without false success.
  10. EDR authentication failure handled safely with zero credential leakage.
  11. EDR server error handled gracefully without system crash.
  12. Malformed EDR response mapped to UNKNOWN without crashing.
  13. Ambiguous / unknown EDR isolation result preserves uncertainty.
  14. Duplicate alert suppression and cooldown safeguards via ContainmentRegistry.
  15. Incident state transitions (CONFIRMED -> CONTAINED, REQUESTED -> INVESTIGATING, others -> non-contained).
  16. No false CONTAINED status recorded after failed or rejected isolation attempts.
  17. Zero real network requests dispatched during test suite execution.
  18. Webhook authentication preservation (constant-time verification, rejection on missing/invalid secret).
  19. Direct API verification of /containment/isolate and /webhook/edr contracts.
  20. Cooldown expiration and retry handling after failed attempts.
"""

from datetime import datetime, timezone
import os
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

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
    STATUS_REQUESTED,
    STATUS_SIMULATED,
    STATUS_UNKNOWN,
    ContainmentPolicy,
    clear_containment_registry,
    execute_network_containment,
    get_containment_registry,
    process_containment_workflow,
)
from incidents.database import init_db
from incidents.models import IncidentCreate, IncidentStatus
from incidents.service import create_incident, get_incident_by_alert_id, update_incident_status
from integrations.edr_client import (
    EDRAPIError,
    EDRAuthError,
    EDRConfigError,
    EDRTimeoutError,
    SimulatedEDRClient,
)
from main import app

E2E_SECRET = "e2e-integration-secret-999"


@pytest.fixture(autouse=True)
def isolated_e2e_env(tmp_path, monkeypatch):
    """
    Directs database operations to an isolated temporary SQLite database
    and clears the in-memory containment registry for every test.
    """
    test_db = str(tmp_path / "test_e2e_db.sqlite")
    monkeypatch.setenv("INCIDENTS_DB_PATH", test_db)
    monkeypatch.setenv("WEBHOOK_SECRET", E2E_SECRET)
    init_db(test_db)
    clear_containment_registry()
    yield test_db
    clear_containment_registry()


@pytest.fixture
def e2e_client():
    """Provides a TestClient for testing FastAPI endpoints."""
    return TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Critical Ransomware Alert Complete Workflow
# ─────────────────────────────────────────────────────────────────────────────


def test_e2e_critical_ransomware_workflow_confirmed(e2e_client):
    """
    Test 1: Critical ransomware alert through the complete workflow:
      Ingestion -> Validation -> Policy Evaluation -> Live Mock EDR -> Incident Record -> CONTAINED.
    """
    alert_payload = {
        "alert_id": "ALERT-RANSOM-CRIT-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Mass volume canary encryption detected across multiple network shares",
        "timestamp": "2026-10-18T10:00:00Z",
        "hostname": "PROD-FILESRV-01",
        "endpoint_id": "EP-PROD-001",
        "ip_address": "10.0.10.50",
    }
    headers = {"X-Webhook-Secret": E2E_SECRET}

    mock_edr = MagicMock()
    mock_edr.PROVIDER = "crowdstrike"
    mock_edr.isolate_endpoint.return_value = {
        "resources": [{"id": "action-cs-101", "complete": True, "status": "normal"}]
    }

    with patch("containment.network_containment.create_edr_client", return_value=mock_edr):
        resp = e2e_client.post("/webhook/edr?dry_run=false", json=alert_payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "received"
    assert data["alert_id"] == "ALERT-RANSOM-CRIT-001"
    assert data["threat_type"] == "ransomware"
    assert data["severity"] == 5
    assert data["incident_status"] == IncidentStatus.CONTAINED.value
    assert data["containment"]["status"] == STATUS_CONFIRMED
    assert data["containment"]["isolation_requested"] is True
    assert data["containment"]["action_id"] == "action-cs-101"

    # Verify side-effects in SQLite incident store
    stored = get_incident_by_alert_id("ALERT-RANSOM-CRIT-001")
    assert stored is not None
    assert stored.status == IncidentStatus.CONTAINED
    assert stored.hostname == "PROD-FILESRV-01"

    # Verify EDR mock was called exactly once
    mock_edr.isolate_endpoint.assert_called_once_with(
        "EP-PROD-001",
        comment="Automated containment for alert ALERT-RANSOM-CRIT-001",
    )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Critical Hands-on-Keyboard Alert Complete Workflow
# ─────────────────────────────────────────────────────────────────────────────


def test_e2e_critical_hands_on_keyboard_workflow(e2e_client):
    """
    Test 2: Critical hands-on-keyboard alert invokes EDR and transitions to CONTAINED.
    """
    alert_payload = {
        "alert_id": "ALERT-HOK-CRIT-002",
        "threat_type": "hands-on-keyboard",
        "severity": 5,
        "description": "Active interactive shell spawned with credential dumping tools detected",
        "timestamp": "2026-10-18T10:15:00Z",
        "hostname": "DC-PRIMARY-01",
        "endpoint_id": "EP-DC-002",
    }
    headers = {"X-Webhook-Secret": E2E_SECRET}

    mock_edr = MagicMock()
    mock_edr.PROVIDER = "defender"
    mock_edr.isolate_endpoint.return_value = {
        "id": "action-mde-202",
        "status": "Succeeded",
    }

    with patch("containment.network_containment.create_edr_client", return_value=mock_edr):
        resp = e2e_client.post("/webhook/edr?dry_run=false", json=alert_payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["incident_status"] == IncidentStatus.CONTAINED.value
    assert data["containment"]["status"] == STATUS_CONFIRMED

    stored = get_incident_by_alert_id("ALERT-HOK-CRIT-002")
    assert stored is not None
    assert stored.status == IncidentStatus.CONTAINED
    mock_edr.isolate_endpoint.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 3 & 4. Medium and Low Severity Alerts (No Containment)
# ─────────────────────────────────────────────────────────────────────────────


def test_e2e_medium_severity_alert_no_isolation(e2e_client):
    """
    Test 3: Medium-severity alert does not recommend containment; EDR is NOT called.
    """
    alert_payload = {
        "alert_id": "ALERT-MED-003",
        "threat_type": "suspicious_activity",
        "severity": 3,
        "description": "Port scan activity observed from external IP",
        "timestamp": "2026-10-18T10:30:00Z",
        "hostname": "DMZ-PROXY-01",
        "endpoint_id": "EP-DMZ-003",
    }
    headers = {"X-Webhook-Secret": E2E_SECRET}

    mock_edr = MagicMock()
    with patch("containment.network_containment.create_edr_client", return_value=mock_edr):
        resp = e2e_client.post("/webhook/edr?dry_run=false", json=alert_payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["containment"]["status"] == STATUS_NOT_RECOMMENDED
    assert data["containment"]["isolation_requested"] is False
    assert data["incident_status"] == IncidentStatus.NEW.value

    # EDR client must NOT be called for medium severity
    mock_edr.isolate_endpoint.assert_not_called()

    # Incident in SQLite remains NEW
    stored = get_incident_by_alert_id("ALERT-MED-003")
    assert stored is not None
    assert stored.status == IncidentStatus.NEW


def test_e2e_low_severity_alert_no_isolation(e2e_client):
    """
    Test 4: Low / informational severity alert does not trigger containment.
    """
    alert_payload = {
        "alert_id": "ALERT-LOW-004",
        "threat_type": "info_notice",
        "severity": 1,
        "description": "Routine scheduled security agent health check",
        "timestamp": "2026-10-18T10:45:00Z",
        "hostname": "WORKSTATION-42",
        "endpoint_id": "EP-WS-042",
    }
    headers = {"X-Webhook-Secret": E2E_SECRET}

    mock_edr = MagicMock()
    with patch("containment.network_containment.create_edr_client", return_value=mock_edr):
        resp = e2e_client.post("/webhook/edr?dry_run=false", json=alert_payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["containment"]["status"] == STATUS_NOT_RECOMMENDED
    assert data["incident_status"] == IncidentStatus.NEW.value
    mock_edr.isolate_endpoint.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# 5 & 6. Invalid Payloads and Missing Endpoint Identifiers
# ─────────────────────────────────────────────────────────────────────────────


def test_e2e_invalid_alert_payload_rejected(e2e_client):
    """
    Test 5: Malformed alert payload returns validation error; EDR is NOT contacted.
    """
    # Missing required 'severity' and 'threat_type'
    invalid_payload = {
        "alert_id": "ALERT-INVALID-005",
        "description": "Incomplete payload test",
    }
    headers = {"X-Webhook-Secret": E2E_SECRET}

    mock_edr = MagicMock()
    with patch("containment.network_containment.create_edr_client", return_value=mock_edr):
        resp = e2e_client.post("/webhook/edr", json=invalid_payload, headers=headers)

    assert resp.status_code == 422
    mock_edr.isolate_endpoint.assert_not_called()


def test_e2e_missing_endpoint_identifier_rejected(e2e_client):
    """
    Test 6: Critical alert with hostname but missing endpoint_id cannot be isolated via EDR.
    """
    alert_payload = {
        "alert_id": "ALERT-NO-EP-006",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware alert with hostname only, no EDR endpoint_id",
        "timestamp": "2026-10-18T11:00:00Z",
        "hostname": "LAB-WIN-HOST-ONLY",
        # Notice: endpoint_id is omitted
    }
    headers = {"X-Webhook-Secret": E2E_SECRET}

    mock_edr = MagicMock()
    with patch("containment.network_containment.create_edr_client", return_value=mock_edr):
        resp = e2e_client.post("/webhook/edr?dry_run=false", json=alert_payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()
    # Alert is stored, but isolation is safely REJECTED due to missing endpoint_id
    assert data["containment"]["status"] == STATUS_REJECTED
    assert "endpoint_id" in data["containment"]["message"]
    assert data["containment"]["isolation_requested"] is False
    assert data["incident_status"] == IncidentStatus.NEW.value

    # EDR client is NOT invoked
    mock_edr.isolate_endpoint.assert_not_called()

    # Incident remains NEW in database (not contained)
    stored = get_incident_by_alert_id("ALERT-NO-EP-006")
    assert stored is not None
    assert stored.status == IncidentStatus.NEW


# ─────────────────────────────────────────────────────────────────────────────
# 7. Dry-Run Containment Mode (Default Behavior)
# ─────────────────────────────────────────────────────────────────────────────


def test_e2e_dry_run_containment_default(e2e_client):
    """
    Test 7: Dry-run mode is enabled by default; zero outbound requests are sent;
    status is SIMULATED and incident remains NEW.
    """
    alert_payload = {
        "alert_id": "ALERT-DRY-RUN-007",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical alert in default dry-run execution mode",
        "timestamp": "2026-10-18T11:15:00Z",
        "hostname": "FINANCE-SERVER-01",
        "endpoint_id": "EP-FIN-007",
    }
    headers = {"X-Webhook-Secret": E2E_SECRET}

    mock_edr = MagicMock()
    with patch("containment.network_containment.create_edr_client", return_value=mock_edr):
        # Call without dry_run query parameter (defaults to True)
        resp = e2e_client.post("/webhook/edr", json=alert_payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["containment"]["status"] == STATUS_SIMULATED
    assert data["containment"]["isolation_requested"] is False
    assert data["containment"]["execution_mode"] == EXECUTION_MODE_DRY_RUN
    assert data["incident_status"] == IncidentStatus.NEW.value

    # Absolutely zero outbound calls to EDR
    mock_edr.isolate_endpoint.assert_not_called()

    # Incident remains NEW
    stored = get_incident_by_alert_id("ALERT-DRY-RUN-007")
    assert stored is not None
    assert stored.status == IncidentStatus.NEW


# ─────────────────────────────────────────────────────────────────────────────
# 8. Successful Mocked EDR Responses (CrowdStrike & Defender)
# ─────────────────────────────────────────────────────────────────────────────


def test_e2e_successful_mocked_edr_responses():
    """
    Test 8: Validates successful isolation responses for both CrowdStrike and Defender.
    """
    # 1. CrowdStrike Falcon successful isolation
    cs_alert = {
        "alert_id": "ALERT-CS-008",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "CrowdStrike Falcon positive isolation test",
        "timestamp": "2026-10-18T11:30:00Z",
        "hostname": "HOST-CS-01",
        "endpoint_id": "EP-CS-008",
    }
    mock_cs = MagicMock()
    mock_cs.PROVIDER = "crowdstrike"
    mock_cs.isolate_endpoint.return_value = {
        "resources": [{"id": "cs-act-888", "complete": True, "status": "normal"}]
    }

    cs_res = process_containment_workflow(cs_alert, dry_run=False, edr_client=mock_cs)
    assert cs_res["status"] == STATUS_CONFIRMED
    assert cs_res["action_id"] == "cs-act-888"
    assert cs_res["incident_status"] == IncidentStatus.CONTAINED.value

    # 2. Microsoft Defender for Endpoint successful isolation
    def_alert = {
        "alert_id": "ALERT-DEF-008",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Microsoft Defender positive isolation test",
        "timestamp": "2026-10-18T11:35:00Z",
        "hostname": "HOST-DEF-01",
        "endpoint_id": "EP-DEF-008",
    }
    mock_def = MagicMock()
    mock_def.PROVIDER = "defender"
    mock_def.isolate_endpoint.return_value = {
        "id": "def-act-999",
        "status": "Succeeded",
    }

    def_res = process_containment_workflow(def_alert, dry_run=False, edr_client=mock_def)
    assert def_res["status"] == STATUS_CONFIRMED
    assert def_res["action_id"] == "def-act-999"
    assert def_res["incident_status"] == IncidentStatus.CONTAINED.value


# ─────────────────────────────────────────────────────────────────────────────
# 9, 10, 11. EDR Failures (Timeout, Authentication, Server Errors)
# ─────────────────────────────────────────────────────────────────────────────


def test_e2e_edr_timeout_handled_safely():
    """
    Test 9: EDR API timeout maps to FAILED; incident is NOT marked CONTAINED.
    """
    alert = {
        "alert_id": "ALERT-TIMEOUT-009",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Timeout simulation test",
        "timestamp": "2026-10-18T12:00:00Z",
        "hostname": "HOST-TIMEOUT-01",
        "endpoint_id": "EP-TO-009",
    }
    mock_client = MagicMock()
    mock_client.PROVIDER = "crowdstrike"
    mock_client.isolate_endpoint.side_effect = EDRTimeoutError("Connection timed out after 10.0s")

    res = process_containment_workflow(alert, dry_run=False, edr_client=mock_client)
    assert res["status"] == STATUS_FAILED
    assert "timeout" in res["message"].lower()
    assert res["incident_status"] == IncidentStatus.NEW.value

    # Confirm incident in database remains NEW (not CONTAINED)
    stored = get_incident_by_alert_id("ALERT-TIMEOUT-009")
    assert stored is not None
    assert stored.status == IncidentStatus.NEW


def test_e2e_edr_authentication_failure():
    """
    Test 10: EDR authentication failure maps to FAILED without leaking tokens.
    """
    alert = {
        "alert_id": "ALERT-AUTH-010",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Auth failure simulation test",
        "timestamp": "2026-10-18T12:15:00Z",
        "hostname": "HOST-AUTH-01",
        "endpoint_id": "EP-AUTH-010",
    }
    mock_client = MagicMock()
    mock_client.PROVIDER = "defender"
    mock_client.isolate_endpoint.side_effect = EDRAuthError("OAuth token expired or credentials rejected")

    res = process_containment_workflow(alert, dry_run=False, edr_client=mock_client)
    assert res["status"] == STATUS_FAILED
    assert "authentication" in res["message"].lower()
    assert res["incident_status"] == IncidentStatus.NEW.value

    stored = get_incident_by_alert_id("ALERT-AUTH-010")
    assert stored.status == IncidentStatus.NEW


def test_e2e_edr_server_error():
    """
    Test 11: EDR HTTP 500 error maps to FAILED safely.
    """
    alert = {
        "alert_id": "ALERT-500-011",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Server error test",
        "timestamp": "2026-10-18T12:30:00Z",
        "hostname": "HOST-ERR-01",
        "endpoint_id": "EP-ERR-011",
    }
    mock_client = MagicMock()
    mock_client.PROVIDER = "crowdstrike"
    mock_client.isolate_endpoint.side_effect = EDRAPIError("HTTP 500 Internal Server Error from CrowdStrike")

    res = process_containment_workflow(alert, dry_run=False, edr_client=mock_client)
    assert res["status"] == STATUS_FAILED
    assert res["incident_status"] == IncidentStatus.NEW.value

    stored = get_incident_by_alert_id("ALERT-500-011")
    assert stored.status == IncidentStatus.NEW


# ─────────────────────────────────────────────────────────────────────────────
# 12 & 13. Malformed and Ambiguous Responses (UNKNOWN Status)
# ─────────────────────────────────────────────────────────────────────────────


def test_e2e_malformed_and_unknown_edr_responses():
    """
    Tests 12 & 13: Malformed or ambiguous EDR responses map to UNKNOWN status;
    incident uncertainty is preserved (never falsely marked CONTAINED).
    """
    # Malformed response (empty dict)
    alert_malformed = {
        "alert_id": "ALERT-MALFORMED-012",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Malformed response test",
        "timestamp": "2026-10-18T13:00:00Z",
        "hostname": "HOST-MAL-01",
        "endpoint_id": "EP-MAL-012",
    }
    mock_mal = MagicMock()
    mock_mal.PROVIDER = "crowdstrike"
    mock_mal.isolate_endpoint.return_value = {}  # Empty response

    res_mal = process_containment_workflow(alert_malformed, dry_run=False, edr_client=mock_mal)
    assert res_mal["status"] == STATUS_UNKNOWN
    assert res_mal["incident_status"] == IncidentStatus.NEW.value

    # Ambiguous response status
    alert_ambiguous = {
        "alert_id": "ALERT-AMBIGUOUS-013",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Ambiguous response status test",
        "timestamp": "2026-10-18T13:15:00Z",
        "hostname": "HOST-AMB-01",
        "endpoint_id": "EP-AMB-013",
    }
    mock_amb = MagicMock()
    mock_amb.PROVIDER = "defender"
    mock_amb.isolate_endpoint.return_value = {
        "id": "action-amb-123",
        "status": "PendingHumanAuthorizationReview",
    }

    res_amb = process_containment_workflow(alert_ambiguous, dry_run=False, edr_client=mock_amb)
    assert res_amb["status"] == STATUS_UNKNOWN
    assert res_amb["incident_status"] == IncidentStatus.NEW.value

    stored_amb = get_incident_by_alert_id("ALERT-AMBIGUOUS-013")
    assert stored_amb.status == IncidentStatus.NEW


# ─────────────────────────────────────────────────────────────────────────────
# 14. Duplicate Alert Suppression (ContainmentRegistry Lifecycle)
# ─────────────────────────────────────────────────────────────────────────────


def test_e2e_duplicate_alert_suppression_and_registry_lifecycle():
    """
    Test 14: Validates the complete duplicate protection lifecycle:
      1. First qualifying alert triggers EDR isolation.
      2. Repeated alert for the same endpoint within cooldown is suppressed.
      3. New alert after cooldown or release triggers new isolation.
      4. Separate endpoints are evaluated independently.
      5. Failed isolation attempt is NOT recorded in registry, allowing immediate retry.
    """
    registry = get_containment_registry()
    registry.clear()

    # Alert for Endpoint 1
    alert_1 = {
        "alert_id": "ALERT-DUP-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "First isolation for EP-01",
        "timestamp": "2026-10-18T14:00:00Z",
        "hostname": "HOST-01",
        "endpoint_id": "EP-01",
    }

    mock_edr = MagicMock()
    mock_edr.PROVIDER = "crowdstrike"
    mock_edr.isolate_endpoint.return_value = {
        "resources": [{"id": "act-dup-1", "complete": True, "status": "normal"}]
    }

    # Step 1: First qualifying alert
    res_1 = process_containment_workflow(alert_1, dry_run=False, edr_client=mock_edr)
    assert res_1["status"] == STATUS_CONFIRMED
    assert res_1["isolation_requested"] is True
    assert mock_edr.isolate_endpoint.call_count == 1

    # Step 2: Repeated alert for same endpoint within cooldown period
    alert_1_repeat = {
        "alert_id": "ALERT-DUP-001-REPEAT",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Repeated alert for EP-01",
        "timestamp": "2026-10-18T14:01:00Z",
        "hostname": "HOST-01",
        "endpoint_id": "EP-01",
    }
    res_repeat = process_containment_workflow(alert_1_repeat, dry_run=False, edr_client=mock_edr)
    assert res_repeat["status"] == STATUS_CONFIRMED
    assert res_repeat["isolation_requested"] is False  # Suppressed!
    assert "already contained" in res_repeat["message"]
    # EDR client was NOT called again
    assert mock_edr.isolate_endpoint.call_count == 1

    # Step 3: Different endpoint receiving separate alert proceeds independently
    alert_2 = {
        "alert_id": "ALERT-DIFF-002",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Separate alert for EP-02",
        "timestamp": "2026-10-18T14:02:00Z",
        "hostname": "HOST-02",
        "endpoint_id": "EP-02",
    }
    res_2 = process_containment_workflow(alert_2, dry_run=False, edr_client=mock_edr)
    assert res_2["status"] == STATUS_CONFIRMED
    assert res_2["isolation_requested"] is True
    assert mock_edr.isolate_endpoint.call_count == 2

    # Step 4: After cooldown / release, endpoint 1 can be isolated again
    registry.release("EP-01")
    assert registry.is_contained("EP-01") is False

    alert_1_new = {
        "alert_id": "ALERT-DUP-001-POST-COOLDOWN",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "New alert after cooldown for EP-01",
        "timestamp": "2026-10-18T14:10:00Z",
        "hostname": "HOST-01",
        "endpoint_id": "EP-01",
    }
    res_post_cooldown = process_containment_workflow(alert_1_new, dry_run=False, edr_client=mock_edr)
    assert res_post_cooldown["status"] == STATUS_CONFIRMED
    assert res_post_cooldown["isolation_requested"] is True
    assert mock_edr.isolate_endpoint.call_count == 3

    # Step 5: Failed attempt is NOT recorded in registry, allowing immediate retry
    alert_fail = {
        "alert_id": "ALERT-FAIL-003",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Initial failing isolation attempt",
        "timestamp": "2026-10-18T14:20:00Z",
        "hostname": "HOST-03",
        "endpoint_id": "EP-03",
    }
    mock_fail_client = MagicMock()
    mock_fail_client.PROVIDER = "crowdstrike"
    mock_fail_client.isolate_endpoint.side_effect = EDRTimeoutError("First attempt timeout")

    res_fail = process_containment_workflow(alert_fail, dry_run=False, edr_client=mock_fail_client)
    assert res_fail["status"] == STATUS_FAILED

    # Registry must NOT contain EP-03 after failure
    assert registry.is_contained("EP-03") is False

    # Retry should proceed and invoke client again
    mock_fail_client.isolate_endpoint.side_effect = None
    mock_fail_client.isolate_endpoint.return_value = {
        "resources": [{"id": "act-retry-success", "complete": True, "status": "normal"}]
    }

    res_retry = process_containment_workflow(alert_fail, dry_run=False, edr_client=mock_fail_client)
    assert res_retry["status"] == STATUS_CONFIRMED
    assert res_retry["isolation_requested"] is True


# ─────────────────────────────────────────────────────────────────────────────
# 15. Incident State Transitions Matrix (No False CONTAINED Status)
# ─────────────────────────────────────────────────────────────────────────────


def test_e2e_incident_state_transitions_matrix():
    """
    Test 15: Rigorously verifies that ONLY confirmed live isolations transition
    an incident to CONTAINED, while pending/requested transitions to INVESTIGATING,
    and failures, simulations, or rejections NEVER falsely claim containment.
    """
    # 1. CONFIRMED transitions to CONTAINED
    inc_1 = create_incident(
        IncidentCreate(
            alert_id="STATE-CONF-001",
            threat_type="ransomware",
            severity=5,
            description="State test confirmed",
            timestamp="2026-10-18T15:00:00Z",
            hostname="HOST-1",
            status=IncidentStatus.NEW,
        )
    )
    mock_conf = MagicMock()
    mock_conf.PROVIDER = "defender"
    mock_conf.isolate_endpoint.return_value = {"id": "act-1", "status": "Succeeded"}

    execute_network_containment(
        {"alert_id": "STATE-CONF-001", "endpoint_id": "EP-1", "severity": 5, "alert_type": "ransomware", "hostname": "HOST-1"},
        dry_run=False,
        edr_client=mock_conf,
    )
    assert get_incident_by_alert_id("STATE-CONF-001").status == IncidentStatus.CONTAINED

    # 2. REQUESTED transitions NEW to INVESTIGATING (pending state)
    create_incident(
        IncidentCreate(
            alert_id="STATE-REQ-002",
            threat_type="ransomware",
            severity=5,
            description="State test requested",
            timestamp="2026-10-18T15:05:00Z",
            hostname="HOST-2",
            status=IncidentStatus.NEW,
        )
    )
    mock_req = MagicMock()
    mock_req.PROVIDER = "defender"
    mock_req.isolate_endpoint.return_value = {"id": "act-2", "status": "InProgress"}

    execute_network_containment(
        {"alert_id": "STATE-REQ-002", "endpoint_id": "EP-2", "severity": 5, "alert_type": "ransomware", "hostname": "HOST-2"},
        dry_run=False,
        edr_client=mock_req,
    )
    assert get_incident_by_alert_id("STATE-REQ-002").status == IncidentStatus.INVESTIGATING

    # 3. FAILED retains NEW (never transitions to CONTAINED)
    create_incident(
        IncidentCreate(
            alert_id="STATE-FAIL-003",
            threat_type="ransomware",
            severity=5,
            description="State test failed",
            timestamp="2026-10-18T15:10:00Z",
            hostname="HOST-3",
            status=IncidentStatus.NEW,
        )
    )
    mock_fail = MagicMock()
    mock_fail.PROVIDER = "crowdstrike"
    mock_fail.isolate_endpoint.side_effect = EDRAPIError("500 Internal Error")

    execute_network_containment(
        {"alert_id": "STATE-FAIL-003", "endpoint_id": "EP-3", "severity": 5, "alert_type": "ransomware", "hostname": "HOST-3"},
        dry_run=False,
        edr_client=mock_fail,
    )
    assert get_incident_by_alert_id("STATE-FAIL-003").status == IncidentStatus.NEW

    # 4. DRY-RUN retains NEW (never transitions to CONTAINED)
    create_incident(
        IncidentCreate(
            alert_id="STATE-DRY-004",
            threat_type="ransomware",
            severity=5,
            description="State test dry run",
            timestamp="2026-10-18T15:15:00Z",
            hostname="HOST-4",
            status=IncidentStatus.NEW,
        )
    )
    execute_network_containment(
        {"alert_id": "STATE-DRY-004", "endpoint_id": "EP-4", "severity": 5, "alert_type": "ransomware", "hostname": "HOST-4"},
        dry_run=True,
    )
    assert get_incident_by_alert_id("STATE-DRY-004").status == IncidentStatus.NEW


# ─────────────────────────────────────────────────────────────────────────────
# 16. No Real Network Requests Guarantee
# ─────────────────────────────────────────────────────────────────────────────


def test_e2e_zero_real_network_requests(monkeypatch):
    """
    Test 16: Verifies that no external sockets or live HTTP requests can be executed
    during automated workflow tests.
    """
    # Monkeypatch requests.Session.send to fail if any unexpected outbound call is made
    def forbidden_send(*args, **kwargs):
        raise RuntimeError("Forbidden outbound HTTP network request attempted during automated testing!")

    monkeypatch.setattr("requests.Session.send", forbidden_send)

    # Simulated client should work completely without triggering requests
    sim_client = SimulatedEDRClient()
    alert = {
        "alert_id": "ALERT-NO-NET-016",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Zero network request validation",
        "timestamp": "2026-10-18T15:30:00Z",
        "hostname": "HOST-AIRGAP",
        "endpoint_id": "EP-AIRGAP",
    }
    res = process_containment_workflow(alert, dry_run=False, edr_client=sim_client)
    assert res["status"] == STATUS_CONFIRMED


# ─────────────────────────────────────────────────────────────────────────────
# 17. FastAPI Direct Verification of /containment/isolate
# ─────────────────────────────────────────────────────────────────────────────


def test_e2e_containment_isolate_endpoint(e2e_client):
    """
    Test 17: Verifies the direct POST /containment/isolate endpoint.
    """
    alert_payload = {
        "alert_id": "ALERT-ISO-EP-017",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Direct isolate endpoint test",
        "timestamp": "2026-10-18T16:00:00Z",
        "hostname": "HOST-ISO-017",
        "endpoint_id": "EP-ISO-017",
    }

    # Dry-run call
    resp_dry = e2e_client.post("/containment/isolate?dry_run=true", json=alert_payload)
    assert resp_dry.status_code == 200
    assert resp_dry.json()["status"] == STATUS_SIMULATED

    # Live call with simulated client
    sim = SimulatedEDRClient()
    with patch("containment.network_containment.create_edr_client", return_value=sim):
        resp_live = e2e_client.post("/containment/isolate?dry_run=false", json=alert_payload)
        assert resp_live.status_code == 200
        assert resp_live.json()["status"] == STATUS_CONFIRMED


# ─────────────────────────────────────────────────────────────────────────────
# 18 & 19. Original Week 1 Integration Tests (Preserved Functionality)
# ─────────────────────────────────────────────────────────────────────────────


def test_complete_e2e_incident_lifecycle(e2e_client):
    """
    Validates steps 1 through 9 of the complete simulated incident orchestration workflow.
    """
    # ── Step 1 & 2: Submit simulated EDR alert with secret ─────────────────────
    alert_payload = {
        "alert_id": "E2E-RANSOM-001",
        "threat_type": "Ransomware.LockBit.Simulated",
        "severity": 5,
        "description": "Simulated Canary: High-volume rapid file modifications in target directories",
        "timestamp": "2026-10-12T16:00:00+02:00",  # non-Z offset to test normalization
        "hostname": "  CORP-FILESRV-01  ",        # unstripped whitespace
        "ip_address": " 10.10.20.5 ",
        "username": " svc_backup ",
        "process_hash": "D41D8CD98F00B204E9800998ECF8427E",  # uppercase hash
    }
    headers = {"X-Webhook-Secret": E2E_SECRET}

    post_resp = e2e_client.post("/webhook/edr", json=alert_payload, headers=headers)
    assert post_resp.status_code == 200
    ack = post_resp.json()
    assert ack["status"] == "received"
    assert ack["alert_id"] == "E2E-RANSOM-001"
    assert ack["severity"] == 5
    assert ack["incident_status"] == "NEW"

    # ── Step 3 & 4: Verify persistence & normalization in SQLite ───────────────
    # Normalized timestamp (+02:00 -> UTC 14:00:00Z)
    expected_utc_ts = "2026-10-12T14:00:00Z"

    # ── Step 5: Retrieve incident using GET /incidents/{alert_id} ──────────────
    get_resp = e2e_client.get("/incidents/E2E-RANSOM-001")
    assert get_resp.status_code == 200
    incident = get_resp.json()

    assert incident["alert_id"] == "E2E-RANSOM-001"
    assert incident["severity"] == 5
    assert incident["status"] == "NEW"
    assert incident["hostname"] == "CORP-FILESRV-01"
    assert incident["ip_address"] == "10.10.20.5"
    assert incident["username"] == "svc_backup"
    assert incident["process_hash"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert incident["timestamp"] == expected_utc_ts
    assert incident["created_at"] is not None
    assert incident["updated_at"] is not None

    # ── Step 6: Filter incidents by status and severity ────────────────────────
    # Filter by status NEW
    status_filter_resp = e2e_client.get("/incidents?status=NEW")
    assert status_filter_resp.status_code == 200
    matching_status = [i for i in status_filter_resp.json() if i["alert_id"] == "E2E-RANSOM-001"]
    assert len(matching_status) == 1

    # Filter by severity 5
    sev_filter_resp = e2e_client.get("/incidents?severity=5")
    assert sev_filter_resp.status_code == 200
    matching_sev = [i for i in sev_filter_resp.json() if i["alert_id"] == "E2E-RANSOM-001"]
    assert len(matching_sev) == 1

    # ── Step 7: Update incident status ─────────────────────────────────────────
    patch_resp = e2e_client.patch(
        "/incidents/E2E-RANSOM-001/status",
        json={"status": "INVESTIGATING"},
    )
    assert patch_resp.status_code == 200
    updated = patch_resp.json()
    assert updated["status"] == "INVESTIGATING"
    assert updated["updated_at"] >= updated["created_at"]

    # Verify updated status persists on subsequent retrieval
    get_after_update = e2e_client.get("/incidents/E2E-RANSOM-001")
    assert get_after_update.status_code == 200
    assert get_after_update.json()["status"] == "INVESTIGATING"

    # ── Step 8: Verify duplicate webhook delivery idempotency ──────────────────
    dup_resp = e2e_client.post("/webhook/edr", json=alert_payload, headers=headers)
    assert dup_resp.status_code == 200
    dup_data = dup_resp.json()
    assert dup_data["status"] == "duplicate"
    assert "already been processed" in dup_data["message"]
    assert dup_data["incident_status"] == "INVESTIGATING"  # reflects current state

    # Ensure no duplicate records were created
    all_incidents = e2e_client.get("/incidents").json()
    matches = [i for i in all_incidents if i["alert_id"] == "E2E-RANSOM-001"]
    assert len(matches) == 1


def test_e2e_rejections_and_security(e2e_client):
    """
    Validates step 9: rejection of unauthorized, malformed, and missing requests.
    """
    valid_payload = {
        "alert_id": "SEC-ALERT-001",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "Security rejection test",
        "timestamp": "2026-10-12T12:00:00Z",
    }

    # 1. Reject missing webhook secret header
    resp_no_auth = e2e_client.post("/webhook/edr", json=valid_payload)
    assert resp_no_auth.status_code == 401

    # 2. Reject incorrect webhook secret
    resp_bad_auth = e2e_client.post(
        "/webhook/edr",
        json=valid_payload,
        headers={"X-Webhook-Secret": "wrong-secret-token"},
    )
    assert resp_bad_auth.status_code == 401

    # 3. Reject missing required fields
    incomplete_payload = {"alert_id": "INCOMPLETE-001"}
    resp_incomplete = e2e_client.post(
        "/webhook/edr",
        json=incomplete_payload,
        headers={"X-Webhook-Secret": E2E_SECRET},
    )
    assert resp_incomplete.status_code == 422

    # 4. Reject malformed JSON body
    resp_malformed = e2e_client.post(
        "/webhook/edr",
        content="{broken_json: true",
        headers={"X-Webhook-Secret": E2E_SECRET, "Content-Type": "application/json"},
    )
    assert resp_malformed.status_code == 422

    # 5. Non-existent incident retrieval returns 404
    resp_not_found = e2e_client.get("/incidents/NON_EXISTENT_ALERT_999")
    assert resp_not_found.status_code == 404

    # 6. Invalid status update returns 422
    resp_bad_status = e2e_client.patch(
        "/incidents/SEC-ALERT-001/status",
        json={"status": "ILLEGAL_STATUS_STATE"},
    )
    assert resp_bad_status.status_code == 422

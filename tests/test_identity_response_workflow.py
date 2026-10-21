# tests/test_identity_response_workflow.py
"""
End-to-End Workflow and Coordinated Response Tests (Week 2 Day 5)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Day     : 5 -- Session Revocation and Coordinated Incident Response

Validates:
  32. Duplicate-request protection (idempotency & cooldown).
  33. Partial incident-response success handling.
  34. EDR failure with successful identity action.
  35. Identity-action failure with successful EDR containment.
  36. Zero false success reported after API failure.
  37. Zero secrets appear in logs or audit trail.
  38. Correct incident audit records stored in SQLite database.
  39. Zero real identity-provider requests dispatched during test suite execution.
  40. Complete coordination across EDR containment, IdP suspension, and session revocation.
"""

import json
import logging
import os
import re
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from containment.identity_response import (
    IdentityActionRegistry,
    IdentityResponsePolicy,
    clear_identity_registry,
    execute_account_suspension,
    execute_session_revocation,
    get_identity_registry,
    process_coordinated_response_workflow,
)
from containment.network_containment import (
    STATUS_CONFIRMED,
    STATUS_FAILED,
    STATUS_SIMULATED,
    STATUS_UNKNOWN,
    clear_containment_registry,
)
from incidents.database import init_db
from incidents.models import IncidentCreate, IncidentStatus
from incidents.service import (
    create_incident,
    get_audit_logs_for_alert,
    get_incident_by_alert_id,
    record_audit_log,
)
from integrations.edr_client import SimulatedEDRClient
from integrations.identity_client import (
    ACTION_REVOKE_SESSIONS,
    ACTION_SUSPEND_ACCOUNT,
    SimulatedIdentityClient,
)
from main import app

TEST_WEBHOOK_SECRET = "coordinated-test-secret-456"


@pytest.fixture(autouse=True)
def isolated_workflow_test_env(tmp_path, monkeypatch):
    """Directs all database operations to an isolated temporary SQLite database."""
    test_db = str(tmp_path / "test_coord_workflow.db")
    monkeypatch.setenv("INCIDENTS_DB_PATH", test_db)
    monkeypatch.setenv("WEBHOOK_SECRET", TEST_WEBHOOK_SECRET)
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
def workflow_client():
    return TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# 32. Duplicate-request protection
# ─────────────────────────────────────────────────────────────────────────────
def test_duplicate_request_protection():
    """Test 32: Duplicate account suspension and session revocation requests are suppressed within cooldown."""
    id_client = SimulatedIdentityClient()
    alert = {
        "alert_id": "ALERT-DUP-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware detected",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-DUP-01",
        "username": "victim@contoso.com",
    }

    # First execution succeeds
    res_1 = execute_account_suspension(alert, identity_client=id_client, dry_run=False)
    assert res_1["status"] == STATUS_CONFIRMED

    # Second immediate execution is suppressed as duplicate
    res_2 = execute_account_suspension(alert, identity_client=id_client, dry_run=False)
    assert res_2["status"] == STATUS_CONFIRMED
    assert "duplicate request suppressed" in res_2["message"]

    # Session revocation duplicate suppression
    res_rev1 = execute_session_revocation(alert, identity_client=id_client, dry_run=False)
    assert res_rev1["status"] == STATUS_CONFIRMED

    res_rev2 = execute_session_revocation(alert, identity_client=id_client, dry_run=False)
    assert res_rev2["status"] == STATUS_CONFIRMED
    assert "duplicate request suppressed" in res_rev2["message"]


# ─────────────────────────────────────────────────────────────────────────────
# 33. Partial incident-response success
# ─────────────────────────────────────────────────────────────────────────────
def test_partial_incident_response_success():
    """
    Test 33: Partial success scenario:
      - EDR endpoint isolation CONFIRMED
      - IdP account suspension CONFIRMED
      - IdP session revocation FAILS
      Outcome: overall_status is PARTIAL_SUCCESS; individual outcomes preserved.
    """
    edr_mock = SimulatedEDRClient()
    id_mock = SimulatedIdentityClient()

    # Hook session revocation to fail
    def fail_revocation(user_id):
        raise IdentityAPIError("Simulated session revocation downstream provider failure.")

    id_mock.revoke_user_sessions = fail_revocation

    alert = {
        "alert_id": "ALERT-PARTIAL-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Ransomware detection on Finance workstation",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-FIN-01",
        "username": "victim@contoso.com",
    }

    res = process_coordinated_response_workflow(
        alert=alert,
        dry_run=False,
        edr_client=edr_mock,
        identity_client=id_mock,
    )

    assert res["endpoint_containment"]["status"] == STATUS_CONFIRMED
    assert res["account_suspension"]["status"] == STATUS_CONFIRMED
    assert res["session_revocation"]["status"] == STATUS_FAILED
    assert res["overall_status"] == "PARTIAL_SUCCESS"
    assert "partial success" in res["message"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# 34. EDR failure with successful identity action
# ─────────────────────────────────────────────────────────────────────────────
def test_edr_failure_with_successful_identity_action():
    """
    Test 34: EDR isolation fails, but IdP account suspension and session revocation succeed.
    Verifies that identity action succeeds and incident is NOT marked falsely CONTAINED.
    """
    edr_mock = SimulatedEDRClient()
    edr_mock.isolate_endpoint = MagicMock(side_effect=Exception("Simulated EDR network connectivity timeout"))
    id_mock = SimulatedIdentityClient()

    # Pre-seed incident
    create_incident(
        IncidentCreate(
            alert_id="ALERT-EDR-FAIL-001",
            threat_type="ransomware",
            severity=5,
            description="Critical ransomware",
            timestamp="2026-10-18T10:00:00Z",
            username="victim@contoso.com",
            status=IncidentStatus.NEW,
        )
    )

    alert = {
        "alert_id": "ALERT-EDR-FAIL-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }

    res = process_coordinated_response_workflow(
        alert=alert,
        dry_run=False,
        edr_client=edr_mock,
        identity_client=id_mock,
    )

    assert res["endpoint_containment"]["status"] == STATUS_FAILED
    assert res["account_suspension"]["status"] == STATUS_CONFIRMED
    assert res["session_revocation"]["status"] == STATUS_CONFIRMED
    assert res["overall_status"] == "PARTIAL_SUCCESS"

    # Incident lifecycle: not marked CONTAINED because network isolation failed
    inc = get_incident_by_alert_id("ALERT-EDR-FAIL-001")
    assert inc is not None
    assert inc.status != IncidentStatus.CONTAINED
    assert inc.status == IncidentStatus.INVESTIGATING


# ─────────────────────────────────────────────────────────────────────────────
# 35. Identity-action failure with successful EDR containment
# ─────────────────────────────────────────────────────────────────────────────
def test_identity_action_failure_with_successful_edr_containment():
    """
    Test 35: EDR containment succeeds, but IdP actions fail.
    Verifies that successful EDR containment is preserved and incident transitions to CONTAINED.
    """
    edr_mock = SimulatedEDRClient()
    id_mock = SimulatedIdentityClient()
    id_mock.simulate_server_error = True

    create_incident(
        IncidentCreate(
            alert_id="ALERT-ID-FAIL-001",
            threat_type="ransomware",
            severity=5,
            description="Critical ransomware",
            timestamp="2026-10-18T10:00:00Z",
            username="victim@contoso.com",
            status=IncidentStatus.NEW,
        )
    )

    alert = {
        "alert_id": "ALERT-ID-FAIL-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-002",
        "username": "victim@contoso.com",
    }

    res = process_coordinated_response_workflow(
        alert=alert,
        dry_run=False,
        edr_client=edr_mock,
        identity_client=id_mock,
    )

    assert res["endpoint_containment"]["status"] == STATUS_CONFIRMED
    assert res["account_suspension"]["status"] == STATUS_FAILED
    assert res["session_revocation"]["status"] == STATUS_FAILED
    assert res["overall_status"] == "PARTIAL_SUCCESS"

    # Incident transitioned to CONTAINED because EDR isolation succeeded
    inc = get_incident_by_alert_id("ALERT-ID-FAIL-001")
    assert inc is not None
    assert inc.status == IncidentStatus.CONTAINED


# ─────────────────────────────────────────────────────────────────────────────
# 36. No false success after API failure
# ─────────────────────────────────────────────────────────────────────────────
def test_no_false_success_after_api_failure():
    """Test 36: System never falsely reports CONFIRMED when identity API fails or times out."""
    id_client = SimulatedIdentityClient()
    id_client.simulate_timeout = True

    alert = {
        "alert_id": "ALERT-NO-FALSE-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "testuser@example.com",
    }

    res_susp = execute_account_suspension(alert, identity_client=id_client, dry_run=False)
    assert res_susp["status"] != STATUS_CONFIRMED
    assert res_susp["status"] == STATUS_FAILED

    res_rev = execute_session_revocation(alert, identity_client=id_client, dry_run=False)
    assert res_rev["status"] != STATUS_CONFIRMED
    assert res_rev["status"] == STATUS_FAILED


# ─────────────────────────────────────────────────────────────────────────────
# 37. No secrets in logs or audit trail
# ─────────────────────────────────────────────────────────────────────────────
def test_no_secrets_in_logs_or_audit():
    """Test 37: Confirms passwords, client secrets, access tokens, and auth headers are never recorded."""
    secret_val = "SECRET_TOP_SECRET_BEARER_KEY_12345"
    auth_header = f"Bearer {secret_val}"

    # Log an audit entry with sensitive keys
    audit_rec = record_audit_log(
        alert_id="ALERT-SEC-001",
        action="TEST_ACTION",
        execution_mode="live",
        status="CONFIRMED",
        message=f"Operation completed with auth {auth_header}",
        details={
            "client_secret": secret_val,
            "access_token": secret_val,
            "password": "Password123!",
            "authorization": auth_header,
            "safe_key": "safe_value",
        },
    )

    # Verify model details scrubbed
    assert secret_val not in str(audit_rec.details)
    assert "Password123!" not in str(audit_rec.details)
    assert audit_rec.details.get("client_secret") == "[REDACTED]"
    assert audit_rec.details.get("password") == "[REDACTED]"
    assert audit_rec.details.get("safe_key") == "safe_value"
    assert secret_val not in audit_rec.message


# ─────────────────────────────────────────────────────────────────────────────
# 38. Correct incident audit records
# ─────────────────────────────────────────────────────────────────────────────
def test_correct_incident_audit_records():
    """Test 38: Audit records for coordinated workflows are stored accurately in SQLite."""
    edr_mock = SimulatedEDRClient()
    id_mock = SimulatedIdentityClient()

    alert = {
        "alert_id": "ALERT-AUDIT-REC-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-AUDIT-01",
        "username": "victim@contoso.com",
    }

    process_coordinated_response_workflow(
        alert=alert,
        dry_run=True,
        edr_client=edr_mock,
        identity_client=id_mock,
    )

    logs = get_audit_logs_for_alert("ALERT-AUDIT-REC-001")
    assert len(logs) >= 3  # Account suspension, session revocation, coordinated response
    actions = [log.action for log in logs]
    assert ACTION_SUSPEND_ACCOUNT in actions
    assert ACTION_REVOKE_SESSIONS in actions
    assert "COORDINATED_RESPONSE" in actions
    for log in logs:
        assert log.alert_id == "ALERT-AUDIT-REC-001"
        assert log.status == STATUS_SIMULATED


# ─────────────────────────────────────────────────────────────────────────────
# 39. No real identity-provider requests during tests
# ─────────────────────────────────────────────────────────────────────────────
def test_no_real_identity_provider_requests_during_tests():
    """Test 39: Verifies that no real external network requests are sent to Microsoft Graph API."""
    with patch("requests.post") as mock_post, patch("requests.patch") as mock_patch, patch("requests.get") as mock_get:
        edr_mock = SimulatedEDRClient()
        id_mock = SimulatedIdentityClient()

        alert = {
            "alert_id": "ALERT-NO-NET-002",
            "threat_type": "ransomware",
            "severity": 5,
            "description": "Critical ransomware",
            "timestamp": "2026-10-18T10:00:00Z",
            "endpoint_id": "EP-001",
            "username": "victim@contoso.com",
        }

        process_coordinated_response_workflow(
            alert=alert,
            dry_run=False,
            edr_client=edr_mock,
            identity_client=id_mock,
        )

        # Neither requests.post, patch, nor get were called against external internet
        mock_post.assert_not_called()
        mock_patch.assert_not_called()
        mock_get.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# 40. Coordinated response FastAPI endpoint integration
# ─────────────────────────────────────────────────────────────────────────────
def test_coordinated_response_fastapi_endpoint(workflow_client):
    """Test 40: Direct API test against POST /containment/coordinate and GET /incidents/{id}/audit-logs."""
    alert_payload = {
        "alert_id": "ALERT-API-COORD-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Simulated ransomware coordinated response test",
        "timestamp": "2026-10-18T10:00:00Z",
        "hostname": "HOST-COORD-01",
        "endpoint_id": "EP-COORD-01",
        "username": "testuser@example.com",
    }

    # 1. Trigger coordinated containment endpoint
    resp = workflow_client.post("/containment/coordinate", json=alert_payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["alert_id"] == "ALERT-API-COORD-001"
    assert "endpoint_containment" in data
    assert "account_suspension" in data
    assert "session_revocation" in data
    assert data["overall_status"] == STATUS_SIMULATED
    assert data["endpoint_containment"]["status"] == STATUS_SIMULATED
    assert data["account_suspension"]["status"] == STATUS_SIMULATED
    assert data["session_revocation"]["status"] == STATUS_SIMULATED

    # 2. Retrieve audit logs via API endpoint
    audit_resp = workflow_client.get("/incidents/ALERT-API-COORD-001/audit-logs")
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert len(logs) >= 3

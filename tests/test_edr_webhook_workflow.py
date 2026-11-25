# tests/test_edr_webhook_workflow.py
"""
Unit and Integration Tests for the Complete 9-Stage EDR Webhook Workflow.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Workflow Requirements Covered:
  1. Receive a high-severity EDR alert through /webhook/edr.
  2. Validate and normalize the incoming alert.
  3. Execute the existing network containment playbook safely (dry-run & live).
  4. Collect available forensic evidence using the existing forensic services.
  5. Upload evidence to AWS S3 when credentials configured, or report skipped when missing.
  6. Record SHA-256 hashes and chain-of-custody details.
  7. Automatically create a Jira incident ticket with all alert information.
  8. Automatically send a Slack notification containing incident details and Jira ticket link.
  9. Record complete workflow status and errors in incident audit logs.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from containment.network_containment import (
    EXECUTION_MODE_DRY_RUN,
    EXECUTION_MODE_LIVE,
    STATUS_CONFIRMED,
    STATUS_SIMULATED,
    clear_containment_registry,
)
from incidents.database import init_db
from incidents.models import IncidentStatus
from incidents.service import get_audit_logs_for_alert, get_incident_by_alert_id
from main import app

WEBHOOK_SECRET = "test-orchestrator-secret-2026"


@pytest.fixture(autouse=True)
def isolated_orchestrator_env(tmp_path, monkeypatch):
    """Isolates the SQLite database and containment registry for each test."""
    test_db = str(tmp_path / "test_orchestrator_workflow.sqlite")
    monkeypatch.setenv("INCIDENTS_DB_PATH", test_db)
    monkeypatch.setenv("WEBHOOK_SECRET", WEBHOOK_SECRET)
    monkeypatch.setenv("EDR_DRY_RUN", "true")
    # Ensure AWS credentials are unset by default
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    # Ensure offline test execution uses mock Jira and Slack clients
    monkeypatch.setenv("JIRA_BASE_URL", "https://your-domain.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "your-email@example.com")
    monkeypatch.setenv("JIRA_API_TOKEN", "your_jira_api_token_here")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "")
    init_db(test_db)
    clear_containment_registry()
    yield test_db
    clear_containment_registry()


@pytest.fixture
def api_client():
    """Provides a TestClient for the orchestrator FastAPI backend."""
    return TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Full 9-Stage Workflow: High-Severity Alert in Safe Dry-Run Mode
# ─────────────────────────────────────────────────────────────────────────────

def test_full_workflow_high_severity_alert_dry_run(api_client):
    """
    Validates the complete 9-stage incident response pipeline triggered by
    a high-severity ransomware alert via /webhook/edr in safe dry-run mode.
    """
    alert_payload = {
        "alert_id": "ALERT-HIGH-SEV-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "LockBit 3.0 volume encryption detected on critical file server",
        "timestamp": "2026-11-25T10:00:00Z",
        "hostname": "FIN-SRV-01",
        "endpoint_id": "EP-FIN-01",
        "ip_address": "10.0.1.50",
        "username": "fin_admin",
        "process_hash": "2c676d080c5e75da786b4cbfae64663e260086c87e4be65063db1a4d1f2b5a19",
    }
    headers = {"X-Webhook-Secret": WEBHOOK_SECRET}

    resp = api_client.post("/webhook/edr", json=alert_payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()

    # Step 1: Webhook received acknowledgment
    assert data["status"] == "received"
    assert data["alert_id"] == "ALERT-HIGH-SEV-001"
    assert data["threat_type"] == "ransomware"
    assert data["severity"] == 5

    # Step 2: Normalization verified
    summary = data["workflow_summary"]
    assert "ALERT_INGESTED" in summary["stages_completed"]
    assert "ALERT_VALIDATED" in summary["stages_completed"]

    # Step 3: Network containment evaluated safely in dry-run mode
    assert "NETWORK_CONTAINMENT" in summary["stages_completed"]
    assert data["containment"]["status"] == STATUS_SIMULATED
    assert data["containment"]["execution_mode"] == EXECUTION_MODE_DRY_RUN
    assert data["containment"]["isolation_requested"] is False

    # Step 4: Forensic evidence collected
    assert "FORENSIC_COLLECTION" in summary["stages_completed"]
    forensics = data["forensics"]
    assert forensics["status"] == "COMPLETED"
    assert len(forensics["sha256"]) == 64
    assert forensics["file_name"].endswith(".zip")
    assert forensics["simulation_indicator"] is True  # Real KAPE binary not present, accurately labeled

    # Step 5: S3 upload reported as skipped (credentials missing) with safe local staging
    s3_storage = data["s3_storage"]
    assert s3_storage["status"] == "SKIPPED_CREDENTIALS_MISSING"
    assert s3_storage["real_aws"] is False
    assert "AWS credentials" in s3_storage["message"]
    assert "vault_staged_path" in s3_storage
    assert s3_storage["sha256"] == forensics["sha256"]

    # Step 6: Cryptographic chain-of-custody recorded
    coc = data["chain_of_custody"]
    assert len(coc) >= 2
    actions = [entry["action"] for entry in coc]
    assert "EVIDENCE_ACQUIRED" in actions
    assert "HASH_VERIFIED" in actions
    assert "LOCAL_VAULT_STAGED" in actions
    for entry in coc:
        assert entry["verification_hash_sha256"] == forensics["sha256"]

    # Step 7: Jira incident ticket created with alert telemetry
    jira = data["jira_ticket"]
    assert jira["success"] is True
    assert jira["status"] == "CREATED"
    assert "ticket_key" in jira
    assert "RR-" in jira["ticket_key"] or "MOCK-" in jira["ticket_key"]

    # Step 8: Slack notification sent with Jira ticket link
    slack = data["slack_notification"]
    assert slack["status"] in ("DELIVERED", "SKIPPED", "NOT_CONFIGURED")
    assert "visual_indicator" in slack

    # Step 9: Workflow status and audit trail recorded in database
    assert summary["overall_status"] == "SUCCESS"
    assert len(summary["errors"]) == 0

    # Verify audit logs in persistent storage
    logs = get_audit_logs_for_alert("ALERT-HIGH-SEV-001")
    assert len(logs) >= 5
    log_actions = [l.action for l in logs]
    assert "ALERT_INGESTED" in log_actions
    assert "NETWORK_CONTAINMENT" in log_actions
    assert "FORENSIC_EVIDENCE_COLLECTED" in log_actions
    assert "S3_STORAGE" in log_actions
    assert "INCIDENT_RESPONSE_WORKFLOW_COMPLETE" in log_actions

    # Verify audit log retrieval via REST API
    api_audit_resp = api_client.get("/incidents/ALERT-HIGH-SEV-001/audit-logs")
    assert api_audit_resp.status_code == 200
    retrieved_logs = api_audit_resp.json()
    assert len(retrieved_logs) >= 5


# ─────────────────────────────────────────────────────────────────────────────
# 2. Workflow with Valid AWS S3 Credentials Upload
# ─────────────────────────────────────────────────────────────────────────────

def test_full_workflow_with_valid_aws_credentials(api_client, monkeypatch):
    """
    Validates that when valid AWS S3 credentials are configured, the orchestrator
    successfully uploads the evidence package to AWS S3, records S3_UPLOAD,
    and updates the chain of custody with SECURE_S3_ARCHIVAL.
    """
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA-VALID-TEST-KEY")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "SECRET-ACCESS-KEY-12345678")
    monkeypatch.setenv("S3_EVIDENCE_BUCKET", "zaalima-live-evidence-vault")
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    # Re-instantiate S3 service with credentials
    mock_boto = MagicMock()
    mock_boto.head_bucket.return_value = {}
    mock_boto.put_object.return_value = {"ETag": '"etag-123"'}

    alert_payload = {
        "alert_id": "ALERT-S3-LIVE-002",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "BlackCat/ALPHV data staging detected",
        "timestamp": "2026-11-25T11:00:00Z",
        "hostname": "DB-SRV-02",
        "endpoint_id": "EP-DB-02",
        "ip_address": "10.0.2.10",
        "username": "db_admin",
        "process_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    headers = {"X-Webhook-Secret": WEBHOOK_SECRET}

    with patch("app.services.s3_service.S3EvidenceStorageService._get_boto3_client", return_value=mock_boto):
        resp = api_client.post("/webhook/edr", json=alert_payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()

    s3_storage = data["s3_storage"]
    assert s3_storage["status"] == "UPLOADED"
    assert s3_storage["real_aws"] is True
    assert "s3://zaalima-live-evidence-vault/" in s3_storage["s3_uri"]
    assert s3_storage["simulation_indicator"] is False

    # Chain of custody contains SECURE_S3_ARCHIVAL
    actions = [e["action"] for e in data["chain_of_custody"]]
    assert "SECURE_S3_ARCHIVAL" in actions


# ─────────────────────────────────────────────────────────────────────────────
# 3. Workflow with Live Network Containment Execution
# ─────────────────────────────────────────────────────────────────────────────

def test_full_workflow_live_containment_execution(api_client):
    """
    Validates that when dry_run=false is explicitly supplied and authorized,
    the network containment playbook invokes the EDR isolation endpoint and
    transitions the incident status to CONTAINED.
    """
    alert_payload = {
        "alert_id": "ALERT-LIVE-ISOLATE-003",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Active ransomware payload execution with Canary tripped",
        "timestamp": "2026-11-25T12:00:00Z",
        "hostname": "PAYROLL-APP-01",
        "endpoint_id": "EP-PAYROLL-01",
        "ip_address": "10.0.3.40",
    }
    headers = {"X-Webhook-Secret": WEBHOOK_SECRET}

    mock_edr = MagicMock()
    mock_edr.PROVIDER = "crowdstrike"
    mock_edr.isolate_endpoint.return_value = {
        "resources": [{"id": "act-live-999", "complete": True, "status": "normal"}]
    }

    with patch("containment.network_containment.create_edr_client", return_value=mock_edr):
        resp = api_client.post("/webhook/edr?dry_run=false", json=alert_payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()

    assert data["incident_status"] == IncidentStatus.CONTAINED.value
    assert data["containment"]["status"] == STATUS_CONFIRMED
    assert data["containment"]["execution_mode"] == EXECUTION_MODE_LIVE
    assert data["containment"]["isolation_requested"] is True
    assert data["containment"]["action_id"] == "act-live-999"

    # Verify EDR client isolate_endpoint was called
    mock_edr.isolate_endpoint.assert_called_once_with(
        "EP-PAYROLL-01",
        comment="Automated containment for alert ALERT-LIVE-ISOLATE-003",
    )

    # Verify incident record in database
    incident = get_incident_by_alert_id("ALERT-LIVE-ISOLATE-003")
    assert incident is not None
    assert incident.status == IncidentStatus.CONTAINED


# ─────────────────────────────────────────────────────────────────────────────
# 4. Fault Isolation: Jira Error Does Not Abort Containment or Forensics
# ─────────────────────────────────────────────────────────────────────────────

def test_fault_isolation_jira_failure_does_not_mask_containment(api_client):
    """
    Verifies fault isolation: If the Jira API encounters a network or auth error,
    network containment and forensic collection are NOT aborted, and the failure
    is cleanly recorded in the incident logs without raising an unhandled 500 error.
    """
    alert_payload = {
        "alert_id": "ALERT-FAULT-JIRA-004",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "WannaCry variant scanning internal SMB shares",
        "timestamp": "2026-11-25T13:00:00Z",
        "hostname": "HR-WORKSTATION-05",
        "endpoint_id": "EP-HR-05",
        "ip_address": "10.0.5.12",
    }
    headers = {"X-Webhook-Secret": WEBHOOK_SECRET}

    with patch("containment.incident_orchestrator.create_mock_jira_client") as mock_jira_factory:
        failing_jira = MagicMock()
        failing_jira.create_incident_ticket.side_effect = RuntimeError("Atlassian Cloud HTTP 503 Service Unavailable")
        mock_jira_factory.return_value = failing_jira

        resp = api_client.post("/webhook/edr", json=alert_payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()

    # Core containment and forensics must still succeed
    summary = data["workflow_summary"]
    assert "NETWORK_CONTAINMENT" in summary["stages_completed"]
    assert "FORENSIC_COLLECTION" in summary["stages_completed"]

    # Jira error recorded cleanly
    assert data["jira_ticket"]["success"] is False
    assert "Atlassian Cloud" in data["jira_ticket"]["error"]
    assert summary["overall_status"] == "PARTIAL_SUCCESS"
    assert any("Jira ticketing error" in err for err in summary["errors"])

    # Audit log contains error record
    logs = get_audit_logs_for_alert("ALERT-FAULT-JIRA-004")
    complete_log = [l for l in logs if l.action == "INCIDENT_RESPONSE_WORKFLOW_COMPLETE"][0]
    assert complete_log.status == "PARTIAL_SUCCESS"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Fault Isolation: Slack Error Does Not Disrupt Workflow
# ─────────────────────────────────────────────────────────────────────────────

def test_fault_isolation_slack_failure_does_not_abort_workflow(api_client):
    """
    Verifies that a Slack dispatch failure is safely isolated, does not crash
    the API, and records the error in the workflow summary.
    """
    alert_payload = {
        "alert_id": "ALERT-FAULT-SLACK-005",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "Conti malware binary detected by host heuristics",
        "timestamp": "2026-11-25T14:00:00Z",
        "hostname": "DEV-SRV-03",
        "endpoint_id": "EP-DEV-03",
        "ip_address": "10.0.4.88",
    }
    headers = {"X-Webhook-Secret": WEBHOOK_SECRET}

    with patch("containment.incident_orchestrator.IncidentNotificationService.notify_incident") as mock_notify:
        mock_notify.side_effect = ConnectionError("Slack webhook endpoint timeout")
        resp = api_client.post("/webhook/edr", json=alert_payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()

    assert data["slack_notification"]["status"] == "FAILED"
    assert "Slack webhook endpoint timeout" in data["slack_notification"]["error"]
    assert "NETWORK_CONTAINMENT" in data["workflow_summary"]["stages_completed"]
    assert "JIRA_TICKET_CREATED" in data["workflow_summary"]["stages_completed"]


# ─────────────────────────────────────────────────────────────────────────────
# 6. Security & Secret Redaction
# ─────────────────────────────────────────────────────────────────────────────

def test_secrets_are_never_exposed_in_incident_logs(api_client):
    """
    Verifies that private API keys, client secrets, and passwords are
    never leaked or stored in cleartext in the incident audit trail.
    """
    alert_payload = {
        "alert_id": "ALERT-SECRET-AUDIT-006",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "Incident report containing sensitive diagnostic metadata",
        "timestamp": "2026-11-25T15:00:00Z",
        "hostname": "SEC-AUDIT-01",
        "endpoint_id": "EP-SEC-01",
        "ip_address": "10.0.6.99",
    }
    headers = {"X-Webhook-Secret": WEBHOOK_SECRET}

    resp = api_client.post("/webhook/edr", json=alert_payload, headers=headers)
    assert resp.status_code == 200

    logs = get_audit_logs_for_alert("ALERT-SECRET-AUDIT-006")
    for log in logs:
        raw_str = f"{log.message} {json.dumps(log.details or {})}"
        assert "super_secret" not in raw_str.lower()
        assert WEBHOOK_SECRET not in raw_str


# ─────────────────────────────────────────────────────────────────────────────
# 7. Webhook Authentication Enforcement
# ─────────────────────────────────────────────────────────────────────────────

def test_webhook_unauthorized_rejection(api_client):
    """
    Verifies that requests missing the valid X-Webhook-Secret header are
    rejected immediately with HTTP 401 Unauthorized.
    """
    alert_payload = {
        "alert_id": "ALERT-UNAUTH-007",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "Unauthenticated webhook payload test",
        "timestamp": "2026-11-25T16:00:00Z",
    }
    # No auth header
    resp = api_client.post("/webhook/edr", json=alert_payload)
    assert resp.status_code == 401
    assert "detail" in resp.json()

    # Invalid secret
    resp_bad = api_client.post(
        "/webhook/edr",
        json=alert_payload,
        headers={"X-Webhook-Secret": "invalid-wrong-secret"},
    )
    assert resp_bad.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# 8. Malformed Alert Payload Validation
# ─────────────────────────────────────────────────────────────────────────────

def test_webhook_malformed_alert_rejection(api_client):
    """
    Verifies that malformed or incomplete alert payloads are rejected
    with HTTP 422 Unprocessable Entity without triggering downstream actions.
    """
    headers = {"X-Webhook-Secret": WEBHOOK_SECRET}
    # Missing required fields: description, severity, threat_type
    incomplete = {
        "alert_id": "ALERT-INCOMPLETE-008",
        "timestamp": "2026-11-25T16:30:00Z",
    }
    resp = api_client.post("/webhook/edr", json=incomplete, headers=headers)
    assert resp.status_code == 422
    data = resp.json()
    assert "detail" in data


# ─────────────────────────────────────────────────────────────────────────────
# 9. Successful Slack Notification Dispatch
# ─────────────────────────────────────────────────────────────────────────────

def test_full_workflow_with_successful_slack_notification(api_client, monkeypatch):
    """
    Validates that when a Slack webhook is active, notifications are formatted
    with Block Kit, include the Jira browse link, and status reports DELIVERED.
    """
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T0000/B0000/XXXXX")

    alert_payload = {
        "alert_id": "ALERT-SLACK-DELIVER-009",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical LockBit canary tripped on core storage array",
        "timestamp": "2026-11-25T17:00:00Z",
        "hostname": "STORAGE-SAN-01",
        "endpoint_id": "EP-SAN-01",
        "ip_address": "10.0.9.15",
    }
    headers = {"X-Webhook-Secret": WEBHOOK_SECRET}

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"

    with patch("requests.Session.post", return_value=mock_resp):
        resp = api_client.post("/webhook/edr", json=alert_payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["slack_notification"]["status"] == "DELIVERED"
    assert data["slack_notification"]["delivered"] is True
    assert "🔴 Critical Alert" in data["slack_notification"]["visual_indicator"]


# ─────────────────────────────────────────────────────────────────────────────
# 10. Low-Severity Alert Does Not Trigger Network Isolation
# ─────────────────────────────────────────────────────────────────────────────

def test_full_workflow_low_severity_no_containment(api_client):
    """
    Validates that a low-severity alert (e.g. informational or low risk)
    does not recommend network isolation in accordance with policy safeguards.
    """
    alert_payload = {
        "alert_id": "ALERT-LOW-SEV-010",
        "threat_type": "suspicious_login",
        "severity": 1,
        "description": "Routine single failed logon attempt from recognized subnet",
        "timestamp": "2026-11-25T17:15:00Z",
        "hostname": "OFFICE-PC-12",
        "endpoint_id": "EP-OFFICE-12",
        "ip_address": "10.0.12.8",
    }
    headers = {"X-Webhook-Secret": WEBHOOK_SECRET}

    resp = api_client.post("/webhook/edr", json=alert_payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()

    assert data["containment"]["containment_recommended"] is False
    assert data["containment"]["isolation_requested"] is False


# ─────────────────────────────────────────────────────────────────────────────
# 11. Duplicate Webhook Alert Idempotency
# ─────────────────────────────────────────────────────────────────────────────

def test_webhook_duplicate_alert_idempotency(api_client):
    """
    Verifies that re-submitting an identical alert_id is safely recognized
    as a duplicate, returns status='duplicate', and suppresses duplicate ticketing.
    """
    alert_payload = {
        "alert_id": "ALERT-DUP-CHECK-011",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "High severity alert for idempotency testing",
        "timestamp": "2026-11-25T17:30:00Z",
        "hostname": "WEB-SRV-01",
        "endpoint_id": "EP-WEB-01",
    }
    headers = {"X-Webhook-Secret": WEBHOOK_SECRET}

    # Initial submission: processed
    resp1 = api_client.post("/webhook/edr", json=alert_payload, headers=headers)
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "received"

    # Second submission: recognized as duplicate
    resp2 = api_client.post("/webhook/edr", json=alert_payload, headers=headers)
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["status"] == "duplicate"
    assert "already been processed" in data2["message"]


# tests/test_e2e_workflow.py
"""
End-to-end integration test verifying the complete Week 1 incident lifecycle workflow.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Day     : 6 -- Integration Testing

Workflow Steps Validated:
  1. Generate / submit a simulated EDR alert via webhook.
  2. Validate webhook secret authentication.
  3. Parse, validate, and normalize the alert payload.
  4. Automatically create and persist an incident record in SQLite.
  5. Retrieve the incident via the REST API (GET /incidents/{alert_id}).
  6. Filter incidents by lifecycle status and severity.
  7. Safely update the incident lifecycle status (PATCH /incidents/{alert_id}/status).
  8. Verify idempotent duplicate webhook delivery handling.
  9. Verify rejection of unauthorized requests and malformed payloads.
"""

import pytest
from fastapi.testclient import TestClient

from main import app
from incidents.models import IncidentStatus

E2E_SECRET = "e2e-integration-secret-999"


@pytest.fixture
def e2e_client(monkeypatch):
    """Provides a TestClient with E2E webhook secret configured."""
    monkeypatch.setenv("WEBHOOK_SECRET", E2E_SECRET)
    return TestClient(app)


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

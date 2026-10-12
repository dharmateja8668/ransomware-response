# tests/test_incidents.py
"""
Unit and integration tests for Incident Data Management (Week 5 -- Day 2).

Scenarios covered:
  1. Database initialization creates tables and indexes.
  2. Successful incident creation via service and API (POST /incidents returns 201).
  3. Retrieving an incident by alert_id (GET /incidents/{alert_id} returns 200).
  4. Listing incidents with pagination limit (GET /incidents returns 200).
  5. Filtering incidents by lifecycle status (e.g. status=NEW, status=INVESTIGATING).
  6. Filtering incidents by severity rating (e.g. severity=5).
  7. Updating incident status (PATCH /incidents/{alert_id}/status returns 200).
  8. Handling missing incident queries and updates (returns 404).
  9. Rejecting duplicate alert IDs on creation (returns 409 Conflict).
  10. Rejecting invalid status values during update (returns 422 Unprocessable Entity).
  11. Webhook alert persistence: incoming POST /webhook/edr records incident in SQLite.
  12. Webhook duplicate handling: repeated webhook delivery returns duplicate status idempotently.
  13. Safe handling of database errors without leaking internal secrets.
"""

import os
import sqlite3
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from main import app
from incidents.database import get_connection, get_db_path, init_db
from incidents.models import IncidentCreate, IncidentStatus, IncidentUpdateStatus
from incidents.service import (
    IncidentDuplicateError,
    IncidentNotFoundError,
    create_incident,
    get_incident_by_alert_id,
    list_incidents,
    update_incident_status,
)

TEST_WEBHOOK_SECRET = "test-secret-incident-suite"


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """
    Directs all database operations to an isolated temporary SQLite file for each test.
    Cleans up automatically when the test finishes.
    """
    test_db_file = str(tmp_path / "test_incidents.db")
    monkeypatch.setenv("INCIDENTS_DB_PATH", test_db_file)
    monkeypatch.setenv("WEBHOOK_SECRET", TEST_WEBHOOK_SECRET)
    init_db(test_db_file)
    return test_db_file


@pytest.fixture
def client():
    """Provides a TestClient for testing FastAPI endpoints."""
    return TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Database Initialization
# ─────────────────────────────────────────────────────────────────────────────
def test_database_initialization(isolated_db):
    """Database initialization creates the incidents table and indexes properly."""
    conn = get_connection(isolated_db)
    cursor = conn.cursor()

    # Verify table existence
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='incidents'")
    assert cursor.fetchone() is not None

    # Verify indexes
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
    index_names = [row["name"] for row in cursor.fetchall()]
    assert "idx_incidents_status" in index_names
    assert "idx_incidents_severity" in index_names
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# 2. Incident Creation (Service & API)
# ─────────────────────────────────────────────────────────────────────────────
def test_create_incident_service(isolated_db):
    """Service successfully inserts an incident and returns IncidentResponse."""
    item = IncidentCreate(
        alert_id="inc-srv-001",
        threat_type="ransomware",
        severity=5,
        description="Mass file encryption activity detected",
        hostname="FINANCE-SRV-01",
        ip_address="10.1.2.50",
        username="finance_admin",
        process_hash="d41d8cd98f00b204e9800998ecf8427e",
        timestamp="2026-10-12T08:00:00Z",
    )
    result = create_incident(item, db_path=isolated_db)
    assert result.alert_id == "inc-srv-001"
    assert result.threat_type == "ransomware"
    assert result.severity == 5
    assert result.status == IncidentStatus.NEW
    assert result.created_at is not None
    assert result.updated_at is not None


def test_create_incident_api_success(client):
    """POST /incidents successfully creates a record and returns HTTP 201."""
    payload = {
        "alert_id": "api-inc-001",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "Suspicious vssadmin shadow copy deletion",
        "hostname=" : "WS-SEC-12",
        "hostname": "WS-SEC-12",
        "ip_address": "192.168.5.21",
        "username": "user1",
        "timestamp": "2026-10-12T09:30:00Z",
    }
    response = client.post("/incidents", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["alert_id"] == "api-inc-001"
    assert data["status"] == "NEW"
    assert data["created_at"] is not None


# ─────────────────────────────────────────────────────────────────────────────
# 3. Retrieving an Incident
# ─────────────────────────────────────────────────────────────────────────────
def test_get_incident_by_alert_id(client, isolated_db):
    """GET /incidents/{alert_id} returns the correct incident details."""
    item = IncidentCreate(
        alert_id="inc-find-001",
        threat_type="ransomware",
        severity=3,
        description="High entropy file write patterns",
        timestamp="2026-10-12T10:00:00Z",
    )
    create_incident(item, db_path=isolated_db)

    response = client.get("/incidents/inc-find-001")
    assert response.status_code == 200
    data = response.json()
    assert data["alert_id"] == "inc-find-001"
    assert data["description"] == "High entropy file write patterns"


def test_get_incident_not_found(client):
    """GET /incidents/{alert_id} returns 404 for non-existent incident."""
    response = client.get("/incidents/nonexistent-alert-999")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# 4. Listing and Filtering Incidents
# ─────────────────────────────────────────────────────────────────────────────
def test_list_and_filter_incidents(client, isolated_db):
    """GET /incidents returns records filtered by status and severity."""
    # Seed test data
    create_incident(
        IncidentCreate(
            alert_id="list-001",
            threat_type="ransomware",
            severity=5,
            description="Alert 1",
            timestamp="2026-10-12T01:00:00Z",
            status=IncidentStatus.NEW,
        ),
        db_path=isolated_db,
    )
    create_incident(
        IncidentCreate(
            alert_id="list-002",
            threat_type="trojan",
            severity=3,
            description="Alert 2",
            timestamp="2026-10-12T02:00:00Z",
            status=IncidentStatus.INVESTIGATING,
        ),
        db_path=isolated_db,
    )
    create_incident(
        IncidentCreate(
            alert_id="list-003",
            threat_type="ransomware",
            severity=5,
            description="Alert 3",
            timestamp="2026-10-12T03:00:00Z",
            status=IncidentStatus.RESOLVED,
        ),
        db_path=isolated_db,
    )

    # All incidents
    res_all = client.get("/incidents")
    assert res_all.status_code == 200
    assert len(res_all.json()) == 3

    # Filter by status: INVESTIGATING
    res_status = client.get("/incidents?status=INVESTIGATING")
    assert res_status.status_code == 200
    data_status = res_status.json()
    assert len(data_status) == 1
    assert data_status[0]["alert_id"] == "list-002"

    # Filter by severity: 5
    res_sev = client.get("/incidents?severity=5")
    assert res_sev.status_code == 200
    data_sev = res_sev.json()
    assert len(data_sev) == 2
    assert {d["alert_id"] for d in data_sev} == {"list-001", "list-003"}


# ─────────────────────────────────────────────────────────────────────────────
# 5. Updating Incident Status
# ─────────────────────────────────────────────────────────────────────────────
def test_update_incident_status_success(client, isolated_db):
    """PATCH /incidents/{alert_id}/status updates the status and updated_at timestamp."""
    create_incident(
        IncidentCreate(
            alert_id="inc-status-01",
            threat_type="ransomware",
            severity=4,
            description="Ransom note detected",
            timestamp="2026-10-12T05:00:00Z",
            status=IncidentStatus.NEW,
        ),
        db_path=isolated_db,
    )

    patch_res = client.patch(
        "/incidents/inc-status-01/status",
        json={"status": "CONTAINED"},
    )
    assert patch_res.status_code == 200
    data = patch_res.json()
    assert data["status"] == "CONTAINED"
    assert data["updated_at"] >= data["created_at"]


def test_update_incident_status_not_found(client):
    """PATCH /incidents/{alert_id}/status returns 404 for unknown alert_id."""
    res = client.patch(
        "/incidents/unknown-alert-404/status",
        json={"status": "INVESTIGATING"},
    )
    assert res.status_code == 404


def test_update_incident_status_invalid_value(client, isolated_db):
    """PATCH /incidents/{alert_id}/status returns 422 for unrecognised status value."""
    create_incident(
        IncidentCreate(
            alert_id="inc-status-02",
            threat_type="ransomware",
            severity=4,
            description="Suspicious binary",
            timestamp="2026-10-12T05:00:00Z",
        ),
        db_path=isolated_db,
    )
    res = client.patch(
        "/incidents/inc-status-02/status",
        json={"status": "COMPLETELY_DESTROYED"},
    )
    assert res.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# 6. Duplicate Alert IDs Rejection
# ─────────────────────────────────────────────────────────────────────────────
def test_duplicate_alert_id_rejected(client, isolated_db):
    """POST /incidents returns HTTP 409 when alert_id is duplicated."""
    payload = {
        "alert_id": "dup-alert-001",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "Original incident",
        "timestamp": "2026-10-12T06:00:00Z",
    }
    # First creation
    res1 = client.post("/incidents", json=payload)
    assert res1.status_code == 201

    # Second creation with identical alert_id
    res2 = client.post("/incidents", json=payload)
    assert res2.status_code == 409
    assert "already exists" in res2.json()["detail"]


# ─────────────────────────────────────────────────────────────────────────────
# 7. Webhook Alert Ingestion and Idempotency
# ─────────────────────────────────────────────────────────────────────────────
def test_webhook_ingests_and_stores_incident(client, isolated_db):
    """Incoming EDR webhook alert automatically creates and persists an incident record."""
    webhook_payload = {
        "alert_id": "edr-auto-001",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "Shadow copy deletion via PowerShell detected",
        "hostname": "DC-01.CORP.LOCAL",
        "ip_address": "10.0.0.10",
        "username": "domain_admin",
        "process_hash": "c157a79031e1c40f85931829bc5fc552",
        "timestamp": "2026-10-12T11:00:00Z",
    }
    headers = {"X-Webhook-Secret": TEST_WEBHOOK_SECRET}
    res = client.post("/webhook/edr", json=webhook_payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "received"
    assert data["alert_id"] == "edr-auto-001"
    assert data["incident_status"] == "NEW"

    # Verify record was stored in SQLite database
    stored = get_incident_by_alert_id("edr-auto-001", db_path=isolated_db)
    assert stored is not None
    assert stored.hostname == "DC-01.CORP.LOCAL"
    assert stored.ip_address == "10.0.0.10"
    assert stored.username == "domain_admin"
    assert stored.severity == 4


def test_webhook_duplicate_handling_idempotent(client, isolated_db):
    """Submitting duplicate webhook delivery returns HTTP 200 with duplicate status idempotently."""
    webhook_payload = {
        "alert_id": "edr-dup-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Rapid encryption in user directory",
        "timestamp": "2026-10-12T11:15:00Z",
    }
    headers = {"X-Webhook-Secret": TEST_WEBHOOK_SECRET}

    # First delivery
    res1 = client.post("/webhook/edr", json=webhook_payload, headers=headers)
    assert res1.status_code == 200
    assert res1.json()["status"] == "received"

    # Second delivery (retry)
    res2 = client.post("/webhook/edr", json=webhook_payload, headers=headers)
    assert res2.status_code == 200
    assert res2.json()["status"] == "duplicate"
    assert "already been processed" in res2.json()["message"]

    # Verify only 1 database entry exists
    all_incidents = list_incidents(db_path=isolated_db)
    matching = [i for i in all_incidents if i.alert_id == "edr-dup-001"]
    assert len(matching) == 1


# ─────────────────────────────────────────────────────────────────────────────
# 8. Database Error Handling
# ─────────────────────────────────────────────────────────────────────────────
def test_webhook_database_error_handling(client):
    """When a database failure occurs during webhook ingestion, HTTP 500 is returned safely."""
    payload = {
        "alert_id": "edr-err-001",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "Simulated DB failure alert",
        "timestamp": "2026-10-12T12:00:00Z",
    }
    headers = {"X-Webhook-Secret": TEST_WEBHOOK_SECRET}

    with patch("main.create_incident", side_effect=sqlite3.OperationalError("Simulated disk error")):
        res = client.post("/webhook/edr", json=payload, headers=headers)
        assert res.status_code == 500
        assert "Failed to store incident record securely." in res.json()["detail"]

# tests/test_webhook.py
"""
Unit tests for the EDR webhook integration endpoint.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Day     : 4 -- Webhook Integration Tests

Scenarios covered:
  TEST 1: A valid simulated EDR alert is received (HTTP 200, confirmation).
  TEST 2: A request is missing required fields (HTTP 422 validation error).
  TEST 3: Malformed JSON is submitted (rejected appropriately with HTTP 422).
  TEST 4: Webhook authentication secret is missing or incorrect (HTTP 401 unauthorized).
  TEST 5: Alert with optional fields is processed according to the model (HTTP 200).
  TEST 6: Existing GET /health endpoint works (HTTP 200).
  TEST 7: Existing POST /alert endpoint still works (HTTP 200).
  TEST 8: /docs page and OpenAPI schema are accessible (HTTP 200).
"""

import pytest
from fastapi.testclient import TestClient
from main import app

TEST_SECRET = "test-webhook-secret-xyz"


@pytest.fixture
def client(monkeypatch):
    """Provides a TestClient with WEBHOOK_SECRET configured."""
    monkeypatch.setenv("WEBHOOK_SECRET", TEST_SECRET)
    return TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 1: Valid simulated EDR alert is received
# ─────────────────────────────────────────────────────────────────────────────
def test_valid_simulated_edr_alert(client):
    """TEST 1: A valid simulated EDR alert returns HTTP 200 and confirmation."""
    payload = {
        "alert_id": "alert-001",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "Simulated ransomware activity detected on endpoint",
        "timestamp": "2026-10-11T10:00:00Z",
    }
    headers = {"X-Webhook-Secret": TEST_SECRET}
    response = client.post("/webhook/edr", json=payload, headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "received"
    assert data["alert_id"] == "alert-001"
    assert data["threat_type"] == "ransomware"
    assert data["severity"] == 4
    assert "processed successfully" in data["message"]


# ─────────────────────────────────────────────────────────────────────────────
# TEST 2: Request is missing required fields
# ─────────────────────────────────────────────────────────────────────────────
def test_missing_required_fields(client):
    """TEST 2: Missing required alert fields returns HTTP 422 validation error."""
    # Missing 'timestamp', 'description', 'severity', and 'threat_type'
    payload = {
        "alert_id": "alert-incomplete-001"
    }
    headers = {"X-Webhook-Secret": TEST_SECRET}
    response = client.post("/webhook/edr", json=payload, headers=headers)

    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    # Verify that missing fields are identified in the validation error details
    missing_fields = [err.get("loc", [])[-1] for err in data["detail"]]
    assert "threat_type" in missing_fields
    assert "severity" in missing_fields
    assert "description" in missing_fields
    assert "timestamp" in missing_fields


# ─────────────────────────────────────────────────────────────────────────────
# TEST 3: Malformed JSON is submitted
# ─────────────────────────────────────────────────────────────────────────────
def test_malformed_json_submitted(client):
    """TEST 3: Malformed JSON body is rejected appropriately (HTTP 422)."""
    headers = {
        "X-Webhook-Secret": TEST_SECRET,
        "Content-Type": "application/json",
    }
    malformed_raw_body = "{invalid_json: true, missing_quotes"
    response = client.post("/webhook/edr", content=malformed_raw_body, headers=headers)

    # FastAPI returns 422 with a JSON decode error
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    assert any("JSON decode error" in str(err.get("msg", "")) for err in data["detail"])


# ─────────────────────────────────────────────────────────────────────────────
# TEST 4: Authentication secret is missing or incorrect
# ─────────────────────────────────────────────────────────────────────────────
def test_auth_secret_missing(client):
    """TEST 4a: Webhook request with no secret header is rejected (HTTP 401)."""
    payload = {
        "alert_id": "alert-002",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Mass file encryption detected",
        "timestamp": "2026-10-11T10:05:00Z",
    }
    # No auth header provided
    response = client.post("/webhook/edr", json=payload)

    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert "Invalid or missing webhook secret" in data["detail"]


def test_auth_secret_incorrect(client):
    """TEST 4b: Webhook request with incorrect secret header is rejected (HTTP 401)."""
    payload = {
        "alert_id": "alert-002",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Mass file encryption detected",
        "timestamp": "2026-10-11T10:05:00Z",
    }
    headers = {"X-Webhook-Secret": "wrong-secret-token"}
    response = client.post("/webhook/edr", json=payload, headers=headers)

    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert "Invalid or missing webhook secret" in data["detail"]


def test_auth_secret_server_not_configured(monkeypatch):
    """TEST 4c: Webhook request when server has no secret configured is rejected (HTTP 401)."""
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    unconfigured_client = TestClient(app)
    payload = {
        "alert_id": "alert-002",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Mass file encryption detected",
        "timestamp": "2026-10-11T10:05:00Z",
    }
    headers = {"X-Webhook-Secret": "any-secret"}
    response = unconfigured_client.post("/webhook/edr", json=payload, headers=headers)

    assert response.status_code == 401
    data = response.json()
    assert "not configured or unauthorized" in data["detail"]


def test_auth_bearer_token_supported(client):
    """TEST 4d: Webhook request using standard Bearer token header is accepted."""
    payload = {
        "alert_id": "alert-003",
        "threat_type": "ransomware",
        "severity": 3,
        "description": "Suspicious shadow copy deletion",
        "timestamp": "2026-10-11T10:10:00Z",
    }
    headers = {"Authorization": f"Bearer {TEST_SECRET}"}
    response = client.post("/webhook/edr", json=payload, headers=headers)

    assert response.status_code == 200
    assert response.json()["alert_id"] == "alert-003"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 5: Alert with optional fields
# ─────────────────────────────────────────────────────────────────────────────
def test_alert_with_optional_fields(client):
    """TEST 5: Webhook processes an alert with optional contextual fields."""
    example_payload = {
        "alert_id": "alert-004",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "Simulated ransomware activity detected",
        "timestamp": "2026-10-11T10:00:00Z",
        "hostname": "LAB-PC-01",
        "ip_address": "192.168.1.100",
        "username": "lab_user",
        "process_hash": "example_hash",
    }
    headers = {"X-Webhook-Secret": TEST_SECRET}
    response = client.post("/webhook/edr", json=example_payload, headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "received"
    assert data["alert_id"] == "alert-004"
    assert data["threat_type"] == "ransomware"
    assert data["severity"] == 4


# ─────────────────────────────────────────────────────────────────────────────
# TEST 6: Existing GET /health endpoint works
# ─────────────────────────────────────────────────────────────────────────────
def test_existing_health_endpoint(client):
    """TEST 6: GET /health returns HTTP 200 and server status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["message"] == "Server is running"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 7: Existing POST /alert endpoint still works
# ─────────────────────────────────────────────────────────────────────────────
def test_existing_alert_endpoint_still_works(client):
    """TEST 7: Existing POST /alert endpoint still works without auth requirement."""
    payload = {
        "alert_id": "day2-alert-101",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "Day 2 legacy alert test",
        "timestamp": "2026-10-11T09:00:00Z",
    }
    response = client.post("/alert", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "received"
    assert data["alert_id"] == "day2-alert-101"
    assert data["message"] == "Alert of type 'ransomware' recorded."


# ─────────────────────────────────────────────────────────────────────────────
# TEST 8: /docs page is accessible
# ─────────────────────────────────────────────────────────────────────────────
def test_docs_page_accessible(client):
    """TEST 8: /docs Swagger UI and /openapi.json are accessible."""
    docs_response = client.get("/docs")
    assert docs_response.status_code == 200
    assert "swagger-ui" in docs_response.text.lower() or "html" in docs_response.headers.get("content-type", "").lower()

    openapi_response = client.get("/openapi.json")
    assert openapi_response.status_code == 200
    schema = openapi_response.json()
    assert "/webhook/edr" in schema["paths"]
    assert "/health" in schema["paths"]
    assert "/alert" in schema["paths"]

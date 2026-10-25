# tests/test_api_security.py
"""
Comprehensive Security & Authorization Tests (Phase 2).
Validates:
  1. Unauthenticated requests to sensitive endpoints are rejected with HTTP 401.
  2. Invalid credentials (API keys, malformed JWTs, invalid signatures, expired tokens) return HTTP 401.
  3. Role-based authorization: insufficient permissions return HTTP 403.
  4. Authorized requests reach intended endpoints successfully.
  5. API key rotation (primary and secondary keys) functions properly.
  6. Rejected requests do not execute underlying containment or identity actions.
  7. Webhook authentication (X-Webhook-Secret) remains intact and distinct from API auth.
  8. Secrets and credentials are never leaked in HTTP response bodies or log messages.
"""

import json
import logging
import os
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from containment.network_containment import (
    STATUS_CONFIRMED,
    STATUS_SIMULATED,
    clear_containment_registry,
)
from containment.identity_response import clear_identity_registry
from incidents.database import init_db
from incidents.models import IncidentCreate, IncidentStatus
from incidents.service import create_incident, get_incident_by_alert_id
from main import app
from security.auth import (
    AuthenticatedIdentity,
    create_test_jwt,
    get_configured_api_keys,
)

TEST_API_KEY_ADMIN = "secops-admin-key-2026"
TEST_API_KEY_SECONDARY = "secops-rotation-key-2026"
TEST_JWT_SECRET = "test-cryptographic-jwt-secret-key-32-bytes!!"
TEST_WEBHOOK_SECRET = "webhook-test-shared-secret-123"

SAMPLE_ALERT_PAYLOAD = {
    "alert_id": "SEC-TEST-ALERT-001",
    "threat_type": "ransomware",
    "severity": 5,
    "description": "Security test alert payload",
    "timestamp": "2026-10-18T12:00:00Z",
    "hostname": "SEC-HOST-01",
    "endpoint_id": "EP-SEC-01",
    "username": "victim.user@domain.com",
}


@pytest.fixture(autouse=True)
def setup_security_test_env(tmp_path, monkeypatch):
    """Set up an isolated environment with defined security credentials."""
    db_file = str(tmp_path / "test_security.db")
    monkeypatch.setenv("INCIDENTS_DB_PATH", db_file)
    monkeypatch.setenv("ORCHESTRATOR_API_KEY", TEST_API_KEY_ADMIN)
    monkeypatch.setenv("ORCHESTRATOR_API_KEY_SECONDARY", TEST_API_KEY_SECONDARY)
    monkeypatch.setenv("JWT_SECRET_KEY", TEST_JWT_SECRET)
    monkeypatch.setenv("WEBHOOK_SECRET", TEST_WEBHOOK_SECRET)
    monkeypatch.setenv(
        "ORCHESTRATOR_API_KEYS",
        json.dumps({
            "key-containment-only": {
                "identity": "containment_bot",
                "roles": ["containment_specialist"],
            },
            "key-analyst-readonly": {
                "identity": "soc_analyst_jim",
                "roles": ["soc_analyst"],
            },
        }),
    )
    init_db(db_file)
    clear_containment_registry()
    clear_identity_registry()
    yield
    clear_containment_registry()
    clear_identity_registry()


@pytest.fixture
def unauthenticated_client():
    """Client with no default authentication headers."""
    return TestClient(app)


# ── 1. Unauthenticated Requests Rejected ──────────────────────────────────────


@pytest.mark.parametrize(
    "endpoint,method,payload",
    [
        ("/containment/isolate", "POST", SAMPLE_ALERT_PAYLOAD),
        ("/identity/suspend", "POST", SAMPLE_ALERT_PAYLOAD),
        ("/identity/revoke-sessions", "POST", SAMPLE_ALERT_PAYLOAD),
        ("/containment/coordinate", "POST", SAMPLE_ALERT_PAYLOAD),
        ("/incidents/SEC-TEST-ALERT-001/status", "PATCH", {"status": "CONTAINED"}),
    ],
)
def test_unauthenticated_requests_rejected(unauthenticated_client, endpoint, method, payload):
    """Verifies that all sensitive endpoints return 401 when called without credentials."""
    if method == "POST":
        res = unauthenticated_client.post(endpoint, json=payload)
    else:
        res = unauthenticated_client.patch(endpoint, json=payload)

    assert res.status_code == 401
    assert "detail" in res.json()
    assert "Authentication required" in res.json()["detail"]


# ── 2. Invalid Credentials Rejected ───────────────────────────────────────────


def test_invalid_api_key_rejected(unauthenticated_client):
    """Verifies that a bad or forged API key returns 401."""
    res = unauthenticated_client.post(
        "/containment/isolate",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"X-API-Key": "completely-invalid-attacker-key"},
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid authentication credentials."


def test_invalid_bearer_token_rejected(unauthenticated_client):
    """Verifies that malformed or non-existent bearer tokens return 401."""
    res = unauthenticated_client.post(
        "/containment/isolate",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"Authorization": "Bearer not-a-valid-token-at-all"},
    )
    assert res.status_code == 401


def test_jwt_invalid_signature_rejected(unauthenticated_client):
    """Verifies that a JWT signed with a different key is rejected."""
    tampered_jwt = create_test_jwt(
        identity_id="attacker",
        roles=["admin"],
        secret="wrong-secret-key-that-does-not-match-server!!",
    )
    res = unauthenticated_client.post(
        "/containment/isolate",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"Authorization": f"Bearer {tampered_jwt}"},
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid token signature."


def test_jwt_expired_token_rejected(unauthenticated_client):
    """Verifies that an expired JWT token is rejected."""
    expired_jwt = create_test_jwt(
        identity_id="expired-user",
        roles=["admin"],
        secret=TEST_JWT_SECRET,
        expires_in=-60,  # Expired 60 seconds ago
    )
    res = unauthenticated_client.post(
        "/containment/isolate",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"Authorization": f"Bearer {expired_jwt}"},
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Token has expired."


def test_jwt_unsupported_algorithm_rejected(unauthenticated_client):
    """Verifies that 'none' algorithm or unsupported algorithms are rejected."""
    alg_none_jwt = create_test_jwt(
        identity_id="hacker",
        roles=["admin"],
        secret=TEST_JWT_SECRET,
        header_alg="none",
    )
    res = unauthenticated_client.post(
        "/containment/isolate",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"Authorization": f"Bearer {alg_none_jwt}"},
    )
    assert res.status_code == 401
    assert "Unsupported token signing algorithm" in res.json()["detail"]


# ── 3. Insufficient Permissions (RBAC 403) ────────────────────────────────────


def test_insufficient_permissions_containment_rejected(unauthenticated_client):
    """An analyst with only incident:read cannot execute containment (returns 403)."""
    res = unauthenticated_client.post(
        "/containment/isolate",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"X-API-Key": "key-analyst-readonly"},
    )
    assert res.status_code == 403
    assert "Insufficient permissions" in res.json()["detail"]
    assert "containment:execute" in res.json()["detail"]


def test_insufficient_permissions_identity_suspend_rejected(unauthenticated_client):
    """A containment specialist cannot suspend identity accounts (returns 403)."""
    res = unauthenticated_client.post(
        "/identity/suspend",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"X-API-Key": "key-containment-only"},
    )
    assert res.status_code == 403
    assert "identity:suspend" in res.json()["detail"]


def test_insufficient_permissions_status_update_rejected(unauthenticated_client):
    """A readonly analyst cannot update incident status (returns 403)."""
    create_incident(
        IncidentCreate(
            alert_id="SEC-TEST-ALERT-001",
            threat_type="ransomware",
            severity=5,
            description="Test incident for status update",
            timestamp="2026-10-18T12:00:00Z",
            status=IncidentStatus.NEW,
        )
    )
    res = unauthenticated_client.patch(
        "/incidents/SEC-TEST-ALERT-001/status",
        json={"status": "CONTAINED"},
        headers={"X-API-Key": "key-analyst-readonly"},
    )
    assert res.status_code == 403
    assert "incident:write" in res.json()["detail"]


# ── 4. Authorized Requests Reach Intended Endpoints ───────────────────────────


def test_primary_api_key_authorized(unauthenticated_client):
    """Verifies that primary admin API key can execute containment."""
    res = unauthenticated_client.post(
        "/containment/isolate?dry_run=true",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"X-API-Key": TEST_API_KEY_ADMIN},
    )
    assert res.status_code == 200
    assert res.json()["status"] == STATUS_SIMULATED


def test_secondary_api_key_rotation_authorized(unauthenticated_client):
    """Verifies that secondary API key allows smooth credential rotation."""
    res = unauthenticated_client.post(
        "/containment/isolate?dry_run=true",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"X-API-Key": TEST_API_KEY_SECONDARY},
    )
    assert res.status_code == 200
    assert res.json()["status"] == STATUS_SIMULATED


def test_scoped_api_key_authorized(unauthenticated_client):
    """Verifies that scoped key-containment-only can execute containment."""
    res = unauthenticated_client.post(
        "/containment/isolate?dry_run=true",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"X-API-Key": "key-containment-only"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == STATUS_SIMULATED


def test_valid_jwt_bearer_authorized(unauthenticated_client):
    """Verifies that a validly signed JWT allows access."""
    valid_jwt = create_test_jwt(
        identity_id="secops_lead",
        roles=["admin"],
        secret=TEST_JWT_SECRET,
        expires_in=3600,
    )
    res = unauthenticated_client.post(
        "/containment/isolate?dry_run=true",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"Authorization": f"Bearer {valid_jwt}"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == STATUS_SIMULATED


# ── 5. Rejected Requests Do NOT Execute Sensitive Operations ──────────────────


def test_unauthorized_does_not_trigger_edr_client(unauthenticated_client):
    """Ensures unauthenticated requests are aborted before invoking EDR client."""
    with patch("containment.network_containment.execute_network_containment") as mock_exec:
        res = unauthenticated_client.post(
            "/containment/isolate",
            json=SAMPLE_ALERT_PAYLOAD,
            headers={"X-API-Key": "wrong-key"},
        )
        assert res.status_code == 401
        mock_exec.assert_not_called()


def test_forbidden_does_not_trigger_identity_client(unauthenticated_client):
    """Ensures forbidden requests are aborted before invoking IdP client."""
    with patch("containment.identity_response.execute_account_suspension") as mock_suspend:
        res = unauthenticated_client.post(
            "/identity/suspend",
            json=SAMPLE_ALERT_PAYLOAD,
            headers={"X-API-Key": "key-containment-only"},
        )
        assert res.status_code == 403
        mock_suspend.assert_not_called()


# ── 6. Webhook Authentication Preserved ───────────────────────────────────────


def test_webhook_with_valid_secret_succeeds(unauthenticated_client):
    """Verifies that POST /webhook/edr works with X-Webhook-Secret without requiring API key."""
    res = unauthenticated_client.post(
        "/webhook/edr?dry_run=true",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"X-Webhook-Secret": TEST_WEBHOOK_SECRET},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "received"
    assert data["alert_id"] == SAMPLE_ALERT_PAYLOAD["alert_id"]


def test_webhook_without_secret_fails(unauthenticated_client):
    """Verifies that POST /webhook/edr rejects requests lacking valid webhook secret."""
    res = unauthenticated_client.post(
        "/webhook/edr",
        json=SAMPLE_ALERT_PAYLOAD,
    )
    assert res.status_code == 401


# ── 7. Zero Secret Leakage ────────────────────────────────────────────────────


def test_secrets_never_leaked_in_error_or_logs(unauthenticated_client, caplog):
    """Verifies that secrets are not included in response bodies or log output."""
    secret_canary = "SUPER_SECRET_CANARY_VALUE_XYZ"

    with caplog.at_level(logging.DEBUG):
        res = unauthenticated_client.post(
            "/containment/isolate",
            json=SAMPLE_ALERT_PAYLOAD,
            headers={"X-API-Key": secret_canary},
        )
        assert res.status_code == 401
        assert secret_canary not in res.text
        assert secret_canary not in caplog.text
        assert TEST_API_KEY_ADMIN not in res.text
        assert TEST_API_KEY_ADMIN not in caplog.text


# ── 8. Secret Strength & Fail-Safe Missing Configuration ───────────────────────


def test_validate_api_secret_strength_helper():
    """Unit test for validate_api_secret_strength helper function."""
    from security.auth import validate_api_secret_strength

    # Valid strong secrets
    assert validate_api_secret_strength("secops-admin-key-2026") is True
    assert validate_api_secret_strength("a-very-long-and-cryptographically-random-string-12345") is True

    # Too short (< 16 characters)
    assert validate_api_secret_strength("") is False
    assert validate_api_secret_strength("short") is False
    assert validate_api_secret_strength("123456789012345") is False  # 15 chars

    # Disallowed weak/trivial/placeholder secrets
    assert validate_api_secret_strength("password") is False
    assert validate_api_secret_strength("admin") is False
    assert validate_api_secret_strength("secops-admin-key-change-me-in-production") is False
    assert validate_api_secret_strength("your-secure-webhook-secret-here") is False


def test_unconfigured_credentials_fails_safely(unauthenticated_client, monkeypatch):
    """When credentials are not set on the server, requests fail safely with 401."""
    monkeypatch.delenv("ORCHESTRATOR_API_KEY", raising=False)
    monkeypatch.delenv("ORCHESTRATOR_API_KEY_SECONDARY", raising=False)
    monkeypatch.delenv("ORCHESTRATOR_API_KEYS", raising=False)

    res = unauthenticated_client.post(
        "/containment/isolate",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"X-API-Key": "attempting-any-key-against-unconfigured-server"},
    )
    assert res.status_code == 401
    assert "Authentication credentials are not configured on the server" in res.json()["detail"]


def test_weak_credentials_not_registered(unauthenticated_client, monkeypatch):
    """Weak credentials configured in environment are ignored, failing safely."""
    monkeypatch.setenv("ORCHESTRATOR_API_KEY", "weak-key")  # < 16 chars
    monkeypatch.delenv("ORCHESTRATOR_API_KEY_SECONDARY", raising=False)
    monkeypatch.delenv("ORCHESTRATOR_API_KEYS", raising=False)

    res = unauthenticated_client.post(
        "/containment/isolate",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"X-API-Key": "weak-key"},
    )
    assert res.status_code == 401
    assert "Authentication credentials are not configured on the server" in res.json()["detail"]


def test_weak_jwt_secret_rejected(unauthenticated_client, monkeypatch):
    """Weak JWT signing secret is rejected during token validation."""
    monkeypatch.setenv("JWT_SECRET_KEY", "short-jwt-key")  # < 16 chars
    valid_jwt = create_test_jwt(
        identity_id="admin_user",
        roles=["admin"],
        secret="short-jwt-key",
    )
    res = unauthenticated_client.post(
        "/containment/isolate",
        json=SAMPLE_ALERT_PAYLOAD,
        headers={"Authorization": f"Bearer {valid_jwt}"},
    )
    assert res.status_code == 401
    assert "Server token validation misconfigured" in res.json()["detail"]


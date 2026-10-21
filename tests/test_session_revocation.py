# tests/test_session_revocation.py
"""
Unit and Integration Tests for Week 2 Day 5 -- Session Revocation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Day     : 5 -- Session Revocation and Coordinated Incident Response

Validates:
  21. Dry-run session revocation (Mode A default).
  22. Authorized mocked session revocation (Mode B live).
  23. Live execution disabled by default.
  24. Missing user ID handling.
  25. Unsupported provider operation mapping (STATUS_UNSUPPORTED).
  26. Session-revocation authentication failure (HTTP 401).
  27. Session-revocation authorization failure (HTTP 403).
  28. API timeout handling without false success.
  29. API server error handling (HTTP 500).
  30. Malformed response handling.
  31. Ambiguous revocation result handling (STATUS_UNKNOWN).
"""

from unittest.mock import MagicMock, patch
import pytest

from containment.identity_response import (
    IdentityResponsePolicy,
    clear_identity_registry,
    execute_session_revocation,
)
from incidents.database import init_db
from integrations.identity_client import (
    ACTION_REVOKE_SESSIONS,
    EXECUTION_MODE_DRY_RUN,
    EXECUTION_MODE_LIVE,
    STATUS_CONFIRMED,
    STATUS_FAILED,
    STATUS_REJECTED,
    STATUS_SIMULATED,
    STATUS_UNKNOWN,
    STATUS_UNSUPPORTED,
    EntraIDClient,
    IdentityConfig,
    IdentityConfigError,
    SimulatedIdentityClient,
    UnsupportedOperationError,
)


@pytest.fixture(autouse=True)
def isolated_session_test_env(tmp_path, monkeypatch):
    """Isolates database and clears registry for every test."""
    test_db = str(tmp_path / "test_session_revocation.db")
    monkeypatch.setenv("INCIDENTS_DB_PATH", test_db)
    monkeypatch.setenv("IDENTITY_EXECUTION_MODE", "dry_run")
    monkeypatch.setenv("IDENTITY_DRY_RUN", "true")
    init_db(test_db)
    clear_identity_registry()
    yield test_db
    clear_identity_registry()


# ─────────────────────────────────────────────────────────────────────────────
# 21. Dry-run session revocation
# ─────────────────────────────────────────────────────────────────────────────
def test_dry_run_session_revocation():
    """Test 21: In dry-run mode, session revocation returns STATUS_SIMULATED."""
    client = SimulatedIdentityClient()
    alert = {
        "alert_id": "ALERT-REV-DRY-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Ransomware detection on user endpoint",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "testuser@example.com",
    }
    res = execute_session_revocation(alert, identity_client=client, dry_run=True)
    assert res["status"] == STATUS_SIMULATED
    assert res["execution_mode"] == EXECUTION_MODE_DRY_RUN
    assert res["action"] == ACTION_REVOKE_SESSIONS
    assert "User session revocation simulated; no real sessions revoked" in res["message"]
    assert res["user_id"] == "c0a80101-0001-0000-0000-000000000001"


# ─────────────────────────────────────────────────────────────────────────────
# 22. Authorized mocked session revocation
# ─────────────────────────────────────────────────────────────────────────────
def test_authorized_mocked_session_revocation():
    """Test 22: In live mode with mock client, returns STATUS_CONFIRMED."""
    client = SimulatedIdentityClient()
    alert = {
        "alert_id": "ALERT-REV-LIVE-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_session_revocation(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_CONFIRMED
    assert res["execution_mode"] == EXECUTION_MODE_LIVE
    assert res["action"] == ACTION_REVOKE_SESSIONS
    assert res["action_id"] == "sim-revoke-c0a80101-0003-0000-0000-000000000003"
    assert "confirmed" in res["message"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# 23. Live execution disabled by default
# ─────────────────────────────────────────────────────────────────────────────
def test_session_revocation_live_disabled_by_default(monkeypatch):
    """Test 23: Default configuration enforces safe dry-run mode."""
    monkeypatch.delenv("IDENTITY_EXECUTION_MODE", raising=False)
    monkeypatch.delenv("IDENTITY_DRY_RUN", raising=False)

    client = SimulatedIdentityClient()
    alert = {
        "alert_id": "ALERT-REV-DEF-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical threat",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_session_revocation(alert, identity_client=client)
    assert res["status"] == STATUS_SIMULATED
    assert res["execution_mode"] == EXECUTION_MODE_DRY_RUN


# ─────────────────────────────────────────────────────────────────────────────
# 24. Missing user ID
# ─────────────────────────────────────────────────────────────────────────────
def test_session_revocation_missing_user_id():
    """Test 24: Missing user ID in alert telemetry safely rejects without IdP call."""
    client = SimulatedIdentityClient()
    alert = {
        "alert_id": "ALERT-NO-USER-REV-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical threat",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "ip_address": "10.0.0.50",  # IP only, no user
    }
    res = execute_session_revocation(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_REJECTED
    assert "No user identification found" in res["message"]


# ─────────────────────────────────────────────────────────────────────────────
# 25. Unsupported provider operation
# ─────────────────────────────────────────────────────────────────────────────
def test_unsupported_provider_operation():
    """Test 25: Providers lacking session revocation capability return STATUS_UNSUPPORTED."""
    client = SimulatedIdentityClient()
    client.simulate_unsupported = True

    alert = {
        "alert_id": "ALERT-UNSUP-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_session_revocation(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_UNSUPPORTED
    assert "unsupported" in res["message"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# 26. Session-revocation authentication failure
# ─────────────────────────────────────────────────────────────────────────────
def test_session_revocation_authentication_failure():
    """Test 26: Authentication failure during session revocation returns STATUS_FAILED."""
    client = SimulatedIdentityClient()
    client.simulate_auth_failure = True

    alert = {
        "alert_id": "ALERT-REV-AUTH-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_session_revocation(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_FAILED
    assert "authentication failure" in res["message"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# 27. Session-revocation authorization failure
# ─────────────────────────────────────────────────────────────────────────────
def test_session_revocation_authorization_failure():
    """Test 27: Authorization failure (HTTP 403) returns STATUS_FAILED."""
    client = SimulatedIdentityClient()
    client.simulate_authz_failure = True

    alert = {
        "alert_id": "ALERT-REV-AUTHZ-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_session_revocation(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_FAILED
    assert "authorization" in res["message"].lower() or "permissions" in res["message"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# 28. API timeout
# ─────────────────────────────────────────────────────────────────────────────
def test_session_revocation_api_timeout():
    """Test 28: Network timeout during session revocation returns STATUS_FAILED without false success."""
    client = SimulatedIdentityClient()
    client.simulate_timeout = True

    alert = {
        "alert_id": "ALERT-REV-TIMEOUT-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_session_revocation(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_FAILED
    assert "timeout" in res["message"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# 29. API server error
# ─────────────────────────────────────────────────────────────────────────────
def test_session_revocation_api_server_error():
    """Test 29: Server error (HTTP 500) returns STATUS_FAILED."""
    client = SimulatedIdentityClient()
    client.simulate_server_error = True

    alert = {
        "alert_id": "ALERT-REV-500-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_session_revocation(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_FAILED
    assert "server error" in res["message"].lower() or "500" in res["message"]


# ─────────────────────────────────────────────────────────────────────────────
# 30. Malformed response
# ─────────────────────────────────────────────────────────────────────────────
def test_session_revocation_malformed_response():
    """Test 30: Malformed response from IdP is handled without crashing."""
    client = SimulatedIdentityClient()
    client.simulate_malformed = True

    alert = {
        "alert_id": "ALERT-REV-MAL-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_session_revocation(alert, identity_client=client, dry_run=False)
    assert res["status"] in (STATUS_UNKNOWN, STATUS_FAILED)


# ─────────────────────────────────────────────────────────────────────────────
# 31. Ambiguous revocation result
# ─────────────────────────────────────────────────────────────────────────────
def test_session_revocation_ambiguous_result():
    """Test 31: Ambiguous provider response is mapped to STATUS_UNKNOWN."""
    client = SimulatedIdentityClient()
    client.simulate_ambiguous_result = True

    alert = {
        "alert_id": "ALERT-REV-AMB-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_session_revocation(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_UNKNOWN
    assert res["status"] != STATUS_CONFIRMED

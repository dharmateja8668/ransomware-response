# tests/test_identity_client.py
"""
Unit and Integration Tests for Week 2 Day 4 -- Identity Provider Integration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Day     : 4 -- Identity Provider Integration and Account Suspension

Validates:
  1.  Valid user lookup.
  2.  User not found.
  3.  Ambiguous user lookup.
  4.  Missing username.
  5.  Missing directory user ID.
  6.  Invalid alert.
  7.  Ineligible account (already disabled).
  8.  Dry-run account suspension (Mode A default).
  9.  Live execution disabled by default.
  10. Missing credentials for live mode.
  11. Authentication failure (HTTP 401).
  12. Authorization failure (HTTP 403).
  13. Identity-provider timeout.
  14. Server error (HTTP 500).
  15. Malformed response handling.
  16. Successful mocked suspension.
  17. Ambiguous suspension result handling.
  18. Emergency administrator account protection.
  19. Service-account protection.
  20. Zero real account modification during test suite execution.
"""

import os
from unittest.mock import MagicMock, patch
import pytest

from containment.identity_response import (
    IdentityResponsePolicy,
    clear_identity_registry,
    execute_account_suspension,
    extract_user_identifier,
    is_account_protected,
)
from incidents.database import init_db
from integrations.identity_client import (
    ACTION_SUSPEND_ACCOUNT,
    EXECUTION_MODE_DRY_RUN,
    EXECUTION_MODE_LIVE,
    STATUS_CONFIRMED,
    STATUS_FAILED,
    STATUS_NOT_RECOMMENDED,
    STATUS_REJECTED,
    STATUS_SIMULATED,
    STATUS_UNKNOWN,
    AmbiguousUserError,
    EntraIDClient,
    IdentityActionResult,
    IdentityAPIError,
    IdentityAuthError,
    IdentityConfig,
    IdentityConfigError,
    IdentityConnectionError,
    IdentityProvider,
    IdentityTimeoutError,
    SimulatedIdentityClient,
    UserNotFoundError,
    create_identity_client,
)


@pytest.fixture(autouse=True)
def isolated_identity_test_env(tmp_path, monkeypatch):
    """Isolates database and clears identity action registry for every test."""
    test_db = str(tmp_path / "test_identity.db")
    monkeypatch.setenv("INCIDENTS_DB_PATH", test_db)
    monkeypatch.setenv("IDENTITY_EXECUTION_MODE", "dry_run")
    monkeypatch.setenv("IDENTITY_DRY_RUN", "true")
    init_db(test_db)
    clear_identity_registry()
    yield test_db
    clear_identity_registry()


# ─────────────────────────────────────────────────────────────────────────────
# 1. Valid user lookup
# ─────────────────────────────────────────────────────────────────────────────
def test_valid_user_lookup():
    """Test 1: Valid user lookup successfully resolves directory user identity."""
    client = SimulatedIdentityClient()
    user = client.resolve_user("testuser@example.com")
    assert user is not None
    assert user.user_principal_name == "testuser@example.com"
    assert user.user_id == "c0a80101-0001-0000-0000-000000000001"
    assert user.account_enabled is True
    assert user.department == "Engineering"


# ─────────────────────────────────────────────────────────────────────────────
# 2. User not found
# ─────────────────────────────────────────────────────────────────────────────
def test_user_not_found():
    """Test 2: Non-existent user identifier safely returns None."""
    client = SimulatedIdentityClient()
    user = client.resolve_user("nonexistent.user.999@contoso.com")
    assert user is None

    # Account suspension for unknown user safely rejects
    alert = {
        "alert_id": "ALERT-NF-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware detected",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "nonexistent.user.999@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=True)
    assert res["status"] == STATUS_REJECTED
    assert "could not be resolved" in res["message"]


# ─────────────────────────────────────────────────────────────────────────────
# 3. Ambiguous user lookup
# ─────────────────────────────────────────────────────────────────────────────
def test_ambiguous_user_lookup():
    """Test 3: Identifier matching multiple directory users raises AmbiguousUserError and rejects."""
    client = SimulatedIdentityClient()
    with pytest.raises(AmbiguousUserError) as exc_info:
        client.resolve_user("ambiguous@contoso.com")
    assert "Multiple directory user accounts" in str(exc_info.value)

    # Workflow safely rejects ambiguous identity
    alert = {
        "alert_id": "ALERT-AMB-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware detected",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "ambiguous@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=True)
    assert res["status"] == STATUS_REJECTED
    assert "Ambiguous user identity" in res["message"]


# ─────────────────────────────────────────────────────────────────────────────
# 4. Missing username
# ─────────────────────────────────────────────────────────────────────────────
def test_missing_username():
    """Test 4: Alert with missing user telemetry is rejected without IdP interaction."""
    client = SimulatedIdentityClient()
    alert = {
        "alert_id": "ALERT-NO-USER-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware detected",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "ip_address": "192.168.1.100",  # Only IP, no username
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=True)
    assert res["status"] == STATUS_REJECTED
    assert "No user identification found" in res["message"]


# ─────────────────────────────────────────────────────────────────────────────
# 5. Missing directory user ID
# ─────────────────────────────────────────────────────────────────────────────
def test_missing_directory_user_id_fallback():
    """Test 5: When directory user ID is missing, system falls back to UPN / username."""
    client = SimulatedIdentityClient()
    alert = {
        "alert_id": "ALERT-FALLBACK-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware detected",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "testuser",  # Plain username without directory UUID
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=True)
    assert res["status"] == STATUS_SIMULATED
    assert res["user_id"] == "c0a80101-0001-0000-0000-000000000001"
    assert res["user_principal_name"] == "testuser@example.com"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Invalid alert
# ─────────────────────────────────────────────────────────────────────────────
def test_invalid_alert():
    """Test 6: Malformed alert missing required fields is rejected safely."""
    client = SimulatedIdentityClient()
    invalid_alert = {"alert_id": "", "severity": "bad_sev"}
    res = execute_account_suspension(invalid_alert, identity_client=client, dry_run=True)
    assert res["status"] == STATUS_REJECTED
    assert "Alert validation failed" in res["message"]


# ─────────────────────────────────────────────────────────────────────────────
# 7. Ineligible account
# ─────────────────────────────────────────────────────────────────────────────
def test_ineligible_account_already_disabled():
    """Test 7: Attempting suspension on an already disabled user is rejected as ineligible."""
    client = SimulatedIdentityClient()
    alert = {
        "alert_id": "ALERT-DIS-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Ransomware detection on disabled employee machine",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "disabled.user@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=True)
    assert res["status"] == STATUS_REJECTED
    assert "already disabled/ineligible" in res["message"]


# ─────────────────────────────────────────────────────────────────────────────
# 8. Dry-run account suspension
# ─────────────────────────────────────────────────────────────────────────────
def test_dry_run_account_suspension():
    """Test 8: Default dry-run mode returns SIMULATED and does not modify user."""
    client = SimulatedIdentityClient()
    alert = {
        "alert_id": "ALERT-DRY-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware detected",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "compromised.user@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=True)
    assert res["status"] == STATUS_SIMULATED
    assert res["execution_mode"] == EXECUTION_MODE_DRY_RUN
    assert "Account suspension simulated; no account modified" in res["message"]
    assert res["user_id"] == "c0a80101-0002-0000-0000-000000000002"

    # User in client directory remains enabled
    target_user = client.get_user("c0a80101-0002-0000-0000-000000000002")
    assert target_user.account_enabled is True


# ─────────────────────────────────────────────────────────────────────────────
# 9. Live execution disabled by default
# ─────────────────────────────────────────────────────────────────────────────
def test_live_execution_disabled_by_default(monkeypatch):
    """Test 9: When no execution mode is explicitly passed, dry_run defaults to True."""
    monkeypatch.delenv("IDENTITY_EXECUTION_MODE", raising=False)
    monkeypatch.delenv("IDENTITY_DRY_RUN", raising=False)

    cfg = IdentityConfig()
    assert cfg.dry_run is True

    client = SimulatedIdentityClient(cfg)
    alert = {
        "alert_id": "ALERT-DEFAULT-DRY-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Ransomware detection",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client)
    assert res["status"] == STATUS_SIMULATED
    assert res["execution_mode"] == EXECUTION_MODE_DRY_RUN


# ─────────────────────────────────────────────────────────────────────────────
# 10. Missing credentials
# ─────────────────────────────────────────────────────────────────────────────
def test_missing_credentials_handled_safely(monkeypatch):
    """Test 10: Missing credentials in live mode raises IdentityConfigError."""
    monkeypatch.setenv("IDENTITY_PROVIDER", "entra_id")
    monkeypatch.setenv("IDENTITY_EXECUTION_MODE", "live")
    monkeypatch.setenv("IDENTITY_DRY_RUN", "false")
    monkeypatch.delenv("IDENTITY_CLIENT_ID", raising=False)
    monkeypatch.delenv("IDENTITY_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("IDENTITY_TENANT_ID", raising=False)

    with pytest.raises(IdentityConfigError) as exc_info:
        IdentityConfig()
    assert "Live Entra ID execution requires" in str(exc_info.value)


# ─────────────────────────────────────────────────────────────────────────────
# 11. Authentication failure
# ─────────────────────────────────────────────────────────────────────────────
def test_authentication_failure():
    """Test 11: IdP authentication failure (HTTP 401) results in STATUS_FAILED."""
    client = SimulatedIdentityClient()
    client.simulate_auth_failure = True

    alert = {
        "alert_id": "ALERT-AUTH-FAIL-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_FAILED
    assert "authentication failure" in res["message"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# 12. Authorization failure
# ─────────────────────────────────────────────────────────────────────────────
def test_authorization_failure():
    """Test 12: IdP authorization failure (HTTP 403) results in STATUS_FAILED."""
    client = SimulatedIdentityClient()
    client.simulate_authz_failure = True

    alert = {
        "alert_id": "ALERT-AUTHZ-FAIL-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_FAILED
    assert "authorization" in res["message"].lower() or "permission" in res["message"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# 13. Identity-provider timeout
# ─────────────────────────────────────────────────────────────────────────────
def test_identity_provider_timeout():
    """Test 13: Identity provider API timeout is handled gracefully without false success."""
    client = SimulatedIdentityClient()
    client.simulate_timeout = True

    alert = {
        "alert_id": "ALERT-TIMEOUT-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_FAILED
    assert "timeout" in res["message"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# 14. Server error
# ─────────────────────────────────────────────────────────────────────────────
def test_server_error():
    """Test 14: Server error (HTTP 500) returns STATUS_FAILED without crashing."""
    client = SimulatedIdentityClient()
    client.simulate_server_error = True

    alert = {
        "alert_id": "ALERT-500-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_FAILED
    assert "server error" in res["message"].lower() or "500" in res["message"]


# ─────────────────────────────────────────────────────────────────────────────
# 15. Malformed response
# ─────────────────────────────────────────────────────────────────────────────
def test_malformed_response():
    """Test 15: Malformed IdP response is mapped to STATUS_UNKNOWN without crashing."""
    client = SimulatedIdentityClient()
    client.simulate_malformed = True

    alert = {
        "alert_id": "ALERT-MAL-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=False)
    assert res["status"] in (STATUS_UNKNOWN, STATUS_FAILED)


# ─────────────────────────────────────────────────────────────────────────────
# 16. Successful mocked suspension
# ─────────────────────────────────────────────────────────────────────────────
def test_successful_mocked_suspension():
    """Test 16: Authorized mocked account suspension returns CONFIRMED."""
    client = SimulatedIdentityClient()
    alert = {
        "alert_id": "ALERT-CONF-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_CONFIRMED
    assert res["execution_mode"] == EXECUTION_MODE_LIVE
    assert res["action_id"] == "sim-susp-c0a80101-0003-0000-0000-000000000003"
    assert "confirmed" in res["message"].lower()

    # In-memory target is now disabled
    target = client.get_user("c0a80101-0003-0000-0000-000000000003")
    assert target.account_enabled is False


# ─────────────────────────────────────────────────────────────────────────────
# 17. Ambiguous suspension result
# ─────────────────────────────────────────────────────────────────────────────
def test_ambiguous_suspension_result():
    """Test 17: Ambiguous response from IdP preserves uncertainty (STATUS_UNKNOWN)."""
    client = SimulatedIdentityClient()
    client.simulate_ambiguous_result = True

    alert = {
        "alert_id": "ALERT-AMB-RESP-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Critical ransomware",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "victim@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_UNKNOWN
    assert res["status"] != STATUS_CONFIRMED


# ─────────────────────────────────────────────────────────────────────────────
# 18. Emergency administrator protection
# ─────────────────────────────────────────────────────────────────────────────
def test_emergency_administrator_protection():
    """Test 18: Emergency break-glass administrator account is shielded from automated suspension."""
    client = SimulatedIdentityClient()
    alert = {
        "alert_id": "ALERT-EMERGENCY-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Compromise detection on admin account",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "breakglass-admin@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_REJECTED
    assert "protected" in res["message"].lower()

    # User remains enabled
    target = client.get_user("c0a80101-0005-0000-0000-000000000005")
    assert target.account_enabled is True


# ─────────────────────────────────────────────────────────────────────────────
# 19. Service-account protection
# ─────────────────────────────────────────────────────────────────────────────
def test_service_account_protection():
    """Test 19: Orchestrator service account is shielded from automated suspension."""
    client = SimulatedIdentityClient()
    alert = {
        "alert_id": "ALERT-SVC-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Suspicious activity detected on orchestrator service account",
        "timestamp": "2026-10-18T10:00:00Z",
        "endpoint_id": "EP-001",
        "username": "svc-orchestrator@contoso.com",
    }
    res = execute_account_suspension(alert, identity_client=client, dry_run=False)
    assert res["status"] == STATUS_REJECTED
    assert "protected" in res["message"].lower()

    target = client.get_user("c0a80101-0006-0000-0000-000000000006")
    assert target.account_enabled is True


# ─────────────────────────────────────────────────────────────────────────────
# 20. No real account modification during tests
# ─────────────────────────────────────────────────────────────────────────────
def test_no_real_account_modification_during_tests():
    """Test 20: Ensures that no live network requests to Microsoft Graph API occur during tests."""
    with patch("requests.Session.patch") as mock_patch, patch("requests.Session.post") as mock_post:
        client = SimulatedIdentityClient()
        alert = {
            "alert_id": "ALERT-NO-NET-001",
            "threat_type": "ransomware",
            "severity": 5,
            "description": "Critical ransomware",
            "timestamp": "2026-10-18T10:00:00Z",
            "endpoint_id": "EP-001",
            "username": "testuser@example.com",
        }
        res = execute_account_suspension(alert, identity_client=client, dry_run=True)
        assert res["status"] == STATUS_SIMULATED
        mock_patch.assert_not_called()
        mock_post.assert_not_called()

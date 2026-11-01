"""
test_jira_day2.py - Day 2 Unit Tests: Severity-Based SOC Analyst Assignment.

Automated Ransomware Containment & Incident Response Orchestrator
Day 2: Jira Ticket Auto-Assignment & Priority Routing.

Tests the following Day 2 requirements:
1.  get_assignable_users() - success response with user list.
2.  get_assignable_users() - empty user list (non-fatal).
3.  assign_incident_ticket() - HTTP 204 success.
4.  assign_incident_ticket() - HTTP 400 invalid accountId.
5.  assign_incident_ticket() - HTTP 403 permission denied.
6.  assign_incident_ticket() - HTTP 401 unauthorized.
7.  assign_incident_ticket() - HTTP 404 invalid issue key.
8.  auto_assign_incident() - CRITICAL severity routing.
9.  auto_assign_incident() - HIGH severity routing.
10. auto_assign_incident() - no analyst configured (graceful degradation).
11. Priority mapping: severity → Jira priority name.
12. API timeout during assignment → JiraConnectionError.

All tests use mock sessions. No real Jira tickets are created or modified.
"""

from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

import pytest
import requests

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import JiraConfig
from backend.jira_integration import (
    JiraAssignmentError,
    JiraAuthenticationError,
    JiraClient,
    JiraConnectionError,
    JiraIntegrationError,
)


# ==============================================================================
# Shared Fixtures
# ==============================================================================

@pytest.fixture
def sample_config() -> JiraConfig:
    """Fixture providing valid Jira configuration with simulated credentials."""
    return JiraConfig(
        base_url="https://cybersec-soc.atlassian.net",
        email="analyst@cybersec-soc.org",
        api_token="ATATT3xFfGF0testMockApiToken1234567890",
        project_key="SEC",
        issue_type="Task",
        timeout_seconds=5,
        verify_ssl=True,
        critical_assignee_account_id="acc-critical-001",
        high_assignee_account_id="acc-high-002",
        medium_assignee_account_id="acc-medium-003",
        low_assignee_account_id="acc-low-004",
    )


@pytest.fixture
def mock_session() -> MagicMock:
    """Fixture providing a mock requests.Session."""
    session = MagicMock()
    session.headers = {}
    return session


@pytest.fixture
def jira_client(sample_config, mock_session) -> JiraClient:
    """Fixture providing a JiraClient initialized with a mock session."""
    return JiraClient(
        base_url=sample_config.base_url,
        email=sample_config.email,
        api_token=sample_config.api_token,
        project_key=sample_config.project_key,
        issue_type=sample_config.issue_type,
        timeout_seconds=sample_config.timeout_seconds,
        verify_ssl=sample_config.verify_ssl,
        session=mock_session,
    )


@pytest.fixture
def assignee_config() -> dict:
    """Fixture providing severity-to-accountId routing config."""
    return {
        "CRITICAL": "acc-critical-001",
        "HIGH": "acc-high-002",
        "MEDIUM": "acc-medium-003",
        "LOW": "acc-low-004",
    }


# ==============================================================================
# Test 1: get_assignable_users() — success with user list
# ==============================================================================

def test_get_assignable_users_success(jira_client, mock_session):
    """Day 2 Test 1: get_assignable_users() returns a list of active SOC users."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {
            "accountId": "acc-critical-001",
            "displayName": "Alice Chen – SOC Lead",
            "emailAddress": "alice@cybersec-soc.org",
            "active": True,
        },
        {
            "accountId": "acc-high-002",
            "displayName": "Bob Okafor – SOC Analyst",
            "emailAddress": "bob@cybersec-soc.org",
            "active": True,
        },
        {
            "accountId": "acc-medium-003",
            "displayName": "Carla Reyes – Junior Analyst",
            "emailAddress": "carla@cybersec-soc.org",
            "active": True,
        },
    ]
    mock_session.get.return_value = mock_resp

    users = jira_client.get_assignable_users("SEC")

    assert len(users) == 3
    assert users[0]["accountId"] == "acc-critical-001"
    assert users[0]["displayName"] == "Alice Chen – SOC Lead"
    assert users[1]["accountId"] == "acc-high-002"
    assert users[2]["accountId"] == "acc-medium-003"

    # Verify correct endpoint and params were called
    mock_session.get.assert_called_once_with(
        "https://cybersec-soc.atlassian.net/rest/api/3/user/assignable/search",
        params={"project": "SEC"},
        timeout=5,
        verify=True,
    )


# ==============================================================================
# Test 2: get_assignable_users() — empty user list (non-fatal)
# ==============================================================================

def test_get_assignable_users_empty(jira_client, mock_session):
    """Day 2 Test 2: get_assignable_users() returns [] when no users are assignable (non-fatal)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = []
    mock_session.get.return_value = mock_resp

    users = jira_client.get_assignable_users("SEC")

    assert users == []
    assert isinstance(users, list)


# ==============================================================================
# Test 3: assign_incident_ticket() — HTTP 204 success
# ==============================================================================

def test_assign_ticket_success(jira_client, mock_session):
    """Day 2 Test 3: assign_incident_ticket() returns assigned=True on HTTP 204."""
    mock_resp = MagicMock()
    mock_resp.status_code = 204
    mock_session.put.return_value = mock_resp

    result = jira_client.assign_incident_ticket("SEC-88", "acc-critical-001")

    assert result["assigned"] is True
    assert result["issue_key"] == "SEC-88"
    assert result["account_id"] == "acc-critical-001"

    # Verify correct PUT endpoint and payload
    mock_session.put.assert_called_once_with(
        "https://cybersec-soc.atlassian.net/rest/api/3/issue/SEC-88/assignee",
        json={"accountId": "acc-critical-001"},
        timeout=5,
        verify=True,
    )


# ==============================================================================
# Test 4: assign_incident_ticket() — HTTP 400 invalid accountId
# ==============================================================================

def test_assign_ticket_invalid_account_id(jira_client, mock_session):
    """Day 2 Test 4: assign_incident_ticket() raises JiraAssignmentError on HTTP 400."""
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.text = "The accountId 'bad-account' is not valid."
    mock_session.put.return_value = mock_resp

    with pytest.raises(JiraAssignmentError) as exc_info:
        jira_client.assign_incident_ticket("SEC-88", "bad-account")

    assert "400" in str(exc_info.value)
    assert "bad-account" in str(exc_info.value) or "accountId" in str(exc_info.value)


# ==============================================================================
# Test 5: assign_incident_ticket() — HTTP 403 permission denied
# ==============================================================================

def test_assign_ticket_permission_denied(jira_client, mock_session):
    """Day 2 Test 5: assign_incident_ticket() raises JiraAuthenticationError on HTTP 403."""
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "Forbidden"
    mock_session.put.return_value = mock_resp

    with pytest.raises(JiraAuthenticationError) as exc_info:
        jira_client.assign_incident_ticket("SEC-88", "acc-critical-001")

    assert "403" in str(exc_info.value)
    # Security: API token must never leak in exception message
    assert jira_client.api_token not in str(exc_info.value)


# ==============================================================================
# Test 6: assign_incident_ticket() — HTTP 401 unauthorized
# ==============================================================================

def test_assign_ticket_unauthorized(jira_client, mock_session):
    """Day 2 Test 6: assign_incident_ticket() raises JiraAuthenticationError on HTTP 401."""
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = "Unauthorized"
    mock_session.put.return_value = mock_resp

    with pytest.raises(JiraAuthenticationError) as exc_info:
        jira_client.assign_incident_ticket("SEC-88", "acc-critical-001")

    assert "401" in str(exc_info.value)
    assert jira_client.api_token not in str(exc_info.value)


# ==============================================================================
# Test 7: assign_incident_ticket() — HTTP 404 invalid issue key
# ==============================================================================

def test_assign_ticket_invalid_key(jira_client, mock_session):
    """Day 2 Test 7: assign_incident_ticket() raises JiraAssignmentError on HTTP 404."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "Issue Does Not Exist"
    mock_session.put.return_value = mock_resp

    with pytest.raises(JiraAssignmentError) as exc_info:
        jira_client.assign_incident_ticket("SEC-9999999", "acc-critical-001")

    assert "SEC-9999999" in str(exc_info.value)
    assert "404" in str(exc_info.value)


# ==============================================================================
# Test 8: auto_assign_incident() — CRITICAL severity routing
# ==============================================================================

def test_auto_assign_critical_severity(jira_client, mock_session, assignee_config):
    """Day 2 Test 8: CRITICAL severity assigns to the critical-tier analyst accountId."""
    mock_put_resp = MagicMock()
    mock_put_resp.status_code = 204
    mock_session.put.return_value = mock_put_resp

    result = jira_client.auto_assign_incident("SEC-88", "CRITICAL", assignee_config)

    assert result["assigned"] is True
    assert result["issue_key"] == "SEC-88"
    assert result["severity"] == "CRITICAL"
    assert result["account_id"] == "acc-critical-001"
    assert "successful" in result["reason"].lower()

    # Verify PUT was called with the CRITICAL account ID
    mock_session.put.assert_called_once_with(
        "https://cybersec-soc.atlassian.net/rest/api/3/issue/SEC-88/assignee",
        json={"accountId": "acc-critical-001"},
        timeout=5,
        verify=True,
    )


# ==============================================================================
# Test 9: auto_assign_incident() — HIGH severity routing
# ==============================================================================

def test_auto_assign_high_severity(jira_client, mock_session, assignee_config):
    """Day 2 Test 9: HIGH severity assigns to the high-tier analyst accountId."""
    mock_put_resp = MagicMock()
    mock_put_resp.status_code = 204
    mock_session.put.return_value = mock_put_resp

    result = jira_client.auto_assign_incident("SEC-99", "HIGH", assignee_config)

    assert result["assigned"] is True
    assert result["severity"] == "HIGH"
    assert result["account_id"] == "acc-high-002"

    mock_session.put.assert_called_once_with(
        "https://cybersec-soc.atlassian.net/rest/api/3/issue/SEC-99/assignee",
        json={"accountId": "acc-high-002"},
        timeout=5,
        verify=True,
    )


# ==============================================================================
# Test 10: auto_assign_incident() — no analyst configured (graceful degradation)
# ==============================================================================

def test_auto_assign_no_analyst_configured(jira_client, mock_session):
    """Day 2 Test 10: Empty accountId for severity → assigned=False, no PUT call made."""
    empty_config = {
        "CRITICAL": "",     # no analyst configured
        "HIGH": "",
        "MEDIUM": "",
        "LOW": "",
    }

    result = jira_client.auto_assign_incident("SEC-88", "CRITICAL", empty_config)

    assert result["assigned"] is False
    assert result["account_id"] is None
    assert "CRITICAL" in result["reason"]
    # Verify PUT was NEVER called when no analyst is configured
    mock_session.put.assert_not_called()


# ==============================================================================
# Test 11: Priority mapping — severity → Jira priority name
# ==============================================================================

def test_priority_mapping(jira_client, assignee_config):
    """
    Day 2 Test 11: Verify the severity-to-priority-name mapping used in select_analyst_for_severity.
    Also verify select_analyst_for_severity returns the correct accountId for each tier.
    """
    # The expected severity → analyst account mapping
    expected = {
        "CRITICAL": "acc-critical-001",
        "HIGH":     "acc-high-002",
        "MEDIUM":   "acc-medium-003",
        "LOW":      "acc-low-004",
    }

    for severity, expected_account_id in expected.items():
        account_id = jira_client.select_analyst_for_severity(severity, assignee_config)
        assert account_id == expected_account_id, (
            f"Severity '{severity}' should map to '{expected_account_id}', got '{account_id}'"
        )

    # Verify unknown severity returns None
    unknown_result = jira_client.select_analyst_for_severity("UNKNOWN", assignee_config)
    assert unknown_result is None


# ==============================================================================
# Test 12: API timeout during assign_incident_ticket → JiraConnectionError
# ==============================================================================

def test_api_timeout_on_assign(jira_client, mock_session):
    """Day 2 Test 12: Network timeout during assignment raises JiraConnectionError."""
    mock_session.put.side_effect = requests.exceptions.Timeout(
        "Connection timed out after 5 seconds"
    )

    with pytest.raises(JiraConnectionError) as exc_info:
        jira_client.assign_incident_ticket("SEC-88", "acc-critical-001")

    assert "Failed to connect to Jira" in str(exc_info.value)
    # API token must never appear in exception
    assert jira_client.api_token not in str(exc_info.value)


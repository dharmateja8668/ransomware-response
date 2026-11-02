"""
test_incident_notifications.py - Comprehensive Unit & Integration Test Suite.

Automated Ransomware Containment & Incident Response Orchestrator
Week 4 Day 3 - Task 2: Jira + Slack Integration.

Tests the following 15 required test cases:
1. Successful Jira ticket creation and Slack notification.
2. Critical incident notification (🔴 Critical Alert indicator).
3. High severity notification (🟠 High Alert indicator).
4. Medium severity notification (🟡 Medium Alert indicator).
5. Low severity notification (🟢 Low Alert indicator).
6. Jira ticket creation failure (notification aborted/suppressed).
7. Jira assignment failure (UNASSIGNED status, ticket URL included).
8. Slack HTTP failure (safe handling, Jira ticket preserved).
9. Slack network connection failure (safe error recovery).
10. Slack webhook not configured (NOT_CONFIGURED status, Jira continues).
11. Missing incident details (rejected before processing).
12. Correct Jira ticket URL generation (verified in text and blocks).
13. Correct analyst information in Slack message (role and status verified).
14. No duplicate notification within a single workflow execution (idempotency).
15. Jira workflow continues when Slack notification fails (resilience).

Plus:
- Full end-to-end workflow simulation test with mocked Jira and Slack clients.
"""

from datetime import datetime, timezone
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

import pytest
import requests

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import SlackConfig
from backend.incident_notifications import (
    IncidentNotificationService,
    SEVERITY_INDICATORS,
    DEFAULT_SEVERITY_ROLES,
)
from backend.jira_integration import IncidentData
from backend.main import run_orchestrator, run_notification_workflow_test
from backend.slack_integration import SlackClient


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture
def sample_incident() -> dict:
    """Fixture providing standard simulated ransomware incident telemetry."""
    return {
        "incident_id": "INC-2026-001",
        "incident_type": "Ransomware (LockBit 3.0)",
        "severity": "CRITICAL",
        "hostname": "TEST-WORKSTATION-01",
        "ip_address": "192.168.1.105",
        "username": "test_user",
        "process_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "detection_time": "2026-11-03 10:30:00 UTC",
        "incident_description": "Canary tripwire file encrypted on endpoint.",
        "source": "EDR Detection",
    }


@pytest.fixture
def sample_ticket() -> dict:
    """Fixture providing simulated successful Jira ticket creation response."""
    return {
        "status": "Created",
        "ticket_key": "RR-10",
        "ticket_id": "10580",
        "ticket_url": "https://zaalima.atlassian.net/browse/RR-10",
        "project_key": "RR",
        "severity": "CRITICAL",
        "summary": "[CRITICAL] Ransomware Detected - TEST-WORKSTATION-01",
    }


@pytest.fixture
def sample_assignment() -> dict:
    """Fixture providing simulated successful Jira ticket assignment outcome."""
    return {
        "assigned": True,
        "issue_key": "RR-10",
        "account_id": "712020:8104d0f4-4513-498e-a474-954999d59be2",
        "role": "Senior SOC Lead",
        "reason": "Successfully assigned to Senior SOC Lead based on CRITICAL severity.",
    }


@pytest.fixture
def mock_slack_session() -> MagicMock:
    """Fixture providing a mock requests.Session returning HTTP 200."""
    session = MagicMock(spec=requests.Session)
    session.headers = {}
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"
    session.post.return_value = mock_resp
    return session


@pytest.fixture
def notification_service(mock_slack_session) -> IncidentNotificationService:
    """Fixture providing an IncidentNotificationService with a mocked SlackClient."""
    client = SlackClient(
        webhook_url="https://hooks.slack.com/services/T123/B456/dummytoken789",
        session=mock_slack_session,
    )
    return IncidentNotificationService(slack_client=client)


# ==============================================================================
# 1. Successful Jira Ticket Creation and Slack Notification
# ==============================================================================

def test_successful_jira_creation_and_slack_notification(
    notification_service, sample_incident, sample_ticket, sample_assignment, mock_slack_session
):
    """CASE 1: Successful Jira ticket creation and assignment triggers Slack notification."""
    result = notification_service.notify_incident(
        incident_data=sample_incident,
        ticket_data=sample_ticket,
        assignment_data=sample_assignment,
    )

    assert result["success"] is True
    assert result["status"] == "DELIVERED"
    assert result["ticket_key"] == "RR-10"
    assert result["incident_id"] == "INC-2026-001"

    # Verify Slack POST call occurred with expected URL & payload
    mock_slack_session.post.assert_called_once()
    _, call_kwargs = mock_slack_session.post.call_args
    payload = call_kwargs["json"]

    assert "text" in payload
    assert "blocks" in payload
    assert "RR-10" in payload["text"]
    assert "https://zaalima.atlassian.net/browse/RR-10" in payload["text"]
    assert "INC-2026-001" in payload["text"]
    assert "INCIDENT TICKET CREATED AND ASSIGNED" in payload["text"]


# ==============================================================================
# 2-5. Severity-Based Visual Alert Indicators (CRITICAL, HIGH, MEDIUM, LOW)
# ==============================================================================

def test_critical_severity_notification(notification_service, sample_incident, sample_ticket, sample_assignment, mock_slack_session):
    """CASE 2: CRITICAL severity formats with 🔴 Critical Alert."""
    sample_incident["severity"] = "CRITICAL"
    result = notification_service.notify_incident(sample_incident, sample_ticket, sample_assignment)

    assert result["success"] is True
    _, call_kwargs = mock_slack_session.post.call_args
    sent_text = call_kwargs["json"]["text"]
    assert "🔴 Critical Alert" in sent_text
    assert "CRITICAL" in sent_text


def test_high_severity_notification(notification_service, sample_incident, sample_ticket, sample_assignment, mock_slack_session):
    """CASE 3: HIGH severity formats with 🟠 High Alert."""
    sample_incident["severity"] = "HIGH"
    sample_assignment["role"] = "SOC Analyst (Tier 2)"
    result = notification_service.notify_incident(sample_incident, sample_ticket, sample_assignment)

    assert result["success"] is True
    _, call_kwargs = mock_slack_session.post.call_args
    sent_text = call_kwargs["json"]["text"]
    assert "🟠 High Alert" in sent_text
    assert "HIGH" in sent_text


def test_medium_severity_notification(notification_service, sample_incident, sample_ticket, sample_assignment, mock_slack_session):
    """CASE 4: MEDIUM severity formats with 🟡 Medium Alert."""
    sample_incident["severity"] = "MEDIUM"
    sample_assignment["role"] = "Junior SOC Analyst (Tier 1)"
    result = notification_service.notify_incident(sample_incident, sample_ticket, sample_assignment)

    assert result["success"] is True
    _, call_kwargs = mock_slack_session.post.call_args
    sent_text = call_kwargs["json"]["text"]
    assert "🟡 Medium Alert" in sent_text
    assert "MEDIUM" in sent_text


def test_low_severity_notification(notification_service, sample_incident, sample_ticket, sample_assignment, mock_slack_session):
    """CASE 5: LOW severity formats with 🟢 Low Alert."""
    sample_incident["severity"] = "LOW"
    sample_assignment["role"] = "Monitoring Analyst"
    result = notification_service.notify_incident(sample_incident, sample_ticket, sample_assignment)

    assert result["success"] is True
    _, call_kwargs = mock_slack_session.post.call_args
    sent_text = call_kwargs["json"]["text"]
    assert "🟢 Low Alert" in sent_text
    assert "LOW" in sent_text


# ==============================================================================
# 6. Jira Ticket Creation Failure
# ==============================================================================

def test_jira_ticket_creation_failure_aborts_notification(notification_service, sample_incident, mock_slack_session):
    """CASE 6: Jira ticket creation failure aborts Slack notification and records failure."""
    failed_ticket_data = {
        "status": "FAILED",
        "error": "HTTP 400: Project key 'SEC' not found",
    }

    result = notification_service.notify_incident(
        incident_data=sample_incident,
        ticket_data=failed_ticket_data,
        assignment_data=None,
    )

    assert result["success"] is False
    assert result["status"] == "JIRA_FAILED"
    assert "Jira ticket creation failed" in result["message"]
    # Verify Slack was NEVER called
    mock_slack_session.post.assert_not_called()


# ==============================================================================
# 7. Jira Assignment Failure
# ==============================================================================

def test_jira_assignment_failure_alerts_unassigned(
    notification_service, sample_incident, sample_ticket, mock_slack_session
):
    """CASE 7: When assignment fails, notification is sent indicating UNASSIGNED status with ticket URL."""
    failed_assignment = {
        "assigned": False,
        "reason": "No analyst configured for CRITICAL severity tier.",
    }

    result = notification_service.notify_incident(
        incident_data=sample_incident,
        ticket_data=sample_ticket,
        assignment_data=failed_assignment,
    )

    assert result["success"] is True
    assert result["status"] == "DELIVERED"

    _, call_kwargs = mock_slack_session.post.call_args
    sent_text = call_kwargs["json"]["text"]

    # Verify unassigned status is prominently alerted
    assert "Assignment Status: UNASSIGNED" in sent_text
    assert "Status: INCIDENT TICKET CREATED (UNASSIGNED)" in sent_text
    assert "Assigned Analyst: Unassigned (Manual triage required)" in sent_text
    # Jira ticket URL must still be present
    assert "https://zaalima.atlassian.net/browse/RR-10" in sent_text


# ==============================================================================
# 8. Slack HTTP Failure
# ==============================================================================

def test_slack_http_failure_handled_safely(notification_service, sample_incident, sample_ticket, sample_assignment, mock_slack_session):
    """CASE 8: Slack HTTP 500 error is handled safely without crashing Jira workflow."""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "internal_server_error"
    mock_slack_session.post.return_value = mock_resp

    result = notification_service.notify_incident(
        incident_data=sample_incident,
        ticket_data=sample_ticket,
        assignment_data=sample_assignment,
    )

    assert result["success"] is False
    assert result["status"] == "FAILED"
    assert "500" in result["error"]
    assert result["ticket_key"] == "RR-10"


# ==============================================================================
# 9. Slack Network Connection Failure
# ==============================================================================

def test_slack_network_connection_failure(notification_service, sample_incident, sample_ticket, sample_assignment, mock_slack_session):
    """CASE 9: Slack network drop or DNS failure is captured without unhandled exceptions."""
    mock_slack_session.post.side_effect = requests.exceptions.ConnectionError("DNS resolution failed for hooks.slack.com")

    result = notification_service.notify_incident(
        incident_data=sample_incident,
        ticket_data=sample_ticket,
        assignment_data=sample_assignment,
    )

    assert result["success"] is False
    assert result["status"] == "FAILED"
    assert "connection" in result["error"].lower() or "network" in result["error"].lower()
    assert result["ticket_key"] == "RR-10"


# ==============================================================================
# 10. Slack Webhook Not Configured
# ==============================================================================

def test_slack_webhook_not_configured(sample_incident, sample_ticket, sample_assignment):
    """CASE 10: Unconfigured Slack webhook records NOT_CONFIGURED without crashing."""
    unconfigured_client = SlackClient(webhook_url="")
    service = IncidentNotificationService(slack_client=unconfigured_client)

    result = service.notify_incident(
        incident_data=sample_incident,
        ticket_data=sample_ticket,
        assignment_data=sample_assignment,
    )

    assert result["success"] is False
    assert result["status"] == "NOT_CONFIGURED"
    assert "not configured" in result["message"].lower()
    assert result["ticket_key"] == "RR-10"


# ==============================================================================
# 11. Missing Incident Details
# ==============================================================================

def test_missing_incident_details_rejected(notification_service, sample_ticket, mock_slack_session):
    """CASE 11: Missing incident ID or hostname causes early rejection."""
    # Empty incident data
    res1 = notification_service.notify_incident({}, sample_ticket)
    assert res1["success"] is False
    assert res1["status"] == "REJECTED_INVALID"

    # Missing hostname
    bad_incident = {"incident_id": "INC-01", "severity": "HIGH", "hostname": ""}
    res2 = notification_service.notify_incident(bad_incident, sample_ticket)
    assert res2["success"] is False
    assert res2["status"] == "REJECTED_INVALID"

    # Verify no Slack message was sent
    mock_slack_session.post.assert_not_called()


# ==============================================================================
# 12. Correct Jira Ticket URL Generation
# ==============================================================================

def test_correct_jira_ticket_url_generation(notification_service, sample_incident, sample_assignment, mock_slack_session):
    """CASE 12: Jira ticket URL is accurately generated and formatted in message."""
    ticket_data = {
        "status": "Created",
        "ticket_key": "SEC-9041",
        "ticket_url": "https://secops-enterprise.atlassian.net/browse/SEC-9041",
    }

    result = notification_service.notify_incident(sample_incident, ticket_data, sample_assignment)
    assert result["success"] is True

    _, call_kwargs = mock_slack_session.post.call_args
    sent_text = call_kwargs["json"]["text"]
    sent_blocks = call_kwargs["json"]["blocks"]

    assert "https://secops-enterprise.atlassian.net/browse/SEC-9041" in sent_text

    # Verify button in Block Kit
    action_block = next((b for b in sent_blocks if b.get("type") == "actions"), None)
    assert action_block is not None
    assert action_block["elements"][0]["url"] == "https://secops-enterprise.atlassian.net/browse/SEC-9041"


# ==============================================================================
# 13. Correct Analyst Information in Slack Message
# ==============================================================================

def test_correct_analyst_information_in_message(notification_service, sample_incident, sample_ticket, mock_slack_session):
    """CASE 13: Analyst name and assigned role are correctly mapped into notification."""
    custom_assignment = {
        "assigned": True,
        "role": "Incident Commander (Lead)",
        "account_id": "acc-998877",
    }

    result = notification_service.notify_incident(sample_incident, sample_ticket, custom_assignment)
    assert result["success"] is True

    _, call_kwargs = mock_slack_session.post.call_args
    sent_text = call_kwargs["json"]["text"]

    assert "Assigned Analyst: Incident Commander (Lead)" in sent_text
    assert "Assignment Status: ASSIGNED" in sent_text


# ==============================================================================
# 14. No Duplicate Notification Within a Single Workflow Execution
# ==============================================================================

def test_no_duplicate_notification_within_single_execution(
    notification_service, sample_incident, sample_ticket, sample_assignment, mock_slack_session
):
    """CASE 14: Calling notify_incident twice with same incident/ticket suppresses duplicate."""
    # First notification: succeeds
    res1 = notification_service.notify_incident(sample_incident, sample_ticket, sample_assignment)
    assert res1["success"] is True
    assert res1["status"] == "DELIVERED"
    assert mock_slack_session.post.call_count == 1

    # Second notification for the exact same incident and ticket: suppressed
    res2 = notification_service.notify_incident(sample_incident, sample_ticket, sample_assignment)
    assert res2["success"] is True
    assert res2["status"] == "SKIPPED_DUPLICATE"
    assert "Duplicate notification suppressed" in res2["message"]

    # Verify HTTP POST was NOT called a second time
    assert mock_slack_session.post.call_count == 1


# ==============================================================================
# 15. Jira Workflow Continues When Slack Notification Fails
# ==============================================================================

def test_jira_workflow_continues_when_slack_notification_fails(sample_incident, monkeypatch):
    """CASE 15: An unhandled Slack network failure does not crash or abort orchestrator."""
    # Configure simulated Jira client and failing Slack webhook
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T11/B22/secret33")

    with patch("requests.Session.post") as mock_post:
        # First call is Jira (handled via simulation), Slack call fails
        mock_post.side_effect = requests.exceptions.ConnectionError("Slack gateway unreachable")

        exit_code = run_orchestrator(simulate=True, alert_data_override=sample_incident)

        # Orchestrator must finish successfully (exit code 0) despite Slack failure
        assert exit_code == 0


# ==============================================================================
# End-to-End Workflow Verification
# ==============================================================================

def test_end_to_end_notification_workflow(sample_incident, monkeypatch):
    """End-to-end integration test verifying full pipeline from alert to Slack delivery."""
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T999/B888/token777")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"

    with patch("requests.Session.post", return_value=mock_resp):
        exit_code = run_notification_workflow_test()
        assert exit_code == 0


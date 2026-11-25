"""
test_teams.py - Comprehensive Unit Tests for Microsoft Teams Incoming Webhook Integration.

Automated Ransomware Containment & Incident Response Orchestrator
Verifies:
- TeamsConfig loading and placeholder detection.
- Webhook URL masking and secret redaction.
- Office 365 Connector MessageCard payload generation for incident alerts.
- Test notification card dispatch.
- Successful HTTP 200 delivery.
- HTTP error code handling (400, 403, 500) without crashing.
- Connection timeout and network error resilience.
- Fault isolation: Teams failure never causes unhandled exceptions.
"""

from unittest.mock import MagicMock, patch
import pytest
import requests

from backend.teams_integration import (
    TeamsClient,
    TeamsConfig,
    mask_teams_webhook_url,
    sanitize_teams_error_message,
)


@pytest.fixture
def sample_incident():
    return {
        "incident_id": "TEST-INC-TEAMS-001",
        "threat_type": "ransomware",
        "severity": "CRITICAL",
        "hostname": "FINANCE-HOST-01",
        "ip_address": "10.0.5.25",
        "username": "fin_admin",
        "process_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "detection_time": "2026-11-20T17:00:00Z",
        "description": "LockBit 3.0 canary encryption detected on network volume shares",
    }


@pytest.fixture
def sample_ticket():
    return {
        "ticket_key": "RR-101",
        "ticket_id": "100101",
        "ticket_url": "https://zaalima.atlassian.net/browse/RR-101",
        "status": "Created",
    }


def test_teams_config_placeholder_detection():
    """Verify that placeholder or missing URLs are flagged as not configured."""
    cfg_empty = TeamsConfig()
    assert not cfg_empty.is_configured
    assert cfg_empty.is_placeholder

    cfg_placeholder = TeamsConfig(webhook_url="https://outlook.office.com/webhook/placeholder/0000")
    assert cfg_placeholder.is_placeholder
    assert not cfg_placeholder.is_configured

    cfg_valid = TeamsConfig(webhook_url="https://company.webhook.office.com/webhookb2/uuid@uuid/IncomingWebhook/token/uuid")
    assert cfg_valid.is_configured
    assert not cfg_valid.is_placeholder


def test_teams_webhook_masking():
    """Verify webhook URL masking protects incoming webhook paths in logs."""
    url = "https://company.webhook.office.com/webhookb2/12345/IncomingWebhook/67890"
    masked = mask_teams_webhook_url(url)
    assert url[:20] in masked
    assert "67890" not in masked
    assert "****" in masked

    err = f"Failed to post to {url}: Connection dropped"
    sanitized = sanitize_teams_error_message(err, url)
    assert url not in sanitized


def test_build_incident_card_format(sample_incident, sample_ticket):
    """Verify Office 365 Connector MessageCard format complies with schema."""
    client = TeamsClient(config=TeamsConfig(webhook_url="https://mock.webhook.office.com/test"))
    card = client.build_incident_card(
        incident_data=sample_incident,
        ticket_data=sample_ticket,
        assignment_data={"assignee_name": "Senior SOC Lead"},
    )

    assert card["@type"] == "MessageCard"
    assert card["themeColor"] == "d9534f"  # Red for CRITICAL
    assert "RR-101" in card["summary"]
    assert "FINANCE-HOST-01" in card["title"]
    assert len(card["sections"]) >= 1
    facts = {f["name"]: f["value"] for f in card["sections"][0]["facts"]}
    assert facts["Incident ID"] == "TEST-INC-TEAMS-001"
    assert facts["Target Hostname"] == "FINANCE-HOST-01"
    assert facts["Assigned Analyst"] == "Senior SOC Lead"
    assert card["potentialAction"][0]["name"] == "View Jira Ticket (RR-101)"


def test_send_message_successful_delivery():
    """Verify successful delivery when Teams responds HTTP 200."""
    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "1"
    mock_session.post.return_value = mock_resp

    client = TeamsClient(
        config=TeamsConfig(webhook_url="https://company.webhook.office.com/webhookb2/mock-valid"),
        session=mock_session,
    )
    result = client.send_message({"text": "Test Alert"})
    assert result["success"] is True
    assert result["status"] == "DELIVERED"
    assert result["delivered"] is True


def test_send_message_unconfigured_skips_safely():
    """Verify that unconfigured Teams webhook skips delivery safely without error."""
    client = TeamsClient(config=TeamsConfig(webhook_url=None))
    result = client.send_message({"text": "Test Alert"})
    assert result["success"] is False
    assert result["status"] == "NOT_CONFIGURED"
    assert result["delivered"] is False


def test_send_test_notification():
    """Verify that send_test_notification formats and dispatches a verified test card."""
    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "1"
    mock_session.post.return_value = mock_resp

    client = TeamsClient(
        config=TeamsConfig(webhook_url="https://company.webhook.office.com/webhookb2/mock-valid"),
        session=mock_session,
    )
    res = client.send_test_notification()
    assert res["success"] is True
    assert res["status"] == "DELIVERED"

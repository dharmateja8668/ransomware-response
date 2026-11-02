"""
test_slack.py - Comprehensive Unit Test Suite for Slack Webhook Integration.

Automated Ransomware Containment & Incident Response Orchestrator
Week 4 Day 3 - Task 1: Slack Webhook Integration.

Tests the following 10 required cases:
1. Successful Slack notification.
2. HTTP 400 response (Bad Request).
3. HTTP 403 response (Forbidden / Invalid Token).
4. HTTP 500 response (Internal Server Error).
5. Network connection error.
6. Request timeout.
7. Missing webhook URL.
8. Invalid webhook URL (non-HTTPS, placeholder, malformed).
9. Webhook URL masking in error messages (zero secret leakage).
10. Correct notification payload (plain text, structured, and test notification).

Plus:
- CLI --slack-test command tests (success, failure, unconfigured).
- Standalone send_slack_notification helper function.
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

from backend.config import SlackConfig, load_slack_config, mask_webhook_url
from backend.slack_integration import (
    SlackClient,
    SlackConfigurationError,
    SlackConnectionError,
    SlackHTTPError,
    SlackIntegrationError,
    TEST_NOTIFICATION_TEXT,
    sanitize_error_message,
    send_slack_notification,
)
from backend.main import run_slack_test


# Sensitive dummy credentials for testing secret redaction
SAMPLE_TEAM_ID = "T01234567"
SAMPLE_CHANNEL_ID = "B09876543"
SAMPLE_SECRET_TOKEN = "SECRET_TOKEN_XYZ_9876543210_ABCDEF"
SAMPLE_WEBHOOK_URL = f"https://hooks.slack.com/services/{SAMPLE_TEAM_ID}/{SAMPLE_CHANNEL_ID}/{SAMPLE_SECRET_TOKEN}"


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture
def sample_slack_config() -> SlackConfig:
    """Fixture providing valid Slack configuration with simulated webhook URL."""
    return SlackConfig(
        webhook_url=SAMPLE_WEBHOOK_URL,
        channel="#soc-alerts",
        timeout_seconds=5,
        verify_ssl=True,
    )


@pytest.fixture
def mock_session() -> MagicMock:
    """Fixture providing a mock requests.Session."""
    session = MagicMock(spec=requests.Session)
    session.headers = {}
    return session


@pytest.fixture
def slack_client(sample_slack_config, mock_session) -> SlackClient:
    """Fixture providing a SlackClient initialized with a mock session."""
    return SlackClient(
        config=sample_slack_config,
        session=mock_session,
    )


# ==============================================================================
# 1. Successful Slack Notification
# ==============================================================================

def test_slack_notification_success(slack_client, mock_session):
    """CASE 1: Successful Slack notification returns 200 and success status."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"
    mock_session.post.return_value = mock_resp

    result = slack_client.send_message("Test notification: SOC alert test.")

    assert result["success"] is True
    assert result["status_code"] == 200
    assert result["error"] is None
    assert result["response"] == "ok"
    mock_session.post.assert_called_once()


# ==============================================================================
# 2. HTTP 400 Response (Bad Request)
# ==============================================================================

def test_slack_notification_http_400_bad_request(slack_client, mock_session):
    """CASE 2: Handling HTTP 400 Bad Request (e.g., malformed payload)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.text = "invalid_payload"
    mock_session.post.return_value = mock_resp

    # Default return dictionary handling
    result = slack_client.send_message("malformed")
    assert result["success"] is False
    assert result["status_code"] == 400
    assert "400" in result["error"]
    assert "invalid_payload" in result["error"]

    # Exception raising mode
    with pytest.raises(SlackHTTPError) as exc_info:
        slack_client.send_message("malformed", raise_on_error=True)

    assert exc_info.value.status_code == 400
    assert "400" in str(exc_info.value)
    assert SAMPLE_SECRET_TOKEN not in str(exc_info.value)


# ==============================================================================
# 3. HTTP 403 Response (Forbidden / Invalid Token)
# ==============================================================================

def test_slack_notification_http_403_forbidden(slack_client, mock_session):
    """CASE 3: Handling HTTP 403 Forbidden (e.g., revoked webhook token)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "invalid_token"
    mock_session.post.return_value = mock_resp

    result = slack_client.send_message("Test alert")
    assert result["success"] is False
    assert result["status_code"] == 403
    assert "403" in result["error"]
    assert "invalid_token" in result["error"]

    with pytest.raises(SlackHTTPError) as exc_info:
        slack_client.send_message("Test alert", raise_on_error=True)

    assert exc_info.value.status_code == 403
    assert SAMPLE_SECRET_TOKEN not in str(exc_info.value)


# ==============================================================================
# 4. HTTP 500 Response (Internal Server Error)
# ==============================================================================

def test_slack_notification_http_500_server_error(slack_client, mock_session):
    """CASE 4: Handling HTTP 500 Slack Internal Server Error."""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "internal_server_error"
    mock_session.post.return_value = mock_resp

    result = slack_client.send_message("Test alert")
    assert result["success"] is False
    assert result["status_code"] == 500
    assert "500" in result["error"]

    with pytest.raises(SlackHTTPError) as exc_info:
        slack_client.send_message("Test alert", raise_on_error=True)

    assert exc_info.value.status_code == 500
    assert SAMPLE_SECRET_TOKEN not in str(exc_info.value)


# ==============================================================================
# 5. Network Connection Error
# ==============================================================================

def test_slack_notification_connection_error(slack_client, mock_session):
    """CASE 5: Handling network connectivity failure or DNS resolution drops."""
    mock_session.post.side_effect = requests.exceptions.ConnectionError(
        f"Failed to establish a new connection to {SAMPLE_WEBHOOK_URL}: [Errno 11001] getaddrinfo failed"
    )

    result = slack_client.send_message("Test alert")
    assert result["success"] is False
    assert result["status_code"] is None
    assert "network" in result["message"].lower() or "connection" in result["error"].lower()

    # Verify secret token is NOT leaked in error message
    assert SAMPLE_SECRET_TOKEN not in result["error"]

    with pytest.raises(SlackConnectionError) as exc_info:
        slack_client.send_message("Test alert", raise_on_error=True)

    assert SAMPLE_SECRET_TOKEN not in str(exc_info.value)


# ==============================================================================
# 6. Request Timeout
# ==============================================================================

def test_slack_notification_timeout(slack_client, mock_session):
    """CASE 6: Handling HTTP network timeout when connecting to Slack."""
    mock_session.post.side_effect = requests.exceptions.Timeout(
        f"HTTPSConnectionPool(host='hooks.slack.com', port=443): Read timed out for {SAMPLE_WEBHOOK_URL}"
    )

    result = slack_client.send_message("Test alert")
    assert result["success"] is False
    assert result["status_code"] is None
    assert "timed out" in result["error"].lower()

    # Secret token masking verification
    assert SAMPLE_SECRET_TOKEN not in result["error"]

    with pytest.raises(SlackConnectionError) as exc_info:
        slack_client.send_message("Test alert", raise_on_error=True)

    assert SAMPLE_SECRET_TOKEN not in str(exc_info.value)


# ==============================================================================
# 7. Missing Webhook URL
# ==============================================================================

def test_slack_missing_webhook_url():
    """CASE 7: Handling completely missing or unconfigured webhook URL."""
    client = SlackClient(webhook_url="")

    assert client.check_configuration() is False

    result = client.send_message("Test alert")
    assert result["success"] is False
    assert result["status_code"] is None
    assert "not configured" in result["error"].lower()

    with pytest.raises(SlackConfigurationError) as exc_info:
        client.send_message("Test alert", raise_on_error=True)

    assert "not configured" in str(exc_info.value).lower()


# ==============================================================================
# 8. Invalid Webhook URL
# ==============================================================================

def test_slack_invalid_webhook_url_insecure_http():
    """CASE 8a: Insecure HTTP protocol detected and rejected."""
    client = SlackClient(webhook_url="http://hooks.slack.com/services/T1/B2/token123")
    assert client.check_configuration() is False

    with pytest.raises(ValueError) as exc_info:
        client.config.validate()
    assert "Insecure protocol" in str(exc_info.value)


def test_slack_invalid_webhook_url_placeholder():
    """CASE 8b: Default placeholder URL detected and rejected."""
    placeholder = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    client = SlackClient(webhook_url=placeholder)
    assert client.config.is_placeholder is True
    assert client.check_configuration() is False

    with pytest.raises(ValueError) as exc_info:
        client.config.validate()
    assert "Placeholder detected" in str(exc_info.value)


def test_slack_invalid_webhook_url_malformed():
    """CASE 8c: Malformed URL missing domain or host rejected."""
    client = SlackClient(webhook_url="not-a-valid-url")
    assert client.check_configuration() is False

    with pytest.raises(ValueError) as exc_info:
        client.config.validate()


# ==============================================================================
# 9. Webhook URL Masking in Error Messages
# ==============================================================================

def test_slack_webhook_url_masking_in_error_messages(slack_client, mock_session):
    """CASE 9: Webhook secrets and URLs are strictly masked in all error outputs."""
    raw_error = f"Error communicating with {SAMPLE_WEBHOOK_URL}: /services/{SAMPLE_TEAM_ID}/{SAMPLE_CHANNEL_ID}/{SAMPLE_SECRET_TOKEN} rejected"
    mock_session.post.side_effect = requests.exceptions.RequestException(raw_error)

    result = slack_client.send_message("Security alert")

    # 1. Real secret token must NEVER be present in result error
    assert SAMPLE_SECRET_TOKEN not in result["error"]
    assert SAMPLE_CHANNEL_ID not in result["error"]

    # 2. Masked string is present
    assert "https://hooks.slack.com/services/...****" in result["error"]

    # 3. Direct sanitize_error_message testing
    sanitized = sanitize_error_message(raw_error, SAMPLE_WEBHOOK_URL)
    assert SAMPLE_SECRET_TOKEN not in sanitized
    assert "https://hooks.slack.com/services/...****" in sanitized

    # 4. mask_webhook_url unit test
    masked = mask_webhook_url(SAMPLE_WEBHOOK_URL)
    assert SAMPLE_SECRET_TOKEN not in masked
    assert masked == "https://hooks.slack.com/services/...****"


# ==============================================================================
# 10. Correct Notification Payload
# ==============================================================================

def test_slack_correct_notification_payload_plain_text(slack_client, mock_session):
    """CASE 10a: Plain text message generates correct Slack JSON payload."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"
    mock_session.post.return_value = mock_resp

    test_msg = "Critical Alert: Ransomware execution detected on HOST-01"
    slack_client.send_message(test_msg)

    mock_session.post.assert_called_once()
    _, call_kwargs = mock_session.post.call_args
    assert call_kwargs["json"]["text"] == test_msg
    assert call_kwargs["json"]["channel"] == "#soc-alerts"
    assert call_kwargs["timeout"] == 5
    assert call_kwargs["verify"] is True


def test_slack_correct_notification_payload_structured_dict(slack_client, mock_session):
    """CASE 10b: Structured dictionary payload is forwarded properly."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"
    mock_session.post.return_value = mock_resp

    dict_payload = {
        "text": "Fallback summary",
        "attachments": [{"color": "#ff0000", "title": "Ransomware Alert"}],
    }
    slack_client.send_message(dict_payload)

    _, call_kwargs = mock_session.post.call_args
    assert call_kwargs["json"]["text"] == "Fallback summary"
    assert call_kwargs["json"]["attachments"][0]["title"] == "Ransomware Alert"


def test_slack_send_test_notification_message_content(slack_client, mock_session):
    """CASE 10c: send_test_notification sends the exact required specification text."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"
    mock_session.post.return_value = mock_resp

    result = slack_client.send_test_notification()

    assert result["success"] is True
    _, call_kwargs = mock_session.post.call_args
    sent_text = call_kwargs["json"]["text"]

    # Verify exact specification requirements from Task 5
    assert "ZAALIMA Slack Integration Test" in sent_text
    assert "Status: SUCCESS" in sent_text
    assert "Message: ZAALIMA is successfully connected to the SOC Slack channel." in sent_text
    assert "Purpose: Verify that the orchestrator can send notifications to Slack." in sent_text


# ==============================================================================
# Helper & CLI Integration Tests
# ==============================================================================

def test_send_slack_notification_convenience_function(slack_client):
    """Test standalone send_slack_notification function accepting client parameter."""
    with patch.object(slack_client, "send_message") as mock_send:
        mock_send.return_value = {"success": True, "status_code": 200, "message": "ok"}
        res = send_slack_notification("Hello SOC", client=slack_client)
        assert res["success"] is True
        mock_send.assert_called_once_with("Hello SOC", channel=None)


def test_slack_cli_slack_test_flag_success(mock_session, monkeypatch):
    """Test backend.main --slack-test flag with valid configuration."""
    monkeypatch.setenv("SLACK_WEBHOOK_URL", SAMPLE_WEBHOOK_URL)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"

    with patch("requests.Session.post", return_value=mock_resp):
        code = run_slack_test()
        assert code == 0


def test_slack_cli_slack_test_flag_unconfigured(monkeypatch):
    """Test backend.main --slack-test flag when SLACK_WEBHOOK_URL is missing."""
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

    code = run_slack_test()
    assert code == 1


def test_slack_cli_slack_test_flag_failure(mock_session, monkeypatch):
    """Test backend.main --slack-test flag when Slack returns an HTTP error."""
    monkeypatch.setenv("SLACK_WEBHOOK_URL", SAMPLE_WEBHOOK_URL)
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "action_prohibited"

    with patch("requests.Session.post", return_value=mock_resp):
        code = run_slack_test()
        assert code == 1


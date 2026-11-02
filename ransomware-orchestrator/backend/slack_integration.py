"""
slack_integration.py - Slack Incoming Webhook Integration Module for ZAALIMA.

Automated Ransomware Containment & Incident Response Orchestrator
Week 4 Day 3 - Task 1: Slack Webhook Integration.

Capabilities:
- Reusable SlackClient supporting Slack Incoming Webhooks over HTTPS.
- Configuration verification and health checking.
- Automated test notification dispatch for SOC channel verification.
- Secure redaction of webhook URLs and tokens in logs, exceptions, and error payloads.
- Resilient error handling covering HTTP errors, network drops, and timeouts.
"""

from dataclasses import dataclass
import logging
import re
from typing import Any, Dict, Optional, Union
from urllib.parse import urlparse

import requests

from backend.config import SlackConfig, load_slack_config, mask_webhook_url

# Logger configuration
logger = logging.getLogger("orchestrator.slack")

# Standardized SOC Test Notification Message
TEST_NOTIFICATION_TEXT = (
    "ZAALIMA Slack Integration Test\n\n"
    "Status: SUCCESS\n\n"
    "Message: ZAALIMA is successfully connected to the SOC Slack channel.\n\n"
    "Purpose: Verify that the orchestrator can send notifications to Slack."
)


# ==============================================================================
# Custom Exceptions Hierarchy
# ==============================================================================

class SlackIntegrationError(Exception):
    """Base exception for all Slack integration errors."""
    pass


class SlackConfigurationError(SlackIntegrationError):
    """Raised when Slack webhook configuration is missing, invalid, or insecure."""
    pass


class SlackConnectionError(SlackIntegrationError):
    """Raised when network, DNS, or timeout connection issues occur connecting to Slack."""
    pass


class SlackHTTPError(SlackIntegrationError):
    """Raised when the Slack API returns an HTTP error status code (e.g., 400, 403, 500)."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_text: str = "",
    ):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


# ==============================================================================
# Secret Redaction and Message Sanitization
# ==============================================================================

def sanitize_error_message(error_msg: str, webhook_url: Optional[str] = None) -> str:
    """
    Remove any sensitive Slack webhook URLs, services paths, or tokens from error text.
    Guarantees no secret tokens leak into logs, exceptions, or console output.
    """
    if not error_msg:
        return ""

    sanitized = str(error_msg)

    # 1. Replace explicit webhook URL if provided
    if webhook_url and webhook_url in sanitized:
        sanitized = sanitized.replace(webhook_url, mask_webhook_url(webhook_url))

    # 2. Redact full Slack webhook URLs (https://hooks.slack.com/services/...)
    sanitized = re.sub(
        r"https?://hooks\.slack\.com/services/[^\s'\",]+",
        "https://hooks.slack.com/services/...****",
        sanitized,
    )

    # 3. Redact /services/T.../B.../token URL paths
    sanitized = re.sub(
        r"/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+",
        "/services/...****",
        sanitized,
    )

    return sanitized


# ==============================================================================
# Slack Client Implementation
# ==============================================================================

class SlackClient:
    """
    Reusable Slack Incoming Webhook Client for ZAALIMA Orchestrator.
    
    Provides secure, TLS-enforced interaction with Slack:
    - Pre-flight webhook configuration validation.
    - Sending plain text or structured block messages.
    - Automated test notification sending for SOC verification.
    - Zero credential leakage in error messages and logs.
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        timeout: int = 10,
        verify_ssl: bool = True,
        config: Optional[SlackConfig] = None,
        session: Optional[requests.Session] = None,
    ):
        """
        Initialize Slack client.
        
        Args:
            webhook_url: Optional explicit webhook URL (overrides environment if provided).
            timeout: Network request timeout in seconds (default: 10s).
            verify_ssl: Enforce SSL certificate verification (default: True).
            config: Optional pre-loaded SlackConfig instance.
            session: Optional custom or mocked requests.Session.
        """
        if config is not None:
            self.config = config
        elif webhook_url is not None:
            self.config = SlackConfig(
                webhook_url=webhook_url.strip(),
                timeout_seconds=timeout,
                verify_ssl=verify_ssl,
            )
        else:
            self.config = load_slack_config()
            if timeout != 10:
                self.config.timeout_seconds = timeout
            if not verify_ssl:
                self.config.verify_ssl = False

        self.webhook_url = self.config.webhook_url
        self.timeout = self.config.timeout_seconds
        self.verify_ssl = self.config.verify_ssl

        # Session configuration
        self.session = session or requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "ZAALIMA-Incident-Orchestrator/1.0",
        })

    def check_configuration(self, raise_on_error: bool = False) -> bool:
        """
        Verify whether Slack webhook is properly configured.
        
        Returns:
            True if configured with a valid HTTPS webhook URL, False otherwise.
        Raises:
            SlackConfigurationError if raise_on_error is True and configuration is invalid.
        """
        try:
            self.config.validate()
            return True
        except ValueError as exc:
            sanitized = sanitize_error_message(str(exc), self.webhook_url)
            logger.warning("Slack configuration check failed: %s", sanitized)
            if raise_on_error:
                raise SlackConfigurationError(sanitized) from exc
            return False

    def send_message(
        self,
        message: Union[str, Dict[str, Any]],
        channel: Optional[str] = None,
        raise_on_error: bool = False,
    ) -> Dict[str, Any]:
        """
        Send a notification message to the configured Slack webhook channel.
        
        Args:
            message: Plain text string or Slack JSON payload dictionary.
            channel: Optional channel override (if supported by webhook app).
            raise_on_error: If True, raises SlackIntegrationError on failure.
            
        Returns:
            Dictionary containing:
                success (bool): Whether the notification succeeded.
                status_code (Optional[int]): HTTP response status code.
                message (str): Human-readable status message.
                error (Optional[str]): Error details if failed, sanitized of secrets.
                response (Optional[str]): Raw response body if available.
        """
        # 1. Verify configuration
        if not self.check_configuration():
            err_msg = (
                "Slack webhook URL is not configured or is invalid. "
                "Please configure SLACK_WEBHOOK_URL in .env."
            )
            logger.error("%s", err_msg)
            if raise_on_error:
                raise SlackConfigurationError(err_msg)
            return {
                "success": False,
                "status_code": None,
                "message": "Slack notification failed: Missing or invalid configuration",
                "error": err_msg,
                "response": None,
            }

        # 2. Construct payload
        if isinstance(message, str):
            payload: Dict[str, Any] = {"text": message}
        elif isinstance(message, dict):
            payload = dict(message)
        else:
            payload = {"text": str(message)}

        # Channel override if provided or configured
        target_channel = channel or self.config.channel
        if target_channel:
            payload["channel"] = target_channel

        masked_url = self.config.masked_url
        logger.info("Sending notification to Slack webhook [%s]", masked_url)

        # 3. Post to webhook
        try:
            resp = self.session.post(
                self.webhook_url,
                json=payload,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except requests.exceptions.Timeout as exc:
            err = sanitize_error_message(
                f"Connection timed out after {self.timeout} seconds connecting to Slack webhook: {exc}",
                self.webhook_url,
            )
            logger.error("%s", err)
            if raise_on_error:
                raise SlackConnectionError(err) from exc
            return {
                "success": False,
                "status_code": None,
                "message": "Slack notification failed: Connection timed out",
                "error": err,
                "response": None,
            }
        except requests.exceptions.ConnectionError as exc:
            err = sanitize_error_message(
                f"Network connection failed while contacting Slack webhook: {exc}",
                self.webhook_url,
            )
            logger.error("%s", err)
            if raise_on_error:
                raise SlackConnectionError(err) from exc
            return {
                "success": False,
                "status_code": None,
                "message": "Slack notification failed: Network connection error",
                "error": err,
                "response": None,
            }
        except requests.exceptions.RequestException as exc:
            err = sanitize_error_message(
                f"Request error occurred while contacting Slack webhook: {exc}",
                self.webhook_url,
            )
            logger.error("%s", err)
            if raise_on_error:
                raise SlackConnectionError(err) from exc
            return {
                "success": False,
                "status_code": None,
                "message": "Slack notification failed: Request exception",
                "error": err,
                "response": None,
            }

        # 4. Process HTTP response
        if resp.status_code == 200:
            logger.info("Slack notification successfully sent to [%s]", masked_url)
            return {
                "success": True,
                "status_code": 200,
                "message": "Notification successfully sent to Slack",
                "error": None,
                "response": resp.text,
            }

        # HTTP error (e.g. 400 bad request, 403 forbidden, 500 server error)
        raw_response = resp.text.strip()
        sanitized_response = sanitize_error_message(raw_response, self.webhook_url)
        err = f"Slack webhook returned HTTP {resp.status_code}: {sanitized_response}"
        logger.error("%s", err)

        if raise_on_error:
            raise SlackHTTPError(
                err,
                status_code=resp.status_code,
                response_text=sanitized_response,
            )

        return {
            "success": False,
            "status_code": resp.status_code,
            "message": f"Slack notification rejected by Slack API (HTTP {resp.status_code})",
            "error": err,
            "response": sanitized_response,
        }

    def send_test_notification(self, raise_on_error: bool = False) -> Dict[str, Any]:
        """
        Send the standardized ZAALIMA SOC test notification to Slack.
        
        Expected Message Content:
            ZAALIMA Slack Integration Test
            Status: SUCCESS
            Message: ZAALIMA is successfully connected to the SOC Slack channel.
            Purpose: Verify that the orchestrator can send notifications to Slack.
        """
        logger.info("Dispatching ZAALIMA test notification to Slack...")
        return self.send_message(TEST_NOTIFICATION_TEXT, raise_on_error=raise_on_error)


# ==============================================================================
# Standalone Convenience Functions
# ==============================================================================

def send_slack_notification(
    message: Union[str, Dict[str, Any]],
    webhook_url: Optional[str] = None,
    channel: Optional[str] = None,
    client: Optional[SlackClient] = None,
) -> Dict[str, Any]:
    """
    Convenience function to send a Slack notification.
    Uses existing client if provided, otherwise instantiates one with webhook_url.
    """
    c = client or SlackClient(webhook_url=webhook_url)
    return c.send_message(message, channel=channel)


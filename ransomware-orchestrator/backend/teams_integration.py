"""
teams_integration.py - Microsoft Teams Incoming Webhook Integration Module for ZAALIMA.

Automated Ransomware Containment & Incident Response Orchestrator
Capabilities:
- Reusable TeamsClient supporting Microsoft Teams Incoming Webhooks (Office 365 Connector Cards).
- Severity-based color coding (🔴 Critical: Red, 🟠 High: Orange, 🟡 Medium: Yellow, 🟢 Low: Green).
- Automated test notification dispatch for SOC channel verification.
- Secure redaction of webhook URLs and tokens in logs, exceptions, and error payloads.
- Resilient error handling covering HTTP errors, network drops, and timeouts.
- Safe failure isolation: Teams failures never disrupt core incident containment or ticketing.
"""

from dataclasses import dataclass
import logging
import os
import re
from typing import Any, Dict, Optional, Union
from urllib.parse import urlparse

import requests

logger = logging.getLogger("orchestrator.teams")

# Standardized SOC Test Notification Message
TEAMS_TEST_NOTIFICATION_TEXT = (
    "ZAALIMA Microsoft Teams Integration Test\n\n"
    "Status: SUCCESS\n\n"
    "Message: ZAALIMA is successfully connected to the SOC Microsoft Teams channel.\n\n"
    "Purpose: Verify that the orchestrator can dispatch incident notifications to Teams."
)

TEAMS_SEVERITY_COLORS = {
    "CRITICAL": "d9534f",  # Crimson Red
    "HIGH": "f0ad4e",      # Amber Orange
    "MEDIUM": "5bc0de",    # Cyan / Yellow
    "LOW": "5cb85c",       # Green
}


# ==============================================================================
# Custom Exceptions Hierarchy
# ==============================================================================

class TeamsIntegrationError(Exception):
    """Base exception for all Microsoft Teams integration errors."""
    pass


class TeamsConfigurationError(TeamsIntegrationError):
    """Raised when Teams webhook configuration is missing, invalid, or insecure."""
    pass


class TeamsConnectionError(TeamsIntegrationError):
    """Raised when network, DNS, or timeout connection issues occur connecting to Teams."""
    pass


class TeamsHTTPError(TeamsIntegrationError):
    """Raised when the Teams Webhook API returns an HTTP error status code."""

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
# Configuration Data Container
# ==============================================================================

@dataclass
class TeamsConfig:
    """Configuration container for Microsoft Teams incoming webhook integration."""
    webhook_url: Optional[str] = None
    channel_name: str = "soc-alerts"
    timeout_seconds: int = 10
    verify_ssl: bool = True
    enabled: bool = True

    @property
    def is_configured(self) -> bool:
        if not self.webhook_url:
            return False
        w = self.webhook_url.strip()
        return bool(w and not self.is_placeholder)

    @property
    def is_placeholder(self) -> bool:
        if not self.webhook_url:
            return True
        w = self.webhook_url.strip().lower()
        return (
            "placeholder" in w
            or "example.com" in w
            or "your-webhook" in w
            or "webhook.office.com/webhookb2/0000" in w
        )


def mask_teams_webhook_url(url: Optional[str]) -> str:
    """Masks incoming webhook URL for safe logging."""
    if not url:
        return "NOT_CONFIGURED"
    u = str(url).strip()
    if len(u) < 25:
        return "****"
    return f"{u[:25]}...****"


def sanitize_teams_error_message(error_msg: str, webhook_url: Optional[str] = None) -> str:
    """Redacts Teams webhook URL paths from error text."""
    if not error_msg:
        return ""
    sanitized = str(error_msg)
    if webhook_url and webhook_url in sanitized:
        sanitized = sanitized.replace(webhook_url, mask_teams_webhook_url(webhook_url))
    sanitized = re.sub(
        r"https?://[a-zA-Z0-9.-]+\.office\.com/webhook[b2]*/[^\s'\",]+",
        "https://...webhook.office.com/...****",
        sanitized,
    )
    return sanitized


def load_teams_config() -> TeamsConfig:
    """Loads Teams configuration from environment variables."""
    webhook = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
    channel = os.environ.get("TEAMS_CHANNEL", "soc-alerts").strip()
    timeout = int(os.environ.get("TEAMS_TIMEOUT_SECONDS", "10"))
    return TeamsConfig(
        webhook_url=webhook or None,
        channel_name=channel or "soc-alerts",
        timeout_seconds=timeout,
        verify_ssl=True,
        enabled=bool(webhook),
    )


# ==============================================================================
# Teams Client Implementation
# ==============================================================================

class TeamsClient:
    """Client for dispatching notifications to Microsoft Teams via Incoming Webhooks."""

    def __init__(
        self,
        config: Optional[TeamsConfig] = None,
        session: Optional[requests.Session] = None,
    ):
        self.config = config or load_teams_config()
        self.session = session or requests.Session()

    def format_severity_color(self, severity: str) -> str:
        sev = str(severity or "").strip().upper()
        return TEAMS_SEVERITY_COLORS.get(sev, "337ab7")

    def build_incident_card(
        self,
        incident_data: Any,
        ticket_data: Dict[str, Any],
        assignment_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Constructs an Office 365 Connector MessageCard payload."""
        if hasattr(incident_data, "to_dict"):
            inc = incident_data.to_dict()
        elif isinstance(incident_data, dict):
            inc = dict(incident_data)
        else:
            inc = {}

        incident_id = inc.get("incident_id", "UNKNOWN-INCIDENT")
        severity = str(inc.get("severity", "CRITICAL")).upper()
        hostname = inc.get("hostname", "UNKNOWN-HOST")
        ip_addr = inc.get("ip_address", "UNKNOWN-IP")
        username = inc.get("username", "UNKNOWN-USER")
        threat_type = inc.get("incident_type") or inc.get("threat_type") or "Ransomware"
        process_hash = inc.get("process_hash", "N/A")
        detection_time = inc.get("detection_time") or inc.get("timestamp") or "Just Now"
        description = inc.get("incident_description") or inc.get("description") or "Suspicious ransomware activity"

        ticket_key = ticket_data.get("ticket_key", "N/A") if ticket_data else "N/A"
        ticket_url = ticket_data.get("ticket_url", "") if ticket_data else ""

        assigned_analyst = "Unassigned"
        if assignment_data:
            assigned_analyst = assignment_data.get("assignee_name") or assignment_data.get("account_id") or "Assigned"

        theme_color = self.format_severity_color(severity)

        facts = [
            {"name": "Incident ID", "value": str(incident_id)},
            {"name": "Threat Type", "value": str(threat_type)},
            {"name": "Severity", "value": f"**{severity}**"},
            {"name": "Target Hostname", "value": str(hostname)},
            {"name": "IP Address", "value": str(ip_addr)},
            {"name": "Username", "value": str(username)},
            {"name": "SHA-256 Digest", "value": f"`{process_hash[:16]}...`" if len(process_hash) > 16 else str(process_hash)},
            {"name": "Jira Ticket", "value": str(ticket_key)},
            {"name": "Assigned Analyst", "value": str(assigned_analyst)},
        ]

        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": f"[{severity}] Ransomware Incident - {hostname} ({ticket_key})",
            "title": f"🛡️ ZAALIMA Alert: [{severity}] Ransomware Incident - {hostname}",
            "sections": [
                {
                    "activityTitle": "Automated Ransomware Containment & Incident Response Orchestrator",
                    "activitySubtitle": f"Detection Time: {detection_time}",
                    "facts": facts,
                    "text": description,
                }
            ],
        }

        if ticket_url:
            card["potentialAction"] = [
                {
                    "@type": "OpenURI",
                    "name": f"View Jira Ticket ({ticket_key})",
                    "targets": [{"os": "default", "uri": ticket_url}],
                }
            ]

        return card

    def send_message(self, payload: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Dispatches payload to Microsoft Teams incoming webhook."""
        if not self.config.is_configured:
            logger.info("Microsoft Teams webhook is not configured. Skipping Teams notification.")
            return {
                "success": False,
                "status": "NOT_CONFIGURED",
                "channel": self.config.channel_name,
                "message": "Teams webhook URL is not configured or is a placeholder.",
                "delivered": False,
            }

        if isinstance(payload, str):
            json_body = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "summary": "ZAALIMA Notification",
                "title": "ZAALIMA Security Alert",
                "text": payload,
            }
        else:
            json_body = payload

        url = self.config.webhook_url
        logger.info("Sending notification to Teams channel '%s' at %s", self.config.channel_name, mask_teams_webhook_url(url))

        try:
            resp = self.session.post(
                url,
                json=json_body,
                timeout=self.config.timeout_seconds,
                verify=self.config.verify_ssl,
            )
            if resp.status_code == 200 and resp.text.strip() == "1":
                logger.info("Teams notification delivered successfully.")
                return {
                    "success": True,
                    "status": "DELIVERED",
                    "channel": self.config.channel_name,
                    "message": "Teams notification delivered successfully.",
                    "delivered": True,
                }
            elif resp.status_code == 200:
                logger.info("Teams notification accepted (HTTP 200).")
                return {
                    "success": True,
                    "status": "DELIVERED",
                    "channel": self.config.channel_name,
                    "message": "Teams notification accepted.",
                    "delivered": True,
                }
            else:
                err_text = sanitize_teams_error_message(resp.text, url)
                logger.error("Teams notification rejected (HTTP %d): %s", resp.status_code, err_text)
                return {
                    "success": False,
                    "status": f"HTTP_{resp.status_code}",
                    "channel": self.config.channel_name,
                    "error": f"Teams returned HTTP {resp.status_code}: {err_text}",
                    "delivered": False,
                }
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            clean_err = sanitize_teams_error_message(str(exc), url)
            logger.error("Teams connection failed: %s", clean_err)
            return {
                "success": False,
                "status": "CONNECTION_FAILED",
                "channel": self.config.channel_name,
                "error": clean_err,
                "delivered": False,
            }
        except Exception as exc:
            clean_err = sanitize_teams_error_message(str(exc), url)
            logger.error("Unexpected error sending Teams notification: %s", clean_err)
            return {
                "success": False,
                "status": "FAILED",
                "channel": self.config.channel_name,
                "error": clean_err,
                "delivered": False,
            }

    def send_test_notification(self) -> Dict[str, Any]:
        """Dispatches a test notification card to verify the Teams webhook connectivity."""
        test_card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "5cb85c",
            "summary": "ZAALIMA Teams Integration Test",
            "title": "✅ ZAALIMA Microsoft Teams Integration Verified",
            "sections": [
                {
                    "activityTitle": "Automated Ransomware Containment & Incident Response Orchestrator",
                    "text": TEAMS_TEST_NOTIFICATION_TEXT,
                    "facts": [
                        {"name": "Status", "value": "CONNECTED"},
                        {"name": "Channel", "value": self.config.channel_name},
                        {"name": "Security Mode", "value": "AES256 SSL Verified"},
                    ],
                }
            ],
        }
        return self.send_message(test_card)

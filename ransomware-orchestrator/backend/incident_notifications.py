"""
incident_notifications.py - Automated Incident Notification Service for ZAALIMA.

Automated Ransomware Containment & Incident Response Orchestrator
Week 4 Day 3 - Task 2: Jira + Slack Integration.

Capabilities:
- Orchestrates automated Slack notifications following Jira incident ticket creation and analyst assignment.
- Severity-based visual alert indicators (🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW).
- Slack Block Kit + markdown formatted payloads with fallback plain text.
- Safe failure handling: Jira failures abort notifications; assignment failures alert with UNASSIGNED status;
  Slack failures or unconfigured webhooks never disrupt core incident response.
- Idempotent deduplication preventing duplicate notifications within the same workflow execution.
- Zero secret leakage in logs, messages, and error tracking.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Union

from backend.config import SlackConfig, load_slack_config, mask_secret
from backend.jira_integration import IncidentData
from backend.slack_integration import SlackClient, sanitize_error_message

# Setup logger
logger = logging.getLogger("orchestrator.notifications")

# Visual severity indicators
SEVERITY_INDICATORS = {
    "CRITICAL": "🔴 Critical Alert",
    "HIGH": "🟠 High Alert",
    "MEDIUM": "🟡 Medium Alert",
    "LOW": "🟢 Low Alert",
}

# Standard severity-to-role fallback mapping
DEFAULT_SEVERITY_ROLES = {
    "CRITICAL": "Senior SOC Lead / Incident Commander",
    "HIGH": "SOC Analyst (Tier 2)",
    "MEDIUM": "Junior SOC Analyst (Tier 1)",
    "LOW": "Monitoring Analyst",
}


# ==============================================================================
# Custom Exceptions Hierarchy
# ==============================================================================

class NotificationServiceError(Exception):
    """Base exception for notification service operations."""
    pass


class NotificationValidationError(NotificationServiceError):
    """Raised when incident telemetry is missing or invalid for notification."""
    pass


# ==============================================================================
# Incident Notification Service
# ==============================================================================

class IncidentNotificationService:
    """
    Reusable notification service integrating Jira incident response with Slack alerts.
    
    Coordinates the delivery of standardized SOC incident alerts whenever a ransomware
    incident is processed through the Jira ticket creation and assignment lifecycle.
    """

    def __init__(
        self,
        slack_client: Optional[SlackClient] = None,
        config: Optional[SlackConfig] = None,
    ):
        """
        Initialize the notification service.
        
        Args:
            slack_client: Optional pre-configured SlackClient instance.
            config: Optional pre-loaded SlackConfig instance.
        """
        self.slack_client = slack_client or SlackClient(config=config)
        self._sent_notifications: Set[str] = set()

    def format_severity(self, severity: str) -> str:
        """
        Convert severity string into standardized visual indicator.
        
        Example:
            "CRITICAL" -> "🔴 Critical Alert"
            "HIGH"     -> "🟠 High Alert"
        """
        sev_upper = str(severity or "").strip().upper()
        return SEVERITY_INDICATORS.get(sev_upper, f"⚪ {sev_upper} Alert")

    def format_jira_ticket_link(self, ticket_key: str, ticket_url: str) -> str:
        """
        Format Jira ticket key and web URL into clean URL link.
        """
        if ticket_url:
            return str(ticket_url).strip()
        if ticket_key:
            return f"Ticket Key: {ticket_key}"
        return "N/A"

    def build_incident_message(
        self,
        incident_data: Union[Dict[str, Any], IncidentData],
        ticket_data: Dict[str, Any],
        assignment_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Construct formatted Slack alert payload including plain text and Block Kit structures.
        
        Args:
            incident_data: Validated incident telemetry or IncidentData container.
            ticket_data: Jira ticket result dictionary (key, id, url, status).
            assignment_data: Optional Jira assignment result dictionary.
            
        Returns:
            Dictionary containing 'text' and 'blocks' ready for SlackClient delivery.
        """
        # Normalize incident data
        inc = incident_data.to_dict() if isinstance(incident_data, IncidentData) else dict(incident_data)

        incident_id = inc.get("incident_id", "UNKNOWN-INCIDENT")
        severity = str(inc.get("severity", "UNKNOWN")).upper()
        severity_indicator = self.format_severity(severity)
        hostname = inc.get("hostname", "UNKNOWN-HOST")
        source = inc.get("source", "EDR Detection")
        detection_time = inc.get("detection_time") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Normalize ticket data
        ticket_key = ticket_data.get("ticket_key", "UNKNOWN-KEY")
        ticket_url = ticket_data.get("ticket_url", "")
        ticket_link = self.format_jira_ticket_link(ticket_key, ticket_url)

        # Normalize assignment data
        assign = assignment_data or {}
        is_assigned = bool(assign.get("assigned", False))

        if is_assigned:
            assignment_status = "ASSIGNED"
            overall_status = "INCIDENT TICKET CREATED AND ASSIGNED"
            assigned_analyst = (
                assign.get("role")
                or DEFAULT_SEVERITY_ROLES.get(severity, "SOC Analyst")
            )
        else:
            assignment_status = "UNASSIGNED"
            overall_status = "INCIDENT TICKET CREATED (UNASSIGNED)"
            assigned_analyst = "Unassigned (Manual triage required)"

        # Plain text notification matching Task 4 specification
        plain_text = (
            f"🚨 ZAALIMA SECURITY INCIDENT ALERT 🚨 - {severity_indicator}\n\n"
            f"Incident Details:\n\n"
            f"Incident ID: {incident_id}\n"
            f"Severity: {severity}\n"
            f"Hostname: {hostname}\n"
            f"Source: {source}\n"
            f"Detection Time: {detection_time}\n\n"
            f"Response Status:\n\n"
            f"Jira Ticket: {ticket_key}\n"
            f"Assigned Analyst: {assigned_analyst}\n"
            f"Assignment Status: {assignment_status}\n\n"
            f"Jira Ticket Link:\n"
            f"{ticket_link}\n\n"
            f"Status: {overall_status}\n\n"
            f"System: ZAALIMA Automated Incident Response Orchestrator"
        )

        # Slack Block Kit structure for rich UI presentation
        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 ZAALIMA INCIDENT: {incident_id}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{severity_indicator}* | *Status:* `{overall_status}`",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Incident ID:*\n`{incident_id}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n*{severity}* ({severity_indicator})"},
                    {"type": "mrkdwn", "text": f"*Target Hostname:*\n`{hostname}`"},
                    {"type": "mrkdwn", "text": f"*Detection Source:*\n{source}"},
                    {"type": "mrkdwn", "text": f"*Detection Time:*\n{detection_time}"},
                    {"type": "mrkdwn", "text": f"*Jira Issue:*\n<{ticket_url}|*{ticket_key}*>"},
                    {"type": "mrkdwn", "text": f"*Assignment Status:*\n`{assignment_status}`"},
                    {"type": "mrkdwn", "text": f"*Assigned Analyst:*\n{assigned_analyst}"},
                ],
            },
        ]

        if ticket_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": f"View Jira Ticket ({ticket_key})"},
                        "url": ticket_url,
                        "style": "primary",
                    }
                ],
            })

        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🛡️ *ZAALIMA Automated Ransomware Containment & Incident Response Orchestrator*",
                }
            ],
        })

        return {
            "text": plain_text,
            "blocks": blocks,
            "metadata": {
                "incident_id": incident_id,
                "ticket_key": ticket_key,
                "severity": severity,
                "assignment_status": assignment_status,
                "overall_status": overall_status,
            },
        }

    def send_incident_notification(
        self,
        payload: Union[str, Dict[str, Any]],
        channel: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Dispatch the notification payload to Slack using the underlying SlackClient.
        
        Guarantees that network errors and API rejections do not raise unhandled
        exceptions into the caller.
        """
        return self.slack_client.send_message(payload, channel=channel)

    def notify_incident(
        self,
        incident_data: Union[Dict[str, Any], IncidentData],
        ticket_data: Dict[str, Any],
        assignment_data: Optional[Dict[str, Any]] = None,
        channel: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute complete incident notification workflow.
        
        Validates telemetry, enforces deduplication, checks configuration, builds
        the notification, and sends the alert to the SOC Slack channel.
        
        Args:
            incident_data: Incident telemetry.
            ticket_data: Created Jira ticket details.
            assignment_data: Optional Jira analyst assignment outcome.
            channel: Optional channel override.
            
        Returns:
            Dict containing:
                success (bool): Whether the notification succeeded.
                status (str): Outcome classification (DELIVERED, FAILED, NOT_CONFIGURED,
                              SKIPPED_DUPLICATE, REJECTED_INVALID, JIRA_FAILED).
                message (str): Human-readable summary.
                error (Optional[str]): Error description if failed.
                ticket_key (Optional[str]): Associated Jira ticket key.
                incident_id (Optional[str]): Incident ID.
                slack_response (Optional[str]): Raw response from Slack API.
        """
        # 1. Telemetry validation (Scenario 5)
        if not incident_data:
            err = "Incident notification rejected: incident data is empty or None."
            logger.error("%s", err)
            return {
                "success": False,
                "status": "REJECTED_INVALID",
                "message": err,
                "error": err,
                "ticket_key": None,
                "incident_id": None,
                "slack_response": None,
            }

        inc = incident_data.to_dict() if isinstance(incident_data, IncidentData) else dict(incident_data)
        incident_id = inc.get("incident_id")
        hostname = inc.get("hostname")
        severity = inc.get("severity")

        if not incident_id or not hostname or not severity:
            err = f"Incident notification rejected: missing required fields (id={incident_id}, host={hostname}, sev={severity})."
            logger.error("%s", err)
            return {
                "success": False,
                "status": "REJECTED_INVALID",
                "message": err,
                "error": err,
                "ticket_key": ticket_data.get("ticket_key") if ticket_data else None,
                "incident_id": incident_id,
                "slack_response": None,
            }

        logger.info("Processing incident notification for Incident [%s] (Severity: %s)", incident_id, severity)

        # 2. Jira ticket validation (Scenario 1)
        ticket_key = ticket_data.get("ticket_key") if ticket_data else None
        ticket_url = ticket_data.get("ticket_url") if ticket_data else None
        ticket_creation_failed = (
            not ticket_data
            or not ticket_key
            or ticket_data.get("status") in ("FAILED", "ERROR")
            or "error" in ticket_data
        )

        if ticket_creation_failed:
            jira_err = ticket_data.get("error", "Jira ticket creation failed or was omitted.") if ticket_data else "No ticket data provided."
            logger.warning("Jira ticket creation failed for incident [%s]. Suppressing Slack success notification: %s", incident_id, jira_err)
            return {
                "success": False,
                "status": "JIRA_FAILED",
                "message": "Jira ticket creation failed; incident notification aborted.",
                "error": str(jira_err),
                "ticket_key": None,
                "incident_id": incident_id,
                "slack_response": None,
            }

        logger.info("Jira ticket verified: [%s] (%s)", ticket_key, ticket_url)

        # 3. Deduplication Check (Rule: No duplicate notifications within single workflow)
        dedup_key = f"{incident_id}:{ticket_key}"
        if dedup_key in self._sent_notifications:
            logger.warning("Duplicate notification suppressed for incident [%s] / ticket [%s]", incident_id, ticket_key)
            return {
                "success": True,
                "status": "SKIPPED_DUPLICATE",
                "message": f"Duplicate notification suppressed for incident {incident_id} and ticket {ticket_key}.",
                "error": None,
                "ticket_key": ticket_key,
                "incident_id": incident_id,
                "slack_response": None,
            }

        # 4. Check Slack Configuration (Scenario 4)
        if not self.slack_client.check_configuration():
            logger.info("Slack webhook is not configured. Recording status as NOT_CONFIGURED.")
            return {
                "success": False,
                "status": "NOT_CONFIGURED",
                "message": "Slack webhook is not configured; Jira operations continue unaffected.",
                "error": None,
                "ticket_key": ticket_key,
                "incident_id": incident_id,
                "slack_response": None,
            }

        # 5. Build Notification Payload (Scenario 2 handles partial assignment inside build_incident_message)
        payload = self.build_incident_message(
            incident_data=inc,
            ticket_data=ticket_data,
            assignment_data=assignment_data,
        )

        # 6. Dispatch Notification to Slack
        logger.info("Dispatching incident notification to Slack for ticket [%s]...", ticket_key)
        slack_result = self.send_incident_notification(payload, channel=channel)

        # 7. Record Delivery Status (Scenario 3: Slack failure handled gracefully)
        if slack_result.get("success"):
            self._sent_notifications.add(dedup_key)
            logger.info("Slack incident notification successfully delivered for [%s] (HTTP %s)", ticket_key, slack_result.get("status_code"))
            return {
                "success": True,
                "status": "DELIVERED",
                "message": f"Slack notification delivered successfully for ticket {ticket_key}.",
                "error": None,
                "ticket_key": ticket_key,
                "incident_id": incident_id,
                "slack_response": slack_result.get("response"),
            }

        # Slack failure
        raw_error = slack_result.get("error", "Unknown Slack dispatch error")
        sanitized_error = sanitize_error_message(raw_error)
        logger.error("Slack incident notification failed for ticket [%s]: %s", ticket_key, sanitized_error)

        return {
            "success": False,
            "status": "FAILED",
            "message": f"Slack notification delivery failed for ticket {ticket_key}.",
            "error": sanitized_error,
            "ticket_key": ticket_key,
            "incident_id": incident_id,
            "slack_response": slack_result.get("response"),
        }


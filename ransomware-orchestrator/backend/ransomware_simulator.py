"""
ransomware_simulator.py - Safe Ransomware Simulation and End-to-End Testing Module.

Automated Ransomware Containment & Incident Response Orchestrator
Week 4 Day 4: Ransomware Simulation and End-to-End Testing.

Capabilities:
- Generates synthetic, safe ransomware and threat telemetry across all severity levels.
- Executes controlled incident response simulations verifying detection, ingestion,
  validation, Jira ticket creation, severity-based analyst routing, and Slack alerts.
- Two testing modes:
    * Mode A (Default): Fully mocked simulation without external API calls.
    * Mode B (Optional): Controlled live integration testing with explicit confirmation.
- Comprehensive failure scenario handling (Jira auth/creation/assignment failures,
  Slack HTTP/connection failures, duplicate incidents, and invalid telemetry).
- Precise end-to-end performance measurement via time.perf_counter().
- Generates structured, zero-leak JSON simulation reports in reports/simulations/.
- STRICT SAFETY GUARANTEE: Never executes actual ransomware, destroys or encrypts files,
  isolates live network endpoints, or suspends real Active Directory accounts.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Dict, List, Optional, Union
import uuid

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import (
    JiraConfig,
    SlackConfig,
    load_config,
    load_slack_config,
    mask_secret,
    mask_webhook_url,
)
from backend.jira_integration import (
    IncidentData,
    IncidentValidationError,
    JiraAssignmentError,
    JiraAuthenticationError,
    JiraClient,
    JiraConnectionError,
    JiraIntegrationError,
    JiraProjectNotFoundError,
    JiraTicketCreationError,
    format_ticket_description,
    format_ticket_summary,
    validate_incident_data,
)
from backend.slack_integration import (
    SlackClient,
    SlackConfigurationError,
    SlackConnectionError,
    SlackHTTPError,
    SlackIntegrationError,
    sanitize_error_message,
)
from backend.incident_notifications import (
    DEFAULT_SEVERITY_ROLES,
    SEVERITY_INDICATORS,
    IncidentNotificationService,
    NotificationServiceError,
    NotificationValidationError,
)

logger = logging.getLogger("orchestrator.simulator")

# ==============================================================================
# Supported Severity Incident Templates
# ==============================================================================

SEVERITY_INCIDENT_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "CRITICAL": {
        "incident_id": "INC-2026-001",
        "threat_type": "Ransomware",
        "severity": "CRITICAL",
        "hostname": "TEST-WORKSTATION-01",
        "ip_address": "192.168.56.101",
        "username": "test_user",
        "process_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "incident_description": (
            "Active ransomware containment alert: Canary file tripwire activated on endpoint. "
            "High-volume encrypted file renames detected in user profile directory. "
            "Volume shadow copy deletion attempted via vssadmin."
        ),
        "telemetry": {
            "process_name": "winlogin_update.exe",
            "process_id": 4892,
            "parent_process": "cmd.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} recoveryenabled No",
            "encrypted_files_count": 247,
            "canary_file_tripped": True,
            "shadow_copies_deleted": True,
            "ransom_note_detected": "HOW_TO_RESTORE_FILES.txt",
            "network_connections": [
                {"destination": "198.51.100.45:4444", "protocol": "TCP", "status": "ESTABLISHED"}
            ],
        },
    },
    "HIGH": {
        "incident_id": "INC-2026-002",
        "threat_type": "Mass File Modification",
        "severity": "HIGH",
        "hostname": "TEST-WORKSTATION-02",
        "ip_address": "192.168.56.102",
        "username": "test_user",
        "process_hash": "a3f5c7891234567890abcdef1234567890abcdef1234567890abcdef12345678",
        "incident_description": (
            "Suspicious mass file modification activity detected. Rapid renames and file extension "
            "tampering observed across departmental file shares."
        ),
        "telemetry": {
            "process_name": "sync_agent.exe",
            "process_id": 3120,
            "parent_process": "explorer.exe",
            "command_line": "sync_agent.exe --batch --force",
            "modified_files_count": 85,
            "canary_file_tripped": False,
            "shadow_copies_deleted": False,
            "ransom_note_detected": None,
            "network_connections": [],
        },
    },
    "MEDIUM": {
        "incident_id": "INC-2026-003",
        "threat_type": "Suspicious Process Execution",
        "severity": "MEDIUM",
        "hostname": "TEST-WORKSTATION-03",
        "ip_address": "192.168.56.103",
        "username": "test_user",
        "process_hash": "b4e6d8901234567890abcdef1234567890abcdef1234567890abcdef12345678",
        "incident_description": (
            "Suspicious process execution detected. Base64-encoded PowerShell invocation "
            "and certutil utility abuse observed."
        ),
        "telemetry": {
            "process_name": "powershell.exe",
            "process_id": 5540,
            "parent_process": "winword.exe",
            "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -Enc JABjAGwAaQBl...",
            "canary_file_tripped": False,
            "certutil_decoded": True,
            "network_connections": [
                {"destination": "203.0.113.88:8443", "protocol": "TCP", "status": "SYN_SENT"}
            ],
        },
    },
    "LOW": {
        "incident_id": "INC-2026-004",
        "threat_type": "Unusual Network Activity",
        "severity": "LOW",
        "hostname": "TEST-WORKSTATION-04",
        "ip_address": "192.168.56.104",
        "username": "test_user",
        "process_hash": "c5f7e9011234567890abcdef1234567890abcdef1234567890abcdef12345678",
        "incident_description": (
            "Unusual outbound network beaconing detected. Periodic connection attempts "
            "to anomalous destination IP on non-standard port."
        ),
        "telemetry": {
            "process_name": "svchost_net.exe",
            "process_id": 1824,
            "parent_process": "services.exe",
            "command_line": "svchost_net.exe -k netsvcs",
            "beacon_interval_seconds": 60,
            "destination_ip": "198.51.100.99",
            "destination_port": 8088,
            "network_connections": [
                {"destination": "198.51.100.99:8088", "protocol": "TCP", "status": "ESTABLISHED"}
            ],
        },
    },
}


# ==============================================================================
# Secret Masking Utility for Reports
# ==============================================================================

def mask_report_secrets(data: Any) -> Any:
    """
    Recursively sanitize dictionaries and lists to eliminate secrets, API tokens,
    Slack webhook URLs, and credentials before serialization to disk.
    Preserves Jira ticket keys and project keys.
    """
    if isinstance(data, dict):
        cleaned: Dict[str, Any] = {}
        for key, value in data.items():
            lower_key = str(key).lower()
            if lower_key in ("ticket_key", "project_key", "issue_key", "key"):
                cleaned[key] = value
            elif any(s in lower_key for s in ("token", "secret", "password", "auth", "credential")):
                cleaned[key] = mask_secret(str(value)) if value else value
            elif "webhook" in lower_key and isinstance(value, str):
                cleaned[key] = mask_webhook_url(value)
            else:
                cleaned[key] = mask_report_secrets(value)
        return cleaned
    elif isinstance(data, list):
        return [mask_report_secrets(item) for item in data]
    elif isinstance(data, str):
        # Redact raw Slack webhook URLs embedded in strings
        if "hooks.slack.com/services/" in data:
            return mask_webhook_url(data)
        return data
    return data


# ==============================================================================
# RansomwareSimulator Class
# ==============================================================================

class RansomwareSimulator:
    """
    Reusable Ransomware and Incident Response Simulation Engine.
    
    Orchestrates synthetic threat simulations across multiple severity tiers
    and validates the end-to-end incident lifecycle:
      Detection -> Ingestion -> Validation -> Jira Creation -> Analyst Assignment
      -> Slack Notification -> Performance Measurement -> Audit Reporting.
    """

    def __init__(
        self,
        jira_client: Optional[JiraClient] = None,
        slack_client: Optional[SlackClient] = None,
        notification_service: Optional[IncidentNotificationService] = None,
        env_file: Optional[str] = None,
        reports_dir: Optional[Union[str, Path]] = None,
    ):
        """
        Initialize the simulator with optional clients or environment configuration.
        """
        self.env_file = env_file
        self.jira_client = jira_client
        self.slack_client = slack_client
        self.notification_service = notification_service

        # Reports directory configuration
        if reports_dir:
            self.reports_dir = Path(reports_dir)
        else:
            # Prefer reports/simulations at project root
            root = Path(__file__).resolve().parent.parent.parent
            if (root / "pytest.ini").exists():
                self.reports_dir = root / "reports" / "simulations"
            else:
                self.reports_dir = PROJECT_ROOT / "reports" / "simulations"

        self._last_result: Optional[Dict[str, Any]] = None

    def generate_test_telemetry(
        self,
        severity: str = "CRITICAL",
        hostname: Optional[str] = None,
        ip_address: Optional[str] = None,
        username: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate synthetic endpoint telemetry matching the requested severity level.
        """
        sev_upper = str(severity or "").strip().upper()
        if sev_upper not in SEVERITY_INCIDENT_TEMPLATES:
            raise ValueError(
                f"Invalid severity level '{severity}'. "
                f"Supported levels: {', '.join(SEVERITY_INCIDENT_TEMPLATES.keys())}"
            )

        template = SEVERITY_INCIDENT_TEMPLATES[sev_upper]
        telemetry = dict(template["telemetry"])
        telemetry["generated_at"] = datetime.now(timezone.utc).isoformat()
        telemetry["target_host"] = hostname or template["hostname"]
        telemetry["target_ip"] = ip_address or template["ip_address"]
        telemetry["target_user"] = username or template["username"]
        return telemetry

    def generate_simulated_incident(
        self,
        severity: str = "CRITICAL",
        incident_id: Optional[str] = None,
        hostname: Optional[str] = None,
        ip_address: Optional[str] = None,
        username: Optional[str] = None,
        threat_type: Optional[str] = None,
        description: Optional[str] = None,
        process_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate complete, synthetic incident data matching the IncidentData schema.
        """
        sev_upper = str(severity or "").strip().upper()
        if sev_upper not in SEVERITY_INCIDENT_TEMPLATES:
            raise ValueError(
                f"Invalid severity level '{severity}'. "
                f"Supported levels: {', '.join(SEVERITY_INCIDENT_TEMPLATES.keys())}"
            )

        template = SEVERITY_INCIDENT_TEMPLATES[sev_upper]
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        target_host = hostname or template["hostname"]
        target_ip = ip_address or template["ip_address"]
        target_user = username or template["username"]

        incident = {
            "incident_id": incident_id or template["incident_id"],
            "incident_type": threat_type or template["threat_type"],
            "severity": sev_upper,
            "hostname": target_host,
            "ip_address": target_ip,
            "username": target_user,
            "process_hash": process_hash or template["process_hash"],
            "detection_time": now_utc,
            "incident_description": description or template["incident_description"],
            "source": "Simulated EDR",
            "telemetry": self.generate_test_telemetry(
                severity=sev_upper,
                hostname=target_host,
                ip_address=target_ip,
                username=target_user,
            ),
        }
        return incident

    def simulate_ransomware_detection(
        self,
        severity: str = "CRITICAL",
        incident_id: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Simulate EDR telemetry detection of a ransomware or suspicious threat event.
        """
        incident = self.generate_simulated_incident(
            severity=severity,
            incident_id=incident_id,
            **kwargs,
        )
        logger.info(
            "Simulated EDR detection: Incident [%s] (Severity: %s, Host: %s, Threat: %s)",
            incident["incident_id"],
            incident["severity"],
            incident["hostname"],
            incident["incident_type"],
        )
        return {
            "status": "DETECTED",
            "source": "Simulated EDR",
            "detection_time": incident["detection_time"],
            "severity": incident["severity"],
            "incident": incident,
        }

    def validate_incident(self, incident_dict: Dict[str, Any]) -> IncidentData:
        """
        Validate and sanitize incident data using the core SOC validation rules.
        """
        if not incident_dict:
            raise IncidentValidationError("Validation failed: incident data is empty or None.")

        return validate_incident_data(
            incident_id=incident_dict.get("incident_id"),
            incident_type=incident_dict.get("incident_type"),
            severity=incident_dict.get("severity"),
            hostname=incident_dict.get("hostname"),
            ip_address=incident_dict.get("ip_address"),
            username=incident_dict.get("username"),
            process_hash=incident_dict.get("process_hash"),
            detection_time=incident_dict.get("detection_time"),
            incident_description=incident_dict.get("incident_description"),
        )

    def run_simulation(
        self,
        severity: str = "CRITICAL",
        live: bool = False,
        incident_data: Optional[Dict[str, Any]] = None,
        fail_jira: Optional[str] = None,
        fail_slack: Optional[str] = None,
        fail_assignment: bool = False,
        is_duplicate: bool = False,
        save_report: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute the end-to-end incident response simulation workflow.
        
        Workflow stages:
          1. Simulated Ransomware Detection
          2. Incident Data Collection
          3. Incident Validation
          4. Jira Ticket Creation
          5. Automatic Analyst Assignment
          6. Slack Notification
          7. Incident Response Logging
          8. End-to-End Performance Measurement
        """
        t_total_start = time.perf_counter()
        processing_start_time = datetime.now(timezone.utc).isoformat()
        simulation_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"

        logger.info(
            "Starting Simulation [%s] (Mode: %s, Severity: %s)",
            simulation_id,
            "LIVE" if live else "MOCKED",
            severity,
        )

        # Stage 1 & 2: Detection and Ingestion
        if incident_data is not None:
            incident = dict(incident_data)
        else:
            incident = self.generate_simulated_incident(severity=severity)

        incident_id = incident.get("incident_id", "UNKNOWN-INCIDENT")
        inc_severity = str(incident.get("severity", severity)).upper()
        hostname = incident.get("hostname", "UNKNOWN-HOST")
        threat_type = incident.get("incident_type", "Ransomware")
        ip_address = incident.get("ip_address", "0.0.0.0")
        username = incident.get("username", "test_user")
        detection_time = incident.get("detection_time") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Stage 3: Incident Validation
        validation_result: Dict[str, Any] = {"valid": False, "status": "PENDING", "error": None}
        validated_data: Optional[IncidentData] = None

        try:
            validated_data = self.validate_incident(incident)
            validation_result = {
                "valid": True,
                "status": "VALID",
                "error": None,
            }
            logger.info("Stage 3: Incident [%s] validated successfully.", incident_id)
        except IncidentValidationError as exc:
            validation_result = {
                "valid": False,
                "status": "INVALID",
                "error": str(exc),
            }
            logger.error("Stage 3: Incident [%s] validation failed: %s", incident_id, exc)

            # Workflow terminates immediately on validation failure
            t_total_end = time.perf_counter()
            total_duration = t_total_end - t_total_start

            result = self._build_result_package(
                simulation_id=simulation_id,
                incident=incident,
                live=live,
                validation_result=validation_result,
                ticket_result={"status": "SKIPPED", "ticket_id": None, "ticket_key": None, "ticket_url": None, "error": "Validation failed"},
                assignment_result={"assigned": False, "role": None, "reason": "Skipped due to validation error"},
                notification_result={"status": "SKIPPED", "delivered": False, "message": "Notification aborted: invalid incident telemetry"},
                metrics={
                    "detection_time": detection_time,
                    "processing_start_time": processing_start_time,
                    "jira_ticket_creation_seconds": 0.0,
                    "analyst_assignment_seconds": 0.0,
                    "slack_notification_seconds": 0.0,
                    "total_response_time_seconds": round(total_duration, 4),
                },
                workflow_status="FAILED",
            )
            if save_report:
                self.save_simulation_report(result)
            self._last_result = result
            return result

        # Stage 4: Jira Ticket Creation
        t_jira_start = time.perf_counter()
        ticket_result: Dict[str, Any] = {}
        jira_error: Optional[str] = None

        if live:
            # LIVE MODE: Connect to real Jira
            jira_conf = load_config(self.env_file)
            client = self.jira_client or JiraClient.from_config(jira_conf)
            try:
                ticket_result = client.create_incident_ticket(
                    incident_id=validated_data.incident_id,
                    incident_type=validated_data.incident_type,
                    severity=validated_data.severity,
                    hostname=validated_data.hostname,
                    ip_address=validated_data.ip_address,
                    username=validated_data.username,
                    process_hash=validated_data.process_hash,
                    detection_time=validated_data.detection_time,
                    incident_description=validated_data.incident_description,
                    check_existing=True,
                )
            except Exception as exc:
                jira_error = str(exc)
                logger.error("Stage 4 (Live Jira): Ticket creation failed: %s", exc)
                ticket_result = {
                    "status": "FAILED",
                    "ticket_id": None,
                    "ticket_key": None,
                    "ticket_url": None,
                    "error": jira_error,
                }
        else:
            # MOCKED MODE (Default)
            if fail_jira == "auth":
                jira_error = "Jira authentication failed: HTTP 401 Unauthorized"
                ticket_result = {"status": "FAILED", "ticket_id": None, "ticket_key": None, "ticket_url": None, "error": jira_error}
            elif fail_jira == "create":
                jira_error = "Jira ticket creation rejected: HTTP 400 Bad Request"
                ticket_result = {"status": "FAILED", "ticket_id": None, "ticket_key": None, "ticket_url": None, "error": jira_error}
            elif fail_jira == "connection":
                jira_error = "Jira connection timed out connecting to Jira Cloud"
                ticket_result = {"status": "FAILED", "ticket_id": None, "ticket_key": None, "ticket_url": None, "error": jira_error}
            elif is_duplicate:
                ticket_result = {
                    "success": True,
                    "ticket_id": "10099",
                    "ticket_key": "RR-101",
                    "ticket_url": "https://zaalima.atlassian.net/browse/RR-101",
                    "status": "Existing (Duplicate Avoided)",
                    "summary": format_ticket_summary(hostname, inc_severity),
                    "project_key": "RR",
                    "severity": inc_severity,
                    "hostname": hostname,
                    "is_duplicate": True,
                }
            else:
                ticket_key = f"RR-{int(time.time()) % 1000:03d}"
                ticket_result = {
                    "success": True,
                    "ticket_id": "10582",
                    "ticket_key": ticket_key,
                    "ticket_url": f"https://zaalima.atlassian.net/browse/{ticket_key}",
                    "status": "Created",
                    "summary": format_ticket_summary(hostname, inc_severity),
                    "project_key": "RR",
                    "severity": inc_severity,
                    "hostname": hostname,
                    "is_duplicate": False,
                }

        jira_duration = time.perf_counter() - t_jira_start

        # Stage 5: Automatic Analyst Assignment
        t_assign_start = time.perf_counter()
        assignment_result: Dict[str, Any] = {}
        assigned_role = DEFAULT_SEVERITY_ROLES.get(inc_severity, "SOC Analyst")

        ticket_key = ticket_result.get("ticket_key")
        jira_succeeded = bool(ticket_key and ticket_result.get("status") not in ("FAILED", "ERROR"))

        if not jira_succeeded:
            assignment_result = {
                "assigned": False,
                "role": None,
                "account_id": None,
                "reason": "Skipped: Jira ticket creation failed or was aborted.",
            }
        elif fail_assignment:
            assignment_result = {
                "assigned": False,
                "issue_key": ticket_key,
                "severity": inc_severity,
                "role": None,
                "account_id": None,
                "reason": "Analyst assignment failed (simulated failure).",
            }
        elif live:
            jira_conf = load_config(self.env_file)
            client = self.jira_client or JiraClient.from_config(jira_conf)
            assign_cfg = jira_conf.get_assignee_config()
            assignment_result = client.auto_assign_incident(
                issue_key=ticket_key,
                severity=inc_severity,
                assignee_config=assign_cfg,
            )
            if assignment_result.get("assigned"):
                assignment_result["role"] = assigned_role
        else:
            # Mocked successful assignment
            assignment_result = {
                "assigned": True,
                "issue_key": ticket_key,
                "severity": inc_severity,
                "role": assigned_role,
                "account_id": f"sim-acc-{inc_severity.lower()}-01",
                "reason": "Assignment successful (simulated).",
            }

        assign_duration = time.perf_counter() - t_assign_start

        # Stage 6: Slack Notification
        t_slack_start = time.perf_counter()
        notification_result: Dict[str, Any] = {}

        if not jira_succeeded:
            # Requirement: Jira failure must suppress Slack success notification
            notification_result = {
                "success": False,
                "status": "JIRA_FAILED",
                "message": "Jira ticket creation failed; incident notification aborted.",
                "error": ticket_result.get("error", "Jira ticket creation failed."),
                "ticket_key": None,
                "incident_id": incident_id,
            }
        elif fail_slack == "missing_webhook":
            notification_result = {
                "success": False,
                "status": "NOT_CONFIGURED",
                "message": "Slack webhook is not configured in environment.",
                "error": "SLACK_WEBHOOK_URL missing or unconfigured.",
                "ticket_key": ticket_key,
                "incident_id": incident_id,
            }
        elif fail_slack == "http500":
            notification_result = {
                "success": False,
                "status": "FAILED",
                "message": "Slack notification failed: HTTP 500 Internal Server Error",
                "error": "HTTP 500 Internal Server Error from Slack webhook",
                "ticket_key": ticket_key,
                "incident_id": incident_id,
            }
        elif fail_slack == "connection":
            notification_result = {
                "success": False,
                "status": "FAILED",
                "message": "Slack notification failed: Connection timed out",
                "error": "Network connection error connecting to Slack webhook",
                "ticket_key": ticket_key,
                "incident_id": incident_id,
            }
        elif is_duplicate:
            notification_result = {
                "success": True,
                "status": "SKIPPED_DUPLICATE",
                "message": f"Duplicate notification suppressed for incident {incident_id}.",
                "error": None,
                "ticket_key": ticket_key,
                "incident_id": incident_id,
            }
        elif live:
            slack_conf = load_slack_config(self.env_file)
            notif_srv = self.notification_service or IncidentNotificationService(config=slack_conf)
            notification_result = notif_srv.notify_incident(
                incident_data=incident,
                ticket_data=ticket_result,
                assignment_data=assignment_result,
            )
        else:
            # Mocked successful Slack notification
            notification_result = {
                "success": True,
                "status": "DELIVERED",
                "message": f"Alert posted to SOC channel: {SEVERITY_INDICATORS.get(inc_severity, inc_severity)}",
                "slack_response": "ok",
                "error": None,
                "ticket_key": ticket_key,
                "incident_id": incident_id,
            }

        slack_duration = time.perf_counter() - t_slack_start

        # Stage 7 & 8: Performance Measurement and Workflow Status Evaluation
        total_duration = time.perf_counter() - t_total_start

        # Determine overall workflow status
        # If Jira failed or validation failed -> FAILED
        # If Jira succeeded but Slack or Assignment failed or was duplicate -> PARTIAL_SUCCESS / SUCCESS
        if not jira_succeeded or not validation_result["valid"]:
            workflow_status = "FAILED"
        elif not assignment_result.get("assigned") or notification_result.get("status") in ("FAILED", "NOT_CONFIGURED"):
            workflow_status = "PARTIAL_SUCCESS"
        else:
            workflow_status = "SUCCESS"

        result = self._build_result_package(
            simulation_id=simulation_id,
            incident=incident,
            live=live,
            validation_result=validation_result,
            ticket_result=ticket_result,
            assignment_result=assignment_result,
            notification_result=notification_result,
            metrics={
                "detection_time": detection_time,
                "processing_start_time": processing_start_time,
                "jira_ticket_creation_seconds": round(jira_duration, 4),
                "analyst_assignment_seconds": round(assign_duration, 4),
                "slack_notification_seconds": round(slack_duration, 4),
                "total_response_time_seconds": round(total_duration, 4),
            },
            workflow_status=workflow_status,
        )

        if save_report:
            self.save_simulation_report(result)

        self._last_result = result
        return result

    def _build_result_package(
        self,
        simulation_id: str,
        incident: Dict[str, Any],
        live: bool,
        validation_result: Dict[str, Any],
        ticket_result: Dict[str, Any],
        assignment_result: Dict[str, Any],
        notification_result: Dict[str, Any],
        metrics: Dict[str, Any],
        workflow_status: str,
    ) -> Dict[str, Any]:
        """Construct the standardized simulation report package."""
        return {
            "simulation_id": simulation_id,
            "incident_id": incident.get("incident_id"),
            "threat_type": incident.get("incident_type"),
            "severity": incident.get("severity"),
            "hostname": incident.get("hostname"),
            "ip_address": incident.get("ip_address"),
            "username": incident.get("username"),
            "detection_timestamp": metrics.get("detection_time"),
            "mode": "LIVE" if live else "MOCKED",
            "incident_validation": validation_result,
            "jira_ticket": {
                "status": ticket_result.get("status"),
                "ticket_id": ticket_result.get("ticket_id"),
                "ticket_key": ticket_result.get("ticket_key"),
                "ticket_url": ticket_result.get("ticket_url"),
                "is_duplicate": ticket_result.get("is_duplicate", False),
                "error": ticket_result.get("error"),
            },
            "analyst_assignment": {
                "status": "ASSIGNED" if assignment_result.get("assigned") else "UNASSIGNED",
                "assigned": bool(assignment_result.get("assigned")),
                "role": assignment_result.get("role"),
                "account_id": mask_secret(assignment_result.get("account_id")) if assignment_result.get("account_id") else None,
                "reason": assignment_result.get("reason"),
            },
            "slack_notification": {
                "status": notification_result.get("status"),
                "delivered": bool(notification_result.get("status") == "DELIVERED"),
                "message": notification_result.get("message"),
                "error": notification_result.get("error"),
            },
            "performance_metrics": metrics,
            "overall_workflow_status": workflow_status,
        }

    def save_simulation_report(
        self,
        result: Dict[str, Any],
        filepath: Optional[Union[str, Path]] = None,
    ) -> str:
        """
        Serialize simulation results to JSON in reports/simulations/ with zero secret leakage.
        """
        if filepath:
            target_file = Path(filepath)
            target_dir = target_file.parent
        else:
            target_dir = self.reports_dir
            sim_id = result.get("simulation_id", f"SIM-{uuid.uuid4().hex[:8].upper()}")
            target_file = target_dir / f"simulation_report_{sim_id}.json"

        target_dir.mkdir(parents=True, exist_ok=True)

        sanitized_data = mask_report_secrets(result)

        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(sanitized_data, f, indent=2)

        logger.info("Simulation report written: %s", target_file)
        return str(target_file)

    def get_simulation_results(self) -> Optional[Dict[str, Any]]:
        """Return the results of the most recently executed simulation."""
        return self._last_result


# ==============================================================================
# Helper Function for CLI / Programmatic Execution
# ==============================================================================

def run_ransomware_simulation(
    severity: str = "CRITICAL",
    live: bool = False,
    env_file: Optional[str] = None,
    confirm_live: bool = False,
) -> int:
    """
    Command-line execution runner for ransomware simulations.
    
    Returns 0 on SUCCESS or PARTIAL_SUCCESS, non-zero on failure.
    """
    banner = f"""
================================================================================
   AUTOMATED RANSOMWARE CONTAINMENT & INCIDENT RESPONSE ORCHESTRATOR
   Week 4 Day 4: Ransomware Simulation & End-to-End Testing
   Mode: {'LIVE INTEGRATION TEST' if live else 'FULLY MOCKED SIMULATION'} | Severity: {severity.upper()}
================================================================================
"""
    print(banner)

    if live:
        print("⚠️  WARNING: LIVE INTEGRATION TEST REQUESTED ⚠️")
        print("  - This mode will connect to LIVE Jira and Slack integrations.")
        print("  - One safe test Jira ticket will be created.")
        print("  - One notification will be sent to the configured test Slack channel.")
        print("  - NO ransomware will be executed. NO files will be encrypted.")
        print("  - NO endpoints will be isolated and NO accounts will be suspended.\n")

        if not confirm_live:
            try:
                response = input("  Proceed with LIVE simulation? (yes/no): ").strip().lower()
                if response not in ("yes", "y"):
                    print("\n[!] Live simulation aborted by user.")
                    return 1
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Live simulation aborted.")
                return 1

    simulator = RansomwareSimulator(env_file=env_file)

    try:
        results = simulator.run_simulation(severity=severity, live=live)
    except Exception as exc:
        print(f"\n[FAIL] Simulation encountered unhandled error: {exc}")
        return 1

    # Display Clean Console Summary
    inc = results
    metrics = results["performance_metrics"]
    jira_info = results["jira_ticket"]
    assign_info = results["analyst_assignment"]
    slack_info = results["slack_notification"]

    print("================================================================================")
    print("                     INCIDENT SIMULATION EXECUTION SUMMARY                      ")
    print("================================================================================")
    print(f"  Simulation ID:           {results['simulation_id']}")
    print(f"  Incident ID:             {results['incident_id']}")
    print(f"  Threat Type:             {results['threat_type']}")
    print(f"  Severity:                {results['severity']}")
    print(f"  Affected Hostname:       {results['hostname']}")
    print(f"  Host IP Address:         {results['ip_address']}")
    print(f"  Detection Timestamp:     {results['detection_timestamp']}")
    print(f"  Telemetry Validation:    {results['incident_validation']['status']}")
    print("--------------------------------------------------------------------------------")
    print("  RESPONSE WORKFLOW STATUS:")
    print(f"  Jira Ticket Status:      {jira_info.get('status')} ({jira_info.get('ticket_key') or 'N/A'})")
    if jira_info.get("ticket_url"):
        print(f"  Jira Ticket URL:         {jira_info.get('ticket_url')}")
    print(f"  Analyst Assignment:      {assign_info.get('status')} ({assign_info.get('role') or 'Unassigned'})")
    print(f"  Slack Notification:      {slack_info.get('status')} ({slack_info.get('message')})")
    print("--------------------------------------------------------------------------------")
    print("  PERFORMANCE MEASUREMENT:")
    print(f"  Jira Ticket Creation:    {metrics['jira_ticket_creation_seconds']:.2f} seconds")
    print(f"  Analyst Assignment:      {metrics['analyst_assignment_seconds']:.2f} seconds")
    print(f"  Slack Notification:      {metrics['slack_notification_seconds']:.2f} seconds")
    print(f"  Total Response Time:     {metrics['total_response_time_seconds']:.2f} seconds")
    print("--------------------------------------------------------------------------------")
    print(f"  OVERALL WORKFLOW STATUS: {results['overall_workflow_status']}")
    print("================================================================================\n")

    report_path = simulator.save_simulation_report(results)
    print(f"[OK] Simulation audit report saved to: {report_path}\n")

    return 0 if results["overall_workflow_status"] in ("SUCCESS", "PARTIAL_SUCCESS") else 1


"""
lambda_handlers.py - AWS Lambda Function Handlers for Incident Response Orchestrator.

Automated Ransomware Containment & Incident Response Orchestrator
Provides individual discrete Lambda handlers matching the AWS Step Functions state machine
as well as an all-in-one unified handler, delegating to the underlying Python services.
"""

from datetime import datetime, timezone
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict

# Ensure project roots are accessible
_ROOT = Path(__file__).resolve().parent.parent.parent
for p in [str(_ROOT), str(_ROOT / "zaalima" / "backend"), str(_ROOT / "ransomware-orchestrator")]:
    if p not in sys.path:
        sys.path.insert(0, p)

from containment.incident_orchestrator import execute_full_incident_response_workflow
from containment.network_containment import execute_network_containment
from integrations.alert_parser import parse_and_enrich_alert

logger = logging.getLogger("orchestrator.aws.lambda")


def lambda_handler_ingest_alert(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda 1: Parse and normalize incoming EDR alert telemetry."""
    raw_alert = event.get("body") if "body" in event and isinstance(event["body"], dict) else event
    if isinstance(raw_alert, str):
        try:
            raw_alert = json.loads(raw_alert)
        except Exception:
            pass

    parsed = parse_and_enrich_alert(raw_alert)
    return parsed.to_dict()


def lambda_handler_containment(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda 2: Execute network containment playbook (dry-run by default)."""
    dry_run = event.get("dry_run", True)
    res = execute_network_containment(alert=event, dry_run=dry_run)
    event["containment"] = res
    return event


def lambda_handler_forensics(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda 3: Trigger forensic triage package acquisition."""
    try:
        from app.services.forensic_service import forensic_service
        alert_id = event.get("alert_id", "UNKNOWN-ALERT")
        hostname = event.get("hostname", "UNKNOWN-HOST")
        f_res = forensic_service.collect_kape_artifacts(
            incident_id=alert_id,
            hostname=hostname,
            analyst_name="AWS Lambda Forensic Worker",
        )
        event["forensics"] = f_res
    except Exception as exc:
        event["forensics"] = {"status": "FAILED", "error": str(exc), "is_simulated": True}
    return event


def lambda_handler_s3_upload(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda 4: Upload forensic artifact to AWS S3 with WORM Object Lock & AES256."""
    try:
        from app.services.s3_service import s3_service
        f_data = event.get("forensics", {})
        file_path = f_data.get("file_path")
        alert_id = event.get("alert_id", "UNKNOWN-ALERT")
        hostname = event.get("hostname", "UNKNOWN-HOST")

        if file_path:
            s3_res = s3_service.upload_evidence_file(
                local_path=file_path,
                incident_id=alert_id,
                hostname=hostname,
                evidence_type="kape_artifacts",
                evidence_id=f_data.get("job_id", f"EV-{alert_id}"),
                enable_object_lock=True,
            )
            event["s3_storage"] = s3_res
        else:
            event["s3_storage"] = {"status": "SKIPPED", "message": "No file path provided."}
    except Exception as exc:
        event["s3_storage"] = {"status": "FAILED", "error": str(exc)}
    return event


def lambda_handler_jira_ticket(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda 5: Create standardized Jira Cloud incident ticket with severity routing."""
    try:
        from backend.config import load_config
        from backend.jira_integration import JiraClient
        cfg = load_config()
        client = JiraClient.from_config(cfg)
        t_res = client.create_incident_ticket(
            incident_id=event.get("alert_id", "UNKNOWN"),
            incident_type=event.get("threat_type", "ransomware"),
            severity=str(event.get("severity", "HIGH")),
            hostname=event.get("hostname", "UNKNOWN"),
            ip_address=event.get("ip_address", "127.0.0.1"),
            username=event.get("username", "UNKNOWN"),
            process_hash=event.get("process_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            detection_time=event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            incident_description=event.get("description", "Automated incident response alert"),
        )
        event["jira_ticket"] = t_res
    except Exception as exc:
        event["jira_ticket"] = {"success": False, "status": "FAILED", "error": str(exc)}
    return event


def lambda_handler_notifications(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda 6: Dispatch real-time notifications to Slack and Microsoft Teams."""
    try:
        from backend.incident_notifications import IncidentNotificationService
        service = IncidentNotificationService()
        notif_res = service.notify_incident(
            incident_data=event,
            ticket_data=event.get("jira_ticket", {}),
        )
        event["notifications"] = notif_res
    except Exception as exc:
        event["notifications"] = {"success": False, "status": "FAILED", "error": str(exc)}
    return event


def lambda_handler_orchestrator(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """All-in-one Lambda Entrypoint: Executes the complete 9-stage workflow in one serverless function."""
    raw_alert = event.get("body") if "body" in event and isinstance(event["body"], dict) else event
    if isinstance(raw_alert, str):
        try:
            raw_alert = json.loads(raw_alert)
        except Exception:
            pass

    dry_run = event.get("dry_run")
    result = execute_full_incident_response_workflow(alert=raw_alert, dry_run=dry_run)
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": result,
    }

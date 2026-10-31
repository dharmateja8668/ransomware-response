"""
main.py - Day 1 Incident Response Orchestrator & Jira Integration Runner.

Automated Ransomware Containment & Incident Response Orchestrator
Day 1: Jira Cloud REST API Incident Ticketing Integration (REST API v3).

Executes the Day 1 lifecycle:
1. Connect to Jira Cloud over HTTPS.
2. Authenticate successfully and verify account credentials (GET /rest/api/3/myself).
3. Verify target Jira project key for security incidents (GET /rest/api/3/project).
4. Verify issue type in target project (GET /rest/api/3/project/{key}).
5. Ingest and validate simulated ransomware incident alert telemetry.
6. Create a standardized Jira incident ticket (POST /rest/api/3/issue).
7. Display generated Jira ticket ID, Key, and web browse URL.
8. Safely handle errors without crashing.
"""

import argparse
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import JiraConfig, audit_configuration, load_config, mask_secret
from backend.jira_integration import (
    JiraClient,
    create_incident_ticket,
    JiraIntegrationError,
    JiraAuthenticationError,
    JiraConnectionError,
    JiraProjectNotFoundError,
    JiraTicketCreationError,
    IncidentValidationError,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("orchestrator.main")


# ==============================================================================
# Simulated Ransomware Alert Telemetry (Task 5 Specification)
# ==============================================================================

def generate_simulated_ransomware_alert() -> Dict[str, str]:
    """
    Generate realistic simulated ransomware incident telemetry matching Task 5.
    
    Incident ID: INC-20261031-001
    Incident Type: Ransomware
    Severity: CRITICAL
    Hostname: TEST-WORKSTATION-01
    IP Address: 192.168.1.105
    Username: test_user
    Process Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    Detection Time: Current UTC time
    """
    detection_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "incident_id": "INC-20261031-001",
        "incident_type": "Ransomware",
        "severity": "CRITICAL",
        "hostname": "TEST-WORKSTATION-01",
        "ip_address": "192.168.1.105",
        "username": "test_user",
        "process_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "detection_time": detection_timestamp,
        "incident_description": (
            "Canary file tripwire activated on endpoint. High-volume encrypted "
            "file renames detected in user profile directory. Immediate containment required."
        ),
    }


# ==============================================================================
# Simulation Mock Client (For Offline College Grading / Testing)
# ==============================================================================

def create_mock_jira_client(config: JiraConfig) -> JiraClient:
    """
    Create a JiraClient configured with simulated responses.
    Allows testing and demonstrations without requiring a live Jira Cloud instance.
    """
    mock_session = MagicMock()
    mock_session.headers = {}

    auth_resp = MagicMock()
    auth_resp.status_code = 200
    auth_resp.json.return_value = {
        "displayName": "SOC Lead Analyst (Simulated)",
        "emailAddress": config.email if not config.is_placeholder else "soc-analyst@college-lab.edu",
        "accountId": "sim-acc-5529041a",
        "active": True,
    }

    projects_resp = MagicMock()
    projects_resp.status_code = 200
    projects_resp.json.return_value = [
        {"id": "10001", "key": config.project_key, "name": "Security Incident Response", "projectTypeKey": "software"},
        {"id": "10002", "key": "IT", "name": "IT Service Desk", "projectTypeKey": "service_desk"},
    ]

    project_detail_resp = MagicMock()
    project_detail_resp.status_code = 200
    project_detail_resp.json.return_value = {
        "id": "10001",
        "key": config.project_key,
        "name": "Security Incident Response",
        "issueTypes": [
            {"id": "1001", "name": "Task", "subtask": False},
            {"id": "1002", "name": "Incident", "subtask": False},
            {"id": "1003", "name": "Bug", "subtask": False},
        ],
    }

    search_resp = MagicMock()
    search_resp.status_code = 200
    search_resp.json.return_value = {"total": 0, "issues": []}

    issue_resp = MagicMock()
    issue_resp.status_code = 201
    issue_resp.json.return_value = {
        "id": "10582",
        "key": f"{config.project_key}-101",
        "self": f"{config.base_url}/rest/api/3/issue/10582",
    }

    def mock_get(url, *args, **kwargs):
        if "myself" in url:
            return auth_resp
        if "project/" in url:
            return project_detail_resp
        if "project" in url:
            return projects_resp
        if "search" in url:
            return search_resp
        return auth_resp

    def mock_post(url, *args, **kwargs):
        return issue_resp

    mock_session.get.side_effect = mock_get
    mock_session.post.side_effect = mock_post

    client = JiraClient(
        base_url=config.base_url,
        email=config.email,
        api_token=config.api_token,
        project_key=config.project_key,
        issue_type=config.issue_type,
        api_version=config.api_version,
        timeout_seconds=config.timeout_seconds,
        verify_ssl=config.verify_ssl,
        session=mock_session,
    )
    return client


# ==============================================================================
# Main Orchestrator Execution Flow
# ==============================================================================

def print_banner() -> None:
    """Print SOC Orchestrator execution banner."""
    banner = """
================================================================================
   AUTOMATED RANSOMWARE CONTAINMENT & INCIDENT RESPONSE ORCHESTRATOR
   Day 1: Jira Cloud REST API Incident Ticketing Integration (REST API v3)
================================================================================
"""
    print(banner)


def run_orchestrator(
    simulate: bool = False,
    check_auth_only: bool = False,
    alert_file: Optional[str] = None,
    env_file: Optional[str] = None,
) -> int:
    """
    Execute the Day 1 Incident Response workflow.
    
    Returns 0 on success, non-zero on error.
    """
    print_banner()

    # Step 1: Load and validate environment configuration
    print("[+] Step 1: Loading Jira configuration from environment...")
    config = load_config(env_file)
    audit = audit_configuration(config)

    print("  Configuration Audit:")
    for var_name, info in audit.items():
        if info["status"] == "PASS":
            val_display = info.get("masked_value") or info.get("value")
            print(f"    - {var_name:<18}: [PASS] {val_display}")
        else:
            print(f"    - {var_name:<18}: [FAIL] {info['reason']}")
    print()

    has_failures = any(info["status"] == "FAIL" for info in audit.values())
    if simulate:
        print("  [*] Operating in explicit SIMULATION MODE (--simulate flag active).\n")
    elif has_failures:
        print("  [FAIL] Real Jira connection cannot proceed due to configuration issue(s) above.")
        failed_vars = [k for k, v in audit.items() if v["status"] == "FAIL"]
        print(f"         Variable(s) requiring attention: {', '.join(failed_vars)}")
        print("         Please update your .env file with your valid Jira Cloud credentials.\n")
        return 1
    else:
        print("  [*] Target: LIVE Jira Cloud REST API v3 over TLS/HTTPS\n")

    # Step 2: Establish connection and verify authentication
    print("[+] Step 2: Establishing Jira Cloud connection & verifying authentication...")
    try:
        if simulate:
            client = create_mock_jira_client(config)
        else:
            client = JiraClient.from_config(config)

        auth_info = client.verify_authentication()
        print(f"  [OK] Authentication SUCCESSFUL!")
        print(f"      Authenticated As: {auth_info['display_name']} ({auth_info['email']})")
        print(f"      Account ID:       {auth_info['account_id']}\n")
    except JiraAuthenticationError as exc:
        print(f"  [FAIL] Jira Authentication FAILED: {exc}")
        print("      Please verify JIRA_EMAIL and JIRA_API_TOKEN in your .env file.")
        return 1
    except JiraConnectionError as exc:
        print(f"  [FAIL] Jira Connection FAILED: {exc}")
        print("      Check your internet connection and verify JIRA_BASE_URL is reachable.")
        return 2
    except Exception as exc:
        print(f"  [FAIL] Unexpected error during connection verification: {exc}")
        return 3

    # Step 3: Enumerate projects and identify target project key
    print("[+] Step 3: Enumerating Jira projects and verifying issue type...")
    try:
        projects = client.get_projects()
        print(f"  [OK] Discovered {len(projects)} accessible Jira project(s):")
        for p in projects:
            print(f"      - [{p['key']}] {p['name']} (Type: {p.get('project_type', 'N/A')})")

        confirmed_key = client.identify_incident_project_key(config.project_key)
        print(f"  [OK] Target Incident Project verified: [{confirmed_key}]")

        proj_info = client.verify_project_and_issue_type(confirmed_key, config.issue_type)
        if proj_info["issue_type_verified"]:
            print(f"  [OK] Target Issue Type verified: [{config.issue_type}] in project [{confirmed_key}]\n")
        else:
            avail = ", ".join(proj_info["available_issue_types"])
            print(f"  [FAIL] Issue type '{config.issue_type}' not available in project '{confirmed_key}'.")
            print(f"         Available issue types: [{avail}]")
            print(f"         Please update JIRA_ISSUE_TYPE in .env to one of the available types.\n")
            return 5

    except JiraProjectNotFoundError as exc:
        print(f"  [FAIL] Project Key Error: {exc}")
        print(f"         Ticket creation aborted because project '{config.project_key}' does not exist.")
        return 4
    except JiraIntegrationError as exc:
        print(f"  [FAIL] Failed to retrieve Jira projects: {exc}")
        return 5

    # If user only wanted to verify authentication & projects, exit now
    if check_auth_only:
        print("[OK] Pre-flight connection and project check complete.")
        return 0

    # Step 4: Collect / Ingest Ransomware Alert Telemetry
    print("[+] Step 4: Ingesting simulated ransomware incident telemetry...")
    if alert_file:
        try:
            with open(alert_file, "r", encoding="utf-8") as f:
                alert_data = json.load(f)
            print(f"  [OK] Loaded custom alert data from {alert_file}")
        except Exception as exc:
            print(f"  [FAIL] Failed to read alert file '{alert_file}': {exc}")
            return 6
    else:
        alert_data = generate_simulated_ransomware_alert()
        print("  [OK] Ingested simulated ransomware detection telemetry:")

    print(f"      Incident ID:          {alert_data.get('incident_id')}")
    print(f"      Threat Type:          {alert_data.get('incident_type')}")
    print(f"      Severity:             {alert_data.get('severity')}")
    print(f"      Affected Hostname:    {alert_data.get('hostname')}")
    print(f"      Host IP Address:      {alert_data.get('ip_address')}")
    print(f"      Compromised User:     {alert_data.get('username')}")
    print(f"      Process Hash:         {alert_data.get('process_hash')}")
    print(f"      Detection Timestamp:  {alert_data.get('detection_time')}\n")

    # Step 5 & 6: Create Jira Incident Ticket (with Duplicate Avoidance)
    print("[+] Step 5: Creating Jira Incident Ticket via REST API v3...")
    try:
        ticket_result = client.create_incident_ticket(
            incident_id=alert_data["incident_id"],
            incident_type=alert_data["incident_type"],
            severity=alert_data["severity"],
            hostname=alert_data["hostname"],
            ip_address=alert_data["ip_address"],
            username=alert_data["username"],
            process_hash=alert_data["process_hash"],
            detection_time=alert_data["detection_time"],
            incident_description=alert_data["incident_description"],
            project_key=confirmed_key,
            check_existing=True,
        )

        # Step 7: Display Generated Ticket Details
        print("[OK] Incident Ticket Handled Successfully!\n")
        print("================================================================================")
        print("                         JIRA INCIDENT TICKET DETAILS                           ")
        print("================================================================================")
        print(f"  Ticket ID:               {ticket_result['ticket_id']}")
        print(f"  Ticket Key:              {ticket_result['ticket_key']}")
        print(f"  Ticket URL:              {ticket_result['ticket_url']}")
        print(f"  Incident Severity:       {ticket_result.get('severity', alert_data.get('severity'))}")
        print(f"  Affected Hostname:       {ticket_result.get('hostname', alert_data.get('hostname'))}")
        print(f"  Ticket Creation Status:  {ticket_result['status']}")
        print(f"  Project Key:             {ticket_result['project_key']}")
        print(f"  Summary:                 {ticket_result['summary']}")
        print("================================================================================\n")
        print("[OK] Day 1 Objective Accomplished: Automated Jira Incident Response Orchestration.")
        return 0

    except IncidentValidationError as exc:
        print(f"  [FAIL] Telemetry Validation Error: {exc}")
        print("      Ticket creation aborted due to malformed incident data.")
        return 7
    except JiraTicketCreationError as exc:
        print(f"  [FAIL] Ticket Creation Error: {exc}")
        print("      Check Jira issue type and project permissions.")
        return 8
    except JiraConnectionError as exc:
        print(f"  [FAIL] Network Error: {exc}")
        return 9
    except Exception as exc:
        print(f"  [FAIL] Unexpected error during ticket creation: {exc}")
        return 10


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Automated Ransomware Containment & Incident Response Orchestrator - Day 1"
    )
    parser.add_argument(
        "--simulate",
        "-s",
        action="store_true",
        help="Run in offline simulation mode (uses mocked Jira API responses).",
    )
    parser.add_argument(
        "--check-auth",
        action="store_true",
        help="Verify Jira authentication and project access without creating a ticket.",
    )
    parser.add_argument(
        "--alert-file",
        type=str,
        default=None,
        help="Path to an optional JSON file containing custom alert data.",
    )
    parser.add_argument(
        "--env-file",
        type=str,
        default=None,
        help="Path to custom .env file (default: looks for .env in current and parent dirs).",
    )

    args = parser.parse_args()
    exit_code = run_orchestrator(
        simulate=args.simulate,
        check_auth_only=args.check_auth,
        alert_file=args.alert_file,
        env_file=args.env_file,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

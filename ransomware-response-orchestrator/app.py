#!/usr/bin/env python3
"""
app.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Automated Ransomware Containment & Incident Response Orchestrator
Day 1: EDR Live Response Integration & Containment Verification

Usage:
  python app.py                      # Run automated triage demo on default incident #1001
  python app.py --incident <ID>      # Retrieve & investigate a specific incident
  python app.py --endpoint <NAME/ID> # Verify containment status of a single endpoint
  python app.py --test-auth          # Test EDR authentication connectivity
  python app.py --mock               # Force mock mode regardless of .env configuration

Security Notes:
  - All Day 1 operations are strictly READ-ONLY.
  - Access tokens, client secrets, and passwords are fully redacted from logs.
  - Mock mode enables complete offline execution without real credentials.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Load environment variables from .env if present
try:
    from dotenv import load_dotenv
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
    else:
        # Fallback to parent directory .env if root .env exists
        parent_env = PROJECT_ROOT.parent / ".env"
        if parent_env.exists():
            load_dotenv(dotenv_path=parent_env)
except ImportError:
    pass

from integrations.defender_client import (
    ContainmentStatus,
    DefenderClient,
    EDRAPIError,
    EDRAuthenticationError,
    EDRConfig,
    EDRConfigError,
    EDRConnectionError,
    EDRError,
    EDRTimeoutError,
)
from services.incident_service import IncidentService, IncidentInvestigationReport, EndpointAssessment


# ─────────────────────────────────────────────────────────────────────────────
# Task 5: Secure Logging Configuration with Secret Redaction
# ─────────────────────────────────────────────────────────────────────────────

class SecretRedactingFormatter(logging.Formatter):
    """
    Log formatter that redacts sensitive values such as Bearer tokens,
    client secrets, and authorization headers from log streams.
    """

    import re
    TOKEN_PATTERN = re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{15,}", re.IGNORECASE)
    SECRET_PATTERN = re.compile(r"(['\"]?client_secret['\"]?\s*[:=]\s*['\"])[^'\"]+(['\"])", re.IGNORECASE)

    def format(self, record: logging.LogRecord) -> str:
        orig = super().format(record)
        redacted = self.TOKEN_PATTERN.sub(r"\1***REDACTED_TOKEN***", orig)
        redacted = self.SECRET_PATTERN.sub(r"\1***REDACTED_SECRET***\2", redacted)
        return redacted


def setup_logging(log_level_str: str = "INFO") -> logging.Logger:
    """Configures safe dual console and file logging."""
    logs_dir = PROJECT_ROOT / "logs"
    logs_dir.mkdir(exist_ok=True)
    log_file = logs_dir / "orchestrator.log"

    level = getattr(logging, log_level_str.upper(), logging.INFO)

    root_logger = logging.getLogger("orchestrator")
    root_logger.setLevel(level)

    # Avoid adding duplicate handlers on re-runs
    if not root_logger.handlers:
        formatter = SecretRedactingFormatter(
            "[%(asctime)s] [%(levelname)-7s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # File Handler (logs/orchestrator.log)
        file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

        # Console Handler (clean output for user terminal)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    return root_logger


# ─────────────────────────────────────────────────────────────────────────────
# Visual Terminal Presentation Helpers
# ─────────────────────────────────────────────────────────────────────────────

BANNER = """
================================================================================
     AUTOMATED RANSOMWARE CONTAINMENT & INCIDENT RESPONSE ORCHESTRATOR
                        DAY 1: EDR LIVE RESPONSE
================================================================================
"""

def print_banner() -> None:
    print(BANNER)


def print_incident_summary(report: IncidentInvestigationReport) -> None:
    """Renders a structured, readable incident triage report."""
    border = "-" * 80
    print("\n" + border)
    print(f"[*] INCIDENT TRIAGE REPORT: #{report.incident_id}")
    print(border)
    print(f"  Title           : {report.title}")
    print(f"  Severity        : {report.severity.upper()}")
    print(f"  Status          : {report.status}")
    print(f"  Created Time    : {report.created_time or 'N/A'}")
    print(f"  Last Update     : {report.last_update_time or 'N/A'}")
    print(f"  Investigated At : {report.investigated_at}")
    print(f"  Affected Devices: {', '.join(report.affected_devices) if report.affected_devices else 'None detected'}")
    print(f"  IP Addresses    : {', '.join(report.ip_addresses) if report.ip_addresses else 'None detected'}")

    print(f"\n[*] ASSOCIATED ALERTS ({report.alerts_count}):")
    if not report.alerts_summary:
        print("    (No alerts associated with this incident)")
    else:
        for idx, alert in enumerate(report.alerts_summary, 1):
            print(f"    [{idx}] Alert ID : {alert['alert_id']}")
            print(f"        Title    : {alert['title']}")
            print(f"        Category : {alert['category']}")
            print(f"        Severity : {alert['severity']}")

    print(f"\n[*] ENDPOINT CONTAINMENT STATUS VERIFICATION:")
    if not report.endpoint_assessments:
        print("    (No affected endpoints identified to evaluate)")
    else:
        for idx, ep in enumerate(report.endpoint_assessments, 1):
            status_tag = f"[{ep.containment_status}]"
            print(f"    [{idx}] Device Name  : {ep.device_name}")
            print(f"        Machine ID   : {ep.machine_id or 'N/A'}")
            print(f"        IP Address   : {ep.ip_address or 'N/A'}")
            print(f"        Status       : {status_tag}")
            print(f"        Raw Details  : {ep.raw_status_details}")
            print(f"        Risk Score   : {ep.risk_score}")
            print(f"        Health Status: {ep.health_status}")
            print(f"        Verified At  : {ep.verified_at}")

    print("\n[*] SOC ASSESSMENT & NEXT STEPS:")
    print(f"    {report.containment_summary}")
    print("    NOTE: Day 1 execution is strictly READ-ONLY. No isolation commands sent.")
    print(border + "\n")


def print_endpoint_assessment(assessment: EndpointAssessment) -> None:
    """Renders a standalone endpoint containment verification."""
    border = "-" * 80
    print("\n" + border)
    print(f"[*] ENDPOINT CONTAINMENT ASSESSMENT: {assessment.device_name}")
    print(border)
    print(f"  Device Name        : {assessment.device_name}")
    print(f"  Machine ID         : {assessment.machine_id or 'N/A'}")
    print(f"  IP Address         : {assessment.ip_address or 'N/A'}")
    print(f"  Containment Status : [{assessment.containment_status}]")
    print(f"  Raw EDR Details    : {assessment.raw_status_details}")
    print(f"  Risk Score         : {assessment.risk_score}")
    print(f"  Health Status      : {assessment.health_status}")
    print(f"  Verified At        : {assessment.verified_at}")
    print(border + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Automated Ransomware Containment & Incident Response Orchestrator - Day 1"
    )
    parser.add_argument(
        "--incident",
        type=str,
        default=None,
        help="Incident ID to retrieve and investigate (e.g. 1001)",
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        default=None,
        help="Endpoint name or machine ID to verify containment status (e.g. FINANCE-SRV-01)",
    )
    parser.add_argument(
        "--test-auth",
        action="store_true",
        help="Test authentication with the EDR API and print connection status",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Force mock mode execution without requiring real EDR API credentials",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON format for machine parsing",
    )

    args = parser.parse_args()

    # Determine logging level from environment
    log_level = os.getenv("LOG_LEVEL", "INFO")
    logger = setup_logging(log_level)

    print_banner()

    # Initialize configuration
    try:
        config = EDRConfig(mock_mode=True if args.mock else None)
    except EDRConfigError as err:
        logger.error("Configuration Error: %s", err)
        print(f"\n[!] Configuration Error: {err}")
        print("[!] To run without credentials, pass --mock or set EDR_MOCK_MODE=true in .env.\n")
        return 1

    client = DefenderClient(config)
    service = IncidentService(client)

    # 1. Test Authentication Mode
    if args.test_auth:
        print("[*] Testing EDR API Authentication...")
        try:
            token = client.authenticate()
            print("[+] Authentication Successful!")
            print(f"    Mode           : {'MOCK SIMULATION' if config.mock_mode else 'LIVE MICROSOFT DEFENDER'}")
            print(f"    Token Status   : Active (Bearer token verified, secrets concealed)")
            print(f"    Target API     : {config.api_base_url}")
            return 0
        except EDRAuthenticationError as err:
            print(f"[-] Authentication Failed: {err}")
            return 2
        except EDRError as err:
            print(f"[-] EDR Connection/Network Error: {err}")
            return 3

    # 2. Standalone Endpoint Containment Verification
    if args.endpoint:
        print(f"[*] Querying containment status for endpoint: {args.endpoint}")
        try:
            assessment = service.verify_single_endpoint(args.endpoint)
            if args.json:
                print(json.dumps(assessment.to_dict(), indent=2))
            else:
                print_endpoint_assessment(assessment)
            return 0
        except EDRError as err:
            logger.error("Failed to verify endpoint %s: %s", args.endpoint, err)
            print(f"[-] Error querying endpoint '{args.endpoint}': {err}")
            return 1

    # 3. Incident Investigation Workflow (Targeted or Demo)
    target_incident = args.incident or "1001"
    print(f"[*] Initiating Day 1 Incident Triage for Incident ID: {target_incident}")
    if config.mock_mode:
        print("    [Notice: Running in MOCK MODE - Safe non-production simulated telemetry]")

    try:
        report = service.investigate_incident(target_incident)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print_incident_summary(report)
        return 0
    except EDRAPIError as err:
        if err.status_code == 404:
            print(f"[-] Incident #{target_incident} was not found (HTTP 404).")
        else:
            print(f"[-] EDR API Error: {err}")
        return 1
    except EDRAuthenticationError as err:
        print(f"[-] Authentication Error: {err}")
        return 2
    except (EDRTimeoutError, EDRConnectionError) as err:
        print(f"[-] Network Connectivity Error: {err}")
        return 3
    except Exception as err:
        logger.exception("Unexpected error during incident investigation: %s", err)
        print(f"[-] Unexpected failure: {err}")
        return 99


if __name__ == "__main__":
    sys.exit(main())

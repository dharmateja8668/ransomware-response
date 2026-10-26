#!/usr/bin/env python3
"""
app.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Automated Ransomware Containment & Incident Response Orchestrator
Day 1: EDR Live Response Integration & Containment Verification
Day 2: Automated Forensic Evidence Collection (KAPE, RAM, Investigation Package)

Usage:
  # Day 1 Operations:
  python app.py                                # Run automated triage demo on default incident #1001
  python app.py --incident <ID>                # Retrieve & investigate a specific incident
  python app.py --endpoint <NAME/ID>           # Verify containment status of a single endpoint
  python app.py --test-auth                    # Test EDR authentication connectivity
  python app.py --mock                         # Force mock mode regardless of .env configuration

  # Day 2 Forensic Evidence Collection Operations:
  python app.py --collect --endpoint <NAME/ID> # Collect KAPE forensic evidence from contained endpoint
  python app.py --collect --endpoint <ID> --method RAM     # Acquire physical RAM memory image
  python app.py --collect --endpoint <ID> --method investigation_package # MDE native package
  python app.py --collect --endpoint <ID> --artifacts Registry,EventLogs,Execution # Specific categories
  python app.py --status <JOB_ID>              # Check status of an evidence collection job
  python app.py --list-collections             # List all tracked evidence collection jobs
  python app.py --collect --endpoint <ID> --wait # Wait and poll until collection completes

Security Notes:
  - Evidence collection is REFUSED unless endpoint containment status is confirmed ISOLATED.
  - Endpoint must belong to the specified incident.
  - Access tokens, client secrets, and passwords are fully redacted from logs and manifests.
  - Mock mode clearly flags simulated artifacts (simulation_indicator=True).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

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
from forensic.metadata import (
    CollectionMethod,
    CollectionStatus,
    DEFAULT_KAPE_CATEGORIES,
    EvidenceMetadata,
    KapeArtifactCategory,
)
from forensic.evidence_collector import (
    CollectionJobError,
    DuplicateJobError,
    EndpointMismatchError,
    EndpointNotContainedError,
    ForensicError,
    SafetyCheckError,
    UnknownContainmentError,
    UnsupportedMethodError,
)
from forensic.collection_service import ForensicCollectionService


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
         DAY 1: EDR LIVE RESPONSE | DAY 2: FORENSIC EVIDENCE COLLECTION
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


def print_forensic_collection(meta: EvidenceMetadata) -> None:
    """Renders a structured, readable forensic evidence collection report."""
    border = "-" * 80
    print("\n" + border)
    print(f"[*] FORENSIC EVIDENCE COLLECTION MANIFEST: Job {meta.collection_job_id}")
    print(border)
    print(f"  Incident ID          : #{meta.incident_id}")
    print(f"  Endpoint Identifier  : {meta.endpoint_id}")
    print(f"  Endpoint Hostname    : {meta.hostname or 'N/A'}")
    print(f"  Collection Method    : {meta.collection_method}")
    print(f"  Requested Artifacts  : {', '.join(meta.requested_artifacts) if meta.requested_artifacts else 'Default Profile'}")
    print(f"  Collection Status    : [{meta.status}]")
    print(f"  Requested At (UTC)   : {meta.requested_at}")
    print(f"  Completed At (UTC)   : {meta.completed_at or 'In Progress'}")
    print(f"  Artifact Location    : {meta.artifact_location or 'N/A'}")
    print(f"  File Size (Bytes)    : {meta.file_size_bytes or 'N/A'}")
    print(f"  SHA-256 Hash         : {meta.file_hash_sha256 or 'N/A'}")
    print(f"  Simulation Indicator : {'SIMULATED RUN (Non-production test)' if meta.simulation_indicator else 'LIVE EDR ACQUISITION'}")
    print(f"  Containment Verified : {'YES (Endpoint confirmed ISOLATED)' if meta.containment_verified else 'NO'}")
    if meta.error_details:
        print(f"  Error Details        : {meta.error_details}")
    if meta.diagnostic_notes:
        print(f"  Diagnostic Notes     : {meta.diagnostic_notes}")
    print(border + "\n")


def print_collections_list(jobs: List[EvidenceMetadata]) -> None:
    """Renders a summary table of forensic collection jobs."""
    border = "-" * 80
    print("\n" + border)
    print(f"[*] RECORDED FORENSIC COLLECTION JOBS ({len(jobs)}):")
    print(border)
    if not jobs:
        print("  (No forensic collection jobs recorded yet)")
    else:
        for idx, job in enumerate(jobs, 1):
            sim_flag = "[SIMULATED]" if job.simulation_indicator else "[LIVE]"
            print(f"  [{idx}] Job ID    : {job.collection_job_id} {sim_flag}")
            print(f"      Incident  : #{job.incident_id}")
            print(f"      Endpoint  : {job.hostname or job.endpoint_id}")
            print(f"      Method    : {job.collection_method}")
            print(f"      Status    : [{job.status}]")
            print(f"      Requested : {job.requested_at}")
            print(f"      Artifact  : {job.artifact_location or 'N/A'}")
            if job.error_details:
                print(f"      Error     : {job.error_details}")
    print(border + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Automated Ransomware Containment & Incident Response Orchestrator - Day 1 & Day 2"
    )
    # Common Options
    parser.add_argument(
        "--incident",
        type=str,
        default=None,
        help="Incident ID to investigate or target for collection (e.g. 1001)",
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        default=None,
        help="Endpoint name or machine ID (e.g. FINANCE-SRV-01)",
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

    # Day 2: Forensic Collection Options
    parser.add_argument(
        "--collect",
        action="store_true",
        help="Initiate authorized forensic evidence collection on contained endpoint",
    )
    parser.add_argument(
        "--method",
        type=str,
        default="KAPE",
        help="Forensic collection method: KAPE (default), RAM, or INVESTIGATION_PACKAGE",
    )
    parser.add_argument(
        "--artifacts",
        type=str,
        default=None,
        help="Comma-separated list of KAPE artifact categories (e.g. Registry,EventLogs,Execution)",
    )
    parser.add_argument(
        "--status",
        type=str,
        default=None,
        help="Query status of an existing forensic collection job ID",
    )
    parser.add_argument(
        "--list-collections",
        action="store_true",
        help="List all tracked forensic evidence collection jobs",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="Wait and poll for collection job completion before exiting",
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
    incident_service = IncidentService(client)
    forensic_service = ForensicCollectionService(client)

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

    # 2. Forensic Job Status Query
    if args.status:
        job_id = args.status.strip()
        print(f"[*] Querying status for collection job: {job_id}")
        try:
            if args.wait:
                print(f"    [Polling job until completion...]")
                meta = forensic_service.track_job(job_id)
            else:
                meta = forensic_service.get_collection_status(job_id)

            if args.json:
                print(meta.to_json(indent=2))
            else:
                print_forensic_collection(meta)
            return 0 if meta.status == CollectionStatus.COMPLETED.value else (1 if meta.status == CollectionStatus.FAILED.value else 0)
        except KeyError:
            print(f"[-] Collection job '{job_id}' not found.")
            return 1
        except Exception as err:
            logger.exception("Failed to query status for job %s: %s", job_id, err)
            print(f"[-] Error querying collection job: {err}")
            return 1

    # 3. List All Forensic Collections
    if args.list_collections:
        print("[*] Listing recorded forensic evidence collection jobs...")
        jobs = forensic_service.list_jobs(incident_id=args.incident, endpoint_id=args.endpoint)
        if args.json:
            print(json.dumps([j.to_dict() for j in jobs], indent=2))
        else:
            print_collections_list(jobs)
        return 0

    # 4. Initiate Forensic Evidence Collection
    if args.collect:
        target_incident = args.incident or "1001"
        target_endpoint = args.endpoint

        if not target_endpoint:
            # Attempt to resolve first affected device from incident
            print(f"[*] Target endpoint not specified. Inspecting Incident #{target_incident} for affected devices...")
            try:
                inc_data = client.get_incident(target_incident)
                devices = inc_data.get("all_affected_devices", [])
                if devices:
                    target_endpoint = devices[0]
                    print(f"    [Auto-selected affected device: {target_endpoint}]")
                else:
                    print("[-] Error: No affected endpoints found in incident. Please specify --endpoint.")
                    return 1
            except Exception as err:
                print(f"[-] Error retrieving incident #{target_incident}: {err}")
                return 1

        # Parse requested categories if provided
        cat_list = None
        if args.artifacts:
            cat_list = [c.strip() for c in args.artifacts.split(",") if c.strip()]

        print(f"[*] Initiating Day 2 Forensic Evidence Collection:")
        print(f"    Incident ID : #{target_incident}")
        print(f"    Endpoint    : {target_endpoint}")
        print(f"    Method      : {args.method.upper()}")
        print(f"    Categories  : {cat_list or 'Default Profile'}")
        if config.mock_mode:
            print("    [Notice: Running in MOCK MODE - Safe non-production simulated collection]")

        try:
            metadata = forensic_service.initiate_collection(
                incident_id=target_incident,
                endpoint_identifier=target_endpoint,
                method=args.method,
                artifact_categories=cat_list,
            )

            # If --wait was requested and job is still running, poll until complete
            if args.wait and metadata.status in (CollectionStatus.PENDING.value, CollectionStatus.RUNNING.value):
                print(f"    [Polling job {metadata.collection_job_id} until completion...]")
                metadata = forensic_service.track_job(metadata.collection_job_id)

            if args.json:
                print(metadata.to_json(indent=2))
            else:
                print_forensic_collection(metadata)

            return 0 if metadata.status == CollectionStatus.COMPLETED.value else (1 if metadata.status == CollectionStatus.FAILED.value else 0)

        except EndpointNotContainedError as err:
            logger.error("Collection refused - endpoint not contained: %s", err)
            print(f"\n[!] SAFETY VIOLATION: {err}")
            print("[!] Forensic collection is STRICTLY REFUSED prior to endpoint containment.")
            return 4
        except UnknownContainmentError as err:
            logger.error("Collection refused - unknown containment status: %s", err)
            print(f"\n[!] SAFETY AUDIT FAILURE: {err}")
            print("[!] Containment status must be verified as ISOLATED before evidence collection.")
            return 4
        except EndpointMismatchError as err:
            logger.error("Collection refused - endpoint mismatch: %s", err)
            print(f"\n[!] AUTHORIZATION MISMATCH: {err}")
            return 5
        except UnsupportedMethodError as err:
            logger.error("Unsupported method: %s", err)
            print(f"\n[-] Method Error: {err}")
            return 6
        except DuplicateJobError as err:
            logger.warning("Duplicate collection request: %s", err)
            print(f"\n[!] IDEMPOTENCY REJECTION: {err}")
            return 7
        except EDRAuthenticationError as err:
            logger.error("EDR authentication failed: %s", err)
            print(f"[-] EDR Authentication Error: {err}")
            return 2
        except (EDRTimeoutError, EDRConnectionError) as err:
            logger.error("Network connectivity error: %s", err)
            print(f"[-] Network Connectivity Error: {err}")
            return 3
        except EDRError as err:
            logger.error("EDR API Error: %s", err)
            print(f"[-] EDR Error: {err}")
            return 1
        except Exception as err:
            logger.exception("Unexpected error during forensic collection: %s", err)
            print(f"[-] Unexpected failure: {err}")
            return 99

    # 5. Standalone Endpoint Containment Verification (Day 1)
    if args.endpoint:
        print(f"[*] Querying containment status for endpoint: {args.endpoint}")
        try:
            assessment = incident_service.verify_single_endpoint(args.endpoint)
            if args.json:
                print(json.dumps(assessment.to_dict(), indent=2))
            else:
                print_endpoint_assessment(assessment)
            return 0
        except EDRError as err:
            logger.error("Failed to verify endpoint %s: %s", args.endpoint, err)
            print(f"[-] Error querying endpoint '{args.endpoint}': {err}")
            return 1

    # 6. Incident Investigation Workflow (Day 1 Targeted or Demo)
    target_incident = args.incident or "1001"
    print(f"[*] Initiating Incident Triage for Incident ID: {target_incident}")
    if config.mock_mode:
        print("    [Notice: Running in MOCK MODE - Safe non-production simulated telemetry]")

    try:
        report = incident_service.investigate_incident(target_incident)
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

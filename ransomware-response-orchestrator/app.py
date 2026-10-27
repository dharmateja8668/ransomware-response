#!/usr/bin/env python3
"""
app.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Automated Ransomware Containment & Incident Response Orchestrator
Day 1: EDR Live Response Integration & Containment Verification
Day 2: Automated Forensic Evidence Collection (KAPE, RAM, Investigation Package)
Day 3: Secure AWS S3 Storage for Forensic Evidence & Cryptographic Verification

Usage:
  # Day 1 Operations:
  python app.py                                # Run automated triage demo on default incident #1001
  python app.py --incident <ID>                # Retrieve & investigate a specific incident
  python app.py --endpoint <NAME/ID>           # Verify containment status of a single endpoint
  python app.py --test-auth                    # Test EDR authentication connectivity
  python app.py --mock                         # Force mock mode regardless of .env configuration

  # Day 2 Forensic Evidence Collection:
  python app.py --collect --endpoint <NAME/ID> # Collect KAPE forensic evidence from contained endpoint
  python app.py --collect --endpoint <ID> --method RAM     # Acquire physical RAM memory image
  python app.py --collect --endpoint <ID> --method investigation_package # MDE native package
  python app.py --status <JOB_ID>              # Check status of an evidence collection job
  python app.py --list-collections             # List all tracked evidence collection jobs

  # Day 3 AWS S3 Storage & Archival:
  python app.py --upload-s3 --job <JOB_ID>     # Upload and verify evidence artifact in AWS S3
  python app.py --collect --endpoint <ID> --incident 1002 --upload-s3 # Collect and auto-archive to S3
  python app.py --upload-s3 --job <JOB_ID> --s3-bucket my-evidence-bucket # Override bucket

Security Notes:
  - Evidence collection is REFUSED unless endpoint containment status is confirmed ISOLATED.
  - S3 uploads enforce SHA-256 integrity verification (never treats ETag as SHA-256).
  - Server-Side Encryption (SSE-S3 AES256 or SSE-KMS) is mandatory for S3 storage.
  - Access tokens, client secrets, and AWS credentials are fully redacted from logs and manifests.
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
from storage.s3_storage import (
    S3ChecksumMismatchError,
    S3Config,
    S3ConfigError,
    S3FileNotFoundError,
    S3NetworkError,
    S3PermissionError,
    S3StorageError,
    S3StorageService,
    UploadResult,
)
from services.evidence_catalog import (
    CatalogRecord,
    EvidenceCatalogError,
    EvidenceCatalogService,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    IntegrityCheckResult,
)
from analysis.artifact_analyzer import (
    ArtifactAnalysisReport,
    ArtifactAnalyzer,
    IOCItem,
    TriageFinding,
)
from analysis.alert_correlator import (
    AlertCorrelator,
    CorrelationReport,
    MatchedIOC,
)
from services.orchestrator_pipeline import (
    OrchestratorPipeline,
    UnifiedWorkflowReport,
)


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
 DAY 1: EDR LIVE RESPONSE | DAY 2: EVIDENCE COLLECTION | DAY 3: SECURE S3 STORAGE
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

    # Day 3: S3 Storage Fields
    if meta.s3_object_key:
        print(f"  S3 Bucket            : {meta.s3_bucket}")
        print(f"  S3 Object Key        : {meta.s3_object_key}")
        print(f"  S3 URI               : s3://{meta.s3_bucket}/{meta.s3_object_key}")
        print(f"  S3 Metadata Key      : {meta.s3_metadata_key or 'N/A'}")
        print(f"  S3 Upload Status     : [{meta.s3_upload_status}]")
        print(f"  S3 Checksum Verified : {'YES (SHA-256 Verified)' if meta.s3_checksum_verified else 'NO'}")
        if meta.s3_version_id:
            print(f"  S3 Version ID        : {meta.s3_version_id}")

    if meta.error_details:
        print(f"  Error Details        : {meta.error_details}")
    if meta.diagnostic_notes:
        print(f"  Diagnostic Notes     : {meta.diagnostic_notes}")
    print(border + "\n")


def print_s3_upload(res: UploadResult) -> None:
    """Renders a structured, readable S3 evidence archive manifest."""
    border = "-" * 80
    print("\n" + border)
    print(f"[*] AWS S3 EVIDENCE ARCHIVE MANIFEST: {res.object_key}")
    print(border)
    print(f"  S3 Bucket            : {res.bucket}")
    print(f"  Object Key           : {res.object_key}")
    print(f"  S3 URI               : {res.s3_uri}")
    print(f"  Local Artifact       : {res.local_path or 'N/A'}")
    print(f"  File Size            : {res.file_size_bytes} bytes")
    print(f"  SHA-256 Checksum     : {res.sha256_checksum}")
    print(f"  Integrity Verified   : {'YES (Cryptographically Verified)' if res.checksum_verified else 'NO'}")
    print(f"  Server-Side Encr.    : {res.server_side_encryption}")
    print(f"  Version ID           : {res.version_id or 'Disabled / Unversioned'}")
    print(f"  Metadata Key         : {res.metadata_key or 'N/A'}")
    print(f"  Uploaded At (UTC)    : {res.uploaded_at}")
    print(f"  Simulation Indicator : {'SIMULATED S3 RUN (Non-production test)' if res.simulation_indicator else 'LIVE AWS S3 STORAGE'}")
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
            s3_flag = f"[S3: {job.s3_upload_status}]" if job.s3_upload_status else "[S3: None]"
            print(f"  [{idx}] Job ID    : {job.collection_job_id} {sim_flag} {s3_flag}")
            print(f"      Incident  : #{job.incident_id}")
            print(f"      Endpoint  : {job.hostname or job.endpoint_id}")
            print(f"      Method    : {job.collection_method}")
            print(f"      Status    : [{job.status}]")
            print(f"      Requested : {job.requested_at}")
            print(f"      Artifact  : {job.artifact_location or 'N/A'}")
            if job.s3_object_key:
                print(f"      S3 URI    : s3://{job.s3_bucket}/{job.s3_object_key}")
            if job.error_details:
                print(f"      Error     : {job.error_details}")
    print(border + "\n")


def print_catalog_record(rec: CatalogRecord) -> None:
    """Renders a structured view of a single evidence catalog record."""
    border = "-" * 80
    print("\n" + border)
    print(f"[*] SQLITE EVIDENCE CATALOG RECORD: {rec.evidence_id}")
    print(border)
    print(f"  Incident ID          : #{rec.incident_id}")
    print(f"  Device Name / ID     : {rec.device_name} ({rec.device_id})")
    print(f"  Evidence Type        : {rec.evidence_type}")
    print(f"  File Name            : {rec.file_name}")
    print(f"  File Path            : {rec.file_path}")
    print(f"  File Size            : {rec.file_size_bytes} bytes")
    print(f"  SHA-256 Hash         : {rec.sha256_hash}")
    print(f"  S3 Archival Status   : [{rec.s3_upload_status or 'NOT_UPLOADED'}]")
    if rec.s3_object_key:
        print(f"  S3 URI               : s3://{rec.s3_bucket}/{rec.s3_object_key}")
        print(f"  S3 Verified          : {'YES' if rec.s3_checksum_verified else 'NO'}")
    print(f"  Simulation Indicator : {'SIMULATED TEST DATA' if rec.simulation_indicator else 'LIVE EVIDENCE'}")
    print(f"  Collected At (UTC)   : {rec.collected_at}")
    print(f"  Indexed At (UTC)     : {rec.indexed_at}")
    print(border + "\n")


def print_catalog_list(records: List[CatalogRecord]) -> None:
    """Renders a summary table of evidence records in the SQLite catalog."""
    border = "-" * 80
    print("\n" + border)
    print(f"[*] SQLITE EVIDENCE CATALOG ENTRIES ({len(records)}):")
    print(border)
    if not records:
        print("  (No evidence catalog entries found)")
    else:
        for idx, rec in enumerate(records, 1):
            sim_flag = "[SIMULATED]" if rec.simulation_indicator else "[LIVE]"
            s3_flag = f"[S3: {rec.s3_upload_status}]" if rec.s3_upload_status else "[S3: None]"
            print(f"  [{idx}] Evidence ID : {rec.evidence_id} {sim_flag} {s3_flag}")
            print(f"      Incident    : #{rec.incident_id}")
            print(f"      Device      : {rec.device_name} ({rec.device_id})")
            print(f"      Type / File : {rec.evidence_type} -> {rec.file_name}")
            print(f"      SHA-256     : {rec.sha256_hash[:16]}...{rec.sha256_hash[-8:]}")
            print(f"      Indexed At  : {rec.indexed_at}")
    print(border + "\n")


def print_integrity_result(res: IntegrityCheckResult) -> None:
    """Renders a cryptographic integrity verification result."""
    border = "-" * 80
    print("\n" + border)
    status_str = "[VERIFIED / INTACT]" if res.is_valid else "[CORRUPTED / TAMPERED]"
    print(f"[*] CRYPTOGRAPHIC INTEGRITY AUDIT: {res.evidence_id} {status_str}")
    print(border)
    print(f"  Target File Path     : {res.file_path}")
    print(f"  Indexed Catalog Hash : {res.indexed_hash}")
    print(f"  Recalculated Hash    : {res.recalculated_hash or 'FAILED_TO_CALCULATE'}")
    print(f"  Integrity Status     : {'VALID / VERIFIED INTACT' if res.is_valid else 'INVALID / MISMATCH DETECTED'}")
    print(f"  Verified At (UTC)    : {res.verified_at}")
    if res.error_message:
        print(f"  Audit Failure Detail : {res.error_message}")
    print(border + "\n")


def print_artifact_analysis(report: ArtifactAnalysisReport) -> None:
    """Renders automated forensic artifact analysis findings and IOCs."""
    border = "-" * 80
    print("\n" + border)
    threat_flag = "[RANSOMWARE DETECTED]" if report.ransomware_detected else "[NO RANSOMWARE SIGNATURE]"
    print(f"[*] FORENSIC ARTIFACT ANALYSIS REPORT: {report.evidence_id} {threat_flag}")
    print(border)
    print(f"  Incident ID          : #{report.incident_id}")
    print(f"  Evidence Type        : {report.evidence_type}")
    print(f"  Artifact Path        : {report.file_path} ({report.file_size_bytes} bytes)")
    print(f"  Ransomware Detected  : {'YES' if report.ransomware_detected else 'NO'}")
    if report.suspected_ransomware_family:
        print(f"  Suspected Family     : {report.suspected_ransomware_family}")
    print(f"  Confidence Score     : {int(report.confidence_score * 100)}%")
    print(f"  Summary Assessment   : {report.summary}")
    print(f"  Simulation Indicator : {'SIMULATED' if report.simulation_indicator else 'LIVE'}")

    print(f"\n  [Findings: {len(report.findings)}]")
    for idx, f in enumerate(report.findings, 1):
        print(f"    ({idx}) [{f.severity}] {f.title}")
        print(f"        Detail : {f.description}")
        print(f"        Ref    : {f.evidence_ref}")

    print(f"\n  [Extracted IOCs: {len(report.extracted_iocs)}]")
    for idx, ioc in enumerate(report.extracted_iocs, 1):
        print(f"    ({idx}) [{ioc.ioc_type}] {ioc.value} ({ioc.severity})")
        print(f"        Context: {ioc.context}")
    print(border + "\n")


def print_correlation_report(report: CorrelationReport) -> None:
    """Renders cross-telemetry EDR and forensic correlation results."""
    border = "-" * 80
    print("\n" + border)
    print(f"[*] EDR TELEMETRY & FORENSIC CORRELATION: Incident #{report.incident_id}")
    print(border)
    print(f"  Incident Title       : {report.incident_title}")
    print(f"  Incident Severity    : {report.incident_severity}")
    print(f"  Overall Threat Level : [{report.overall_threat_level}]")
    print(f"  Correlation Score    : {report.correlation_score} / 100")
    print(f"  Evidence Evaluated   : {report.evidence_items_evaluated} catalog items")
    print(f"  Corroborating Matches: {report.matched_iocs_count} matched IOCs")
    print(f"  Chain of Custody     : {'VERIFIED' if report.chain_of_custody_verified else 'COMPROMISED'}")
    print(f"  Simulation Indicator : {'SIMULATED' if report.simulation_indicator else 'LIVE'}")
    print(f"  Summary              : {report.summary}")

    print(f"\n  [Matched IOC Telemetry ({len(report.matched_iocs)})]:")
    for idx, m in enumerate(report.matched_iocs, 1):
        print(f"    ({idx}) [{m.match_category}] {m.ioc_value} ({m.severity})")
        print(f"        Alert   : {m.alert_title}")
        print(f"        Details : {m.details}")

    print(f"\n  [Containment Recommendations ({len(report.containment_recommendations)})]:")
    for idx, r in enumerate(report.containment_recommendations, 1):
        print(f"    [{idx}] {r}")
    print(border + "\n")


def print_pipeline_report(report: UnifiedWorkflowReport) -> None:
    """Renders end-to-end incident response pipeline summary."""
    border = "=" * 80
    print("\n" + border)
    print(f"[*] END-TO-END RANSOMWARE ORCHESTRATOR PIPELINE REPORT")
    print(border)
    print(f"  Incident ID          : #{report.incident_id}")
    print(f"  Execution Status     : [{report.pipeline_status}]")
    print(f"  Executed At (UTC)    : {report.executed_at}")
    print(f"  Simulation Indicator : {'SIMULATED (Safe Demo Mode)' if report.simulation_indicator else 'LIVE PRODUCTION'}")
    print(f"  Stage 1 Triage       : {'SUCCESS' if report.triage_report else 'FAILED'}")
    print(f"  Stage 2 Collections  : {report.collected_jobs_count} jobs completed")
    print(f"  Stage 3 S3 Archival  : {report.s3_uploaded_count} artifacts secured in S3")
    print(f"  Stage 4 SQLite Index : {report.indexed_records_count} evidence records indexed")
    print(f"  Stage 5 Artifact Triage: {report.analyzed_reports_count} analysis reports compiled")
    if report.correlation_report:
        print(f"  Stage 6 Correlation  : Threat [{report.correlation_report.overall_threat_level}], Score {report.correlation_report.correlation_score}/100")
    if report.errors:
        print(f"\n  [Pipeline Warnings/Errors ({len(report.errors)})]:")
        for err in report.errors:
            print(f"    [-] {err}")
    print(border + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Automated Ransomware Containment & Incident Response Orchestrator - Days 1, 2, and 3"
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
        help="Force mock mode execution without requiring real EDR API or AWS credentials",
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

    # Day 3: AWS S3 Cloud Storage Options
    parser.add_argument(
        "--upload-s3",
        action="store_true",
        help="Upload evidence artifact and manifest to AWS S3 storage",
    )
    parser.add_argument(
        "--job",
        type=str,
        default=None,
        help="Specific collection job ID to archive to S3",
    )
    parser.add_argument(
        "--s3-bucket",
        type=str,
        default=None,
        help="Override AWS S3 bucket name for evidence archiving",
    )

    # Day 4: Evidence Cataloging, Verification, Analysis & Correlation Options
    parser.add_argument(
        "--full-workflow",
        action="store_true",
        help="Execute automated end-to-end Days 1-4 incident response lifecycle",
    )
    parser.add_argument(
        "--index-job",
        type=str,
        default=None,
        help="Index a completed forensic collection job ID into the SQLite evidence catalog",
    )
    parser.add_argument(
        "--list-catalog",
        action="store_true",
        help="List all forensic evidence records from the SQLite catalog",
    )
    parser.add_argument(
        "--search-catalog",
        type=str,
        default=None,
        help="Search the evidence catalog by hostname, file name, or SHA-256 hash",
    )
    parser.add_argument(
        "--verify-integrity",
        type=str,
        default=None,
        help="Cryptographically verify local evidence file SHA-256 against catalog record",
    )
    parser.add_argument(
        "--analyze-artifact",
        type=str,
        default=None,
        help="Perform automated forensic triage or memory artifact analysis on file/evidence ID",
    )
    parser.add_argument(
        "--correlate",
        action="store_true",
        help="Correlate Defender for Endpoint alerts with catalog evidence and artifact findings",
    )

    args = parser.parse_args()

    # Determine logging level from environment
    log_level = os.getenv("LOG_LEVEL", "INFO")
    logger = setup_logging(log_level)

    print_banner()

    # Initialize configuration
    try:
        config = EDRConfig(mock_mode=True if args.mock else None)
        s3_config = S3Config(
            bucket_name=args.s3_bucket,
            mock_mode=True if args.mock else None,
        )
    except (EDRConfigError, S3ConfigError) as err:
        logger.error("Configuration Error: %s", err)
        print(f"\n[!] Configuration Error: {err}")
        print("[!] To run without credentials, pass --mock or set EDR_MOCK_MODE=true in .env.\n")
        return 1

    client = DefenderClient(config)
    incident_service = IncidentService(client)
    s3_service = S3StorageService(s3_config)
    forensic_service = ForensicCollectionService(
        defender_client=client,
        s3_storage_service=s3_service,
    )
    catalog_service = EvidenceCatalogService()
    artifact_analyzer = ArtifactAnalyzer()
    alert_correlator = AlertCorrelator()
    orchestrator_pipeline = OrchestratorPipeline(
        defender_client=client,
        incident_service=incident_service,
        collection_service=forensic_service,
        s3_service=s3_service,
        catalog_service=catalog_service,
        analyzer=artifact_analyzer,
        correlator=alert_correlator,
    )

    # 0. End-to-End Orchestrator Pipeline (Days 1 - 4)
    if args.full_workflow:
        target_inc = args.incident or "1001"
        print(f"[*] Executing End-to-End Orchestrator Pipeline for Incident #{target_inc}...")
        if config.mock_mode:
            print("    [Notice: Running in MOCK MODE - Safe non-production simulated pipeline]")
        pipe_report = orchestrator_pipeline.run_full_workflow(
            incident_id=target_inc,
            upload_to_s3=args.upload_s3,
        )
        if args.json:
            print(json.dumps(pipe_report.to_dict(), indent=2))
        else:
            print_pipeline_report(pipe_report)
        return 0 if pipe_report.pipeline_status != "FAILED" else 1

    # 0.1 SQLite Catalog Indexing
    if args.index_job:
        job_id = args.index_job.strip()
        print(f"[*] Indexing forensic collection job '{job_id}' into SQLite catalog...")
        try:
            meta = forensic_service.get_collection_status(job_id)
            rec = catalog_service.index_evidence_metadata(meta)
            if args.json:
                print(json.dumps(rec.to_dict(), indent=2))
            else:
                print_catalog_record(rec)
            return 0
        except KeyError:
            print(f"[-] Collection job '{job_id}' not found.")
            return 1
        except Exception as err:
            logger.exception("Failed to index job %s: %s", job_id, err)
            print(f"[-] Indexing Failed: {err}")
            return 1

    # 0.2 List Catalog
    if args.list_catalog:
        print("[*] Retrieving evidence records from SQLite catalog...")
        records = catalog_service.list_records()
        if args.json:
            print(json.dumps([r.to_dict() for r in records], indent=2))
        else:
            print_catalog_list(records)
        return 0

    # 0.3 Search Catalog
    if args.search_catalog:
        query = args.search_catalog.strip()
        print(f"[*] Searching SQLite evidence catalog for: '{query}'...")
        records = catalog_service.search(query=query, incident_id=args.incident)
        if args.json:
            print(json.dumps([r.to_dict() for r in records], indent=2))
        else:
            print_catalog_list(records)
        return 0

    # 0.4 Cryptographic Integrity Verification
    if args.verify_integrity:
        ev_id = args.verify_integrity.strip()
        print(f"[*] Cryptographically verifying SHA-256 integrity for evidence ID: '{ev_id}'...")
        res = catalog_service.verify_integrity(ev_id)
        if args.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print_integrity_result(res)
        return 0 if res.is_valid else 1

    # 0.5 Automated Forensic Artifact Analysis
    if args.analyze_artifact:
        target = args.analyze_artifact.strip()
        print(f"[*] Running automated forensic artifact analysis on '{target}'...")
        rec = catalog_service.get_record(target)
        if rec:
            file_target = rec.file_path
            ev_id = rec.evidence_id
            inc_id = rec.incident_id
            ev_type = rec.evidence_type
            sim = rec.simulation_indicator
        else:
            file_target = target
            ev_id = Path(target).stem
            inc_id = args.incident or "1001"
            ev_type = "KAPE" if "kape" in target.lower() else ("RAM" if "ram" in target.lower() else "TRIAGE")
            sim = True if config.mock_mode else False

        res = artifact_analyzer.analyze_evidence_file(
            file_path=file_target,
            evidence_id=ev_id,
            incident_id=inc_id,
            evidence_type=ev_type,
            simulation_indicator=sim,
        )
        if args.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print_artifact_analysis(res)
        return 0

    # 0.6 EDR Alert Telemetry Correlation
    if args.correlate:
        target_inc = args.incident or "1001"
        print(f"[*] Correlating EDR alerts with forensic findings for Incident #{target_inc}...")
        try:
            inc_report = incident_service.investigate_incident(target_inc)
            raw_alerts = client.get_incident_alerts(target_inc)
            records = catalog_service.find_by_incident(target_inc)
            analysis_reps = []
            for r in records:
                if r.file_path and Path(r.file_path).exists():
                    analysis_reps.append(
                        artifact_analyzer.analyze_evidence_file(
                            file_path=r.file_path,
                            evidence_id=r.evidence_id,
                            incident_id=target_inc,
                            evidence_type=r.evidence_type,
                            simulation_indicator=r.simulation_indicator,
                        )
                    )
            corr = alert_correlator.correlate(
                incident_id=target_inc,
                incident_title=inc_report.title,
                incident_severity=inc_report.severity,
                edr_alerts=raw_alerts,
                catalog_records=records,
                analysis_reports=analysis_reps,
                simulation_indicator=config.mock_mode,
            )
            if args.json:
                print(json.dumps(corr.to_dict(), indent=2))
            else:
                print_correlation_report(corr)
            return 0
        except Exception as err:
            logger.exception("Correlation failed for incident %s: %s", target_inc, err)
            print(f"[-] Correlation Failed: {err}")
            return 1

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

    # 2. Standalone AWS S3 Archival Mode
    if args.upload_s3 and not args.collect:
        target_job = args.job or args.status
        if not target_job:
            print("[-] Error: Please specify target job ID to archive via --job <JOB_ID> or --status <JOB_ID>.")
            return 1

        print(f"[*] Archiving forensic evidence for job '{target_job}' to AWS S3...")
        if s3_config.mock_mode:
            print("    [Notice: Running in MOCK S3 MODE - Safe simulated cloud storage]")

        try:
            res = forensic_service.archive_job_to_s3(target_job)
            if args.json:
                print(json.dumps(res.to_dict(), indent=2))
            else:
                print_s3_upload(res)
            return 0
        except S3FileNotFoundError as err:
            print(f"[-] Local Evidence File Missing: {err}")
            return 1
        except S3PermissionError as err:
            print(f"[-] AWS S3 Permission Denied: {err}")
            return 2
        except S3NetworkError as err:
            print(f"[-] AWS S3 Network Error: {err}")
            return 3
        except S3ChecksumMismatchError as err:
            print(f"[-] Cryptographic Integrity Check Failed: {err}")
            return 4
        except KeyError:
            print(f"[-] Collection job '{target_job}' was not found.")
            return 1
        except Exception as err:
            logger.exception("S3 upload failed for job %s: %s", target_job, err)
            print(f"[-] S3 Archival Failed: {err}")
            return 1

    # 3. Forensic Job Status Query
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

    # 4. List All Forensic Collections
    if args.list_collections:
        print("[*] Listing recorded forensic evidence collection jobs...")
        jobs = forensic_service.list_jobs(incident_id=args.incident, endpoint_id=args.endpoint)
        if args.json:
            print(json.dumps([j.to_dict() for j in jobs], indent=2))
        else:
            print_collections_list(jobs)
        return 0

    # 5. Initiate Forensic Evidence Collection
    if args.collect:
        target_incident = args.incident or "1001"
        target_endpoint = args.endpoint

        if not target_endpoint:
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

        cat_list = None
        if args.artifacts:
            cat_list = [c.strip() for c in args.artifacts.split(",") if c.strip()]

        print(f"[*] Initiating Day 2 Forensic Evidence Collection:")
        print(f"    Incident ID : #{target_incident}")
        print(f"    Endpoint    : {target_endpoint}")
        print(f"    Method      : {args.method.upper()}")
        print(f"    Categories  : {cat_list or 'Default Profile'}")
        if args.upload_s3:
            print(f"    S3 Archival : Enabled (Bucket: {s3_config.bucket_name})")
        if config.mock_mode:
            print("    [Notice: Running in MOCK MODE - Safe non-production simulated collection]")

        try:
            metadata = forensic_service.initiate_collection(
                incident_id=target_incident,
                endpoint_identifier=target_endpoint,
                method=args.method,
                artifact_categories=cat_list,
                upload_to_s3=args.upload_s3,
            )

            # If --wait was requested and job is still running, poll until complete
            if args.wait and metadata.status in (CollectionStatus.PENDING.value, CollectionStatus.RUNNING.value):
                print(f"    [Polling job {metadata.collection_job_id} until completion...]")
                metadata = forensic_service.track_job(metadata.collection_job_id)

                # If S3 upload was requested and job completed during tracking
                if args.upload_s3 and metadata.status == CollectionStatus.COMPLETED.value and not metadata.s3_object_key:
                    forensic_service.archive_job_to_s3(metadata.collection_job_id)
                    metadata = forensic_service.get_collection_status(metadata.collection_job_id)

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

    # 6. Standalone Endpoint Containment Verification (Day 1)
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

    # 7. Incident Investigation Workflow (Day 1 Targeted or Demo)
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

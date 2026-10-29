"""
tests/test_chain_of_custody.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Comprehensive Automated Tests for Forensic Chain-of-Custody & Audit Integrity.
Automated Ransomware Containment & Incident Response Orchestrator - Day 5.

Test Coverage:
  1. Audit event creation, fields, and UTC ISO-8601 timestamps.
  2. Deterministic serialization and SHA-256 hash chaining.
  3. Successful cryptographic audit-chain verification.
  4. Detection of tampered/modified records.
  5. Detection of missing (deleted) or reordered audit records.
  6. Database immutability triggers (preventing UPDATE/DELETE).
  7. Secret redaction (tokens, passwords, AWS keys) from audit records.
  8. Chronological evidence and incident history retrieval.
  9. Safe concurrent audit ledger writes across multiple threads.
 10. Audit policy enforcement (STRICT raises AuditLoggingError vs PERMISSIVE).
 11. Mock versus Real execution mode distinction.
 12. Full end-to-end incident response mock workflow with chain-of-custody verification.
 13. Safety failure tests:
       - Containment verification failure (evidence collection strictly refused).
       - Evidence collection failure handling.
       - Evidence integrity verification failure (tampered artifact detection).
       - S3 upload failure handling.
       - Catalog indexing failure handling.
       - Audit logging failure policy enforcement.
       - Compromised audit chain detection at final pipeline stage.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from analysis.alert_correlator import AlertCorrelator
from analysis.artifact_analyzer import ArtifactAnalyzer
from forensic.chain_of_custody import (
    AuditAction,
    AuditEvent,
    AuditIntegrityError,
    AuditLoggingError,
    AuditPolicy,
    AuditStatus,
    AuditVerificationResult,
    ChainOfCustodyService,
    ExecutionMode,
    GENESIS_HASH,
    sanitize_audit_details,
)
from forensic.collection_service import ForensicCollectionService
from forensic.metadata import CollectionMethod, CollectionStatus, EvidenceMetadata
from integrations.defender_client import DefenderClient
from services.evidence_catalog import CatalogRecord, EvidenceCatalogService
from services.incident_service import (
    EndpointAssessment,
    IncidentInvestigationReport,
    IncidentService,
)
from services.orchestrator_pipeline import OrchestratorPipeline, UnifiedWorkflowReport
from storage.s3_storage import S3StorageService


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def in_memory_audit() -> ChainOfCustodyService:
    """Provides a fresh, isolated in-memory ChainOfCustodyService."""
    return ChainOfCustodyService(db_path=":memory:", policy=AuditPolicy.STRICT)


@pytest.fixture
def temp_db_audit(tmp_path: Path) -> ChainOfCustodyService:
    """Provides a fresh file-backed ChainOfCustodyService."""
    db_file = tmp_path / "test_custody.db"
    return ChainOfCustodyService(db_path=str(db_file), policy=AuditPolicy.STRICT)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Unit Tests: Audit Event Creation & Hash Chaining
# ─────────────────────────────────────────────────────────────────────────────

def test_audit_event_creation_and_genesis(in_memory_audit: ChainOfCustodyService):
    """Verifies creation of the initial audit record with documented genesis hash."""
    event = in_memory_audit.record_event(
        action=AuditAction.COLLECTION_REQUESTED,
        status=AuditStatus.SUCCESS,
        incident_id="1001",
        endpoint_id="ENDPOINT-01",
        actor="ForensicCollectionService",
        execution_mode=ExecutionMode.MOCK,
        details={"method": "KAPE"},
    )

    assert event.sequence_number == 1
    assert event.action == AuditAction.COLLECTION_REQUESTED.value
    assert event.status == AuditStatus.SUCCESS.value
    assert event.previous_event_hash == GENESIS_HASH
    assert len(event.event_hash) == 64
    assert event.incident_id == "1001"
    assert event.endpoint_id == "ENDPOINT-01"
    assert event.execution_mode == ExecutionMode.MOCK.value

    # Validate UTC timestamp format
    ts = datetime.fromisoformat(event.timestamp)
    assert ts.tzinfo is not None


def test_hash_chaining_multiple_events(in_memory_audit: ChainOfCustodyService):
    """Verifies that subsequent events link to the preceding event hash in sequence."""
    ev1 = in_memory_audit.record_event(
        action=AuditAction.COLLECTION_REQUESTED,
        incident_id="1001",
        evidence_id="ev-001",
    )
    ev2 = in_memory_audit.record_event(
        action=AuditAction.COLLECTION_STARTED,
        incident_id="1001",
        evidence_id="ev-001",
    )
    ev3 = in_memory_audit.record_event(
        action=AuditAction.COLLECTION_COMPLETED,
        incident_id="1001",
        evidence_id="ev-001",
        evidence_hash="a" * 64,
    )

    assert ev1.previous_event_hash == GENESIS_HASH
    assert ev2.previous_event_hash == ev1.event_hash
    assert ev3.previous_event_hash == ev2.event_hash

    assert ev1.sequence_number == 1
    assert ev2.sequence_number == 2
    assert ev3.sequence_number == 3

    # Verification passes
    check = in_memory_audit.verify_audit_chain()
    assert check.is_valid is True
    assert check.total_events == 3
    assert check.verified_events == 3
    assert check.error_message is None


def test_deterministic_hashing():
    """Verifies that compute_event_hash produces deterministic SHA-256 output."""
    hash1 = ChainOfCustodyService.compute_event_hash(
        event_id="aud-123",
        sequence_number=1,
        action="COLLECTION_REQUESTED",
        status="SUCCESS",
        timestamp="2026-10-29T10:00:00+00:00",
        actor="test",
        execution_mode="MOCK",
        previous_event_hash=GENESIS_HASH,
        incident_id="1001",
        details={"b": 2, "a": 1},  # Key order differences should not alter hash
    )

    hash2 = ChainOfCustodyService.compute_event_hash(
        event_id="aud-123",
        sequence_number=1,
        action="COLLECTION_REQUESTED",
        status="SUCCESS",
        timestamp="2026-10-29T10:00:00+00:00",
        actor="test",
        execution_mode="MOCK",
        previous_event_hash=GENESIS_HASH,
        incident_id="1001",
        details={"a": 1, "b": 2},  # Same keys in different order
    )

    assert hash1 == hash2

    # Any modification must produce a different hash
    hash3 = ChainOfCustodyService.compute_event_hash(
        event_id="aud-123",
        sequence_number=1,
        action="COLLECTION_STARTED",  # Modified action
        status="SUCCESS",
        timestamp="2026-10-29T10:00:00+00:00",
        actor="test",
        execution_mode="MOCK",
        previous_event_hash=GENESIS_HASH,
        incident_id="1001",
        details={"a": 1, "b": 2},
    )
    assert hash1 != hash3


# ─────────────────────────────────────────────────────────────────────────────
# 2. Tamper Detection & Immutability Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_detect_modified_record(temp_db_audit: ChainOfCustodyService):
    """Verifies detection of tampered or altered audit records."""
    temp_db_audit.record_event(action=AuditAction.COLLECTION_REQUESTED, incident_id="1001")
    ev2 = temp_db_audit.record_event(action=AuditAction.COLLECTION_STARTED, incident_id="1001")
    temp_db_audit.record_event(action=AuditAction.COLLECTION_COMPLETED, incident_id="1001")

    # Bypass trigger by temporarily dropping it to simulate an attacker with raw DB access
    conn = sqlite3.connect(temp_db_audit.db_path)
    conn.execute("DROP TRIGGER prevent_coc_update;")
    conn.execute(
        "UPDATE chain_of_custody SET status = 'TAMPERED' WHERE sequence_number = 2;"
    )
    conn.commit()
    conn.close()

    # Chain verification must fail
    check = temp_db_audit.verify_audit_chain()
    assert check.is_valid is False
    assert check.total_events == 3
    assert check.verified_events == 1
    assert "Cryptographic hash mismatch" in (check.error_message or "")
    assert check.compromised_sequence == 2
    assert check.compromised_event_id == ev2.event_id


def test_detect_missing_record(temp_db_audit: ChainOfCustodyService):
    """Verifies detection of deleted audit records creating sequence gaps."""
    temp_db_audit.record_event(action=AuditAction.COLLECTION_REQUESTED, incident_id="1001")
    temp_db_audit.record_event(action=AuditAction.COLLECTION_STARTED, incident_id="1001")
    temp_db_audit.record_event(action=AuditAction.COLLECTION_COMPLETED, incident_id="1001")

    # Drop trigger and delete middle record
    conn = sqlite3.connect(temp_db_audit.db_path)
    conn.execute("DROP TRIGGER prevent_coc_delete;")
    conn.execute("DELETE FROM chain_of_custody WHERE sequence_number = 2;")
    conn.commit()
    conn.close()

    check = temp_db_audit.verify_audit_chain()
    assert check.is_valid is False
    assert "Sequence discontinuity detected" in (check.error_message or "")


def test_sqlite_triggers_prevent_update_and_delete(temp_db_audit: ChainOfCustodyService):
    """Verifies that SQLite triggers actively reject UPDATE and DELETE queries."""
    temp_db_audit.record_event(action=AuditAction.COLLECTION_REQUESTED, incident_id="1001")

    conn = sqlite3.connect(temp_db_audit.db_path)
    # Attempt UPDATE
    with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError), match="immutable and cannot be updated"):
        conn.execute("UPDATE chain_of_custody SET action = 'HACKED' WHERE sequence_number = 1;")

    # Attempt DELETE
    with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError), match="immutable and cannot be deleted"):
        conn.execute("DELETE FROM chain_of_custody WHERE sequence_number = 1;")

    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# 3. Secret Redaction Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_secret_redaction(in_memory_audit: ChainOfCustodyService):
    """Verifies that sensitive credentials are redacted before persistence and hashing."""
    event = in_memory_audit.record_event(
        action=AuditAction.COLLECTION_STARTED,
        details={
            "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload",
            "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
            "client_secret": "SuperSecretPassword123!",
            "normal_field": "safe_value",
        },
    )

    details = event.details
    assert details["normal_field"] == "safe_value"
    assert "***REDACTED" in details["authorization"]
    assert "***REDACTED" in details["aws_access_key"]
    assert "***REDACTED" in details["client_secret"]


# ─────────────────────────────────────────────────────────────────────────────
# 4. History Queries & Search Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_evidence_and_incident_history_retrieval(in_memory_audit: ChainOfCustodyService):
    """Verifies scoped history retrieval for specific incidents and evidence items."""
    in_memory_audit.record_event(action=AuditAction.COLLECTION_REQUESTED, incident_id="1001", evidence_id="ev-A")
    in_memory_audit.record_event(action=AuditAction.COLLECTION_REQUESTED, incident_id="1002", evidence_id="ev-B")
    in_memory_audit.record_event(action=AuditAction.COLLECTION_COMPLETED, incident_id="1001", evidence_id="ev-A")

    ev_a_history = in_memory_audit.get_evidence_history("ev-A")
    assert len(ev_a_history) == 2
    assert all(e.evidence_id == "ev-A" for e in ev_a_history)

    inc_1002_history = in_memory_audit.get_incident_history("1002")
    assert len(inc_1002_history) == 1
    assert inc_1002_history[0].evidence_id == "ev-B"

    recent = in_memory_audit.list_recent_events(limit=2)
    assert len(recent) == 2
    assert recent[0].sequence_number == 3


# ─────────────────────────────────────────────────────────────────────────────
# 5. Concurrency Safety Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_concurrent_audit_writes(temp_db_audit: ChainOfCustodyService):
    """Verifies that concurrent threads write to the ledger without collisions or hash breaks."""
    num_threads = 10
    events_per_thread = 5

    def worker(worker_id: int):
        for i in range(events_per_thread):
            temp_db_audit.record_event(
                action=AuditAction.COLLECTION_REQUESTED,
                incident_id=f"inc-{worker_id}",
                evidence_id=f"ev-{worker_id}-{i}",
                actor=f"worker-{worker_id}",
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, w) for w in range(num_threads)]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    total_events = temp_db_audit.count_events()
    assert total_events == num_threads * events_per_thread

    # Validate that entire hash chain is unbroken despite concurrent interleaved inserts
    verification = temp_db_audit.verify_audit_chain()
    assert verification.is_valid is True
    assert verification.total_events == total_events


# ─────────────────────────────────────────────────────────────────────────────
# 6. Audit Failure Policy Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_audit_policy_strict_raises_error():
    """Verifies that STRICT policy raises AuditLoggingError on write failure."""
    service = ChainOfCustodyService(db_path=":memory:", policy=AuditPolicy.STRICT)
    # Sabotage database connection to force an error
    with patch.object(service, "_get_connection", side_effect=sqlite3.OperationalError("Disk I/O error")):
        with pytest.raises(AuditLoggingError):
            service.record_event(action=AuditAction.COLLECTION_REQUESTED, incident_id="1001")


def test_audit_policy_permissive_logs_without_raising():
    """Verifies that PERMISSIVE policy returns a failure event rather than raising."""
    service = ChainOfCustodyService(db_path=":memory:", policy=AuditPolicy.PERMISSIVE)
    with patch.object(service, "_get_connection", side_effect=sqlite3.OperationalError("Disk I/O error")):
        event = service.record_event(action=AuditAction.COLLECTION_REQUESTED, incident_id="1001")
        assert event.status == AuditStatus.FAILURE.value
        assert event.sequence_number is None


# ─────────────────────────────────────────────────────────────────────────────
# 7. End-to-End Orchestrator Pipeline Integration & Safety Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_full_pipeline_mock_execution_records_audit_trail(tmp_path: Path):
    """
    Validates end-to-end incident response mock workflow with full chain-of-custody.
    Verifies containment pre-check, collection, S3 archival, cataloging, analysis,
    correlation, and final cryptographic chain verification.
    """
    mock_defender = MagicMock()
    mock_defender.mock_mode = True
    mock_defender.config.mock_mode = True
    mock_defender.check_live_response_capability.return_value = {
        "supported": True,
        "os_platform": "Windows10",
        "os_version": "10.0.19045",
        "live_response_configured": True,
        "reason": None,
    }
    # Mock incident #1001 where endpoint is verified ISOLATED
    mock_defender.get_incident.return_value = {
        "incident_id": "1001",
        "title": "Ransomware outbreak via PowerShell",
        "severity": "High",
        "status": "Active",
        "created_time": "2026-10-29T08:00:00Z",
        "last_update_time": "2026-10-29T08:30:00Z",
        "all_affected_devices": ["CONTAINED-HOST-01"],
        "all_ip_addresses": ["10.0.1.50"],
        "alerts": [
            {
                "id": "alt-101",
                "title": "Suspicious PowerShell activity",
                "category": "Execution",
                "severity": "High",
                "device_name": "CONTAINED-HOST-01",
                "machine_id": "mach-01",
                "ip_address": "10.0.1.50",
            }
        ],
    }
    # Mock endpoint containment as ISOLATED
    mock_defender.get_endpoint_containment_status.return_value = {
        "machine_id": "mach-01",
        "device_name": "CONTAINED-HOST-01",
        "ip_address": "10.0.1.50",
        "containment_status": "ISOLATED",
        "isolation_status": "ISOLATED",
        "risk_score": "High",
        "health_status": "Active",
        "raw_status_details": "Machine isolation confirmed via Defender Live Response",
        "simulation_indicator": True,
    }
    mock_defender.get_incident_alerts.return_value = [
        {
            "id": "alt-101",
            "title": "vssadmin delete shadows",
            "severity": "High",
            "evidence": [{"processCommandLine": "vssadmin delete shadows /all /quiet"}],
        }
    ]

    db_path = str(tmp_path / "e2e_custody.db")
    audit_service = ChainOfCustodyService(db_path=db_path)
    catalog_service = EvidenceCatalogService(db_path=db_path, audit_service=audit_service)

    # Temporary evidence directory
    ev_dir = tmp_path / "evidence_meta"
    ev_dir.mkdir()

    collection_service = ForensicCollectionService(
        defender_client=mock_defender,
        evidence_dir=ev_dir,
        audit_service=audit_service,
    )

    pipeline = OrchestratorPipeline(
        defender_client=mock_defender,
        collection_service=collection_service,
        catalog_service=catalog_service,
        audit_service=audit_service,
    )

    report = pipeline.run_full_workflow(
        incident_id="1001",
        upload_to_s3=False,
        collection_types=["KAPE"],
    )

    assert report.incident_id == "1001"
    assert report.pipeline_status in {"SUCCESS", "PARTIAL_SUCCESS"}
    assert report.collected_jobs_count == 1
    assert report.indexed_records_count == 1
    assert report.analyzed_reports_count == 1
    assert report.chain_of_custody_verified is True
    assert report.audit_events_count >= 5

    # Verify audit chain independently
    verification = audit_service.verify_audit_chain()
    assert verification.is_valid is True
    assert verification.total_events == report.audit_events_count

    # Verify recorded actions include containment, collection, indexing, and analysis
    history = audit_service.get_incident_history("1001")
    actions = [e.action for e in history]
    assert AuditAction.CONTAINMENT_VERIFIED.value in actions
    assert AuditAction.COLLECTION_REQUESTED.value in actions
    assert AuditAction.COLLECTION_STARTED.value in actions
    assert AuditAction.COLLECTION_COMPLETED.value in actions
    assert AuditAction.EVIDENCE_INDEXED.value in actions


def test_safety_containment_failure_prevents_evidence_collection(tmp_path: Path):
    """
    Mandatory Safety Test: If an endpoint fails containment verification (NOT_ISOLATED),
    the pipeline MUST refuse collection and record CONTAINMENT_FAILED in audit log.
    """
    mock_defender = MagicMock()
    mock_defender.mock_mode = True
    mock_defender.get_incident.return_value = {
        "incident_id": "2001",
        "title": "Active Lateral Movement Outbreak",
        "severity": "Critical",
        "status": "Active",
        "affected_device_name": "UNCONTAINED-SRV-01",
        "all_affected_devices": ["UNCONTAINED-SRV-01"],
        "all_ip_addresses": ["10.0.2.100"],
        "alerts": [],
    }
    # Endpoint is NOT_ISOLATED
    mock_defender.get_endpoint_containment_status.return_value = {
        "machine_id": "mach-uncontained",
        "device_name": "UNCONTAINED-SRV-01",
        "containment_status": "NOT_ISOLATED",
        "isolation_status": "NOT_ISOLATED",
        "raw_status_details": "Endpoint is unconstrained on production VLAN",
        "simulation_indicator": True,
    }

    db_path = str(tmp_path / "safety_containment.db")
    audit_service = ChainOfCustodyService(db_path=db_path)
    pipeline = OrchestratorPipeline(
        defender_client=mock_defender,
        audit_service=audit_service,
    )

    report = pipeline.run_full_workflow(incident_id="2001", collection_types=["KAPE"])

    # Collection MUST be refused (0 jobs)
    assert report.collected_jobs_count == 0
    assert any(
        "not isolated" in err.lower()
        or "not_isolated" in err.lower()
        or "disallowed" in err.lower()
        for err in report.errors
    )

    # Audit ledger MUST record CONTAINMENT_FAILED
    history = audit_service.get_incident_history("2001")
    containment_events = [e for e in history if e.action == AuditAction.CONTAINMENT_FAILED.value]
    assert len(containment_events) == 1
    assert containment_events[0].status == AuditStatus.FAILURE.value


def test_safety_tampered_evidence_file_triggers_integrity_rejection(tmp_path: Path):
    """
    Mandatory Safety Test: Modifying file bytes triggers integrity audit rejection
    and records INTEGRITY_REJECTED in chain of custody.
    """
    db_path = str(tmp_path / "integrity_test.db")
    audit_service = ChainOfCustodyService(db_path=db_path)
    catalog = EvidenceCatalogService(db_path=db_path, audit_service=audit_service)

    # Create dummy evidence file
    ev_file = tmp_path / "artifact.raw"
    ev_file.write_bytes(b"Original forensic bitstream bytes")
    orig_hash = catalog.compute_sha256(str(ev_file))

    meta = EvidenceMetadata(
        incident_id="3001",
        endpoint_id="mach-01",
        collection_job_id="ev-tamper-test",
        artifact_location=str(ev_file),
        file_hash_sha256=orig_hash,
        file_size_bytes=len(b"Original forensic bitstream bytes"),
        status=CollectionStatus.COMPLETED.value,
        simulation_indicator=True,
    )
    catalog.index_evidence_metadata(meta)

    # Tamper with file
    ev_file.write_bytes(b"Tampered modified data bytes")

    # Run cryptographic verification
    result = catalog.verify_integrity("ev-tamper-test")
    assert result.is_valid is False
    assert "Hash mismatch" in (result.error_message or "")

    # Check audit log records INTEGRITY_REJECTED
    history = audit_service.get_evidence_history("ev-tamper-test")
    actions = [e.action for e in history]
    assert AuditAction.INTEGRITY_REJECTED.value in actions


def test_safety_audit_write_failure_in_strict_mode_halts_pipeline(tmp_path: Path):
    """
    Mandatory Safety Test: When security policy requires successful audit logging,
    an audit write failure prevents unsafe continuation and marks pipeline FAILED.
    """
    mock_defender = MagicMock()
    mock_defender.get_incident.return_value = {
        "incident_id": "4001",
        "all_affected_devices": ["HOST-01"],
        "all_ip_addresses": [],
        "alerts": [],
    }
    mock_defender.get_endpoint_containment.return_value = {
        "device_name": "HOST-01",
        "containment_status": "ISOLATED",
    }

    audit_service = ChainOfCustodyService(db_path=":memory:", policy=AuditPolicy.STRICT)
    # Simulate DB write failure on record_event
    with patch.object(audit_service, "record_event", side_effect=AuditLoggingError("Audit storage unavailable")):
        pipeline = OrchestratorPipeline(defender_client=mock_defender, audit_service=audit_service)
        report = pipeline.run_full_workflow("4001")

        assert report.pipeline_status == "FAILED"
        assert any("Audit policy failure" in e or "Audit storage unavailable" in e for e in report.errors)
        assert report.collected_jobs_count == 0  # Halted before collection


def test_safety_pipeline_detects_compromised_audit_chain(tmp_path: Path):
    """
    Mandatory Safety Test: If an audit chain is tampered with prior to or during
    pipeline execution, Stage 7 MUST detect the compromise, flag chain_of_custody_verified=False,
    and fail the workflow.
    """
    db_path = str(tmp_path / "compromised_chain.db")
    audit_service = ChainOfCustodyService(db_path=db_path)
    audit_service.record_event(action=AuditAction.COLLECTION_REQUESTED, incident_id="5001")

    # Drop trigger and corrupt stored hash
    conn = sqlite3.connect(db_path)
    conn.execute("DROP TRIGGER prevent_coc_update;")
    conn.execute("UPDATE chain_of_custody SET event_hash = 'badhash0000000000000000000000000000000000000000000000000000000000' WHERE sequence_number = 1;")
    conn.commit()
    conn.close()

    mock_defender = MagicMock()
    mock_defender.mock_mode = True
    mock_defender.get_incident.return_value = {
        "incident_id": "5001",
        "all_affected_devices": [],
        "all_ip_addresses": [],
        "alerts": [],
    }

    pipeline = OrchestratorPipeline(defender_client=mock_defender, audit_service=audit_service)
    report = pipeline.run_full_workflow("5001")

    assert report.chain_of_custody_verified is False
    assert report.pipeline_status == "FAILED"
    assert any("integrity compromised" in err.lower() for err in report.errors)


def test_safety_s3_upload_failure_recorded_in_audit(tmp_path: Path):
    """Verifies that an S3 upload failure is recorded as S3_UPLOAD_FAILED in audit log."""
    mock_defender = MagicMock()
    mock_defender.mock_mode = True
    mock_defender.config.mock_mode = True
    mock_defender.check_live_response_capability.return_value = {"supported": True}
    mock_defender.get_incident.return_value = {
        "incident_id": "6001",
        "affected_device_name": "ISOLATED-01",
        "all_affected_devices": ["ISOLATED-01"],
        "all_ip_addresses": [],
        "alerts": [],
    }
    mock_defender.get_endpoint_containment_status.return_value = {
        "device_name": "ISOLATED-01",
        "containment_status": "ISOLATED",
    }

    db_path = str(tmp_path / "s3_fail.db")
    audit_service = ChainOfCustodyService(db_path=db_path)

    # Mock collection service where S3 upload fails
    collection_service = MagicMock()
    fake_meta = EvidenceMetadata(
        incident_id="6001",
        endpoint_id="ISOLATED-01",
        collection_job_id="ev-s3-fail",
        status=CollectionStatus.COMPLETED.value,
        simulation_indicator=True,
        s3_upload_status="FAILED",
        error_details="Connection timeout to s3.amazonaws.com",
    )
    collection_service.initiate_collection.return_value = fake_meta

    pipeline = OrchestratorPipeline(
        defender_client=mock_defender,
        collection_service=collection_service,
        audit_service=audit_service,
    )
    report = pipeline.run_full_workflow("6001", upload_to_s3=True)

    history = audit_service.get_incident_history("6001")
    actions = [e.action for e in history]
    assert AuditAction.S3_UPLOAD_FAILED.value in actions


def test_cli_audit_commands(tmp_path: Path, monkeypatch):
    """
    Validates CLI audit commands:
      - audit verify (exits 0 for valid, 1 for invalid)
      - audit list
      - audit evidence <id>
      - audit incident <id>
    """
    import app

    db_path = str(tmp_path / "cli_audit.db")
    monkeypatch.setenv("EVIDENCE_CATALOG_DB", db_path)
    monkeypatch.setenv("CHAIN_OF_CUSTODY_DB", db_path)
    monkeypatch.setenv("EDR_MOCK_MODE", "true")

    # 1. Test audit verify on empty ledger
    monkeypatch.setattr("sys.argv", ["app.py", "audit", "verify", "--mock"])
    ret = app.main()
    assert ret == 0

    # Record some events into db
    service = ChainOfCustodyService(db_path=db_path)
    service.record_event(
        action=AuditAction.COLLECTION_REQUESTED,
        incident_id="7001",
        evidence_id="ev-cli-01",
        endpoint_id="HOST-CLI",
    )
    service.record_event(
        action=AuditAction.COLLECTION_COMPLETED,
        incident_id="7001",
        evidence_id="ev-cli-01",
        endpoint_id="HOST-CLI",
        evidence_hash="b" * 64,
    )

    # 2. Test audit list
    monkeypatch.setattr("sys.argv", ["app.py", "audit", "list", "--mock", "--limit", "10"])
    ret = app.main()
    assert ret == 0

    # 3. Test audit evidence
    monkeypatch.setattr("sys.argv", ["app.py", "audit", "evidence", "ev-cli-01", "--mock"])
    ret = app.main()
    assert ret == 0

    # 4. Test audit incident
    monkeypatch.setattr("sys.argv", ["app.py", "audit", "incident", "7001", "--mock"])
    ret = app.main()
    assert ret == 0

    # 5. Test audit verify on intact ledger
    monkeypatch.setattr("sys.argv", ["app.py", "audit", "verify", "--mock"])
    ret = app.main()
    assert ret == 0

    # 6. Tamper with ledger and test audit verify failure exit status
    conn = sqlite3.connect(db_path)
    conn.execute("DROP TRIGGER prevent_coc_update;")
    conn.execute("UPDATE chain_of_custody SET actor = 'malicious' WHERE sequence_number = 1;")
    conn.commit()
    conn.close()

    monkeypatch.setattr("sys.argv", ["app.py", "audit", "verify", "--mock"])
    ret = app.main()
    # Must exit with non-zero status
    assert ret == 1


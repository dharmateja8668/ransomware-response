"""
tests/test_evidence_analysis.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Comprehensive Unit Test Suite for Week 3 Day 4:
  - SQLite Evidence Catalog (indexing, querying, search, simulation flag)
  - Cryptographic SHA-256 Integrity Verification (intact vs tampered)
  - Forensic Artifact Analysis (KAPE triage zips, memory dumps, IOC extraction)
  - EDR Alert Correlation (telemetry matching, threat scoring, recommendations)
  - Unified Orchestrator Pipeline (end-to-end Days 1-4 mock workflow)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from analysis.alert_correlator import AlertCorrelator, CorrelationReport, MatchedIOC
from analysis.artifact_analyzer import (
    ArtifactAnalysisReport,
    ArtifactAnalyzer,
    IOCItem,
    TriageFinding,
)
from forensic.metadata import EvidenceMetadata
from services.evidence_catalog import (
    CatalogRecord,
    EvidenceCatalogService,
    IntegrityCheckResult,
)
from services.orchestrator_pipeline import OrchestratorPipeline, UnifiedWorkflowReport


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def in_memory_catalog():
    """Provides an in-memory SQLite EvidenceCatalogService."""
    return EvidenceCatalogService(db_path=":memory:")


@pytest.fixture
def sample_metadata():
    """Generates a sample EvidenceMetadata record."""
    return EvidenceMetadata(
        incident_id="1001",
        endpoint_id="FINANCE-SRV-01",
        collection_method="KAPE",
        requested_artifacts=["Registry", "EventLogs"],
        status="COMPLETED",
        collection_job_id="ev-kape-1001-01",
        hostname="FINANCE-SRV-01.corp.local",
        artifact_location="/mock/path/triage.zip",
        file_hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size_bytes=4096,
        s3_bucket="forensic-evidence-soc",
        s3_object_key="incidents/1001/ev-kape-1001-01/triage.zip",
        s3_upload_status="SUCCESS",
        s3_checksum_sha256="47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
        s3_checksum_verified=True,
        simulation_indicator=True,
        containment_verified=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. SQLite Evidence Catalog Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_catalog_index_and_get_record(in_memory_catalog, sample_metadata):
    """Verifies indexing and retrieval of an EvidenceMetadata record."""
    rec = in_memory_catalog.index_evidence_metadata(sample_metadata)
    assert rec.evidence_id == "ev-kape-1001-01"  # collection_job_id
    assert rec.incident_id == "1001"
    assert rec.device_id == "FINANCE-SRV-01"     # endpoint_id
    assert rec.sha256_hash == sample_metadata.file_hash_sha256.lower()
    assert rec.simulation_indicator is True
    assert rec.s3_checksum_verified is True

    fetched = in_memory_catalog.get_record("ev-kape-1001-01")
    assert fetched is not None
    assert fetched.evidence_id == "ev-kape-1001-01"
    assert fetched.file_name == "triage.zip"
    assert fetched.s3_bucket == "forensic-evidence-soc"


def test_catalog_find_queries(in_memory_catalog, sample_metadata):
    """Verifies querying by incident, device, and SHA-256 hash."""
    in_memory_catalog.index_evidence_metadata(sample_metadata)

    # Incident query
    by_inc = in_memory_catalog.find_by_incident("1001")
    assert len(by_inc) == 1
    assert by_inc[0].incident_id == "1001"
    assert len(in_memory_catalog.find_by_incident("9999")) == 0

    # Device query (maps from endpoint_id)
    by_dev = in_memory_catalog.find_by_device("FINANCE-SRV-01")
    assert len(by_dev) == 1
    assert by_dev[0].device_id == "FINANCE-SRV-01"

    # Hash query
    by_hash = in_memory_catalog.find_by_hash(sample_metadata.file_hash_sha256)
    assert len(by_hash) == 1
    assert by_hash[0].sha256_hash == sample_metadata.file_hash_sha256.lower()


def test_catalog_multi_criteria_search(in_memory_catalog, sample_metadata):
    """Verifies flexible multi-criteria search."""
    in_memory_catalog.index_evidence_metadata(sample_metadata)

    # Search by filename
    results = in_memory_catalog.search(query="triage")
    assert len(results) == 1

    # Search by device name
    results_dev = in_memory_catalog.search(query="FINANCE")
    assert len(results_dev) == 1

    # Search by hash fragment
    results_hash = in_memory_catalog.search(query="e3b0c442")
    assert len(results_hash) == 1

    # Filter by non-matching incident
    assert len(in_memory_catalog.search(query="triage", incident_id="9999")) == 0


def test_catalog_upsert_on_conflict(in_memory_catalog, sample_metadata):
    """Verifies that indexing an existing evidence ID updates the record rather than duplicating."""
    in_memory_catalog.index_evidence_metadata(sample_metadata)

    # Update metadata
    sample_metadata.s3_upload_status = "VERIFIED_WORM_LOCKED"
    sample_metadata.file_size_bytes = 8192
    in_memory_catalog.index_evidence_metadata(sample_metadata)

    records = in_memory_catalog.list_records()
    assert len(records) == 1
    assert records[0].s3_upload_status == "VERIFIED_WORM_LOCKED"
    assert records[0].file_size_bytes == 8192


# ─────────────────────────────────────────────────────────────────────────────
# 2. Cryptographic SHA-256 Integrity Verification Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_integrity_verification_success(in_memory_catalog):
    """Verifies successful cryptographic hash verification for an unaltered file."""
    with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
        content = b"CRITICAL FORENSIC EVIDENCE ARTIFACT"
        tf.write(content)
        temp_path = tf.name

    try:
        calculated_hash = hashlib.sha256(content).hexdigest()
        meta = EvidenceMetadata(
            incident_id="1002",
            endpoint_id="DC-01",
            collection_method="KAPE",
            collection_job_id="ev-intact-01",
            artifact_location=temp_path,
            file_hash_sha256=calculated_hash,
            file_size_bytes=len(content),
        )
        in_memory_catalog.index_evidence_metadata(meta)

        audit = in_memory_catalog.verify_integrity("ev-intact-01")
        assert audit.is_valid is True
        assert audit.indexed_hash == calculated_hash
        assert audit.recalculated_hash == calculated_hash
        assert audit.error_message is None
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_integrity_verification_tamper_detected(in_memory_catalog):
    """Verifies that modifying file bytes triggers an integrity audit failure."""
    with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
        tf.write(b"ORIGINAL ARTIFACT")
        temp_path = tf.name

    try:
        orig_hash = hashlib.sha256(b"ORIGINAL ARTIFACT").hexdigest()
        meta = EvidenceMetadata(
            incident_id="1002",
            endpoint_id="DC-01",
            collection_method="KAPE",
            collection_job_id="ev-tampered-01",
            artifact_location=temp_path,
            file_hash_sha256=orig_hash,
            file_size_bytes=len(b"ORIGINAL ARTIFACT"),
        )
        in_memory_catalog.index_evidence_metadata(meta)

        # Tamper with file
        with open(temp_path, "wb") as f:
            f.write(b"TAMPERED / CORRUPTED CONTENT")

        audit = in_memory_catalog.verify_integrity("ev-tampered-01")
        assert audit.is_valid is False
        assert "Hash mismatch" in audit.error_message
        assert audit.recalculated_hash != orig_hash
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_integrity_verification_missing_file(in_memory_catalog):
    """Verifies integrity audit failure when file does not exist on disk."""
    meta = EvidenceMetadata(
        incident_id="1002",
        endpoint_id="DC-01",
        collection_method="KAPE",
        collection_job_id="ev-missing-file",
        artifact_location="/path/does/not/exist.zip",
        file_hash_sha256="abc123def456",
    )
    in_memory_catalog.index_evidence_metadata(meta)

    audit = in_memory_catalog.verify_integrity("ev-missing-file")
    assert audit.is_valid is False
    assert "does not exist on disk" in audit.error_message


def test_integrity_verification_unknown_evidence_id(in_memory_catalog):
    """Verifies handling when evidence ID is not indexed in catalog."""
    audit = in_memory_catalog.verify_integrity("non-existent-id")
    assert audit.is_valid is False
    assert "does not exist in catalog" in audit.error_message


# ─────────────────────────────────────────────────────────────────────────────
# 3. Forensic Artifact Analysis Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_artifact_analyzer_detects_ransom_note_in_zip():
    """Verifies detection of ransom notes and encrypted extensions inside a KAPE zip."""
    analyzer = ArtifactAnalyzer()
    with tempfile.NamedTemporaryFile("wb", suffix=".zip", delete=False) as ztf:
        zip_path = ztf.name

    try:
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("C/Users/Victim/Desktop/README_TO_RESTORE.txt", "Your files have been encrypted. Pay 5 BTC.")
            zf.writestr("C/Users/Victim/Documents/report.docx.locked", "ENCRYPTED_PAYLOAD")
            zf.writestr("C/Windows/Temp/mimikatz.exe", "MOCK_EXE")
            zf.writestr("C/Windows/System32/winevt/Logs/Security.evtx", "vssadmin delete shadows /all /quiet")

        report = analyzer.analyze_evidence_file(
            file_path=zip_path,
            evidence_id="ev-zip-01",
            incident_id="1001",
            evidence_type="KAPE",
            simulation_indicator=True,
        )

        assert report.ransomware_detected is True
        assert report.confidence_score > 0.6
        assert any(f.category == "RANSOM_NOTE" for f in report.findings)
        assert any(f.category == "ENCRYPTION_INDICATOR" for f in report.findings)
        assert any(f.category == "SUSPICIOUS_PROCESS" for f in report.findings)
        assert any(f.category == "SUSPICIOUS_CMD" for f in report.findings)
        assert report.simulation_indicator is True
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)


def test_artifact_analyzer_anti_forensics_command():
    """Verifies detection of shadow copy deletion and boot recovery tampering."""
    analyzer = ArtifactAnalyzer()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write("Executing command: vssadmin.exe delete shadows /all /quiet\n")
        tf.write("bcdedit.exe /set {default} recoveryenabled no\n")
        tf.write("Connecting to remote C2: 198.51.100.45:443\n")
        log_path = tf.name

    try:
        report = analyzer.analyze_evidence_file(
            file_path=log_path,
            evidence_id="ev-txt-01",
            incident_id="1001",
            evidence_type="TRIAGE",
        )

        assert report.ransomware_detected is True
        cmd_findings = [f for f in report.findings if f.category == "SUSPICIOUS_CMD"]
        assert len(cmd_findings) >= 2
        
        # Verify network IOC extracted
        net_iocs = [i for i in report.extracted_iocs if i.ioc_type == "NETWORK_IP"]
        assert any(i.value == "198.51.100.45" for i in net_iocs)
    finally:
        if os.path.exists(log_path):
            os.remove(log_path)


def test_artifact_analyzer_memory_injection_detection():
    """Verifies memory dump triage detecting suspicious hollowed process descriptors."""
    analyzer = ArtifactAnalyzer()
    with tempfile.NamedTemporaryFile("wb", suffix=".dmp", delete=False) as tf:
        # Create memory dump header with suspicious svchost path
        content = b"DUMP_HEADER\x00\x00C:\\Users\\Admin\\AppData\\Local\\Temp\\svchost.exe\x00\x00"
        tf.write(content)
        dmp_path = tf.name

    try:
        report = analyzer.analyze_evidence_file(
            file_path=dmp_path,
            evidence_id="ev-ram-01",
            incident_id="1001",
            evidence_type="RAM",
        )

        assert any(f.category == "MEMORY_INJECTION" for f in report.findings)
        assert any(i.ioc_type == "PROCESS_NAME" and i.value == "svchost.exe" for i in report.extracted_iocs)
    finally:
        if os.path.exists(dmp_path):
            os.remove(dmp_path)


# ─────────────────────────────────────────────────────────────────────────────
# 4. EDR Alert Correlation Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_alert_correlator_hash_and_process_match():
    """Verifies cross-telemetry correlation matching hashes, processes, and devices."""
    correlator = AlertCorrelator()
    incident_id = "1001"
    matched_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

    edr_alerts = [
        {
            "id": "alert-001",
            "title": "Ransomware Behavior Detected",
            "severity": "High",
            "machineId": "dev-fin-01",
            "evidence": [
                {"sha256": matched_hash, "fileName": "mimikatz.exe"},
                {"processCommandLine": "vssadmin.exe delete shadows /all /quiet"},
            ],
        }
    ]

    catalog_records = [
        CatalogRecord(
            evidence_id="ev-01",
            incident_id=incident_id,
            device_id="dev-fin-01",
            device_name="FINANCE-SRV-01",
            evidence_type="KAPE",
            file_name="triage.zip",
            file_path="/mock/triage.zip",
            file_size_bytes=1024,
            sha256_hash=matched_hash,
        )
    ]

    analysis_reports = [
        ArtifactAnalysisReport(
            evidence_id="ev-01",
            incident_id=incident_id,
            evidence_type="KAPE",
            file_path="/mock/triage.zip",
            file_size_bytes=1024,
            ransomware_detected=True,
            extracted_iocs=[
                IOCItem(ioc_type="PROCESS_NAME", value="mimikatz.exe", context="Triage executable", severity="HIGH"),
                IOCItem(ioc_type="COMMAND_LINE", value="vssadmin delete shadows", context="Anti-forensics", severity="CRITICAL"),
            ],
        )
    ]

    correlation = correlator.correlate(
        incident_id=incident_id,
        incident_title="Multi-stage Ransomware Attack",
        incident_severity="High",
        edr_alerts=edr_alerts,
        catalog_records=catalog_records,
        analysis_reports=analysis_reports,
        simulation_indicator=True,
    )

    assert correlation.correlation_score >= 80
    assert correlation.overall_threat_level == "CRITICAL"
    assert correlation.matched_iocs_count >= 3
    assert any(m.match_category == "HASH_MATCH" for m in correlation.matched_iocs)
    assert any(m.match_category == "PROCESS_MATCH" for m in correlation.matched_iocs)
    assert any(m.match_category == "COMMAND_LINE_MATCH" for m in correlation.matched_iocs)
    assert len(correlation.containment_recommendations) >= 3


def test_alert_correlator_low_threat_no_matches():
    """Verifies that non-matching telemetry results in a low threat score."""
    correlator = AlertCorrelator()
    correlation = correlator.correlate(
        incident_id="1003",
        incident_title="Informational Audit",
        incident_severity="Informational",
        edr_alerts=[{"id": "a-1", "title": "Routine Audit", "evidence": []}],
        catalog_records=[],
        analysis_reports=[],
    )

    assert correlation.correlation_score == 0
    assert correlation.overall_threat_level == "LOW"
    assert correlation.matched_iocs_count == 0


# ─────────────────────────────────────────────────────────────────────────────
# 5. Unified Orchestrator Pipeline Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_unified_orchestrator_pipeline_mock_run():
    """Verifies the complete end-to-end IR lifecycle runs cleanly in mock mode
    using a fully mocked Defender client that allows authorized mock evidence collection.
    Endpoint containment is verified as ISOLATED so the safety pre-check authorizes collection.
    """
    from integrations.defender_client import DefenderClient

    mock_defender = MagicMock(spec=DefenderClient)
    mock_defender.config = MagicMock()
    mock_defender.config.mock_mode = True
    mock_defender.config.api_base_url = "https://api.securitycenter.microsoft.com"

    # Incident details for Stage 1 triage and Stage 2 authorization
    mock_defender.get_incident.return_value = {
        "incident_id": "1001",
        "title": "Multi-stage Ransomware Activity Detected",
        "severity": "High",
        "status": "Active",
        "affected_device_name": "FINANCE-SRV-01.corp.contoso.com",
        "device_ip_address": "10.0.4.15",
        "machine_id": "f489a71b-324e-4f01-92bb-187640df21a1",
        "all_affected_devices": ["FINANCE-SRV-01.corp.contoso.com"],
        "all_ip_addresses": ["10.0.4.15"],
        "alerts_count": 1,
        "alerts": [
            {
                "alert_id": "da-77821-alert-01",
                "title": "Suspicious PowerShell command attempting shadow copy deletion (vssadmin)",
                "category": "DefenseEvasion",
                "severity": "High",
                "machine_id": "f489a71b-324e-4f01-92bb-187640df21a1",
                "device_name": "FINANCE-SRV-01.corp.contoso.com",
                "ip_address": "10.0.4.15",
            }
        ],
    }

    # Endpoint containment status: confirmed ISOLATED to satisfy authorization checks
    mock_defender.get_endpoint_containment_status.return_value = {
        "device_id": "f489a71b-324e-4f01-92bb-187640df21a1",
        "device_name": "FINANCE-SRV-01.corp.contoso.com",
        "containment_status": "ISOLATED",
        "isolation_details": "Isolated",
        "risk_score": "High",
        "health_status": "Active",
        "last_ip_address": "10.0.4.15",
        "verified_at": "2026-10-25T14:38:15Z",
    }

    # Live Response capability check (required by adapter prerequisite check)
    mock_defender.check_live_response_capability.return_value = {
        "supported": True,
        "os_platform": "Windows10",
        "os_version": "10.0.19045",
        "live_response_configured": True,
        "reason": None,
    }

    # Alert telemetry for Stage 6 correlation
    mock_defender.get_incident_alerts.return_value = [
        {
            "id": "da-77821-alert-01",
            "title": "Suspicious PowerShell command attempting shadow copy deletion (vssadmin)",
            "severity": "High",
            "machineId": "f489a71b-324e-4f01-92bb-187640df21a1",
            "computerDnsName": "FINANCE-SRV-01.corp.contoso.com",
            "evidence": [
                {"processCommandLine": "vssadmin delete shadows /all /quiet"},
            ],
        }
    ]

    pipeline = OrchestratorPipeline(defender_client=mock_defender)
    pipeline.catalog_service = EvidenceCatalogService(db_path=":memory:")

    report = pipeline.run_full_workflow(
        incident_id="1001",
        upload_to_s3=False,
        collection_types=["KAPE"],
    )

    assert report.incident_id == "1001"
    assert report.pipeline_status in {"SUCCESS", "PARTIAL_SUCCESS"}
    assert report.triage_report is not None
    assert report.triage_report.incident_id == "1001"
    assert report.collected_jobs_count >= 1
    assert report.indexed_records_count >= 1
    assert report.analyzed_reports_count >= 1
    assert report.correlation_report is not None
    assert report.simulation_indicator is True
    mock_defender.get_incident_alerts.assert_called_with("1001")


def test_unified_orchestrator_pipeline_handles_invalid_incident():
    """Verifies that invalid incident IDs cleanly fail at Stage 1 triage."""
    mock_defender = MagicMock()
    mock_defender.get_incident.side_effect = Exception("Incident not found (HTTP 404)")
    pipeline = OrchestratorPipeline(defender_client=mock_defender)

    report = pipeline.run_full_workflow(incident_id="999999")
    assert report.pipeline_status == "FAILED"
    assert len(report.errors) >= 1
    assert "Stage 1 Triage failed" in report.errors[0]

"""
tests/test_evidence_collector.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit Tests for Forensic Evidence Collector Adapters & Metadata.
Automated Ransomware Containment & Incident Response Orchestrator - Day 2.

Covers:
  - EvidenceMetadata data model, lifecycle states, and JSON persistence.
  - KapeCollectionAdapter: category validation, mock execution, live checks.
  - RAMAcquisitionAdapter: prerequisite validation, simulated metadata, truthfulness.
  - DefenderInvestigationPackageAdapter: action creation, status, and package URI.
  - Verification that simulated artifacts are NEVER marked as real evidence.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from integrations.defender_client import (
    DefenderClient,
    EDRAPIError,
    EDRAuthenticationError,
    EDRConfig,
    EDRTimeoutError,
)
from forensic.metadata import (
    CollectionMethod,
    CollectionStatus,
    DEFAULT_KAPE_CATEGORIES,
    EvidenceMetadata,
    KapeArtifactCategory,
)
from forensic.evidence_collector import (
    DefenderInvestigationPackageAdapter,
    ForensicCollectorAdapter,
    KapeCollectionAdapter,
    RAMAcquisitionAdapter,
    UnsupportedMethodError,
)


@pytest.fixture
def mock_defender_client():
    config = EDRConfig(mock_mode=True)
    return DefenderClient(config)


@pytest.fixture
def live_defender_client():
    config = EDRConfig(
        tenant_id="00000000-0000-0000-0000-000000000001",
        client_id="11111111-1111-1111-1111-111111111111",
        client_secret="mock-secret-live-12345",
        api_base_url="https://api.securitycenter.microsoft.com",
        mock_mode=False,
    )
    return DefenderClient(config)


# ─────────────────────────────────────────────────────────────────────────────
# 1. EvidenceMetadata Unit Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_evidence_metadata_defaults():
    meta = EvidenceMetadata(
        incident_id="1001",
        endpoint_id="mach-01",
        hostname="FINANCE-SRV-01",
    )
    assert meta.incident_id == "1001"
    assert meta.endpoint_id == "mach-01"
    assert meta.hostname == "FINANCE-SRV-01"
    assert meta.status == CollectionStatus.PENDING.value
    assert meta.collection_method == CollectionMethod.KAPE.value
    assert meta.collection_job_id.startswith("col-")
    assert meta.requested_at is not None
    assert meta.completed_at is None
    assert meta.simulation_indicator is True


def test_evidence_metadata_lifecycle_transitions():
    meta = EvidenceMetadata(incident_id="1001", endpoint_id="mach-01")

    # Pending -> Running
    meta.mark_running()
    assert meta.status == CollectionStatus.RUNNING.value
    assert meta.completed_at is None

    # Running -> Completed
    meta.mark_completed(
        artifact_location="evidence/test.zip",
        file_hash_sha256="abc123sha",
        file_size_bytes=1024,
        diagnostic_notes="Completed cleanly",
    )
    assert meta.status == CollectionStatus.COMPLETED.value
    assert meta.artifact_location == "evidence/test.zip"
    assert meta.file_hash_sha256 == "abc123sha"
    assert meta.file_size_bytes == 1024
    assert meta.completed_at is not None

    # Completed -> Failed (simulation of state reset/failure update)
    meta.mark_failed("Test error message", diagnostic_notes="Notes")
    assert meta.status == CollectionStatus.FAILED.value
    assert meta.error_details == "Test error message"


def test_evidence_metadata_serialization_and_persistence(tmp_path: Path):
    meta = EvidenceMetadata(
        incident_id="1002",
        endpoint_id="mach-02",
        hostname="ISOLATED-HOST",
        collection_method=CollectionMethod.RAM.value,
        requested_artifacts=["Physical_Memory_RAM"],
        status=CollectionStatus.COMPLETED.value,
        simulation_indicator=True,
    )

    # Dictionary & JSON Serialization
    data = meta.to_dict()
    assert data["incident_id"] == "1002"
    assert data["collection_method"] == "RAM"
    assert data["simulation_indicator"] is True

    json_str = meta.to_json()
    assert "ISOLATED-HOST" in json_str

    # Disk Save and Load
    saved_file = meta.save(tmp_path)
    assert saved_file.exists()

    loaded = EvidenceMetadata.load(saved_file)
    assert loaded.incident_id == meta.incident_id
    assert loaded.collection_job_id == meta.collection_job_id
    assert loaded.hostname == meta.hostname
    assert loaded.status == meta.status
    assert loaded.simulation_indicator is True


def test_evidence_metadata_contains_no_sensitive_secrets(tmp_path: Path):
    meta = EvidenceMetadata(
        incident_id="1001",
        endpoint_id="mach-01",
        hostname="FINANCE-SRV-01",
    )
    data = meta.to_dict()
    json_str = meta.to_json()

    # Verify no authentication fields exist in schema
    assert "client_secret" not in data
    assert "access_token" not in data
    assert "bearer" not in json_str.lower()
    assert "password" not in json_str.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 2. KAPE Collection Adapter Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_kape_adapter_properties(mock_defender_client):
    adapter = KapeCollectionAdapter(mock_defender_client)
    assert adapter.method == CollectionMethod.KAPE
    assert "KAPE" in adapter.name
    assert adapter.is_available() is True


def test_kape_adapter_validate_categories(mock_defender_client):
    adapter = KapeCollectionAdapter(mock_defender_client)

    # Default categories when None provided
    defaults = adapter.validate_categories(None)
    assert set(defaults) == set(DEFAULT_KAPE_CATEGORIES)

    # Valid specific categories
    valid = adapter.validate_categories(["Registry", "EventLogs", "Execution"])
    assert valid == ["Registry", "EventLogs", "Execution"]

    # Invalid category raises UnsupportedMethodError
    with pytest.raises(UnsupportedMethodError) as exc_info:
        adapter.validate_categories(["Registry", "InvalidCat", "Browser"])
    assert "Invalid KAPE artifact categories" in str(exc_info.value)


def test_kape_adapter_mock_successful_execution(mock_defender_client):
    adapter = KapeCollectionAdapter(mock_defender_client)
    meta = adapter.initiate(
        incident_id="1002",
        endpoint_id="mach-isolated-host",
        hostname="ISOLATED-HOST",
        artifact_categories=["Registry", "EventLogs"],
    )

    assert meta.collection_method == CollectionMethod.KAPE.value
    assert meta.status == CollectionStatus.COMPLETED.value
    assert meta.simulation_indicator is True
    assert meta.artifact_location is not None
    assert "kape" in meta.artifact_location
    assert meta.completed_at is not None
    assert meta.file_size_bytes is not None
    assert meta.file_hash_sha256 is not None


def test_kape_adapter_mock_failure_simulation(mock_defender_client):
    adapter = KapeCollectionAdapter(mock_defender_client)
    meta = adapter.initiate(
        incident_id="1002",
        endpoint_id="mach-fail-host",
        hostname="FAIL-HOST",
        options={"simulate_failure": True},
    )

    assert meta.status == CollectionStatus.FAILED.value
    assert meta.error_details is not None
    assert "failed" in meta.error_details.lower()
    assert meta.completed_at is not None


def test_kape_adapter_mock_running_simulation_and_poll(mock_defender_client):
    adapter = KapeCollectionAdapter(mock_defender_client)
    meta = adapter.initiate(
        incident_id="1002",
        endpoint_id="mach-running-host",
        hostname="RUNNING-HOST",
        options={"simulate_running": True},
    )

    assert meta.status == CollectionStatus.RUNNING.value
    assert meta.completed_at is None

    # Polling should advance the simulated job
    polled = adapter.poll_status(meta)
    assert polled.status == CollectionStatus.COMPLETED.value
    assert polled.artifact_location is not None
    assert polled.completed_at is not None


def test_kape_adapter_live_rejection_without_library_scripts(live_defender_client):
    adapter = KapeCollectionAdapter(live_defender_client)
    meta = adapter.initiate(
        incident_id="1002",
        endpoint_id="f489a71b-324e-4f01-92bb-187640df21a1",
        hostname="FINANCE-SRV-01",
    )
    # Must fail safely without claiming execution succeeded
    assert meta.status == CollectionStatus.FAILED.value
    assert "Live Response" in meta.error_details


# ─────────────────────────────────────────────────────────────────────────────
# 3. RAM Acquisition Adapter Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_ram_adapter_properties(mock_defender_client):
    adapter = RAMAcquisitionAdapter(mock_defender_client)
    assert adapter.method == CollectionMethod.RAM
    assert "RAM" in adapter.name
    assert adapter.is_available() is True


def test_ram_adapter_mock_successful_workflow(mock_defender_client):
    adapter = RAMAcquisitionAdapter(mock_defender_client)
    meta = adapter.initiate(
        incident_id="1002",
        endpoint_id="mach-isolated-host",
        hostname="ISOLATED-HOST",
    )

    assert meta.collection_method == CollectionMethod.RAM.value
    assert meta.status == CollectionStatus.COMPLETED.value
    assert meta.simulation_indicator is True
    assert meta.artifact_location.startswith("simulated://")
    assert "SIMULATED RAM ACQUISITION" in meta.diagnostic_notes


def test_ram_adapter_never_labels_arbitrary_files_as_real_ram(mock_defender_client):
    adapter = RAMAcquisitionAdapter(mock_defender_client)
    meta = adapter.initiate(
        incident_id="1002",
        endpoint_id="mach-isolated-host",
    )
    # Verification that simulated indicator is explicitly True
    assert meta.simulation_indicator is True
    assert "simulated://" in meta.artifact_location


def test_ram_adapter_mock_failure_simulation(mock_defender_client):
    adapter = RAMAcquisitionAdapter(mock_defender_client)
    meta = adapter.initiate(
        incident_id="1002",
        endpoint_id="mach-fail-host",
        options={"simulate_failure": True},
    )

    assert meta.status == CollectionStatus.FAILED.value
    assert "aborted" in meta.error_details.lower()
    assert meta.completed_at is not None


def test_ram_adapter_live_rejection(live_defender_client):
    adapter = RAMAcquisitionAdapter(live_defender_client)
    meta = adapter.initiate(
        incident_id="1002",
        endpoint_id="f489a71b-324e-4f01-92bb-187640df21a1",
    )
    # Raw physical RAM is not supported by standard EDR cloud API
    assert meta.status == CollectionStatus.FAILED.value
    assert "kernel driver" in meta.error_details.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 4. Defender Investigation Package Adapter Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_investigation_package_mock_initiation(mock_defender_client):
    adapter = DefenderInvestigationPackageAdapter(mock_defender_client)
    meta = adapter.initiate(
        incident_id="1002",
        endpoint_id="mach-isolated-host",
        hostname="ISOLATED-HOST",
    )

    assert meta.collection_method == CollectionMethod.INVESTIGATION_PACKAGE.value
    assert meta.status == CollectionStatus.COMPLETED.value
    assert meta.artifact_location is not None
    assert "InvestigationPackage_" in meta.artifact_location
    assert meta.simulation_indicator is True


def test_investigation_package_polling(mock_defender_client):
    adapter = DefenderInvestigationPackageAdapter(mock_defender_client)
    meta = adapter.initiate(
        incident_id="1002",
        endpoint_id="mach-running-host",
    )
    # Polling action
    polled = adapter.poll_status(meta)
    assert polled.collection_job_id == meta.collection_job_id

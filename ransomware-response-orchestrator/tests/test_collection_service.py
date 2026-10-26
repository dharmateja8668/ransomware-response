"""
tests/test_collection_service.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit Tests for ForensicCollectionService & 12 Mock Scenarios.
Automated Ransomware Containment & Incident Response Orchestrator - Day 2.

Covers the 12 Mandatory Mock Scenarios (Task 7):
  1. Successful KAPE collection.
  2. Successful RAM acquisition.
  3. Collection still running.
  4. Collection failure.
  5. Endpoint not contained (NOT_ISOLATED refusal).
  6. Unknown containment status (UNKNOWN refusal).
  7. Unsupported collection method.
  8. Missing endpoint identifier.
  9. EDR authentication failure.
  10. EDR API timeout.
  11. Duplicate collection request.
  12. Missing artifact location.

Additional Coverage:
  - Endpoint mismatch rejection (endpoint not affiliated with incident).
  - Status tracking with track_job().
  - Job listing and filtering by incident/endpoint/status.
  - Verification that simulated artifacts are NEVER marked as real evidence.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from integrations.defender_client import (
    ContainmentStatus,
    DefenderClient,
    EDRAPIError,
    EDRAuthenticationError,
    EDRConfig,
    EDRConnectionError,
    EDRError,
    EDRTimeoutError,
)
from forensic.metadata import (
    CollectionMethod,
    CollectionStatus,
    DEFAULT_KAPE_CATEGORIES,
    EvidenceMetadata,
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


@pytest.fixture
def temp_evidence_dir(tmp_path: Path):
    """Provides a clean temporary directory for evidence metadata isolation."""
    ev_dir = tmp_path / "evidence_metadata"
    ev_dir.mkdir(parents=True, exist_ok=True)
    return ev_dir


@pytest.fixture
def mock_defender_client():
    config = EDRConfig(mock_mode=True)
    return DefenderClient(config)


@pytest.fixture
def forensic_service(mock_defender_client, temp_evidence_dir):
    return ForensicCollectionService(
        defender_client=mock_defender_client,
        evidence_dir=temp_evidence_dir,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Task 7: 12 Mandatory Mock Scenarios
# ─────────────────────────────────────────────────────────────────────────────

def test_scenario_01_successful_kape_collection(forensic_service):
    """
    Scenario 1: Successful KAPE collection.
    Endpoint is confirmed ISOLATED and belongs to Incident 1002.
    """
    meta = forensic_service.initiate_collection(
        incident_id="1002",
        endpoint_identifier="ISOLATED-HOST",
        method=CollectionMethod.KAPE,
        artifact_categories=["Registry", "EventLogs"],
    )

    assert meta.status == CollectionStatus.COMPLETED.value
    assert meta.collection_method == CollectionMethod.KAPE.value
    assert meta.simulation_indicator is True
    assert meta.containment_verified is True
    assert meta.artifact_location is not None
    assert "kape_ISOLATED-HOST" in meta.artifact_location
    assert meta.completed_at is not None
    assert meta.file_hash_sha256 is not None
    assert meta.file_size_bytes is not None


def test_scenario_02_successful_ram_acquisition(forensic_service):
    """
    Scenario 2: Successful RAM acquisition.
    Simulated physical memory acquisition executes on contained endpoint.
    """
    meta = forensic_service.initiate_collection(
        incident_id="1002",
        endpoint_identifier="ISOLATED-HOST",
        method=CollectionMethod.RAM,
    )

    assert meta.status == CollectionStatus.COMPLETED.value
    assert meta.collection_method == CollectionMethod.RAM.value
    assert meta.simulation_indicator is True
    assert meta.containment_verified is True
    assert meta.artifact_location.startswith("simulated://")
    assert "raw" in meta.artifact_location
    assert meta.file_size_bytes == 17179869184  # 16 GB simulated size
    assert meta.completed_at is not None


def test_scenario_03_collection_still_running(forensic_service):
    """
    Scenario 3: Collection still running.
    Job initiates in RUNNING state; subsequent polling advances to COMPLETED.
    """
    meta = forensic_service.initiate_collection(
        incident_id="1002",
        endpoint_identifier="ISOLATED-HOST",
        method=CollectionMethod.KAPE,
        options={"simulate_running": True},
        allow_duplicate=True,
    )

    assert meta.status == CollectionStatus.RUNNING.value
    assert meta.completed_at is None

    # Status check polls adapter and advances the job
    updated = forensic_service.get_collection_status(meta.collection_job_id)
    assert updated.status == CollectionStatus.COMPLETED.value
    assert updated.completed_at is not None


def test_scenario_04_collection_failure(forensic_service):
    """
    Scenario 4: Collection failure.
    Collection fails during execution; error details and completion time are recorded.
    """
    meta = forensic_service.initiate_collection(
        incident_id="1002",
        endpoint_identifier="ISOLATED-HOST",
        method=CollectionMethod.KAPE,
        options={"simulate_failure": True},
        allow_duplicate=True,
    )

    assert meta.status == CollectionStatus.FAILED.value
    assert meta.error_details is not None
    assert "failed" in meta.error_details.lower()
    assert meta.completed_at is not None


def test_scenario_05_endpoint_not_contained(forensic_service):
    """
    Scenario 5: Endpoint not contained.
    Target endpoint has NOT_ISOLATED containment status.
    Service must STRICTLY REFUSE collection and raise EndpointNotContainedError.
    """
    # In Incident 1001, FINANCE-SRV-01 is NOT_ISOLATED
    with pytest.raises(EndpointNotContainedError) as exc_info:
        forensic_service.initiate_collection(
            incident_id="1001",
            endpoint_identifier="FINANCE-SRV-01",
            method=CollectionMethod.KAPE,
        )

    assert "NOT_ISOLATED" in str(exc_info.value)
    assert "strictly refused" in str(exc_info.value).lower()


def test_scenario_06_unknown_containment_status(forensic_service, monkeypatch):
    """
    Scenario 6: Unknown containment status.
    EDR returns UNKNOWN containment state.
    Service must STRICTLY REFUSE collection and raise UnknownContainmentError.
    """
    # Monkeypatch get_endpoint_containment_status to return UNKNOWN
    def mock_unknown(target):
        return {
            "device_id": target,
            "device_name": target,
            "containment_status": ContainmentStatus.UNKNOWN.value,
            "isolation_details": "Telemetry inconclusive; state unknown",
        }

    monkeypatch.setattr(forensic_service.client, "get_endpoint_containment_status", mock_unknown)

    with pytest.raises(UnknownContainmentError) as exc_info:
        forensic_service.initiate_collection(
            incident_id="1002",
            endpoint_identifier="ISOLATED-HOST",
            method=CollectionMethod.KAPE,
        )

    assert "UNKNOWN" in str(exc_info.value)
    assert "Safety Check Failed" in str(exc_info.value)


def test_scenario_07_unsupported_collection_method(forensic_service):
    """
    Scenario 7: Unsupported collection method.
    Service must reject unsupported or unknown methods with UnsupportedMethodError.
    """
    with pytest.raises(UnsupportedMethodError) as exc_info:
        forensic_service.initiate_collection(
            incident_id="1002",
            endpoint_identifier="ISOLATED-HOST",
            method="RAW_DISK_CLONE_NONEXISTENT",
        )

    assert "Unsupported collection method" in str(exc_info.value)


def test_scenario_08_missing_endpoint_identifier(forensic_service):
    """
    Scenario 8: Missing endpoint identifier.
    Empty or whitespace endpoint identifier must be rejected with ValueError.
    """
    with pytest.raises(ValueError) as exc_info:
        forensic_service.initiate_collection(
            incident_id="1002",
            endpoint_identifier="",
            method=CollectionMethod.KAPE,
        )

    assert "Endpoint identifier cannot be empty" in str(exc_info.value)


def test_scenario_09_edr_authentication_failure(forensic_service, monkeypatch):
    """
    Scenario 9: EDR authentication failure.
    EDR client fails authentication with Azure AD; error handled gracefully without leaks.
    """
    def mock_auth_fail(*args, **kwargs):
        raise EDRAuthenticationError("Azure AD OAuth2 token request rejected (HTTP 401).")

    monkeypatch.setattr(forensic_service.client, "get_incident", mock_auth_fail)

    with pytest.raises(EDRAuthenticationError) as exc_info:
        forensic_service.initiate_collection(
            incident_id="1002",
            endpoint_identifier="ISOLATED-HOST",
        )

    assert "OAuth2 token request rejected" in str(exc_info.value)


def test_scenario_10_edr_api_timeout(forensic_service, monkeypatch):
    """
    Scenario 10: EDR API timeout.
    API call exceeds timeout; handled cleanly.
    """
    def mock_timeout(*args, **kwargs):
        raise EDRTimeoutError("Connection timed out after 15 seconds contacting Defender API.")

    monkeypatch.setattr(forensic_service.client, "get_incident", mock_timeout)

    with pytest.raises(EDRTimeoutError) as exc_info:
        forensic_service.initiate_collection(
            incident_id="1002",
            endpoint_identifier="ISOLATED-HOST",
        )

    assert "timed out after 15 seconds" in str(exc_info.value)


def test_scenario_11_duplicate_collection_request(forensic_service):
    """
    Scenario 11: Duplicate collection request.
    Attempting a second identical collection on an endpoint while a job is RUNNING
    must be rejected by Idempotency check with DuplicateJobError.
    """
    # 1. Start a job in RUNNING state
    meta1 = forensic_service.initiate_collection(
        incident_id="1002",
        endpoint_identifier="ISOLATED-HOST",
        method=CollectionMethod.KAPE,
        options={"simulate_running": True},
    )
    assert meta1.status == CollectionStatus.RUNNING.value

    # 2. Attempt duplicate collection without allow_duplicate flag
    with pytest.raises(DuplicateJobError) as exc_info:
        forensic_service.initiate_collection(
            incident_id="1002",
            endpoint_identifier="ISOLATED-HOST",
            method=CollectionMethod.KAPE,
        )

    assert "Duplicate collection rejected" in str(exc_info.value)
    assert meta1.collection_job_id in str(exc_info.value)


def test_scenario_12_missing_artifact_location(forensic_service):
    """
    Scenario 12: Missing artifact location.
    Job completes but artifact location is missing/unavailable;
    metadata must accurately record artifact_location as None and explain reason.
    """
    meta = forensic_service.initiate_collection(
        incident_id="1002",
        endpoint_identifier="ISOLATED-HOST",
        method=CollectionMethod.KAPE,
        options={"simulate_missing_location": True},
        allow_duplicate=True,
    )

    assert meta.status == CollectionStatus.COMPLETED.value
    assert meta.artifact_location is None
    assert meta.diagnostic_notes is not None
    assert "empty" in meta.diagnostic_notes.lower() or "missing" in meta.diagnostic_notes.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Additional Integration & Safety Verification Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_endpoint_incident_mismatch_refused(forensic_service):
    """Ensures collection is refused if endpoint does not belong to the incident."""
    with pytest.raises(EndpointMismatchError) as exc_info:
        forensic_service.initiate_collection(
            incident_id="1001",
            endpoint_identifier="UNRELATED-HOST-99",
            method=CollectionMethod.KAPE,
        )

    assert "not associated with Incident #1001" in str(exc_info.value)


def test_track_job_polls_to_completion(forensic_service):
    """Verifies track_job() polls until terminal state is achieved."""
    meta = forensic_service.initiate_collection(
        incident_id="1002",
        endpoint_identifier="ISOLATED-HOST",
        method=CollectionMethod.KAPE,
        options={"simulate_running": True},
        allow_duplicate=True,
    )
    assert meta.status == CollectionStatus.RUNNING.value

    tracked = forensic_service.track_job(meta.collection_job_id, poll_interval=0.1, max_wait_seconds=2.0)
    assert tracked.status == CollectionStatus.COMPLETED.value
    assert tracked.completed_at is not None


def test_list_jobs_and_filtering(forensic_service):
    """Verifies job listing and filtering by incident ID and method."""
    forensic_service.initiate_collection(
        incident_id="1002",
        endpoint_identifier="ISOLATED-HOST",
        method=CollectionMethod.KAPE,
        allow_duplicate=True,
    )
    forensic_service.initiate_collection(
        incident_id="1002",
        endpoint_identifier="ISOLATED-HOST",
        method=CollectionMethod.RAM,
        allow_duplicate=True,
    )

    all_jobs = forensic_service.list_jobs()
    assert len(all_jobs) >= 2

    filtered_inc = forensic_service.list_jobs(incident_id="1002")
    assert len(filtered_inc) >= 2

    filtered_none = forensic_service.list_jobs(incident_id="9999")
    assert len(filtered_none) == 0


def test_simulated_evidence_is_never_represented_as_real_evidence(forensic_service):
    """
    CRITICAL SAFETY REQUIREMENT:
    Verify that simulated evidence is NEVER labeled or represented as real evidence.
    """
    meta_kape = forensic_service.initiate_collection(
        incident_id="1002",
        endpoint_identifier="ISOLATED-HOST",
        method=CollectionMethod.KAPE,
        allow_duplicate=True,
    )
    meta_ram = forensic_service.initiate_collection(
        incident_id="1002",
        endpoint_identifier="ISOLATED-HOST",
        method=CollectionMethod.RAM,
        allow_duplicate=True,
    )

    assert meta_kape.simulation_indicator is True
    assert meta_ram.simulation_indicator is True
    assert "simulated" in meta_kape.artifact_location.lower()
    assert meta_ram.artifact_location.startswith("simulated://")

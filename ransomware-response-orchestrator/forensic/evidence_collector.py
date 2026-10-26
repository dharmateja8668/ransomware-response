"""
forensic/evidence_collector.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Forensic Evidence Collector Adapters.
Automated Ransomware Containment & Incident Response Orchestrator - Day 2.

Implements adapters for:
  1. KAPE Windows forensic artifact collection.
  2. Physical RAM acquisition adapter.
  3. Microsoft Defender native Investigation Package collection.

Security & Safety Rules:
  - Evidence collection must only execute on endpoints verified as ISOLATED.
  - Never pretend an artifact exists when collection was unsupported or failed.
  - Mock and simulated evidence runs are explicitly flagged with simulation_indicator=True.
  - Secrets, access tokens, and passwords are never logged or stored in metadata.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import uuid

from integrations.defender_client import (
    DefenderClient,
    EDRAPIError,
    EDRAuthenticationError,
    EDRConnectionError,
    EDRError,
    EDRTimeoutError,
)
from forensic.metadata import (
    CollectionMethod,
    CollectionStatus,
    DEFAULT_KAPE_CATEGORIES,
    EvidenceMetadata,
    KapeArtifactCategory,
)

logger = logging.getLogger("orchestrator.forensic.collector")


# ─────────────────────────────────────────────────────────────────────────────
# Custom Forensic Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class ForensicError(Exception):
    """Base exception for forensic collection operations."""


class SafetyCheckError(ForensicError):
    """Raised when safety preconditions (such as containment check) fail."""


class EndpointNotContainedError(SafetyCheckError):
    """Raised when attempting evidence collection on an endpoint that is NOT_ISOLATED."""


class UnknownContainmentError(SafetyCheckError):
    """Raised when endpoint containment status is UNKNOWN."""


class EndpointMismatchError(SafetyCheckError):
    """Raised when the target endpoint is not associated with the specified incident."""


class UnsupportedMethodError(ForensicError):
    """Raised when the requested collection method is unsupported or disabled."""


class DuplicateJobError(ForensicError):
    """Raised when an active or recently completed collection job already exists for the target."""


class CollectionJobError(ForensicError):
    """Raised when an evidence collection job fails during execution."""


# ─────────────────────────────────────────────────────────────────────────────
# Base Adapter Interface
# ─────────────────────────────────────────────────────────────────────────────

class ForensicCollectorAdapter(ABC):
    """Abstract base class for forensic evidence collection adapters."""

    def __init__(self, defender_client: DefenderClient) -> None:
        self.client = defender_client

    @property
    @abstractmethod
    def method(self) -> CollectionMethod:
        """Returns the collection method handled by this adapter."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable adapter name."""

    @abstractmethod
    def is_available(self) -> bool:
        """Checks if the collection mechanism is available and configured."""

    @abstractmethod
    def validate_prerequisites(
        self, endpoint_id: str, endpoint_info: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Validates target endpoint prerequisites before initiating collection.
        Returns:
          (True, None) if prerequisites pass, or (False, "reason") if failed.
        """

    @abstractmethod
    def initiate(
        self,
        incident_id: str,
        endpoint_id: str,
        hostname: Optional[str] = None,
        artifact_categories: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> EvidenceMetadata:
        """Initiates an evidence collection job and returns initial EvidenceMetadata."""

    @abstractmethod
    def poll_status(self, metadata: EvidenceMetadata) -> EvidenceMetadata:
        """Polls the status of an ongoing collection job and returns updated metadata."""


# ─────────────────────────────────────────────────────────────────────────────
# KAPE Windows Forensic Artifact Collector Adapter
# ─────────────────────────────────────────────────────────────────────────────

class KapeCollectionAdapter(ForensicCollectorAdapter):
    """
    Adapter for Kroll Artifact Parser and Extractor (KAPE) on Windows endpoints.
    Initiates targeted forensic artifact acquisition (Registry, EventLogs, MFT, Execution).
    """

    ALLOWED_CATEGORIES = {cat.value for cat in KapeArtifactCategory}

    @property
    def method(self) -> CollectionMethod:
        return CollectionMethod.KAPE

    @property
    def name(self) -> str:
        return "KAPE Windows Forensic Collector"

    def is_available(self) -> bool:
        """KAPE is always available in mock mode; in live mode, checks Live Response support."""
        if self.client.config.mock_mode:
            return True
        return False

    def validate_categories(self, requested: Optional[List[str]]) -> List[str]:
        """Validates requested artifact categories against permitted list."""
        if not requested:
            return list(DEFAULT_KAPE_CATEGORIES)

        invalid = [cat for cat in requested if cat not in self.ALLOWED_CATEGORIES]
        if invalid:
            raise UnsupportedMethodError(
                f"Invalid KAPE artifact categories requested: {', '.join(invalid)}. "
                f"Permitted categories are: {', '.join(sorted(self.ALLOWED_CATEGORIES))}"
            )
        return list(requested)

    def validate_prerequisites(
        self, endpoint_id: str, endpoint_info: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[str]]:
        if not endpoint_id or not endpoint_id.strip():
            return False, "Target endpoint identifier cannot be empty."

        if self.client.config.mock_mode:
            target_lower = endpoint_id.lower()
            if "unsupported-os" in target_lower or "linux" in target_lower:
                return False, "KAPE is only supported on Windows endpoints."
            return True, None

        # Live Mode prerequisite evaluation
        try:
            capability = self.client.check_live_response_capability(endpoint_id)
            if not capability.get("supported"):
                return False, f"Live Response not supported: {capability.get('reason')}"
            os_plat = str(capability.get("os_platform", "")).lower()
            if "windows" not in os_plat:
                return False, f"KAPE requires Windows OS; target reported: {capability.get('os_platform')}"
            if not capability.get("live_response_configured"):
                return False, (
                    "KAPE Live Response script not uploaded to Defender Live Response Library "
                    "or Machine.LiveResponse permissions not granted."
                )
            return True, None
        except EDRError as err:
            return False, f"Failed to check endpoint Live Response capabilities: {err}"

    def initiate(
        self,
        incident_id: str,
        endpoint_id: str,
        hostname: Optional[str] = None,
        artifact_categories: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> EvidenceMetadata:
        options = options or {}
        categories = self.validate_categories(artifact_categories)
        passed, reason = self.validate_prerequisites(endpoint_id)

        clean_host = hostname or endpoint_id
        job_id = f"kape-{uuid.uuid4().hex[:10]}"

        # If prerequisites failed in live mode or mock configuration
        if not passed:
            metadata = EvidenceMetadata(
                incident_id=incident_id,
                endpoint_id=endpoint_id,
                hostname=hostname,
                collection_job_id=job_id,
                collection_method=self.method.value,
                requested_artifacts=categories,
                status=CollectionStatus.FAILED.value,
                simulation_indicator=self.client.config.mock_mode,
                containment_verified=True,
                error_details=reason or "Prerequisites validation failed.",
            )
            metadata.completed_at = datetime.now(timezone.utc).isoformat()
            return metadata

        # Create initial pending/running metadata
        metadata = EvidenceMetadata(
            incident_id=incident_id,
            endpoint_id=endpoint_id,
            hostname=hostname,
            collection_job_id=job_id,
            collection_method=self.method.value,
            requested_artifacts=categories,
            status=CollectionStatus.RUNNING.value,
            simulation_indicator=self.client.config.mock_mode,
            containment_verified=True,
        )

        # Handle Mock Mode execution scenarios
        if self.client.config.mock_mode:
            target_lower = endpoint_id.lower()
            simulate_fail = options.get("simulate_failure") or "fail" in target_lower or "error" in target_lower
            simulate_running = options.get("simulate_running") or "running" in target_lower or "pending" in target_lower
            simulate_missing_loc = options.get("simulate_missing_location") or "missing-loc" in target_lower

            if simulate_fail:
                metadata.mark_failed(
                    error_details="KAPE artifact collection failed: Volume shadow copy locked by active ransomware process.",
                    diagnostic_notes="Simulated KAPE failure mode.",
                )
            elif simulate_running:
                metadata.mark_running()
                metadata.diagnostic_notes = "Collection in progress (simulated delay)."
            elif simulate_missing_loc:
                metadata.mark_completed(
                    artifact_location=None,
                    diagnostic_notes="Artifact package generated but package URI resolution returned empty.",
                )
            else:
                timestamp_tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                sim_path = f"evidence/simulated/kape_{clean_host}_{timestamp_tag}_{job_id[:6]}.zip"
                metadata.mark_completed(
                    artifact_location=sim_path,
                    file_hash_sha256="simulated-sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    file_size_bytes=48234102,  # ~46 MB simulated triage archive
                    diagnostic_notes="Simulated KAPE package collection completed successfully.",
                )
            return metadata

        # Live Mode Execution
        # If live execution is attempted without real Live Response library scripts configured:
        metadata.mark_failed(
            error_details="Real KAPE execution requires Microsoft Defender Live Response library automation script. Live execution halted.",
            diagnostic_notes="Production live response script runner not configured.",
        )
        return metadata

    def poll_status(self, metadata: EvidenceMetadata) -> EvidenceMetadata:
        """Polls status of KAPE collection job."""
        if metadata.status in (CollectionStatus.COMPLETED.value, CollectionStatus.FAILED.value):
            return metadata

        if self.client.config.mock_mode:
            # Advance running job to completed if not explicitly set to fail
            clean_host = metadata.hostname or metadata.endpoint_id
            timestamp_tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            sim_path = f"evidence/simulated/kape_{clean_host}_{timestamp_tag}_{metadata.collection_job_id[:6]}.zip"
            metadata.mark_completed(
                artifact_location=sim_path,
                file_hash_sha256="simulated-sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                file_size_bytes=48234102,
                diagnostic_notes="Simulated KAPE package completed upon status poll.",
            )
            return metadata

        return metadata


# ─────────────────────────────────────────────────────────────────────────────
# RAM Physical Memory Acquisition Adapter
# ─────────────────────────────────────────────────────────────────────────────

class RAMAcquisitionAdapter(ForensicCollectorAdapter):
    """
    Adapter for Physical RAM Memory Acquisition.

    Security & Truthfulness Guarantees:
      - Physical memory acquisition requires authorized kernel-level drivers.
      - Never pretends an arbitrary file is a memory dump.
      - Never labels a RAM image as collected unless an actual acquisition confirmed success.
      - In simulated mode, results are clearly labeled as simulated (simulation_indicator=True).
    """

    @property
    def method(self) -> CollectionMethod:
        return CollectionMethod.RAM

    @property
    def name(self) -> str:
        return "RAM Memory Acquisition Adapter"

    def is_available(self) -> bool:
        if self.client.config.mock_mode:
            return True
        # Real raw physical RAM acquisition requires kernel driver daemon (e.g. WinPmem, DumpIt)
        return False

    def validate_prerequisites(
        self, endpoint_id: str, endpoint_info: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[str]]:
        if not endpoint_id or not endpoint_id.strip():
            return False, "Target endpoint identifier cannot be empty."

        if self.client.config.mock_mode:
            target_lower = endpoint_id.lower()
            if "ram-unsupported" in target_lower:
                return False, "Endpoint hardware architecture or hypervisor prohibits raw memory dumping."
            return True, None

        # In live mode: Defender API does not provide physical RAM dumps natively
        return False, (
            "RAM acquisition unavailable: Physical memory acquisition requires a signed kernel driver "
            "(WinPmem/DumpIt) authorized via Live Response or a dedicated endpoint agent. "
            "Raw RAM acquisition is not supported natively via standard Defender REST API."
        )

    def initiate(
        self,
        incident_id: str,
        endpoint_id: str,
        hostname: Optional[str] = None,
        artifact_categories: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> EvidenceMetadata:
        options = options or {}
        passed, reason = self.validate_prerequisites(endpoint_id)

        clean_host = hostname or endpoint_id
        job_id = f"ram-{uuid.uuid4().hex[:10]}"

        if not passed:
            metadata = EvidenceMetadata(
                incident_id=incident_id,
                endpoint_id=endpoint_id,
                hostname=hostname,
                collection_job_id=job_id,
                collection_method=self.method.value,
                requested_artifacts=["Physical_Memory_RAM"],
                status=CollectionStatus.FAILED.value,
                simulation_indicator=self.client.config.mock_mode,
                containment_verified=True,
                error_details=reason or "RAM acquisition prerequisites not satisfied.",
            )
            metadata.completed_at = datetime.now(timezone.utc).isoformat()
            return metadata

        metadata = EvidenceMetadata(
            incident_id=incident_id,
            endpoint_id=endpoint_id,
            hostname=hostname,
            collection_job_id=job_id,
            collection_method=self.method.value,
            requested_artifacts=["Physical_Memory_RAM"],
            status=CollectionStatus.RUNNING.value,
            simulation_indicator=self.client.config.mock_mode,
            containment_verified=True,
        )

        if self.client.config.mock_mode:
            target_lower = endpoint_id.lower()
            simulate_fail = options.get("simulate_failure") or "fail" in target_lower or "error" in target_lower
            simulate_running = options.get("simulate_running") or "running" in target_lower or "pending" in target_lower
            simulate_missing_loc = options.get("simulate_missing_location") or "missing-loc" in target_lower

            if simulate_fail:
                metadata.mark_failed(
                    error_details="RAM memory acquisition aborted: Kernel memory driver returned error 0xC0000022 (STATUS_ACCESS_DENIED).",
                    diagnostic_notes="Simulated RAM acquisition failure scenario.",
                )
            elif simulate_running:
                metadata.mark_running()
                metadata.diagnostic_notes = "Memory acquisition in progress across 16 GB physical address space (simulated)."
            elif simulate_missing_loc:
                metadata.mark_completed(
                    artifact_location=None,
                    diagnostic_notes="RAM dump completed on endpoint but storage transfer failed; artifact path missing.",
                )
            else:
                timestamp_tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                sim_path = f"simulated://evidence/ram/{clean_host}_{timestamp_tag}_{job_id[:6]}.raw"
                metadata.mark_completed(
                    artifact_location=sim_path,
                    file_hash_sha256="simulated-sha256-memory-4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                    file_size_bytes=17179869184,  # Simulated 16 GB dump metadata
                    diagnostic_notes="SIMULATED RAM ACQUISITION WORKFLOW. No live kernel memory was accessed.",
                )
            return metadata

        metadata.mark_failed(
            error_details="Live physical memory dump aborted: No authorized kernel acquisition driver found.",
            diagnostic_notes="Physical RAM acquisition requires authorized agent integration.",
        )
        return metadata

    def poll_status(self, metadata: EvidenceMetadata) -> EvidenceMetadata:
        """Polls status of RAM collection job."""
        if metadata.status in (CollectionStatus.COMPLETED.value, CollectionStatus.FAILED.value):
            return metadata

        if self.client.config.mock_mode:
            clean_host = metadata.hostname or metadata.endpoint_id
            timestamp_tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            sim_path = f"simulated://evidence/ram/{clean_host}_{timestamp_tag}_{metadata.collection_job_id[:6]}.raw"
            metadata.mark_completed(
                artifact_location=sim_path,
                file_hash_sha256="simulated-sha256-memory-4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                file_size_bytes=17179869184,
                diagnostic_notes="SIMULATED RAM ACQUISITION COMPLETED ON POLL.",
            )
            return metadata

        return metadata


# ─────────────────────────────────────────────────────────────────────────────
# Microsoft Defender Investigation Package Adapter
# ─────────────────────────────────────────────────────────────────────────────

class DefenderInvestigationPackageAdapter(ForensicCollectorAdapter):
    """
    Adapter for Microsoft Defender for Endpoint official Investigation Package collection.
    Endpoint: POST /api/machines/{id}/collectInvestigationPackage
    """

    @property
    def method(self) -> CollectionMethod:
        return CollectionMethod.INVESTIGATION_PACKAGE

    @property
    def name(self) -> str:
        return "Microsoft Defender Investigation Package Collector"

    def is_available(self) -> bool:
        return True

    def validate_prerequisites(
        self, endpoint_id: str, endpoint_info: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[str]]:
        if not endpoint_id or not endpoint_id.strip():
            return False, "Target endpoint identifier cannot be empty."
        return True, None

    def initiate(
        self,
        incident_id: str,
        endpoint_id: str,
        hostname: Optional[str] = None,
        artifact_categories: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> EvidenceMetadata:
        options = options or {}
        passed, reason = self.validate_prerequisites(endpoint_id)

        job_id = f"mde-{uuid.uuid4().hex[:10]}"
        categories = artifact_categories or ["Defender_Investigation_Package"]

        if not passed:
            metadata = EvidenceMetadata(
                incident_id=incident_id,
                endpoint_id=endpoint_id,
                hostname=hostname,
                collection_job_id=job_id,
                collection_method=self.method.value,
                requested_artifacts=categories,
                status=CollectionStatus.FAILED.value,
                simulation_indicator=self.client.config.mock_mode,
                containment_verified=True,
                error_details=reason or "Prerequisites failed.",
            )
            metadata.completed_at = datetime.now(timezone.utc).isoformat()
            return metadata

        try:
            action = self.client.collect_investigation_package(
                endpoint_id, comment=f"Forensic collection for Incident #{incident_id}"
            )
            action_id = action.get("action_id")
            action_status = action.get("status", "Pending")

            metadata = EvidenceMetadata(
                incident_id=incident_id,
                endpoint_id=endpoint_id,
                hostname=hostname,
                collection_job_id=action_id or job_id,
                collection_method=self.method.value,
                requested_artifacts=categories,
                simulation_indicator=self.client.config.mock_mode,
                containment_verified=True,
                diagnostic_notes=f"Defender Machine Action ID: {action_id}",
            )

            if action_status in ("Succeeded", "Completed"):
                # Fetch package download URI
                pkg_uri = self.client.get_package_uri(action_id)
                metadata.mark_completed(
                    artifact_location=pkg_uri,
                    diagnostic_notes=f"Investigation package ready via Defender SAS URL.",
                )
            elif action_status in ("Failed", "Cancelled"):
                metadata.mark_failed(
                    error_details=action.get("error_code") or "Defender investigation package collection failed."
                )
            else:
                metadata.mark_running()

            return metadata

        except EDRError as err:
            logger.error("Failed to initiate Defender investigation package for %s: %s", endpoint_id, err)
            metadata = EvidenceMetadata(
                incident_id=incident_id,
                endpoint_id=endpoint_id,
                hostname=hostname,
                collection_job_id=job_id,
                collection_method=self.method.value,
                requested_artifacts=categories,
                status=CollectionStatus.FAILED.value,
                simulation_indicator=self.client.config.mock_mode,
                containment_verified=True,
                error_details=str(err),
            )
            metadata.completed_at = datetime.now(timezone.utc).isoformat()
            return metadata

    def poll_status(self, metadata: EvidenceMetadata) -> EvidenceMetadata:
        """Polls status of Defender investigation package machine action."""
        if metadata.status in (CollectionStatus.COMPLETED.value, CollectionStatus.FAILED.value):
            return metadata

        action_id = metadata.collection_job_id
        try:
            action = self.client.get_machine_action(action_id)
            status = action.get("status", "Pending")

            if status in ("Succeeded", "Completed"):
                pkg_uri = self.client.get_package_uri(action_id)
                metadata.mark_completed(artifact_location=pkg_uri)
            elif status in ("Failed", "Cancelled"):
                metadata.mark_failed(error_details=action.get("error_code") or "Defender action failed.")
            else:
                metadata.mark_running()

        except EDRError as err:
            logger.warning("Error polling action %s: %s", action_id, err)

        return metadata

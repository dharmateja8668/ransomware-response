"""
forensic/collection_service.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Forensic Evidence Collection Service.
Automated Ransomware Containment & Incident Response Orchestrator - Day 2.

Orchestrates the complete forensic evidence collection workflow:
  1. Validates incident association and endpoint authorization.
  2. Verifies endpoint containment status (ISOLATED mandatory).
  3. Prevents duplicate collection requests (Idempotency).
  4. Dispatches collection to appropriate adapter (KAPE, RAM, Investigation Package).
  5. Tracks collection states (PENDING, RUNNING, COMPLETED, FAILED).
  6. Generates, audits, and persists structured evidence metadata records.

Security Rules:
  - REFUSES collection if endpoint is NOT_ISOLATED or UNKNOWN.
  - REFUSES collection if endpoint does not belong to the incident.
  - Never leaks bearer tokens or client secrets into metadata or logs.
  - Clearly differentiates mock/simulated collections from real acquisitions.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple

from integrations.defender_client import (
    ContainmentStatus,
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
from forensic.evidence_collector import (
    CollectionJobError,
    DefenderInvestigationPackageAdapter,
    DuplicateJobError,
    EndpointMismatchError,
    EndpointNotContainedError,
    ForensicCollectorAdapter,
    ForensicError,
    KapeCollectionAdapter,
    RAMAcquisitionAdapter,
    SafetyCheckError,
    UnknownContainmentError,
    UnsupportedMethodError,
)

logger = logging.getLogger("orchestrator.forensic.service")


class ForensicCollectionService:
    """
    Central orchestration service for authorized forensic evidence collection.
    """

    def __init__(
        self,
        defender_client: Optional[DefenderClient] = None,
        evidence_dir: Optional[Path | str] = None,
    ) -> None:
        self.client = defender_client or DefenderClient()

        # Determine evidence storage directory
        if evidence_dir:
            self.evidence_dir = Path(evidence_dir).resolve()
        else:
            env_dir = os.getenv("EVIDENCE_DIR")
            if env_dir:
                self.evidence_dir = Path(env_dir).resolve()
            else:
                self.evidence_dir = Path(__file__).resolve().parent.parent / "evidence" / "metadata"

        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # Initialize adapters
        self.adapters: Dict[CollectionMethod, ForensicCollectorAdapter] = {
            CollectionMethod.KAPE: KapeCollectionAdapter(self.client),
            CollectionMethod.RAM: RAMAcquisitionAdapter(self.client),
            CollectionMethod.INVESTIGATION_PACKAGE: DefenderInvestigationPackageAdapter(self.client),
        }

        # In-memory tracking of active/recent jobs
        self._jobs: Dict[str, EvidenceMetadata] = {}
        # Key: (incident_id, endpoint_identifier, method) -> job_id
        self._active_dedup_index: Dict[Tuple[str, str, str], str] = {}

        # Pre-load existing metadata records from disk
        self._load_existing_metadata()

        logger.info(
            "Initialized ForensicCollectionService (evidence_dir=%s, mock_mode=%s)",
            self.evidence_dir,
            self.client.config.mock_mode,
        )

    def _load_existing_metadata(self) -> None:
        """Loads previously persisted metadata files from evidence directory."""
        try:
            for json_file in self.evidence_dir.glob("*_metadata.json"):
                try:
                    meta = EvidenceMetadata.load(json_file)
                    self._jobs[meta.collection_job_id] = meta
                    if meta.status in (CollectionStatus.PENDING.value, CollectionStatus.RUNNING.value):
                        dedup_key = (str(meta.incident_id), str(meta.endpoint_id).lower(), meta.collection_method)
                        self._active_dedup_index[dedup_key] = meta.collection_job_id
                except Exception as err:
                    logger.warning("Failed to load metadata file %s: %s", json_file.name, err)
        except Exception as err:
            logger.warning("Error scanning evidence directory %s: %s", self.evidence_dir, err)

    def get_adapter(self, method: CollectionMethod | str) -> ForensicCollectorAdapter:
        """Resolves the adapter for the requested collection method."""
        if isinstance(method, str):
            clean_method = method.strip().upper()
            try:
                enum_method = CollectionMethod(clean_method)
            except ValueError:
                supported = [m.value for m in CollectionMethod]
                raise UnsupportedMethodError(
                    f"Unsupported collection method '{method}'. Supported methods: {', '.join(supported)}"
                )
        else:
            enum_method = method

        adapter = self.adapters.get(enum_method)
        if not adapter:
            raise UnsupportedMethodError(f"No adapter registered for method {enum_method.value}")
        return adapter

    # ─────────────────────────────────────────────────────────────────────────
    # Incident & Containment Safety Pre-Checks
    # ─────────────────────────────────────────────────────────────────────────

    def verify_authorization(
        self, incident_id: str | int, endpoint_identifier: str
    ) -> Dict[str, Any]:
        """
        Executes critical pre-collection authorization checks:
          1. Validates inputs.
          2. Verifies that the endpoint belongs to the given incident.
          3. Checks endpoint containment status (must be ISOLATED).

        Returns:
          Dict containing canonical endpoint information and containment assessment.

        Raises:
          ValueError: If input arguments are missing.
          EndpointMismatchError: If the endpoint is not associated with the incident.
          EndpointNotContainedError: If endpoint is NOT_ISOLATED.
          UnknownContainmentError: If endpoint containment status is UNKNOWN.
          EDRError: On API or network failure.
        """
        str_incident = str(incident_id).strip()
        str_target = str(endpoint_identifier).strip()

        if not str_incident:
            raise ValueError("Incident ID cannot be empty.")
        if not str_target:
            raise ValueError("Endpoint identifier cannot be empty.")

        logger.info(
            "Verifying collection authorization: Incident=#%s, Target='%s'",
            str_incident,
            str_target,
        )

        # 1. Retrieve incident and verify endpoint affiliation
        incident_data = self.client.get_incident(str_incident)

        affected_devices = [d.lower() for d in incident_data.get("all_affected_devices", [])]
        all_ips = [ip.lower() for ip in incident_data.get("all_ip_addresses", [])]
        machine_ids = []

        for alert in incident_data.get("alerts", []):
            if alert.get("machine_id"):
                machine_ids.append(alert["machine_id"].lower())
            if alert.get("device_name"):
                affected_devices.append(alert["device_name"].lower())
            if alert.get("ip_address"):
                all_ips.append(alert["ip_address"].lower())

        target_lower = str_target.lower()
        target_short = target_lower.split(".")[0]

        # Check for device match
        is_member = (
            target_lower in affected_devices
            or target_short in [d.split(".")[0] for d in affected_devices]
            or target_lower in machine_ids
            or target_lower in all_ips
            or (incident_data.get("affected_device_name", "").lower() in (target_lower, target_short))
            or (incident_data.get("machine_id", "").lower() == target_lower)
            or (incident_data.get("device_ip_address", "").lower() == target_lower)
        )

        if not is_member:
            err_msg = (
                f"Safety Check Failed: Endpoint '{str_target}' is not associated with Incident #{str_incident}. "
                f"Affected incident entities: {incident_data.get('all_affected_devices', [])}. "
                "Forensic collection is strictly refused for unassociated endpoints."
            )
            logger.error(err_msg)
            raise EndpointMismatchError(err_msg)

        # 2. Verify endpoint containment status
        containment_info = self.client.get_endpoint_containment_status(str_target)
        status_val = containment_info.get("containment_status")

        if status_val == ContainmentStatus.NOT_ISOLATED.value:
            err_msg = (
                f"Safety Check Failed: Endpoint '{str_target}' containment status is NOT_ISOLATED. "
                "Forensic evidence collection is strictly refused prior to endpoint containment. "
                "Isolate endpoint before collecting evidence."
            )
            logger.error(err_msg)
            raise EndpointNotContainedError(err_msg)

        if status_val == ContainmentStatus.UNKNOWN.value:
            err_msg = (
                f"Safety Check Failed: Endpoint '{str_target}' containment status is UNKNOWN. "
                f"Details: {containment_info.get('isolation_details')}. "
                "Evidence collection is refused when containment state cannot be verified."
            )
            logger.error(err_msg)
            raise UnknownContainmentError(err_msg)

        if status_val != ContainmentStatus.ISOLATED.value:
            err_msg = (
                f"Safety Check Failed: Endpoint '{str_target}' has unverified status '{status_val}'. "
                "Only confirmed ISOLATED endpoints are eligible for collection."
            )
            logger.error(err_msg)
            raise SafetyCheckError(err_msg)

        logger.info(
            "Authorization confirmed: Endpoint '%s' belongs to Incident #%s and is confirmed ISOLATED.",
            str_target,
            str_incident,
        )

        return {
            "incident": incident_data,
            "containment": containment_info,
            "canonical_device_id": containment_info.get("device_id", str_target),
            "canonical_hostname": containment_info.get("device_name", str_target),
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Initiate Forensic Collection
    # ─────────────────────────────────────────────────────────────────────────

    def initiate_collection(
        self,
        incident_id: str | int,
        endpoint_identifier: str,
        method: CollectionMethod | str = CollectionMethod.KAPE,
        artifact_categories: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None,
        allow_duplicate: bool = False,
    ) -> EvidenceMetadata:
        """
        Orchestrates authorized evidence collection on an endpoint.

        Workflow:
          1. Safety Check: Verify endpoint belongs to incident and is ISOLATED.
          2. Idempotency Check: Refuse or return existing active job if duplicate.
          3. Adapter Dispatch: Delegate to method adapter (KAPE, RAM, etc.).
          4. Metadata Record: Save and audit metadata manifest.

        Returns:
          EvidenceMetadata tracking the collection job.
        """
        options = options or {}
        adapter = self.get_adapter(method)
        method_str = adapter.method.value

        # Step 1: Authorization & Containment Safety Pre-Checks
        auth_data = self.verify_authorization(incident_id, endpoint_identifier)
        canonical_id = auth_data["canonical_device_id"]
        canonical_host = auth_data["canonical_hostname"]

        # Step 2: Idempotency & Duplicate Request Prevention
        dedup_key = (str(incident_id), canonical_id.lower(), method_str)
        existing_job_id = self._active_dedup_index.get(dedup_key)

        if existing_job_id and not allow_duplicate:
            existing_job = self._jobs.get(existing_job_id)
            if existing_job and existing_job.status in (CollectionStatus.PENDING.value, CollectionStatus.RUNNING.value):
                err_msg = (
                    f"Duplicate collection rejected: An active {method_str} collection job "
                    f"({existing_job_id}) is currently in progress for endpoint '{endpoint_identifier}' "
                    f"under incident #{incident_id}."
                )
                logger.warning(err_msg)
                raise DuplicateJobError(err_msg)

        logger.info(
            "Initiating %s evidence collection on '%s' (Incident #%s)",
            method_str,
            canonical_host,
            incident_id,
        )

        # Step 3: Initiate collection via adapter
        metadata = adapter.initiate(
            incident_id=str(incident_id),
            endpoint_id=canonical_id,
            hostname=canonical_host,
            artifact_categories=artifact_categories,
            options=options,
        )

        # Step 4: Register and persist metadata
        self._jobs[metadata.collection_job_id] = metadata
        if metadata.status in (CollectionStatus.PENDING.value, CollectionStatus.RUNNING.value):
            self._active_dedup_index[dedup_key] = metadata.collection_job_id

        metadata.save(self.evidence_dir)

        logger.info(
            "Evidence collection job %s started: Status=%s, Method=%s",
            metadata.collection_job_id,
            metadata.status,
            metadata.collection_method,
        )
        return metadata

    # ─────────────────────────────────────────────────────────────────────────
    # Status Tracking & Polling
    # ─────────────────────────────────────────────────────────────────────────

    def get_collection_status(self, job_id: str) -> EvidenceMetadata:
        """
        Retrieves the latest status for a forensic collection job.
        Polls the adapter if the job is still active, updates metadata, and persists changes.
        """
        str_job = str(job_id).strip()
        if not str_job:
            raise ValueError("Job ID cannot be empty.")

        metadata = self._jobs.get(str_job)
        if not metadata:
            # Attempt to load from disk
            json_path = self.evidence_dir / f"{str_job}_metadata.json"
            if json_path.exists():
                metadata = EvidenceMetadata.load(json_path)
                self._jobs[str_job] = metadata
            else:
                raise KeyError(f"Collection job '{str_job}' not found.")

        # If job is already terminal, return current metadata
        if metadata.status in (CollectionStatus.COMPLETED.value, CollectionStatus.FAILED.value):
            return metadata

        # Poll adapter for updated status
        adapter = self.get_adapter(metadata.collection_method)
        updated = adapter.poll_status(metadata)

        # If job transitioned to terminal state, remove from active dedup index
        if updated.status in (CollectionStatus.COMPLETED.value, CollectionStatus.FAILED.value):
            dedup_key = (str(updated.incident_id), updated.endpoint_id.lower(), updated.collection_method)
            self._active_dedup_index.pop(dedup_key, None)

        # Persist updated status
        updated.save(self.evidence_dir)
        self._jobs[str_job] = updated
        return updated

    def track_job(
        self,
        job_id: str,
        poll_interval: float = 0.5,
        max_wait_seconds: float = 15.0,
    ) -> EvidenceMetadata:
        """
        Polls a collection job until it reaches a terminal state (COMPLETED or FAILED)
        or the maximum wait time is exceeded.
        """
        start_time = time.time()
        logger.info("Tracking collection job %s (max_wait=%.1fs)...", job_id, max_wait_seconds)

        metadata = self.get_collection_status(job_id)
        while metadata.status in (CollectionStatus.PENDING.value, CollectionStatus.RUNNING.value):
            if time.time() - start_time >= max_wait_seconds:
                logger.warning("Tracking timed out for job %s after %.1fs.", job_id, max_wait_seconds)
                break
            time.sleep(poll_interval)
            metadata = self.get_collection_status(job_id)

        return metadata

    def list_jobs(
        self,
        incident_id: Optional[str | int] = None,
        endpoint_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[EvidenceMetadata]:
        """Lists all recorded collection jobs, with optional filtering."""
        self._load_existing_metadata()
        jobs = list(self._jobs.values())

        if incident_id is not None:
            jobs = [j for j in jobs if str(j.incident_id) == str(incident_id)]
        if endpoint_id is not None:
            target_lower = str(endpoint_id).lower()
            jobs = [
                j
                for j in jobs
                if target_lower in (j.endpoint_id.lower(), (j.hostname or "").lower())
            ]
        if status is not None:
            status_clean = status.strip().upper()
            jobs = [j for j in jobs if j.status == status_clean]

        return sorted(jobs, key=lambda j: j.requested_at, reverse=True)

"""
services/incident_service.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Incident Response Investigation Service.
Orchestrates EDR incident triage and endpoint containment status verification.

Responsibilities:
  - Retrieve security incident details from Microsoft Defender for Endpoint.
  - Extract affected endpoint entities (Device DNS name, Machine ID, IP Address).
  - Verify real-time containment/isolation status for each affected endpoint.
  - Compile an immutable SOC triage report with containment recommendations.
  - Strictly READ-ONLY: Never initiates containment or modifications during Day 1.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from integrations.defender_client import (
    ContainmentStatus,
    DefenderClient,
    EDRAPIError,
    EDRAuthenticationError,
    EDRConnectionError,
    EDRError,
    EDRTimeoutError,
)

logger = logging.getLogger("orchestrator.incident_service")


@dataclass
class EndpointAssessment:
    """Represents the verified containment assessment for a single endpoint."""
    device_name: str
    machine_id: Optional[str]
    ip_address: Optional[str]
    containment_status: str  # ISOLATED, NOT_ISOLATED, UNKNOWN
    raw_status_details: str
    risk_score: str
    health_status: str
    verified_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentInvestigationReport:
    """Comprehensive investigation report compiled during SOC Day 1 triage."""
    incident_id: str
    title: str
    severity: str
    status: str
    created_time: Optional[str]
    last_update_time: Optional[str]
    affected_devices: List[str]
    ip_addresses: List[str]
    alerts_count: int
    alerts_summary: List[Dict[str, str]]
    endpoint_assessments: List[EndpointAssessment] = field(default_factory=list)
    investigated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    containment_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["endpoint_assessments"] = [e.to_dict() for e in self.endpoint_assessments]
        return data


class IncidentService:
    """
    Service coordinating incident triage and containment status checks.
    """

    def __init__(self, defender_client: Optional[DefenderClient] = None) -> None:
        self.defender_client = defender_client or DefenderClient()
        logger.info("Initialized IncidentService with client mode: %s", "Mock" if self.defender_client.config.mock_mode else "Live")

    def investigate_incident(self, incident_id: str | int) -> IncidentInvestigationReport:
        """
        Executes a full read-only Day 1 investigation workflow:
          1. Authenticate with Defender API (handled lazily by client).
          2. Fetch incident details, severity, status, and alert indicators.
          3. Identify all affected endpoints (names, IDs, IPs).
          4. Query endpoint containment status (ISOLATED, NOT_ISOLATED, UNKNOWN).
          5. Compile and log the containment verification assessment.

        Returns:
          IncidentInvestigationReport containing complete triage telemetry.
        """
        str_id = str(incident_id).strip()
        logger.info("Starting incident triage investigation for incident #%s", str_id)

        # Step 1 & 2: Retrieve Incident
        try:
            incident_data = self.defender_client.get_incident(str_id)
        except EDRError as err:
            logger.error("Failed to retrieve incident #%s: %s", str_id, err)
            raise

        # Extract incident summary telemetry
        title = incident_data.get("title", "Unknown Incident")
        severity = incident_data.get("severity", "Unknown")
        status = incident_data.get("status", "Unknown")
        created_time = incident_data.get("created_time")
        last_update = incident_data.get("last_update_time")

        all_devices = incident_data.get("all_affected_devices", [])
        all_ips = incident_data.get("all_ip_addresses", [])
        alerts = incident_data.get("alerts", [])

        alerts_summary = [
            {
                "alert_id": a.get("alert_id", ""),
                "title": a.get("title", ""),
                "category": a.get("category", ""),
                "severity": a.get("severity", ""),
            }
            for a in alerts
        ]

        logger.info(
            "Incident #%s parsed: Severity=%s, Status=%s, Affected Devices=%d, Alerts=%d",
            str_id,
            severity,
            status,
            len(all_devices),
            len(alerts),
        )

        # Step 3 & 4: Verify containment status for affected devices
        assessments: List[EndpointAssessment] = []

        # Build list of devices to assess: prefer machineId, fallback to deviceName
        devices_to_check: List[Dict[str, Optional[str]]] = []
        for alert in alerts:
            dev_entry = {
                "name": alert.get("device_name"),
                "machine_id": alert.get("machine_id"),
                "ip": alert.get("ip_address"),
            }
            if dev_entry["name"] or dev_entry["machine_id"]:
                # Avoid duplicates
                if not any(
                    d.get("machine_id") == dev_entry["machine_id"] and d.get("name") == dev_entry["name"]
                    for d in devices_to_check
                ):
                    devices_to_check.append(dev_entry)

        # Fallback if alerts did not populate devices
        if not devices_to_check:
            devices_to_check.append({
                "name": incident_data.get("affected_device_name"),
                "machine_id": incident_data.get("machine_id"),
                "ip": incident_data.get("device_ip_address"),
            })

        for target in devices_to_check:
            target_identifier = target["machine_id"] or target["name"] or "Unknown"
            if target_identifier == "Unknown":
                continue

            try:
                containment_res = self.defender_client.get_endpoint_containment_status(target_identifier)
                assessment = EndpointAssessment(
                    device_name=target["name"] or containment_res.get("device_name", target_identifier),
                    machine_id=target["machine_id"] or containment_res.get("device_id"),
                    ip_address=target["ip"] or containment_res.get("last_ip_address"),
                    containment_status=containment_res["containment_status"],
                    raw_status_details=containment_res.get("isolation_details", ""),
                    risk_score=containment_res.get("risk_score", "Unknown"),
                    health_status=containment_res.get("health_status", "Unknown"),
                    verified_at=containment_res.get("verified_at", datetime.now(timezone.utc).isoformat()),
                )
            except EDRError as err:
                logger.warning("Error verifying containment for %s: %s; marking as UNKNOWN", target_identifier, err)
                assessment = EndpointAssessment(
                    device_name=target["name"] or target_identifier,
                    machine_id=target["machine_id"],
                    ip_address=target["ip"],
                    containment_status=ContainmentStatus.UNKNOWN.value,
                    raw_status_details=f"Query error: {err}",
                    risk_score="Unknown",
                    health_status="Unknown",
                    verified_at=datetime.now(timezone.utc).isoformat(),
                )

            assessments.append(assessment)
            logger.info(
                "Endpoint containment verification: Device='%s' (IP=%s) -> STATUS: %s",
                assessment.device_name,
                assessment.ip_address or "N/A",
                assessment.containment_status,
            )

        # Step 5: Synthesize containment summary
        unisolated_count = sum(1 for a in assessments if a.containment_status == ContainmentStatus.NOT_ISOLATED.value)
        isolated_count = sum(1 for a in assessments if a.containment_status == ContainmentStatus.ISOLATED.value)
        unknown_count = sum(1 for a in assessments if a.containment_status == ContainmentStatus.UNKNOWN.value)

        if unisolated_count > 0:
            containment_summary = (
                f"ACTION REQUIRED: {unisolated_count} active device(s) are NOT_ISOLATED under {severity} severity incident. "
                "Containment will be coordinated in subsequent response phases."
            )
        elif isolated_count > 0 and unknown_count == 0:
            containment_summary = (
                f"PROTECTED: All {isolated_count} affected device(s) are confirmed ISOLATED in Defender."
            )
        else:
            containment_summary = (
                f"AUDIT CAUTION: Containment verification results contain unknown states "
                f"({unknown_count} UNKNOWN, {isolated_count} ISOLATED, {unisolated_count} NOT_ISOLATED)."
            )

        report = IncidentInvestigationReport(
            incident_id=str_id,
            title=title,
            severity=severity,
            status=status,
            created_time=created_time,
            last_update_time=last_update,
            affected_devices=all_devices or [a.device_name for a in assessments],
            ip_addresses=all_ips or [a.ip_address for a in assessments if a.ip_address],
            alerts_count=len(alerts_summary),
            alerts_summary=alerts_summary,
            endpoint_assessments=assessments,
            containment_summary=containment_summary,
        )

        logger.info("Completed triage for incident #%s. %s", str_id, containment_summary)
        return report

    def verify_single_endpoint(self, device_name_or_id: str) -> EndpointAssessment:
        """
        Standalone endpoint containment check.
        Does not perform destructive actions or isolation changes.
        """
        str_target = str(device_name_or_id).strip()
        logger.info("Standalone containment verification requested for endpoint: %s", str_target)

        res = self.defender_client.get_endpoint_containment_status(str_target)
        assessment = EndpointAssessment(
            device_name=res.get("device_name", str_target),
            machine_id=res.get("device_id"),
            ip_address=res.get("last_ip_address"),
            containment_status=res["containment_status"],
            raw_status_details=res.get("isolation_details", ""),
            risk_score=res.get("risk_score", "Unknown"),
            health_status=res.get("health_status", "Unknown"),
            verified_at=res.get("verified_at", datetime.now(timezone.utc).isoformat()),
        )
        return assessment

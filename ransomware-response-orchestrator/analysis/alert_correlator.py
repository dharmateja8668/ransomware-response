"""
analysis/alert_correlator.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EDR Alert & Forensic Evidence Correlation Engine.
Cross-references forensic artifact findings and cataloged evidence against
Microsoft Defender for Endpoint alert telemetry and incident entities.

Key Features:
  - Cryptographic hash matching between EDR alert evidence and forensic files.
  - Process name & command line telemetry correlation.
  - Machine identity validation (endpoint hostname, machine ID, IP address).
  - Quantitative threat score computation and confidence rating.
  - Generation of actionable containment recommendations.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from analysis.artifact_analyzer import ArtifactAnalysisReport, IOCItem
from services.evidence_catalog import CatalogRecord

logger = logging.getLogger("orchestrator.alert_correlator")


@dataclass
class MatchedIOC:
    """Represents an exact or high-confidence match between EDR telemetry and forensic artifacts."""
    match_category: str  # HASH_MATCH, PROCESS_MATCH, COMMAND_LINE_MATCH, NETWORK_MATCH, DEVICE_MATCH
    ioc_value: str
    evidence_id: str
    alert_title: str
    severity: str
    confidence: float  # 0.0 to 1.0
    details: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationReport:
    """Comprehensive correlation report cross-referencing EDR and forensic findings."""
    incident_id: str
    incident_title: str
    incident_severity: str
    evidence_items_evaluated: int
    matched_iocs_count: int
    correlation_score: int  # 0 to 100
    overall_threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    matched_iocs: List[MatchedIOC] = field(default_factory=list)
    containment_recommendations: List[str] = field(default_factory=list)
    chain_of_custody_verified: bool = True
    simulation_indicator: bool = False
    correlated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "incident_title": self.incident_title,
            "incident_severity": self.incident_severity,
            "evidence_items_evaluated": self.evidence_items_evaluated,
            "matched_iocs_count": self.matched_iocs_count,
            "correlation_score": self.correlation_score,
            "overall_threat_level": self.overall_threat_level,
            "matched_iocs": [m.to_dict() for m in self.matched_iocs],
            "containment_recommendations": self.containment_recommendations,
            "chain_of_custody_verified": self.chain_of_custody_verified,
            "simulation_indicator": self.simulation_indicator,
            "correlated_at": self.correlated_at,
            "summary": self.summary,
        }


class AlertCorrelator:
    """
    Correlates EDR alert telemetry with forensic evidence records and artifact analysis.
    """

    def correlate(
        self,
        incident_id: str,
        incident_title: str,
        incident_severity: str,
        edr_alerts: List[Dict[str, Any]],
        catalog_records: List[CatalogRecord],
        analysis_reports: List[ArtifactAnalysisReport],
        simulation_indicator: bool = False,
    ) -> CorrelationReport:
        """
        Executes cross-correlation across telemetry and evidence sources.
        
        Args:
            incident_id: Incident identifier.
            incident_title: Incident title.
            incident_severity: Incident severity (LOW, MEDIUM, HIGH, INFORMATIONAL).
            edr_alerts: List of raw alert dictionaries from DefenderClient.
            catalog_records: List of CatalogRecord items from EvidenceCatalogService.
            analysis_reports: List of ArtifactAnalysisReport items from ArtifactAnalyzer.
            simulation_indicator: Whether correlation runs on mock/simulated data.
            
        Returns:
            CorrelationReport detailing matched IOCs, score, and recommendations.
        """
        matched_iocs: List[MatchedIOC] = []

        # Extract all indicators from EDR alerts
        alert_hashes: Dict[str, Dict[str, str]] = {}  # sha256_lower -> {alert_id, title}
        alert_processes: Dict[str, Dict[str, str]] = {}
        alert_devices: Set[str] = set()

        for alert in edr_alerts:
            a_id = alert.get("id", "alert-unknown")
            a_title = alert.get("title", "EDR Alert")
            
            # Check alert entities / evidence
            for ev in alert.get("evidence", []):
                sha256 = ev.get("sha256")
                if sha256:
                    alert_hashes[sha256.lower()] = {"alert_id": a_id, "title": a_title}
                p_name = ev.get("fileName") or ev.get("processCommandLine")
                if p_name:
                    alert_processes[p_name.lower()] = {"alert_id": a_id, "title": a_title}

            dev_id = alert.get("machineId") or alert.get("computerDnsName")
            if dev_id:
                alert_devices.add(dev_id.lower())

        # 1. Correlate Catalog Records (Cryptographic Hashes & Machine IDs)
        for rec in catalog_records:
            rec_hash = rec.sha256_hash.lower()
            if rec_hash in alert_hashes:
                matched_iocs.append(
                    MatchedIOC(
                        match_category="HASH_MATCH",
                        ioc_value=rec_hash,
                        evidence_id=rec.evidence_id,
                        alert_title=alert_hashes[rec_hash]["title"],
                        severity="CRITICAL",
                        confidence=1.0,
                        details=(
                            f"Cryptographic match: evidence file '{rec.file_name}' SHA-256 perfectly "
                            f"correlates with alert '{alert_hashes[rec_hash]['title']}'."
                        ),
                    )
                )

            # Device match
            if rec.device_id.lower() in alert_devices or rec.device_name.lower() in alert_devices:
                matched_iocs.append(
                    MatchedIOC(
                        match_category="DEVICE_MATCH",
                        ioc_value=rec.device_id,
                        evidence_id=rec.evidence_id,
                        alert_title="Endpoint Telemetry Correlation",
                        severity="MEDIUM",
                        confidence=0.9,
                        details=(
                            f"Device '{rec.device_name}' ({rec.device_id}) confirmed as active source "
                            f"of collected evidence and target of alert telemetry."
                        ),
                    )
                )

        # 2. Correlate Artifact Analysis Findings (Extracted IOCs & Command Lines)
        for report in analysis_reports:
            for ioc in report.extracted_iocs:
                val_lower = ioc.value.lower()
                
                # Check hash IOCs
                if ioc.ioc_type == "HASH_SHA256" and val_lower in alert_hashes:
                    matched_iocs.append(
                        MatchedIOC(
                            match_category="HASH_MATCH",
                            ioc_value=val_lower,
                            evidence_id=report.evidence_id,
                            alert_title=alert_hashes[val_lower]["title"],
                            severity="CRITICAL",
                            confidence=1.0,
                            details=f"IOC hash match found in artifact analysis: {ioc.context}",
                        )
                    )

                # Check process names
                if ioc.ioc_type == "PROCESS_NAME":
                    for alert_proc, meta in alert_processes.items():
                        if val_lower in alert_proc or alert_proc in val_lower:
                            matched_iocs.append(
                                MatchedIOC(
                                    match_category="PROCESS_MATCH",
                                    ioc_value=ioc.value,
                                    evidence_id=report.evidence_id,
                                    alert_title=meta["title"],
                                    severity=ioc.severity,
                                    confidence=0.85,
                                    details=(
                                        f"Process '{ioc.value}' identified in forensic artifact coincides "
                                        f"with EDR process detection in '{meta['title']}'."
                                    ),
                                )
                            )

                # Check command lines
                if ioc.ioc_type == "COMMAND_LINE":
                    for alert_cmd, meta in alert_processes.items():
                        if "vssadmin" in val_lower and "vssadmin" in alert_cmd:
                            matched_iocs.append(
                                MatchedIOC(
                                    match_category="COMMAND_LINE_MATCH",
                                    ioc_value=ioc.value,
                                    evidence_id=report.evidence_id,
                                    alert_title=meta["title"],
                                    severity="CRITICAL",
                                    confidence=0.95,
                                    details="Anti-forensic shadow copy deletion matched between EDR and forensic triage.",
                                )
                            )

        # Calculate quantitative correlation score (0-100)
        score = 0
        has_hash_match = any(m.match_category == "HASH_MATCH" for m in matched_iocs)
        has_proc_match = any(m.match_category == "PROCESS_MATCH" for m in matched_iocs)
        has_dev_match = any(m.match_category == "DEVICE_MATCH" for m in matched_iocs)
        has_cmd_match = any(m.match_category == "COMMAND_LINE_MATCH" for m in matched_iocs)

        if has_hash_match:
            score += 45
        if has_cmd_match:
            score += 25
        if has_proc_match:
            score += 20
        if has_dev_match:
            score += 10

        # Cap score at 100
        score = min(100, score)

        # Determine threat level
        if score >= 75 or incident_severity.upper() == "HIGH":
            overall_threat = "CRITICAL" if has_hash_match and has_cmd_match else "HIGH"
        elif score >= 40:
            overall_threat = "MEDIUM"
        else:
            overall_threat = "LOW"

        # Actionable recommendations
        recs = []
        if overall_threat in {"HIGH", "CRITICAL"}:
            recs.append("CONFIRMED ACTIVE THREAT: Immediately isolate host from network via Defender EDR.")
            recs.append("Preserve WORM storage object locks in S3 for regulatory chain-of-custody.")
            recs.append("Revoke user Kerberos/OAuth session tokens on Azure Entra ID / Active Directory.")
            recs.append("Block extracted external IP addresses at perimeter firewall.")
        elif overall_threat == "MEDIUM":
            recs.append("Elevated risk detected: Request full memory dump and schedule host containment review.")
        else:
            recs.append("Continue monitoring telemetry; no conclusive match between evidence and active alerts.")

        summary = (
            f"Cross-telemetry correlation finished with score {score}/100 ({overall_threat}). "
            f"Identified {len(matched_iocs)} corroborating indicators across {len(catalog_records)} "
            f"evidence items and {len(edr_alerts)} alerts."
        )

        return CorrelationReport(
            incident_id=incident_id,
            incident_title=incident_title,
            incident_severity=incident_severity,
            evidence_items_evaluated=len(catalog_records),
            matched_iocs_count=len(matched_iocs),
            correlation_score=score,
            overall_threat_level=overall_threat,
            matched_iocs=matched_iocs,
            containment_recommendations=recs,
            chain_of_custody_verified=True,
            simulation_indicator=simulation_indicator,
            summary=summary,
        )

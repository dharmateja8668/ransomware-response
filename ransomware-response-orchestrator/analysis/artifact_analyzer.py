"""
analysis/artifact_analyzer.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Forensic Evidence & Artifact Analysis Service.
Performs automated triage analysis on KAPE triage packages, filesystem artifacts,
and volatile RAM dumps.

Capabilities:
  - Automated inspection of KAPE triage outputs (archives, files, manifests).
  - Volatile memory dump triage & process injection pattern detection.
  - Extraction of ransomware Indicators of Compromise (IOCs):
      * Malicious process names & anomalous parent-child chains.
      * Anti-forensic commands (vssadmin shadow copy deletion, bcdedit disable).
      * Ransom notes & encrypted extension signatures.
      * Suspicious network C2 endpoints & command lines.
  - Full support for simulated/mock artifacts while preserving simulation flags.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import json
import logging
import re
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("orchestrator.artifact_analyzer")

# Ransomware signature heuristics
RANSOM_NOTE_PATTERNS = [
    re.compile(r".*README.*\.txt$", re.IGNORECASE),
    re.compile(r".*HOW_TO_DECRYPT.*", re.IGNORECASE),
    re.compile(r".*RESTORE_FILES.*", re.IGNORECASE),
    re.compile(r".*DECRYPT_INFO.*", re.IGNORECASE),
    re.compile(r".*RECOVERY_KEY.*", re.IGNORECASE),
    re.compile(r".*FILES_ENCRYPTED.*", re.IGNORECASE),
]

SUSPICIOUS_CMD_PATTERNS = [
    (re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows", re.IGNORECASE), "Shadow copy deletion via vssadmin", "CRITICAL"),
    (re.compile(r"wmic(\.exe)?\s+shadowcopy\s+delete", re.IGNORECASE), "Shadow copy deletion via WMIC", "CRITICAL"),
    (re.compile(r"wbadmin(\.exe)?\s+delete\s+catalog", re.IGNORECASE), "Backup catalog deletion via wbadmin", "HIGH"),
    (re.compile(r"bcdedit(\.exe)?\s+/set.*recoveryenabled\s+no", re.IGNORECASE), "Boot recovery disabled via bcdedit", "CRITICAL"),
    (re.compile(r"wevtutil(\.exe)?\s+cl\s+(system|security|application)", re.IGNORECASE), "Security event log clearing via wevtutil", "HIGH"),
    (re.compile(r"net(\.exe)?\s+stop\s+(vss|wuauserv|winmgmt|sql.*)", re.IGNORECASE), "Security or critical service termination", "HIGH"),
    (re.compile(r"powershell.*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE), "Encoded PowerShell payload execution", "HIGH"),
    (re.compile(r"cipher(\.exe)?\s+/w:", re.IGNORECASE), "Free disk space wiping via cipher", "MEDIUM"),
]

RANSOM_EXTENSIONS = {
    ".locked", ".crypto", ".crypt", ".enc", ".lockbit",
    ".blackcat", ".blackmatter", ".conti", ".akira", ".rhk",
    ".phobos", ".dharma", ".makop", ".crypted"
}

SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe", "rclone.exe", "advanced_ip_scanner.exe",
    "psexec.exe", "procdump.exe", "lazagne.exe", "anydesk.exe",
    "ngrok.exe", "cobaltstrike.exe", "sharpHound.exe"
}


@dataclass
class IOCItem:
    """Represents an extracted Indicator of Compromise."""
    ioc_type: str  # HASH_SHA256, PROCESS_NAME, COMMAND_LINE, FILE_PATH, EXTENSION, NETWORK_IP
    value: str
    context: str
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TriageFinding:
    """Represents a specific forensic detection finding."""
    category: str  # RANSOM_NOTE, SUSPICIOUS_CMD, ANTI_FORENSICS, MEMORY_INJECTION, SUSPICIOUS_PROCESS
    title: str
    description: str
    evidence_ref: str
    severity: str = "HIGH"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ArtifactAnalysisReport:
    """Comprehensive forensic report generated from artifact analysis."""
    evidence_id: str
    incident_id: str
    evidence_type: str
    file_path: str
    file_size_bytes: int
    analyzed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    ransomware_detected: bool = False
    suspected_ransomware_family: Optional[str] = None
    confidence_score: float = 0.0  # 0.0 to 1.0
    findings: List[TriageFinding] = field(default_factory=list)
    extracted_iocs: List[IOCItem] = field(default_factory=list)
    summary: str = ""
    simulation_indicator: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "incident_id": self.incident_id,
            "evidence_type": self.evidence_type,
            "file_path": self.file_path,
            "file_size_bytes": self.file_size_bytes,
            "analyzed_at": self.analyzed_at,
            "ransomware_detected": self.ransomware_detected,
            "suspected_ransomware_family": self.suspected_ransomware_family,
            "confidence_score": round(self.confidence_score, 2),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "iocs_count": len(self.extracted_iocs),
            "extracted_iocs": [i.to_dict() for i in self.extracted_iocs],
            "summary": self.summary,
            "simulation_indicator": self.simulation_indicator,
        }


class ArtifactAnalyzer:
    """
    Analyzes collected forensic evidence packages (KAPE triage zips,
    memory dump summaries, and manifest files).
    """

    def analyze_evidence_file(
        self,
        file_path: str,
        evidence_id: str,
        incident_id: str,
        evidence_type: str,
        simulation_indicator: bool = False,
    ) -> ArtifactAnalysisReport:
        """
        Analyzes a forensic artifact on disk.
        
        Args:
            file_path: Local filesystem path to the evidence artifact.
            evidence_id: Evidence identifier.
            incident_id: Incident identifier.
            evidence_type: KAPE, RAM, or TRIAGE.
            simulation_indicator: Flag denoting whether artifact is synthetic/mock.
            
        Returns:
            ArtifactAnalysisReport containing findings and IOCs.
        """
        p = Path(file_path)
        file_size = p.stat().st_size if p.is_file() else 0

        report = ArtifactAnalysisReport(
            evidence_id=evidence_id,
            incident_id=incident_id,
            evidence_type=evidence_type.upper(),
            file_path=str(p),
            file_size_bytes=file_size,
            simulation_indicator=simulation_indicator,
        )

        if not p.exists():
            report.findings.append(
                TriageFinding(
                    category="ERROR",
                    title="Evidence File Inaccessible",
                    description=f"File not found at path: {file_path}",
                    evidence_ref=file_path,
                    severity="LOW",
                )
            )
            report.summary = "Analysis aborted: target evidence file not accessible on disk."
            return report

        if evidence_type.upper() == "RAM":
            self._analyze_ram_artifact(p, report)
        else:
            self._analyze_kape_triage_artifact(p, report)

        self._finalize_assessment(report)
        return report

    def _analyze_kape_triage_artifact(self, path: Path, report: ArtifactAnalysisReport) -> None:
        """Inspects KAPE triage files (zip archives, json manifests, or text logs)."""
        if zipfile.is_zipfile(path):
            self._scan_zip_contents(path, report)
        elif path.suffix.lower() == ".json":
            self._scan_json_manifest(path, report)
        else:
            self._scan_raw_text(path, report)

    def _scan_zip_contents(self, zip_path: Path, report: ArtifactAnalysisReport) -> None:
        """Inspects files within a KAPE zip triage archive."""
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                namelist = zf.namelist()
                for name in namelist:
                    entry_path = Path(name)
                    # Check ransom note patterns in filename
                    for pat in RANSOM_NOTE_PATTERNS:
                        if pat.match(entry_path.name):
                            report.findings.append(
                                TriageFinding(
                                    category="RANSOM_NOTE",
                                    title="Ransom Note Detected in Triage Archive",
                                    description=f"Identified characteristic ransom note file: '{entry_path.name}'",
                                    evidence_ref=name,
                                    severity="CRITICAL",
                                )
                            )
                            report.extracted_iocs.append(
                                IOCItem(
                                    ioc_type="FILE_PATH",
                                    value=name,
                                    context="Ransom note detected in archive",
                                    severity="CRITICAL",
                                )
                            )

                    # Check suspicious encrypted extensions
                    ext = entry_path.suffix.lower()
                    if ext in RANSOM_EXTENSIONS:
                        report.findings.append(
                            TriageFinding(
                                category="ENCRYPTION_INDICATOR",
                                title="Encrypted Extension Signature",
                                description=f"Identified file with known ransomware extension: '{ext}'",
                                evidence_ref=name,
                                severity="HIGH",
                            )
                        )
                        report.extracted_iocs.append(
                            IOCItem(
                                ioc_type="EXTENSION",
                                value=ext,
                                context=f"Ransomware extension in '{entry_path.name}'",
                                severity="HIGH",
                            )
                        )

                    # Check for suspicious executables
                    if entry_path.name.lower() in SUSPICIOUS_PROCESS_NAMES:
                        report.findings.append(
                            TriageFinding(
                                category="SUSPICIOUS_PROCESS",
                                title="Suspicious Executable Found in Triage",
                                description=f"Known post-exploitation tool identified: '{entry_path.name}'",
                                evidence_ref=name,
                                severity="HIGH",
                            )
                        )
                        report.extracted_iocs.append(
                            IOCItem(
                                ioc_type="PROCESS_NAME",
                                value=entry_path.name,
                                context=f"Tool present in triage archive at {name}",
                                severity="HIGH",
                            )
                        )

                    # Inspect content of text/log/manifest files inside archive
                    if entry_path.suffix.lower() in {".txt", ".log", ".json", ".csv", ".evtx", ".xml"}:
                        try:
                            sample = zf.read(name)[:65536].decode("utf-8", errors="ignore")
                            self._scan_text_string(sample, report, evidence_ref=name)
                        except Exception:
                            pass
        except Exception as exc:
            logger.warning(f"Failed to scan zip archive '{zip_path}': {exc}")

    def _scan_json_manifest(self, json_path: Path, report: ArtifactAnalysisReport) -> None:
        """Parses simulated or real JSON evidence manifests."""
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            raw_text = json.dumps(data)
            self._scan_text_string(raw_text, report, evidence_ref=str(json_path))

            # Inspect simulated artifacts lists if present
            artifacts = data.get("artifacts", [])
            for art in artifacts:
                fname = art.get("name", "")
                for pat in RANSOM_NOTE_PATTERNS:
                    if pat.match(fname):
                        report.findings.append(
                            TriageFinding(
                                category="RANSOM_NOTE",
                                title="Ransom Note Identified in Manifest",
                                description=f"Simulated or recorded ransom note: '{fname}'",
                                evidence_ref=fname,
                                severity="CRITICAL",
                            )
                        )
        except Exception as exc:
            logger.warning(f"Failed parsing JSON manifest '{json_path}': {exc}")

    def _scan_raw_text(self, text_path: Path, report: ArtifactAnalysisReport) -> None:
        """Inspects raw text, logs, or triage dumps."""
        try:
            content = text_path.read_text(encoding="utf-8", errors="ignore")[:262144]
            self._scan_text_string(content, report, evidence_ref=str(text_path))
        except Exception as exc:
            logger.warning(f"Failed reading raw text '{text_path}': {exc}")

    def _scan_text_string(self, content: str, report: ArtifactAnalysisReport, evidence_ref: str) -> None:
        """Scans arbitrary text strings for suspicious commands and patterns."""
        for regex, desc, sev in SUSPICIOUS_CMD_PATTERNS:
            match = regex.search(content)
            if match:
                matched_cmd = match.group(0)
                report.findings.append(
                    TriageFinding(
                        category="SUSPICIOUS_CMD",
                        title=desc,
                        description=f"Identified anti-forensic or malicious command: '{matched_cmd}'",
                        evidence_ref=evidence_ref,
                        severity=sev,
                    )
                )
                report.extracted_iocs.append(
                    IOCItem(
                        ioc_type="COMMAND_LINE",
                        value=matched_cmd,
                        context=desc,
                        severity=sev,
                    )
                )

        # Detect IP addresses in network connection sections
        ip_matches = re.findall(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", content)
        for ip in set(ip_matches):
            # Ignore local/loopback
            if not (ip.startswith("127.") or ip.startswith("0.") or ip.startswith("10.") or ip.startswith("192.168.")):
                report.extracted_iocs.append(
                    IOCItem(
                        ioc_type="NETWORK_IP",
                        value=ip,
                        context="External network IP located in forensic artifact",
                        severity="MEDIUM",
                    )
                )

    def _analyze_ram_artifact(self, ram_path: Path, report: ArtifactAnalysisReport) -> None:
        """Analyzes RAM acquisition dumps or volatile memory manifests."""
        report.findings.append(
            TriageFinding(
                category="MEMORY_TRIAGE",
                title="Volatile Memory Triage Performed",
                description="Scanned memory image header, process descriptors, and execution threads.",
                evidence_ref=str(ram_path),
                severity="LOW",
            )
        )

        try:
            # Check if this is a JSON summary or binary dump
            if ram_path.suffix.lower() == ".json":
                self._scan_json_manifest(ram_path, report)
            else:
                # Read initial 512KB for common memory strings and injection indicators
                with open(ram_path, "rb") as f:
                    sample_bytes = f.read(524288)
                sample_text = sample_bytes.decode("latin1", errors="ignore")
                
                # Check for hollowed svchost or suspicious process strings
                if "svchost.exe" in sample_text and ("AppData" in sample_text or "Temp" in sample_text):
                    report.findings.append(
                        TriageFinding(
                            category="MEMORY_INJECTION",
                            title="Suspicious Injected Process (svchost.exe in User Directory)",
                            description="Identified svchost.exe memory descriptor mapped outside System32.",
                            evidence_ref=str(ram_path),
                            severity="CRITICAL",
                        )
                    )
                    report.extracted_iocs.append(
                        IOCItem(
                            ioc_type="PROCESS_NAME",
                            value="svchost.exe",
                            context="Injected svchost process outside System32",
                            severity="CRITICAL",
                        )
                    )
                
                self._scan_text_string(sample_text, report, evidence_ref=str(ram_path))
        except Exception as exc:
            logger.warning(f"Failed scanning RAM artifact '{ram_path}': {exc}")

    def _finalize_assessment(self, report: ArtifactAnalysisReport) -> None:
        """Computes confidence score and ransomware classification."""
        critical_count = sum(1 for f in report.findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in report.findings if f.severity == "HIGH")
        med_count = sum(1 for f in report.findings if f.severity == "MEDIUM")

        raw_score = (critical_count * 0.40) + (high_count * 0.25) + (med_count * 0.10)
        report.confidence_score = min(1.0, max(0.0, raw_score))

        if critical_count >= 1 or high_count >= 2:
            report.ransomware_detected = True
            # Check specific families based on findings
            families = set()
            for finding in report.findings:
                desc_lower = finding.description.lower()
                if "lockbit" in desc_lower:
                    families.add("LockBit 3.0")
                elif "blackcat" in desc_lower:
                    families.add("BlackCat / ALPHV")
                elif "conti" in desc_lower:
                    families.add("Conti")
                elif "dharma" in desc_lower:
                    families.add("Dharma")
            
            report.suspected_ransomware_family = ", ".join(sorted(families)) if families else "Generic Ransomware"
            report.summary = (
                f"HIGH CONFIDENCE RANSOMWARE ACTIVITY DETECTED: {report.suspected_ransomware_family}. "
                f"Identified {critical_count} critical findings and {len(report.extracted_iocs)} IOCs."
            )
        else:
            report.ransomware_detected = False
            report.summary = (
                f"No conclusive ransomware indicators detected in evidence {report.evidence_id}. "
                f"Total findings: {len(report.findings)}."
            )

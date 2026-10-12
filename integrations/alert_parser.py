# integrations/alert_parser.py
"""
Alert parsing and enrichment module for incoming security detections.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Day     : 5 -- Alert Parsing and Enrichment

PURPOSE
-------
Provides safe parsing, structural validation, normalization, and safe
telemetry enrichment for incoming security alerts before they are stored
as incidents or forwarded for orchestration.

FEATURES
--------
- Field validation: Verifies required fields (alert_id, threat_type, severity, description, timestamp).
- Severity normalization: Maps string levels ("critical", "high", "medium", "low", "informational")
  or numeric values (1 to 5) into a consistent integer scale (1 = lowest, 5 = critical).
- Timestamp normalization: Standardizes diverse timestamp formats into standard ISO 8601 UTC strings.
- Telemetry normalization: Cleans and trims hostnames, IP addresses, usernames, and hashes without inventing data.
- Enriched telemetry attributes: Computes safe derived metadata (e.g., severity label, is_ransomware flag).
- Non-destructive: Does NOT execute suspicious processes or make external network calls.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Dict, Optional, Union


class AlertParsingError(ValueError):
    """Raised when an incoming alert payload is invalid, malformed, or missing required fields."""


# Mapping textual severity ratings to integer scale 1-5
SEVERITY_TEXT_MAP = {
    "critical": 5,
    "crit": 5,
    "high": 4,
    "medium": 3,
    "med": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
}

# Reverse mapping for human-readable labels
SEVERITY_LABEL_MAP = {
    5: "CRITICAL",
    4: "HIGH",
    3: "MEDIUM",
    2: "LOW",
    1: "INFORMATIONAL",
}


def normalize_severity(severity: Union[int, float, str]) -> int:
    """
    Normalizes severity input into an integer between 1 and 5.
    Accepts integers (1-5), string representations ("5"), or string levels ("high", "critical", etc.).
    """
    if severity is None:
        raise AlertParsingError("Field 'severity' cannot be null or empty.")

    if isinstance(severity, (int, float)):
        val = int(severity)
        if 1 <= val <= 5:
            return val
        raise AlertParsingError(f"Numeric severity '{severity}' out of valid range (1 to 5).")

    if isinstance(severity, str):
        clean = severity.strip().lower()
        if clean.isdigit():
            val = int(clean)
            if 1 <= val <= 5:
                return val
            raise AlertParsingError(f"Numeric severity string '{severity}' out of valid range (1 to 5).")
        if clean in SEVERITY_TEXT_MAP:
            return SEVERITY_TEXT_MAP[clean]
        raise AlertParsingError(f"Unrecognized severity string '{severity}'. Allowed: 1-5 or Critical/High/Medium/Low/Informational.")

    raise AlertParsingError(f"Invalid severity type '{type(severity).__name__}'.")


def normalize_timestamp(timestamp_str: str) -> str:
    """
    Validates and standardizes a timestamp into an ISO 8601 UTC string (YYYY-MM-DDTHH:MM:SSZ).
    Handles ISO 8601 formats, trailing 'Z', offsets, and common space-separated timestamps.
    """
    if not timestamp_str or not isinstance(timestamp_str, str) or not timestamp_str.strip():
        raise AlertParsingError("Field 'timestamp' cannot be empty.")

    clean_ts = timestamp_str.strip()

    # Attempt parsing with datetime.fromisoformat
    try:
        # Standard fromisoformat in Python 3.11+ handles 'Z' and offsets
        dt = datetime.fromisoformat(clean_ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        # Format as standard ISO UTC
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Common alternate formats
    fallback_formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y/%m/%d %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
    ]
    for fmt in fallback_formats:
        try:
            dt = datetime.strptime(clean_ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue

    raise AlertParsingError(f"Timestamp '{timestamp_str}' cannot be parsed into a valid ISO 8601 timestamp.")


def _clean_optional_string(val: Optional[Any]) -> Optional[str]:
    """Cleans optional string attributes; empty strings or whitespace become None."""
    if val is None:
        return None
    s = str(val).strip()
    return s if s else None


def _clean_hash(val: Optional[Any]) -> Optional[str]:
    """Cleans process/file hash, standardizing to lowercase if alphanumeric."""
    h = _clean_optional_string(val)
    if not h:
        return None
    # Normalize alphanumeric hashes (MD5, SHA1, SHA256) to lowercase
    if re.fullmatch(r"[A-Fa-f0-9]+", h):
        return h.lower()
    return h


@dataclass
class ParsedAlert:
    """Represents a validated, normalized, and enriched security alert."""
    alert_id: str
    threat_type: str
    severity: int
    description: str
    timestamp: str
    hostname: Optional[str]
    ip_address: Optional[str]
    username: Optional[str]
    process_hash: Optional[str]
    # Enriched fields
    severity_label: str
    is_ransomware: bool
    raw_payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Converts parsed alert fields to dictionary matching Incident model attributes."""
        return {
            "alert_id": self.alert_id,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "description": self.description,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "username": self.username,
            "process_hash": self.process_hash,
            "severity_label": self.severity_label,
            "is_ransomware": self.is_ransomware,
        }


def parse_and_enrich_alert(raw_data: Union[Dict[str, Any], Any]) -> ParsedAlert:
    """
    Parses, validates, normalizes, and enriches an incoming alert dictionary or object.

    Parameters:
      raw_data: Dictionary or object with alert fields.

    Returns:
      ParsedAlert: Normalized alert instance.

    Raises:
      AlertParsingError: If any required field is missing or invalid.
    """
    if not isinstance(raw_data, dict):
        if hasattr(raw_data, "model_dump"):
            data = raw_data.model_dump()
        elif hasattr(raw_data, "dict"):
            data = raw_data.dict()
        elif hasattr(raw_data, "__dict__"):
            data = vars(raw_data)
        else:
            raise AlertParsingError("Alert payload must be a dictionary or structured object.")
    else:
        data = dict(raw_data)

    # 1. Validate required fields
    required_fields = ["alert_id", "threat_type", "severity", "description", "timestamp"]
    for field in required_fields:
        if field not in data or data[field] is None:
            raise AlertParsingError(f"Missing required alert field: '{field}'.")

    # 2. Normalize required strings
    alert_id = str(data["alert_id"]).strip()
    if not alert_id:
        raise AlertParsingError("Field 'alert_id' cannot be blank.")

    threat_type = str(data["threat_type"]).strip().lower()
    if not threat_type:
        raise AlertParsingError("Field 'threat_type' cannot be blank.")

    description = str(data["description"]).strip()
    if not description:
        raise AlertParsingError("Field 'description' cannot be blank.")

    # 3. Normalize severity and timestamp
    norm_severity = normalize_severity(data["severity"])
    norm_timestamp = normalize_timestamp(str(data["timestamp"]))

    # 4. Clean optional telemetry fields
    hostname = _clean_optional_string(data.get("hostname"))
    ip_address = _clean_optional_string(data.get("ip_address"))
    username = _clean_optional_string(data.get("username"))
    process_hash = _clean_hash(data.get("process_hash"))

    # 5. Enrichment derivations (safe, no external calls)
    severity_label = SEVERITY_LABEL_MAP.get(norm_severity, "UNKNOWN")
    is_ransomware = (
        "ransomware" in threat_type
        or "ransom" in description.lower()
        or "encrypt" in description.lower()
    )

    return ParsedAlert(
        alert_id=alert_id,
        threat_type=threat_type,
        severity=norm_severity,
        description=description,
        timestamp=norm_timestamp,
        hostname=hostname,
        ip_address=ip_address,
        username=username,
        process_hash=process_hash,
        severity_label=severity_label,
        is_ransomware=is_ransomware,
        raw_payload=data,
    )

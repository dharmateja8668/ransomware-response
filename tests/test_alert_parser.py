# tests/test_alert_parser.py
"""
Unit tests for alert parsing, normalization, and enrichment.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Day     : 5 -- Alert Parsing and Enrichment Tests

Scenarios covered:
  1. Valid standard alert parsing with all fields populated.
  2. Parsing with optional fields omitted or null.
  3. Severity normalization: string text ('critical', 'high', etc.) and numeric ranges.
  4. Rejecting invalid or out-of-range severity values.
  5. Timestamp normalization: ISO with 'Z', ISO with offset, and fallback date formats.
  6. Rejecting invalid or unparseable timestamps.
  7. Missing required fields (alert_id, threat_type, severity, description, timestamp).
  8. Blank required strings are rejected.
  9. Telemetry cleaning (whitespace stripping, lowercase hash normalization).
  10. Ransomware detection enrichment flag logic.
"""

import pytest

from integrations.alert_parser import (
    AlertParsingError,
    ParsedAlert,
    normalize_severity,
    normalize_timestamp,
    parse_and_enrich_alert,
)


def test_valid_alert_full_telemetry():
    """Valid alert with complete telemetry parses and enriches accurately."""
    payload = {
        "alert_id": "ALERT-PARSE-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Mass volume encryption with known ransomware note detected",
        "timestamp": "2026-10-12T14:30:00Z",
        "hostname": "  SRV-FINANCE-01  ",
        "ip_address": " 10.0.1.50 ",
        "username": " admin_ops ",
        "process_hash": "A1B2C3D4E5F67890123456789ABCDEF0 ",
    }
    parsed = parse_and_enrich_alert(payload)

    assert isinstance(parsed, ParsedAlert)
    assert parsed.alert_id == "ALERT-PARSE-001"
    assert parsed.threat_type == "ransomware"
    assert parsed.severity == 5
    assert parsed.severity_label == "CRITICAL"
    assert parsed.timestamp == "2026-10-12T14:30:00Z"
    assert parsed.hostname == "SRV-FINANCE-01"
    assert parsed.ip_address == "10.0.1.50"
    assert parsed.username == "admin_ops"
    assert parsed.process_hash == "a1b2c3d4e5f67890123456789abcdef0"  # normalized to lowercase
    assert parsed.is_ransomware is True


def test_valid_alert_optional_fields_omitted():
    """Alert parsing handles missing or None optional contextual fields gracefully."""
    payload = {
        "alert_id": "ALERT-PARSE-MIN",
        "threat_type": "trojan",
        "severity": 3,
        "description": "Trojan dropper detected",
        "timestamp": "2026-10-12T10:00:00+00:00",
    }
    parsed = parse_and_enrich_alert(payload)

    assert parsed.alert_id == "ALERT-PARSE-MIN"
    assert parsed.hostname is None
    assert parsed.ip_address is None
    assert parsed.username is None
    assert parsed.process_hash is None
    assert parsed.severity_label == "MEDIUM"
    assert parsed.is_ransomware is False


@pytest.mark.parametrize(
    "raw_sev,expected_sev,expected_label",
    [
        (5, 5, "CRITICAL"),
        (4, 4, "HIGH"),
        (3, 3, "MEDIUM"),
        (2, 2, "LOW"),
        (1, 1, "INFORMATIONAL"),
        ("5", 5, "CRITICAL"),
        ("critical", 5, "CRITICAL"),
        ("High", 4, "HIGH"),
        ("medium", 3, "MEDIUM"),
        ("low", 2, "LOW"),
        ("informational", 1, "INFORMATIONAL"),
        ("info", 1, "INFORMATIONAL"),
    ],
)
def test_severity_normalization_valid(raw_sev, expected_sev, expected_label):
    """Various severity formats are safely normalized into 1-5 scale."""
    val = normalize_severity(raw_sev)
    assert val == expected_sev


@pytest.mark.parametrize(
    "bad_sev",
    [0, 6, -1, 10, "extreme", "unknown", "", None, [1]],
)
def test_severity_normalization_invalid(bad_sev):
    """Invalid severity inputs raise AlertParsingError."""
    with pytest.raises(AlertParsingError):
        normalize_severity(bad_sev)


@pytest.mark.parametrize(
    "raw_ts,expected_ts",
    [
        ("2026-10-12T15:00:00Z", "2026-10-12T15:00:00Z"),
        ("2026-10-12T15:00:00+00:00", "2026-10-12T15:00:00Z"),
        ("2026-10-12T17:00:00+02:00", "2026-10-12T15:00:00Z"),  # offset converted to UTC
        ("2026-10-12 15:00:00", "2026-10-12T15:00:00Z"),
    ],
)
def test_timestamp_normalization_valid(raw_ts, expected_ts):
    """Timestamps are normalized into standardized ISO 8601 UTC format."""
    normalized = normalize_timestamp(raw_ts)
    assert normalized == expected_ts


@pytest.mark.parametrize(
    "bad_ts",
    ["not-a-timestamp", "2026-99-99", "", "   ", None],
)
def test_timestamp_normalization_invalid(bad_ts):
    """Malformed or invalid timestamps raise AlertParsingError."""
    with pytest.raises(AlertParsingError):
        normalize_timestamp(bad_ts)


@pytest.mark.parametrize(
    "missing_field",
    ["alert_id", "threat_type", "severity", "description", "timestamp"],
)
def test_missing_required_fields_rejected(missing_field):
    """Missing any core alert field raises AlertParsingError."""
    payload = {
        "alert_id": "test-id",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "test desc",
        "timestamp": "2026-10-12T10:00:00Z",
    }
    del payload[missing_field]
    with pytest.raises(AlertParsingError, match=f"Missing required alert field: '{missing_field}'"):
        parse_and_enrich_alert(payload)


def test_blank_required_strings_rejected():
    """Blank or whitespace-only required strings are rejected."""
    payload = {
        "alert_id": "   ",
        "threat_type": "ransomware",
        "severity": 4,
        "description": "test",
        "timestamp": "2026-10-12T10:00:00Z",
    }
    with pytest.raises(AlertParsingError, match="Field 'alert_id' cannot be blank."):
        parse_and_enrich_alert(payload)


def test_ransomware_enrichment_flag():
    """Verifies that ransomware detection heuristic sets is_ransomware accurately."""
    # Matched by threat_type
    p1 = parse_and_enrich_alert({
        "alert_id": "a-1",
        "threat_type": "ransomware_variant_a",
        "severity": 4,
        "description": "Suspicious script",
        "timestamp": "2026-10-12T10:00:00Z",
    })
    assert p1.is_ransomware is True

    # Matched by description
    p2 = parse_and_enrich_alert({
        "alert_id": "a-2",
        "threat_type": "malware",
        "severity": 4,
        "description": "Process attempting mass file encrypt operations",
        "timestamp": "2026-10-12T10:00:00Z",
    })
    assert p2.is_ransomware is True

    # Benign / non-ransomware threat
    p3 = parse_and_enrich_alert({
        "alert_id": "a-3",
        "threat_type": "adware",
        "severity": 1,
        "description": "Browser extension popup",
        "timestamp": "2026-10-12T10:00:00Z",
    })
    assert p3.is_ransomware is False

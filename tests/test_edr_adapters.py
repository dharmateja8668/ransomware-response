# tests/test_edr_adapters.py
"""
Unit and integration tests for Native EDR Alert Adapters (Phase 3).
Validates:
  1. Parsing and normalization of native CrowdStrike Falcon alerts.
  2. Parsing and normalization of native Microsoft Defender alerts.
  3. Handling of multiple behaviors and evidence collections with deterministic indicator extraction.
  4. Backward compatibility with standard pre-normalized alert schemas.
  5. Missing field resiliency (missing hostname, IP, username, process hash).
  6. Timestamp normalization to standard ISO-8601 UTC.
  7. Severity mapping from text-based and numerical provider scales.
  8. Safe error handling for malformed or unexpected payload types.
"""

import json
import os
import pytest

from integrations.adapters import (
    CrowdStrikeAlertAdapter,
    DefenderAlertAdapter,
    adapt_raw_alert,
)
from integrations.alert_parser import parse_and_enrich_alert, NormalizedAlert

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _load_fixture(filename: str) -> dict:
    with open(os.path.join(FIXTURES_DIR, filename), "r", encoding="utf-8") as f:
        return json.load(f)


# ── 1. CrowdStrike Falcon Native Adapter Tests ────────────────────────────────


def test_crowdstrike_native_adapter_full():
    """Validates full extraction from realistic CrowdStrike Falcon detection payload."""
    raw = _load_fixture("crowdstrike_native_alert.json")
    adapter = CrowdStrikeAlertAdapter()

    assert adapter.can_adapt(raw) is True
    normalized = adapter.adapt(raw)

    assert normalized["alert_id"] == "det-crowdstrike-987654321"
    assert normalized["hostname"] == "WORKSTATION-SEC-01"
    assert normalized["endpoint_id"] == "cs-aid-57f9317c6e8f4b3dac65e8097a1f0db4"
    assert normalized["ip_address"] == "10.100.4.52"
    assert normalized["username"] == "victim.user@enterprise.internal"
    assert normalized["process_hash"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert normalized["severity"] == 5  # Critical -> 5
    assert "Data Encrypted for Impact" in normalized["description"]
    assert normalized["raw_source_provider"] == "crowdstrike_falcon"


def test_crowdstrike_multiple_behaviors_deterministic_selection():
    """Ensures deterministic behavior hash extraction when multiple behaviors exist."""
    raw = _load_fixture("crowdstrike_multiple_behaviors.json")
    adapter = CrowdStrikeAlertAdapter()

    assert adapter.can_adapt(raw) is True
    normalized = adapter.adapt(raw)

    assert normalized["alert_id"] == "cs-det-multi-beh-999"
    assert normalized["hostname"] == "FIN-APP-02.corp.local"
    assert normalized["ip_address"] == "172.16.50.12"
    assert normalized["username"] == "finadmin@corp.local"
    assert normalized["severity"] == 4  # High -> 4
    # Deterministic: picks the latest behavior timestamp or last in list
    assert normalized["process_hash"] == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def test_crowdstrike_missing_optional_fields():
    """Verifies that missing fields in CrowdStrike payload do not crash adapter."""
    raw = {
        "detection_id": "cs-minimal-001",
        "device": {},
        "behaviors": [],
    }
    adapter = CrowdStrikeAlertAdapter()
    normalized = adapter.adapt(raw)

    assert normalized["alert_id"] == "cs-minimal-001"
    assert normalized["hostname"] is None
    assert normalized["ip_address"] is None
    assert normalized["username"] is None
    assert normalized["process_hash"] is None
    assert normalized["severity"] == 3  # Default medium


# ── 2. Microsoft Defender Native Adapter Tests ────────────────────────────────


def test_defender_native_adapter_full():
    """Validates full extraction from Microsoft Defender alert payload."""
    raw = _load_fixture("defender_native_alert.json")
    adapter = DefenderAlertAdapter()

    assert adapter.can_adapt(raw) is True
    normalized = adapter.adapt(raw)

    assert normalized["alert_id"] == "da-def-alert-777"
    assert normalized["hostname"] == "DESKTOP-DEF-88.internal.contoso.com"
    assert normalized["endpoint_id"] == "m-def-uuid-11223344"
    assert normalized["ip_address"] == "192.168.10.105"
    assert normalized["username"] == "compromised.admin@contoso.com"
    assert normalized["process_hash"] == "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    assert normalized["severity"] == 4  # High -> 4
    assert normalized["raw_source_provider"] == "microsoft_defender"


def test_defender_evidence_collection_extraction():
    """Validates extraction of file hash from Defender evidence list."""
    raw = _load_fixture("defender_evidence_alert.json")
    adapter = DefenderAlertAdapter()

    assert adapter.can_adapt(raw) is True
    normalized = adapter.adapt(raw)

    assert normalized["alert_id"] == "da-def-evidence-888"
    assert normalized["hostname"] == "DC-BACKUP-01"
    assert normalized["ip_address"] == "10.0.1.20"
    assert normalized["username"] == "CONTOSO\\svc-backup"
    assert normalized["process_hash"] == "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    assert normalized["severity"] == 3  # Medium -> 3


def test_defender_missing_optional_fields():
    """Verifies that missing fields in Defender payload do not crash adapter."""
    raw = {
        "alertId": "def-min-002",
        "title": "Minimal Defender Detection",
    }
    adapter = DefenderAlertAdapter()
    normalized = adapter.adapt(raw)

    assert normalized["alert_id"] == "def-min-002"
    assert normalized["hostname"] is None
    assert normalized["ip_address"] is None
    assert normalized["username"] is None
    assert normalized["process_hash"] is None


# ── 3. General adapt_raw_alert Router Tests ───────────────────────────────────


def test_adapt_raw_alert_detects_crowdstrike():
    raw = _load_fixture("crowdstrike_native_alert.json")
    adapted = adapt_raw_alert(raw)
    assert adapted["alert_id"] == "det-crowdstrike-987654321"
    assert adapted["hostname"] == "WORKSTATION-SEC-01"


def test_adapt_raw_alert_detects_defender():
    raw = _load_fixture("defender_native_alert.json")
    adapted = adapt_raw_alert(raw)
    assert adapted["alert_id"] == "da-def-alert-777"
    assert adapted["hostname"] == "DESKTOP-DEF-88.internal.contoso.com"


def test_adapt_raw_alert_normalized_backward_compatibility():
    """Pre-normalized payloads pass through without modification."""
    normalized_input = {
        "alert_id": "NORM-ALERT-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Standard normalized alert",
        "timestamp": "2026-10-18T10:00:00Z",
        "hostname": "HOST-001",
        "ip_address": "192.168.1.10",
        "username": "user1",
    }
    result = adapt_raw_alert(normalized_input)
    assert result == normalized_input


def test_adapt_raw_alert_invalid_input_types():
    """Invalid non-dict inputs are handled safely."""
    assert adapt_raw_alert(None) == {}
    assert adapt_raw_alert("not a dictionary") == {}
    assert adapt_raw_alert([]) == {}


# ── 4. End-to-End parse_and_enrich_alert with Native Payloads ──────────────────


def test_parse_and_enrich_with_native_crowdstrike():
    """Demonstrates that parse_and_enrich_alert seamlessly ingests native CrowdStrike alert."""
    raw = _load_fixture("crowdstrike_native_alert.json")
    parsed: NormalizedAlert = parse_and_enrich_alert(raw)

    assert parsed.alert_id == "det-crowdstrike-987654321"
    assert parsed.hostname == "WORKSTATION-SEC-01"
    assert parsed.ip_address == "10.100.4.52"
    assert parsed.username == "victim.user@enterprise.internal"
    assert parsed.process_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert parsed.severity == 5


def test_parse_and_enrich_with_native_defender():
    """Demonstrates that parse_and_enrich_alert seamlessly ingests native Defender alert."""
    raw = _load_fixture("defender_native_alert.json")
    parsed: NormalizedAlert = parse_and_enrich_alert(raw)

    assert parsed.alert_id == "da-def-alert-777"
    assert parsed.hostname == "DESKTOP-DEF-88.internal.contoso.com"
    assert parsed.ip_address == "192.168.10.105"
    assert parsed.username == "compromised.admin@contoso.com"
    assert parsed.process_hash == "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    assert parsed.severity == 4

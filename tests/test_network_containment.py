# tests/test_network_containment.py
"""
Unit tests for the Network Containment Decision Logic.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Week    : 2
Day     : 1 -- Network Containment Decision Logic Tests

Test Coverage:
  1. Critical ransomware alert produces containment recommendation.
  2. Critical hands-on-keyboard alert produces containment recommendation.
  3. High-severity alert with policy disabled does not recommend containment.
  4. Medium-severity alert does not recommend automatic containment.
  5. Low-severity alert does not recommend automatic containment.
  6. Missing alert ID triggers validation error and safe rejection.
  7. Missing hostname and endpoint ID triggers validation error and safe rejection.
  8. Invalid severity rating triggers validation error and safe rejection.
  9. Empty alert input triggers validation error and safe rejection.
  10. Malformed alert data triggers validation error and safe rejection.
  11. High-severity suspicious activity with policy enabled recommends containment.
  12. Endpoint identification with hostname only is valid.
  13. Endpoint identification with endpoint_id only is valid.
  14. Support for structured object and Pydantic model payloads.
  15. Permissive custom policy for medium/low severity containment.
  16. Evaluation with raise_on_invalid=True raises ContainmentValidationError.
  17. Safe logging verification without secret exposure.
  18. Verification that structured decision contains all required fields.
"""

import logging
import pytest

from containment.network_containment import (
    DECISION_CONTAINMENT_NOT_RECOMMENDED,
    DECISION_CONTAINMENT_RECOMMENDED,
    DECISION_CONTAINMENT_REJECTED,
    ContainmentDecision,
    ContainmentPolicy,
    ContainmentValidationError,
    build_containment_decision,
    evaluate_containment,
    evaluate_policy,
    validate_alert,
)
from main import Alert


@pytest.fixture
def sample_critical_ransomware_alert():
    """Standard valid critical ransomware alert from Day 1 specification."""
    return {
        "alert_id": "ALERT-1001",
        "severity": "critical",
        "alert_type": "ransomware",
        "hostname": "LAB-WINDOWS-01",
        "endpoint_id": "ENDPOINT-001",
        "ip_address": "192.168.56.101",
        "username": "lab_user",
        "timestamp": "2026-10-16T10:30:00Z",
    }


# ── Test 1: Critical Ransomware Alert ─────────────────────────────────────────


def test_critical_ransomware_alert_recommends_containment(sample_critical_ransomware_alert):
    """Critical ransomware alert must trigger a containment recommendation."""
    decision = evaluate_containment(sample_critical_ransomware_alert, dry_run=True)

    assert isinstance(decision, dict)
    assert decision["alert_id"] == "ALERT-1001"
    assert decision["endpoint_id"] == "ENDPOINT-001"
    assert decision["hostname"] == "LAB-WINDOWS-01"
    assert decision["containment_recommended"] is True
    assert decision["decision"] == DECISION_CONTAINMENT_RECOMMENDED
    assert "Critical ransomware alert meets the configured containment policy." in decision["reason"]
    assert decision["timestamp"] == "2026-10-16T10:30:00Z"

    # Verify exact required schema keys
    expected_keys = {
        "alert_id",
        "endpoint_id",
        "hostname",
        "containment_recommended",
        "decision",
        "reason",
        "timestamp",
    }
    assert set(decision.keys()) == expected_keys


# ── Test 2: Critical Hands-On-Keyboard Alert ──────────────────────────────────


@pytest.mark.parametrize("alert_type_variant", ["hands-on-keyboard", "hands_on_keyboard", "hands on keyboard"])
def test_critical_hands_on_keyboard_alert_recommends_containment(alert_type_variant):
    """Critical hands-on-keyboard alert must trigger containment recommendation across variant spellings."""
    alert = {
        "alert_id": "ALERT-1002",
        "severity": 5,
        "alert_type": alert_type_variant,
        "hostname": "LAB-SRV-01",
        "endpoint_id": "ENDPOINT-002",
        "timestamp": "2026-10-16T10:35:00Z",
    }
    decision = evaluate_containment(alert, dry_run=True)

    assert decision["alert_id"] == "ALERT-1002"
    assert decision["containment_recommended"] is True
    assert decision["decision"] == DECISION_CONTAINMENT_RECOMMENDED
    assert "hands-on-keyboard" in decision["reason"].lower()


# ── Test 3: High-Severity Alert with Policy Disabled ──────────────────────────


def test_high_severity_alert_with_policy_disabled():
    """High-severity suspicious activity must not recommend containment when policy is disabled (default)."""
    alert = {
        "alert_id": "ALERT-1003",
        "severity": "high",
        "alert_type": "suspicious_activity",
        "hostname": "LAB-WINDOWS-03",
        "endpoint_id": "ENDPOINT-003",
        "timestamp": "2026-10-16T10:40:00Z",
    }
    # Default policy has contain_high_suspicious_activity = False
    policy = ContainmentPolicy(contain_high_suspicious_activity=False)
    decision = evaluate_containment(alert, policy=policy, dry_run=True)

    assert decision["alert_id"] == "ALERT-1003"
    assert decision["containment_recommended"] is False
    assert decision["decision"] == DECISION_CONTAINMENT_NOT_RECOMMENDED
    assert "disabled" in decision["reason"].lower()


# ── Test 4: Medium-Severity Alert ─────────────────────────────────────────────


def test_medium_severity_alert_not_recommended():
    """Medium-severity alert must not trigger automatic containment under the default policy."""
    alert = {
        "alert_id": "ALERT-1004",
        "severity": "medium",
        "alert_type": "suspicious_activity",
        "hostname": "LAB-WINDOWS-04",
        "endpoint_id": "ENDPOINT-004",
        "timestamp": "2026-10-16T10:45:00Z",
    }
    decision = evaluate_containment(alert, dry_run=True)

    assert decision["alert_id"] == "ALERT-1004"
    assert decision["containment_recommended"] is False
    assert decision["decision"] == DECISION_CONTAINMENT_NOT_RECOMMENDED
    assert "does not meet the minimum threshold" in decision["reason"]


# ── Test 5: Low-Severity Alert ────────────────────────────────────────────────


@pytest.mark.parametrize("low_severity", ["low", "informational", 2, 1])
def test_low_severity_alert_not_recommended(low_severity):
    """Low-severity and informational alerts must not trigger automatic containment."""
    alert = {
        "alert_id": "ALERT-1005",
        "severity": low_severity,
        "alert_type": "port_scan",
        "hostname": "LAB-WINDOWS-05",
        "endpoint_id": "ENDPOINT-005",
        "timestamp": "2026-10-16T10:50:00Z",
    }
    decision = evaluate_containment(alert, dry_run=True)

    assert decision["alert_id"] == "ALERT-1005"
    assert decision["containment_recommended"] is False
    assert decision["decision"] == DECISION_CONTAINMENT_NOT_RECOMMENDED


# ── Test 6: Missing Alert ID ──────────────────────────────────────────────────


@pytest.mark.parametrize("bad_id", [None, "", "   "])
def test_missing_alert_id_validation_and_decision(bad_id):
    """Missing or empty alert_id must fail validation and be safely rejected."""
    payload = {
        "alert_id": bad_id,
        "severity": "critical",
        "alert_type": "ransomware",
        "hostname": "LAB-WINDOWS-01",
    }

    # Direct validation check
    with pytest.raises(ContainmentValidationError, match="alert_id"):
        validate_alert(payload)

    # Safe evaluation rejection
    decision = evaluate_containment(payload, raise_on_invalid=False)
    assert decision["containment_recommended"] is False
    assert decision["decision"] == DECISION_CONTAINMENT_REJECTED
    assert "alert_id" in decision["reason"].lower()


# ── Test 7: Missing Hostname and Endpoint ID ──────────────────────────────────


def test_missing_hostname_and_endpoint_id_validation_and_decision():
    """An alert lacking both hostname and endpoint_id must fail validation and be rejected."""
    payload = {
        "alert_id": "ALERT-1007",
        "severity": "critical",
        "alert_type": "ransomware",
        # Neither hostname nor endpoint_id provided
        "ip_address": "192.168.1.50",
    }

    with pytest.raises(ContainmentValidationError, match="Endpoint identification missing"):
        validate_alert(payload)

    decision = evaluate_containment(payload, raise_on_invalid=False)
    assert decision["alert_id"] == "ALERT-1007"
    assert decision["containment_recommended"] is False
    assert decision["decision"] == DECISION_CONTAINMENT_REJECTED
    assert "endpoint identification missing" in decision["reason"].lower()


# ── Test 8: Invalid Severity ──────────────────────────────────────────────────


@pytest.mark.parametrize("invalid_sev", ["catastrophic", "unknown", 0, 6, -1, 999])
def test_invalid_severity_validation_and_decision(invalid_sev):
    """Unrecognized or out-of-range severity must fail validation and be rejected."""
    payload = {
        "alert_id": "ALERT-1008",
        "severity": invalid_sev,
        "alert_type": "ransomware",
        "hostname": "LAB-WINDOWS-01",
    }

    with pytest.raises(ContainmentValidationError, match="Invalid alert severity"):
        validate_alert(payload)

    decision = evaluate_containment(payload, raise_on_invalid=False)
    assert decision["containment_recommended"] is False
    assert decision["decision"] == DECISION_CONTAINMENT_REJECTED


# ── Test 9: Empty Alert Input ─────────────────────────────────────────────────


@pytest.mark.parametrize("empty_payload", [{}, None])
def test_empty_alert_input_validation_and_decision(empty_payload):
    """Empty or None alert input must fail validation and be rejected safely."""
    with pytest.raises(ContainmentValidationError):
        validate_alert(empty_payload)

    decision = evaluate_containment(empty_payload, raise_on_invalid=False)
    assert decision["containment_recommended"] is False
    assert decision["decision"] == DECISION_CONTAINMENT_REJECTED


# ── Test 10: Malformed Alert Data ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "malformed_payload",
    [
        "this is a raw string",
        ["item1", "item2"],
        12345,
        {"alert_id": "ALERT-MALFORMED", "severity": "critical", "alert_type": "ransomware", "hostname": "HOST", "timestamp": "invalid-time"},
    ],
)
def test_malformed_alert_data_validation_and_decision(malformed_payload):
    """Malformed non-dict types or invalid timestamps must be rejected safely."""
    with pytest.raises(ContainmentValidationError):
        validate_alert(malformed_payload)

    decision = evaluate_containment(malformed_payload, raise_on_invalid=False)
    assert decision["containment_recommended"] is False
    assert decision["decision"] == DECISION_CONTAINMENT_REJECTED


# ── Test 11: High-Severity Suspicious Activity with Policy Enabled ─────────────


def test_high_severity_alert_with_policy_enabled():
    """High-severity suspicious activity must recommend containment when configured policy enables it."""
    alert = {
        "alert_id": "ALERT-1011",
        "severity": "high",
        "alert_type": "suspicious_activity",
        "hostname": "LAB-WINDOWS-11",
        "endpoint_id": "ENDPOINT-011",
    }
    policy = ContainmentPolicy(contain_high_suspicious_activity=True)
    decision = evaluate_containment(alert, policy=policy, dry_run=True)

    assert decision["containment_recommended"] is True
    assert decision["decision"] == DECISION_CONTAINMENT_RECOMMENDED
    assert "High-severity suspicious activity meets the configured containment policy." in decision["reason"]


# ── Test 12: Endpoint Identification with Hostname Only ───────────────────────


def test_endpoint_identification_hostname_only():
    """Alert with only hostname (no endpoint_id) is valid and triggers recommendation."""
    alert = {
        "alert_id": "ALERT-1012",
        "severity": 5,
        "alert_type": "ransomware",
        "hostname": "WIN-STANDALONE",
    }
    decision = evaluate_containment(alert, dry_run=True)

    assert decision["hostname"] == "WIN-STANDALONE"
    assert decision["endpoint_id"] is None
    assert decision["containment_recommended"] is True


# ── Test 13: Endpoint Identification with Endpoint ID Only ───────────────────


def test_endpoint_identification_endpoint_id_only():
    """Alert with only endpoint_id (no hostname) is valid and triggers recommendation."""
    alert = {
        "alert_id": "ALERT-1013",
        "severity": 5,
        "alert_type": "ransomware",
        "endpoint_id": "CS-SENSOR-9999",
    }
    decision = evaluate_containment(alert, dry_run=True)

    assert decision["hostname"] is None
    assert decision["endpoint_id"] == "CS-SENSOR-9999"
    assert decision["containment_recommended"] is True


# ── Test 14: Structured Object and Pydantic Model Support ─────────────────────


def test_pydantic_model_payload_support():
    """Existing project Pydantic Alert model is supported as input to containment logic."""
    pydantic_alert = Alert(
        alert_id="ALERT-PYDANTIC-01",
        threat_type="ransomware",
        severity=5,
        description="Mass volume canary file encrypted",
        timestamp="2026-10-16T12:00:00Z",
        hostname="PROD-DB-01",
    )
    decision = evaluate_containment(pydantic_alert, dry_run=True)

    assert decision["alert_id"] == "ALERT-PYDANTIC-01"
    assert decision["hostname"] == "PROD-DB-01"
    assert decision["containment_recommended"] is True
    assert decision["decision"] == DECISION_CONTAINMENT_RECOMMENDED


# ── Test 15: Permissive Custom Policy for Medium/Low Severity ──────────────────


def test_permissive_custom_policy_medium_low():
    """Custom policy configured with contain_medium_low=True recommends containment on medium alerts."""
    alert = {
        "alert_id": "ALERT-PERMISSIVE-01",
        "severity": "medium",
        "alert_type": "malware",
        "hostname": "HOST-TEST",
    }
    permissive_policy = ContainmentPolicy(contain_medium_low=True)
    decision = evaluate_containment(alert, policy=permissive_policy, dry_run=True)

    assert decision["containment_recommended"] is True
    assert decision["decision"] == DECISION_CONTAINMENT_RECOMMENDED
    assert "permissive" in decision["reason"].lower()


# ── Test 16: Evaluation with raise_on_invalid=True ────────────────────────────


def test_evaluate_containment_raise_on_invalid():
    """When raise_on_invalid=True, evaluate_containment propagates ContainmentValidationError."""
    invalid_alert = {"alert_id": "ALERT-BAD"}

    with pytest.raises(ContainmentValidationError):
        evaluate_containment(invalid_alert, raise_on_invalid=True)


# ── Test 17: Safe Logging Verification ────────────────────────────────────────


def test_safe_logging_verification(caplog, sample_critical_ransomware_alert):
    """Verify that alert receipt, validation success, and decision generation are safely logged."""
    with caplog.at_level(logging.INFO):
        evaluate_containment(sample_critical_ransomware_alert, dry_run=True)

    log_text = caplog.text
    assert "Security alert received for containment evaluation: alert_id=ALERT-1001" in log_text
    assert "Alert validation succeeded for alert_id=ALERT-1001" in log_text
    assert "Containment decision generated: alert_id=ALERT-1001" in log_text
    assert "CONTAINMENT_RECOMMENDED" in log_text

    # Verify no auth tokens, passwords, or secrets appear in logs
    assert "password" not in log_text.lower()
    assert "secret" not in log_text.lower()
    assert "token" not in log_text.lower()


# ── Test 18: ContainmentDecision Dataclass Serialization ───────────────────────


def test_containment_decision_dataclass():
    """Verify ContainmentDecision dataclass produces expected structured dictionary."""
    decision_obj = ContainmentDecision(
        alert_id="ALERT-OBJ-01",
        endpoint_id="EP-01",
        hostname="HOST-01",
        containment_recommended=True,
        decision=DECISION_CONTAINMENT_RECOMMENDED,
        reason="Test reason",
        timestamp="2026-10-16T10:00:00Z",
    )
    data = decision_obj.to_dict()

    assert data["alert_id"] == "ALERT-OBJ-01"
    assert data["endpoint_id"] == "EP-01"
    assert data["hostname"] == "HOST-01"
    assert data["containment_recommended"] is True
    assert data["decision"] == DECISION_CONTAINMENT_RECOMMENDED
    assert data["reason"] == "Test reason"
    assert data["timestamp"] == "2026-10-16T10:00:00Z"

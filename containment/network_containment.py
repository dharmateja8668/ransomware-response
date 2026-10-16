# containment/network_containment.py
"""
Network Containment Decision Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Week    : 2
Day     : 1 -- Develop the Network Containment Logic

PURPOSE
-------
Evaluates high-severity security detections to determine whether automated
network containment should be recommended for an affected endpoint.

Validates incoming alert telemetry, applies configurable containment policy
rules, enforces safety controls (dry-run mode enabled by default), and outputs
a structured containment decision dictionary.

SAFETY NOTICE
-------------
- Dry-run mode is enabled by default.
- This module evaluates decision logic only; NO operating system commands,
  firewall modifications, or live EDR network isolation requests are executed.
- Network isolation actions and EDR API integrations are scheduled for Day 2.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Set, Tuple, Union

# Ensure project root is accessible when executing script directly
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from integrations.alert_parser import (
    SEVERITY_LABEL_MAP,
    AlertParsingError,
    normalize_severity,
    normalize_timestamp,
)

# Standard logging configuration (safe logging without secrets)
logger = logging.getLogger("orchestrator.containment")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


class ContainmentValidationError(ValueError):
    """Raised when an alert payload is invalid, incomplete, or malformed for containment evaluation."""


# Decision outcome constants
DECISION_CONTAINMENT_RECOMMENDED = "CONTAINMENT_RECOMMENDED"
DECISION_CONTAINMENT_NOT_RECOMMENDED = "CONTAINMENT_NOT_RECOMMENDED"
DECISION_CONTAINMENT_REJECTED = "CONTAINMENT_REJECTED"


@dataclass
class ContainmentPolicy:
    """
    Configurable policy rules determining network containment conditions.

    Attributes:
        contain_critical_ransomware: Whether critical ransomware alerts trigger containment recommendation (default: True).
        contain_critical_hands_on_keyboard: Whether critical hands-on-keyboard alerts trigger containment recommendation (default: True).
        contain_high_suspicious_activity: Whether high-severity suspicious activity triggers containment recommendation (default: False).
        contain_medium_low: Whether medium or low severity alerts trigger containment recommendation under default policy (default: False).
        critical_alert_types: Set of alert types treated as critical triggers.
        high_alert_types: Set of alert types evaluated at high severity.
        dry_run: Whether dry-run safety mode is active (default: True).
    """

    contain_critical_ransomware: bool = True
    contain_critical_hands_on_keyboard: bool = True
    contain_high_suspicious_activity: bool = False
    contain_medium_low: bool = False
    critical_alert_types: Optional[Set[str]] = None
    high_alert_types: Optional[Set[str]] = None
    dry_run: bool = True

    def __post_init__(self) -> None:
        if self.critical_alert_types is None:
            self.critical_alert_types = {
                "ransomware",
                "hands-on-keyboard",
                "hands_on_keyboard",
                "hands on keyboard",
            }
        else:
            self.critical_alert_types = {
                t.strip().lower() for t in self.critical_alert_types if t and t.strip()
            }

        if self.high_alert_types is None:
            self.high_alert_types = {
                "suspicious_activity",
                "suspicious-activity",
                "suspicious activity",
            }
        else:
            self.high_alert_types = {
                t.strip().lower() for t in self.high_alert_types if t and t.strip()
            }


@dataclass
class ContainmentDecision:
    """Represents a structured containment decision result."""

    alert_id: str
    endpoint_id: Optional[str]
    hostname: Optional[str]
    containment_recommended: bool
    decision: str
    reason: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the containment decision to a standard Python dictionary."""
        return {
            "alert_id": self.alert_id,
            "endpoint_id": self.endpoint_id,
            "hostname": self.hostname,
            "containment_recommended": self.containment_recommended,
            "decision": self.decision,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


def _clean_string(val: Optional[Any]) -> Optional[str]:
    """Helper to strip and clean optional string fields."""
    if val is None:
        return None
    s = str(val).strip()
    return s if s else None


def _normalize_alert_type_key(alert_type: str) -> str:
    """Normalizes an alert type string for consistent policy comparisons."""
    return alert_type.strip().lower().replace("_", "-").replace(" ", "-")


def validate_alert(alert: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
    """
    Validates the structure and required fields of an incoming security alert.

    Validation Rules:
      1. Alert payload must be a non-empty dictionary or structured object.
      2. Alert ID ('alert_id') must be present and non-empty.
      3. Alert type ('alert_type' or 'threat_type') must be present and non-empty.
      4. Affected endpoint identification ('hostname' or 'endpoint_id') must identify the compromised machine.
      5. Severity ('severity') must be recognized and within valid range (1-5 or recognized string).
      6. Timestamp ('timestamp'), if provided, must be valid and convertible to ISO 8601 UTC.

    Parameters:
        alert: Incoming alert dictionary or object.

    Returns:
        Dict[str, Any]: Normalized and validated alert fields.

    Raises:
        ContainmentValidationError: If any required identification or metadata is missing or invalid.
    """
    if alert is None:
        raise ContainmentValidationError("Alert payload cannot be None.")

    # 1. Convert object to dictionary
    if isinstance(alert, dict):
        data = dict(alert)
    elif hasattr(alert, "model_dump"):
        data = alert.model_dump()
    elif hasattr(alert, "dict"):
        data = alert.dict()
    elif hasattr(alert, "__dict__"):
        data = vars(alert)
    else:
        raise ContainmentValidationError("Alert payload must be a dictionary or structured object.")

    if not data:
        raise ContainmentValidationError("Alert payload is empty.")

    # 2. Validate alert_id
    raw_alert_id = data.get("alert_id")
    if raw_alert_id is None or not str(raw_alert_id).strip():
        raise ContainmentValidationError("Missing or empty required field: 'alert_id'.")
    alert_id = str(raw_alert_id).strip()

    # 3. Validate alert_type (accepts alert_type or threat_type for project compatibility)
    raw_type = data.get("alert_type") or data.get("threat_type")
    if raw_type is None or not str(raw_type).strip():
        raise ContainmentValidationError(
            "Missing or empty required field: 'alert_type' (or 'threat_type')."
        )
    alert_type = str(raw_type).strip().lower()

    # 4. Validate endpoint identification (hostname or endpoint_id is required)
    hostname = _clean_string(data.get("hostname"))
    endpoint_id = _clean_string(data.get("endpoint_id"))
    if not hostname and not endpoint_id:
        raise ContainmentValidationError(
            "Endpoint identification missing: either 'hostname' or 'endpoint_id' must be provided."
        )

    # 5. Validate and normalize severity
    raw_severity = data.get("severity")
    if raw_severity is None:
        raise ContainmentValidationError("Missing required field: 'severity'.")

    try:
        norm_severity = normalize_severity(raw_severity)
    except AlertParsingError as err:
        raise ContainmentValidationError(f"Invalid alert severity: {err}") from err

    severity_label = SEVERITY_LABEL_MAP.get(norm_severity, "UNKNOWN")

    # 6. Validate and normalize timestamp
    raw_timestamp = data.get("timestamp")
    if raw_timestamp is not None and str(raw_timestamp).strip():
        try:
            norm_timestamp = normalize_timestamp(str(raw_timestamp).strip())
        except AlertParsingError as err:
            raise ContainmentValidationError(f"Invalid timestamp format: {err}") from err
    else:
        norm_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Clean optional fields
    ip_address = _clean_string(data.get("ip_address"))
    username = _clean_string(data.get("username"))

    return {
        "alert_id": alert_id,
        "alert_type": alert_type,
        "severity": norm_severity,
        "severity_label": severity_label,
        "hostname": hostname,
        "endpoint_id": endpoint_id,
        "ip_address": ip_address,
        "username": username,
        "timestamp": norm_timestamp,
        "raw_payload": data,
    }


def evaluate_policy(
    validated_alert: Dict[str, Any],
    policy: Optional[ContainmentPolicy] = None,
) -> Tuple[bool, str, str]:
    """
    Evaluates policy containment conditions against a validated alert.

    Condition Rules:
      - Critical ransomware alert: recommend containment (if enabled in policy).
      - Critical hands-on-keyboard activity: recommend containment (if enabled in policy).
      - Other critical alert types: recommend containment if present in policy.critical_alert_types.
      - High-severity suspicious activity: recommend containment only when configured in policy.
      - Medium or low severity: do not automatically recommend containment under default policy.

    Parameters:
        validated_alert: Dictionary containing normalized alert data.
        policy: Configured ContainmentPolicy instance (uses defaults if None).

    Returns:
        Tuple[bool, str, str]: (containment_recommended, decision, reason)
    """
    active_policy = policy or ContainmentPolicy()
    severity = validated_alert["severity"]
    severity_label = validated_alert["severity_label"]
    alert_type = validated_alert["alert_type"]
    canon_type = _normalize_alert_type_key(alert_type)

    # 1. Critical Severity (Level 5)
    if severity == 5:
        if canon_type == "ransomware":
            if active_policy.contain_critical_ransomware:
                return (
                    True,
                    DECISION_CONTAINMENT_RECOMMENDED,
                    "Critical ransomware alert meets the configured containment policy.",
                )
            return (
                False,
                DECISION_CONTAINMENT_NOT_RECOMMENDED,
                "Critical ransomware containment is disabled in the active policy.",
            )

        if canon_type == "hands-on-keyboard":
            if active_policy.contain_critical_hands_on_keyboard:
                return (
                    True,
                    DECISION_CONTAINMENT_RECOMMENDED,
                    "Critical hands-on-keyboard activity meets the configured containment policy.",
                )
            return (
                False,
                DECISION_CONTAINMENT_NOT_RECOMMENDED,
                "Critical hands-on-keyboard containment is disabled in the active policy.",
            )

        # Check other critical alert types in policy
        norm_critical_types = {
            _normalize_alert_type_key(t) for t in (active_policy.critical_alert_types or set())
        }
        if canon_type in norm_critical_types:
            return (
                True,
                DECISION_CONTAINMENT_RECOMMENDED,
                f"Critical {alert_type} alert meets the configured containment policy.",
            )

        return (
            False,
            DECISION_CONTAINMENT_NOT_RECOMMENDED,
            f"Critical alert type '{alert_type}' is not configured for automatic containment.",
        )

    # 2. High Severity (Level 4)
    if severity == 4:
        norm_high_types = {
            _normalize_alert_type_key(t) for t in (active_policy.high_alert_types or set())
        }
        if canon_type == "suspicious-activity" or canon_type in norm_high_types:
            if active_policy.contain_high_suspicious_activity:
                return (
                    True,
                    DECISION_CONTAINMENT_RECOMMENDED,
                    "High-severity suspicious activity meets the configured containment policy.",
                )
            return (
                False,
                DECISION_CONTAINMENT_NOT_RECOMMENDED,
                "High-severity suspicious activity containment is disabled by the current policy.",
            )

        return (
            False,
            DECISION_CONTAINMENT_NOT_RECOMMENDED,
            f"High-severity alert type '{alert_type}' is not configured for automatic containment under the current policy.",
        )

    # 3. Medium, Low, or Informational Severity (Levels 1 to 3)
    if active_policy.contain_medium_low:
        return (
            True,
            DECISION_CONTAINMENT_RECOMMENDED,
            f"Alert severity '{severity_label.lower()}' ({severity}) meets the permissive containment policy.",
        )

    return (
        False,
        DECISION_CONTAINMENT_NOT_RECOMMENDED,
        f"Alert severity '{severity_label.lower()}' ({severity}) does not meet the minimum threshold for automatic containment under the default policy.",
    )


def build_containment_decision(
    alert_id: str,
    endpoint_id: Optional[str],
    hostname: Optional[str],
    containment_recommended: bool,
    decision: str,
    reason: str,
    timestamp: str,
) -> Dict[str, Any]:
    """
    Constructs a structured Python dictionary representing the containment decision.

    Returned fields:
      - alert_id
      - endpoint_id
      - hostname
      - containment_recommended
      - decision
      - reason
      - timestamp
    """
    decision_obj = ContainmentDecision(
        alert_id=alert_id,
        endpoint_id=endpoint_id,
        hostname=hostname,
        containment_recommended=containment_recommended,
        decision=decision,
        reason=reason,
        timestamp=timestamp,
    )
    return decision_obj.to_dict()


def evaluate_containment(
    alert: Union[Dict[str, Any], Any],
    policy: Optional[ContainmentPolicy] = None,
    dry_run: bool = True,
    raise_on_invalid: bool = False,
) -> Dict[str, Any]:
    """
    Evaluates whether an affected endpoint should be recommended for network containment.

    Workflow:
      1. Logs receipt of alert.
      2. Validates incoming alert payload.
         - If validation fails and raise_on_invalid=True, raises ContainmentValidationError.
         - If validation fails and raise_on_invalid=False, safely rejects containment (CONTAINMENT_REJECTED).
      3. Evaluates containment conditions against active ContainmentPolicy.
      4. Builds structured decision dictionary.
      5. Logs decision and rationale safely (no secrets).
      6. Returns the structured decision.

    Parameters:
        alert: Security alert payload (dictionary or structured object).
        policy: Optional custom ContainmentPolicy instance.
        dry_run: Safety control flag; defaults to True.
        raise_on_invalid: If True, raises ContainmentValidationError on malformed input.

    Returns:
        Dict[str, Any]: Structured containment decision dictionary.
    """
    active_policy = policy or ContainmentPolicy(dry_run=dry_run)
    # Ensure policy dry_run reflects parameter if passed explicitly
    active_policy.dry_run = dry_run

    # Extract alert_id safely for early logging if possible
    raw_alert_id = "UNKNOWN"
    if isinstance(alert, dict):
        raw_alert_id = str(alert.get("alert_id") or "UNKNOWN")
    elif hasattr(alert, "alert_id"):
        raw_alert_id = str(getattr(alert, "alert_id") or "UNKNOWN")

    logger.info("Security alert received for containment evaluation: alert_id=%s", raw_alert_id)

    # 1. Validate the alert
    try:
        validated = validate_alert(alert)
        logger.info(
            "Alert validation succeeded for alert_id=%s (endpoint_id=%s, hostname=%s, severity=%d)",
            validated["alert_id"],
            validated["endpoint_id"] or "N/A",
            validated["hostname"] or "N/A",
            validated["severity"],
        )
    except ContainmentValidationError as err:
        logger.warning("Alert validation failed for alert_id=%s: %s", raw_alert_id, err)
        if raise_on_invalid:
            raise

        # Generate a safe rejected decision for invalid/incomplete alert
        timestamp_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        host_fallback = None
        ep_fallback = None
        if isinstance(alert, dict):
            host_fallback = _clean_string(alert.get("hostname"))
            ep_fallback = _clean_string(alert.get("endpoint_id"))

        decision_dict = build_containment_decision(
            alert_id=raw_alert_id,
            endpoint_id=ep_fallback,
            hostname=host_fallback,
            containment_recommended=False,
            decision=DECISION_CONTAINMENT_REJECTED,
            reason=f"Alert validation failed: {err}",
            timestamp=timestamp_now,
        )
        logger.info(
            "Containment decision generated: alert_id=%s, decision=%s, recommended=%s, reason=%s",
            decision_dict["alert_id"],
            decision_dict["decision"],
            decision_dict["containment_recommended"],
            decision_dict["reason"],
        )
        return decision_dict
    except Exception as exc:
        logger.error(
            "Unexpected error during alert validation for alert_id=%s: %s",
            raw_alert_id,
            exc,
            exc_info=True,
        )
        if raise_on_invalid:
            raise ContainmentValidationError(f"Unexpected validation error: {exc}") from exc

        timestamp_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        decision_dict = build_containment_decision(
            alert_id=raw_alert_id,
            endpoint_id=None,
            hostname=None,
            containment_recommended=False,
            decision=DECISION_CONTAINMENT_REJECTED,
            reason=f"Unexpected processing error during validation: {exc}",
            timestamp=timestamp_now,
        )
        return decision_dict

    # 2. Evaluate containment conditions
    try:
        recommended, decision_type, reason = evaluate_policy(validated, active_policy)
    except Exception as exc:
        logger.error(
            "Unexpected error during containment policy evaluation for alert_id=%s: %s",
            validated["alert_id"],
            exc,
            exc_info=True,
        )
        timestamp_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return build_containment_decision(
            alert_id=validated["alert_id"],
            endpoint_id=validated["endpoint_id"],
            hostname=validated["hostname"],
            containment_recommended=False,
            decision=DECISION_CONTAINMENT_REJECTED,
            reason=f"Unexpected error during policy evaluation: {exc}",
            timestamp=timestamp_now,
        )

    # 3. Generate structured decision
    decision_dict = build_containment_decision(
        alert_id=validated["alert_id"],
        endpoint_id=validated["endpoint_id"],
        hostname=validated["hostname"],
        containment_recommended=recommended,
        decision=decision_type,
        reason=reason,
        timestamp=validated["timestamp"],
    )

    logger.info(
        "Containment decision generated: alert_id=%s, decision=%s, recommended=%s, reason=%s",
        decision_dict["alert_id"],
        decision_dict["decision"],
        decision_dict["containment_recommended"],
        decision_dict["reason"],
    )

    return decision_dict


def main() -> None:
    """Command-line demonstration of Day 1 Network Containment Decision Logic."""
    print("=" * 70)
    print("Automated Ransomware Containment -- Day 1 Containment Decision Logic")
    print("=" * 70)

    # Sample Alert from Day 1 specification
    sample_alert = {
        "alert_id": "ALERT-1001",
        "severity": "critical",
        "alert_type": "ransomware",
        "hostname": "LAB-WINDOWS-01",
        "endpoint_id": "ENDPOINT-001",
        "ip_address": "192.168.56.101",
        "username": "lab_user",
        "timestamp": "2026-10-16T10:30:00Z",
    }

    print("\n[+] Input Security Alert:")
    print(json.dumps(sample_alert, indent=2))

    print("\n[+] Evaluating Containment Decision (Dry-Run Mode)...")
    decision = evaluate_containment(sample_alert, dry_run=True)

    print("\n[+] Generated Containment Decision:")
    print(json.dumps(decision, indent=2))

    # Demonstrate Medium Severity Alert (No automatic containment)
    medium_alert = {
        "alert_id": "ALERT-2002",
        "severity": "medium",
        "alert_type": "suspicious_activity",
        "hostname": "LAB-WINDOWS-02",
        "endpoint_id": "ENDPOINT-002",
        "ip_address": "192.168.56.102",
        "username": "lab_user",
        "timestamp": "2026-10-16T11:00:00Z",
    }
    print("\n[+] Evaluating Medium Severity Alert:")
    med_decision = evaluate_containment(medium_alert, dry_run=True)
    print(json.dumps(med_decision, indent=2))

    # Demonstrate Invalid Alert (Rejection)
    invalid_alert = {
        "alert_id": "ALERT-9999",
        "severity": "unknown_sev",
        "alert_type": "ransomware",
    }
    print("\n[+] Evaluating Invalid Alert (Malformed severity, missing host ID):")
    invalid_decision = evaluate_containment(invalid_alert, dry_run=True)
    print(json.dumps(invalid_decision, indent=2))


if __name__ == "__main__":
    main()

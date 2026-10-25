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
import os
from pathlib import Path
import sys
import threading
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
from integrations.edr_client import (
    EDRAPIError,
    EDRAuthError,
    EDRConfigError,
    EDRConnectionError,
    EDRTimeoutError,
    create_edr_client,
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


# Decision outcome constants (Day 1)
DECISION_CONTAINMENT_RECOMMENDED = "CONTAINMENT_RECOMMENDED"
DECISION_CONTAINMENT_NOT_RECOMMENDED = "CONTAINMENT_NOT_RECOMMENDED"
DECISION_CONTAINMENT_REJECTED = "CONTAINMENT_REJECTED"

# Execution mode constants (Day 2)
EXECUTION_MODE_DRY_RUN = "dry_run"
EXECUTION_MODE_LIVE = "live"

# Isolation result status constants (Day 2)
STATUS_SIMULATED = "SIMULATED"
STATUS_REQUESTED = "REQUESTED"
STATUS_CONFIRMED = "CONFIRMED"
STATUS_FAILED = "FAILED"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_NOT_RECOMMENDED = "NOT_RECOMMENDED"
STATUS_REJECTED = "REJECTED"


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


@dataclass
class ContainmentExecutionResult:
    """
    Represents the end-to-end outcome of an EDR network containment workflow.

    Attributes:
        alert_id: Identifier of the evaluated security alert.
        endpoint_id: Identifier of the target machine/host (or None if missing/rejected).
        hostname: Hostname of the target machine (if known).
        containment_recommended: Whether policy recommended containment.
        execution_mode: Execution mode ('dry_run' or 'live').
        isolation_requested: Whether an isolation API request was dispatched to EDR.
        status: Operation status ('SIMULATED', 'REQUESTED', 'CONFIRMED', 'FAILED', 'UNKNOWN', 'NOT_RECOMMENDED', 'REJECTED').
        message: Human-readable explanation of the action or failure rationale.
        edr_provider: EDR platform targeted ('crowdstrike', 'defender', 'simulated', or None).
        action_id: Identifier or correlation ID returned by the EDR API (if available).
        timestamp: ISO 8601 UTC timestamp of execution.
        details: Optional sanitized diagnostic telemetry (without secrets).
    """

    alert_id: str
    endpoint_id: Optional[str]
    hostname: Optional[str]
    containment_recommended: bool
    execution_mode: str
    isolation_requested: bool
    status: str
    message: str
    edr_provider: Optional[str] = None
    action_id: Optional[str] = None
    timestamp: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the result to a standard dictionary compatible with application schemas."""
        res: Dict[str, Any] = {
            "alert_id": self.alert_id,
            "endpoint_id": self.endpoint_id,
            "hostname": self.hostname,
            "containment_recommended": self.containment_recommended,
            "execution_mode": self.execution_mode,
            "isolation_requested": self.isolation_requested,
            "status": self.status,
            "message": self.message,
            "edr_provider": self.edr_provider,
            "action_id": self.action_id,
            "timestamp": self.timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if self.details is not None:
            res["details"] = self.details
        return res


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


from incidents.coordination import (
    ACTION_TYPE_CONTAINMENT,
    get_dedup_store,
)


class ContainmentRegistry:
    """
    Database-backed, thread-safe, and multi-process safe registry tracking containment actions
    to prevent redundant or duplicate isolation requests from being sent to the EDR platform.

    ARCHITECTURE & CONCURRENCY:
      - Primary storage is backed by SQLite (action_deduplication table) with atomic transactions.
      - Guarantees coordination across multiple Uvicorn/FastAPI worker processes.
      - Automatically recovers stale in-progress locks from crashed workers.
      - Maintains in-memory cache mirror for ultra-fast local lookups.
    """

    def __init__(self, cooldown_seconds: int = 300, db_path: Optional[str] = None) -> None:
        self.cooldown_seconds = cooldown_seconds
        self.db_path = db_path
        self._records: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def is_contained(self, endpoint_id: str) -> bool:
        """Checks whether the endpoint has an active or recent containment record within cooldown."""
        # 1. Check persistent database-backed coordination
        try:
            if get_dedup_store(self.db_path).is_action_active(ACTION_TYPE_CONTAINMENT, endpoint_id):
                return True
        except Exception as exc:
            logger.warning("Error querying persistent dedup store for is_contained(%s): %s", endpoint_id, exc)

        # 2. In-memory fallback
        with self._lock:
            rec = self._records.get(endpoint_id)
            if not rec:
                return False
            rec_time = rec.get("time")
            if not rec_time:
                return False
            elapsed = (datetime.now(timezone.utc) - rec_time).total_seconds()
            if elapsed < self.cooldown_seconds and rec.get("status") in (STATUS_CONFIRMED, STATUS_REQUESTED):
                return True
            return False

    def get_record(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves the latest containment record for an endpoint."""
        try:
            db_rec = get_dedup_store(self.db_path).get_action_record(ACTION_TYPE_CONTAINMENT, endpoint_id)
            if db_rec:
                return {
                    "alert_id": db_rec.get("alert_id"),
                    "provider": db_rec.get("provider"),
                    "status": db_rec.get("status"),
                    "action_id": db_rec.get("action_id"),
                    "time": datetime.fromisoformat(db_rec["updated_at"]) if "updated_at" in db_rec else datetime.now(timezone.utc),
                }
        except Exception as exc:
            logger.warning("Error reading from db_rec for endpoint %s: %s", endpoint_id, exc)

        with self._lock:
            return dict(self._records[endpoint_id]) if endpoint_id in self._records else None

    def record(
        self,
        endpoint_id: str,
        alert_id: str,
        provider: str,
        status: str,
        action_id: Optional[str] = None,
    ) -> None:
        """Stores a containment action record in persistent database and memory cache."""
        try:
            get_dedup_store(self.db_path).complete_action(
                action_type=ACTION_TYPE_CONTAINMENT,
                target_id=endpoint_id,
                status=status,
                action_id=action_id,
                cooldown_seconds=self.cooldown_seconds,
            )
        except Exception as exc:
            logger.warning("Error updating persistent dedup store: %s", exc)

        with self._lock:
            self._records[endpoint_id] = {
                "alert_id": alert_id,
                "provider": provider,
                "status": status,
                "action_id": action_id,
                "time": datetime.now(timezone.utc),
            }

    def release(self, endpoint_id: str) -> bool:
        """Removes an endpoint record from the registry (e.g. upon uncontainment)."""
        db_released = False
        try:
            db_released = get_dedup_store(self.db_path).release_action(ACTION_TYPE_CONTAINMENT, endpoint_id)
        except Exception as exc:
            logger.warning("Error releasing from persistent dedup store: %s", exc)

        with self._lock:
            mem_released = bool(self._records.pop(endpoint_id, None))
        return db_released or mem_released

    def clear(self) -> None:
        """Clears all stored containment records across database and memory."""
        try:
            get_dedup_store(self.db_path).clear()
        except Exception as exc:
            logger.warning("Error clearing persistent dedup store: %s", exc)

        with self._lock:
            self._records.clear()

    def is_duplicate(self, target: str) -> bool:
        """Alias for is_contained for standardized duplicate checking."""
        return self.is_contained(target)

    def record_containment(
        self,
        target: str,
        alert_id: str,
        status: str,
        provider: str = "falcon",
        action_id: Optional[str] = None,
        telemetry: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Convenience alias for record()."""
        self.record(
            endpoint_id=target,
            alert_id=alert_id,
            provider=provider,
            status=status,
            action_id=action_id,
        )

    def get_duplicate_response(self, target: str) -> Optional[Dict[str, Any]]:
        """Returns standard duplicate response dictionary for an active target."""
        rec = self.get_record(target)
        if not rec:
            return None
        return {
            "status": "duplicate",
            "original_status": rec.get("status"),
            "target": target,
            "alert_id": rec.get("alert_id"),
        }


_GLOBAL_CONTAINMENT_REGISTRY = ContainmentRegistry()


def get_containment_registry() -> ContainmentRegistry:
    """Returns the singleton global containment registry."""
    return _GLOBAL_CONTAINMENT_REGISTRY


def clear_containment_registry() -> None:
    """Clears the global containment registry (useful between test runs)."""
    _GLOBAL_CONTAINMENT_REGISTRY.clear()


def parse_edr_isolation_response(
    provider: str,
    response_data: Any,
) -> Tuple[str, Optional[str], str]:
    """
    Parses the response payload from an EDR isolation API request and determines
    whether the containment is CONFIRMED, REQUESTED, FAILED, or UNKNOWN.

    Never assumes success simply because an HTTP response was returned.

    Parameters:
        provider: Provider identifier ('crowdstrike', 'defender', 'simulated').
        response_data: Raw JSON dictionary returned by the EDR API.

    Returns:
        Tuple[str, Optional[str], str]: (status, action_id, message)
    """
    if not isinstance(response_data, dict):
        return (
            STATUS_UNKNOWN,
            None,
            "EDR response was not a dictionary or was malformed.",
        )

    norm_provider = str(provider).strip().lower()

    # 1. CrowdStrike Falcon response parsing
    if norm_provider == "crowdstrike":
        errors = response_data.get("errors")
        if isinstance(errors, list) and len(errors) > 0:
            err_msgs = [
                e.get("message", str(e)) if isinstance(e, dict) else str(e)
                for e in errors
            ]
            return (
                STATUS_FAILED,
                None,
                f"CrowdStrike reported errors: {'; '.join(err_msgs)}",
            )

        resources = response_data.get("resources")
        if not isinstance(resources, list) or len(resources) == 0:
            return (
                STATUS_UNKNOWN,
                None,
                "CrowdStrike response contained no resource items.",
            )

        item = resources[0]
        if not isinstance(item, dict):
            return (
                STATUS_UNKNOWN,
                None,
                "CrowdStrike resource item is malformed.",
            )

        action_id = str(item.get("id") or response_data.get("meta", {}).get("trace_id") or "")
        complete = item.get("complete")
        raw_status = str(item.get("status", "")).strip().lower()

        if complete is True or raw_status in ("normal", "success", "completed", "contained", "true"):
            return (
                STATUS_CONFIRMED,
                action_id or None,
                "CrowdStrike Falcon network containment confirmed successfully.",
            )
        elif complete is False or raw_status in ("in_progress", "pending", "queued"):
            return (
                STATUS_REQUESTED,
                action_id or None,
                "CrowdStrike Falcon network containment requested and pending.",
            )
        elif raw_status in ("failed", "error"):
            return (
                STATUS_FAILED,
                action_id or None,
                f"CrowdStrike Falcon containment reported failure: {raw_status}",
            )
        else:
            return (
                STATUS_UNKNOWN,
                action_id or None,
                f"Ambiguous CrowdStrike status: '{raw_status}'. Preserving diagnostic data.",
            )

    # 2. Microsoft Defender for Endpoint response parsing
    elif norm_provider == "defender":
        action_id = str(response_data.get("id") or response_data.get("actionId") or "")
        mde_status = str(response_data.get("status") or response_data.get("actionStatus") or "").strip().lower()

        if not mde_status:
            return (
                STATUS_UNKNOWN,
                action_id or None,
                "Microsoft Defender response did not include a status field.",
            )

        if mde_status in ("succeeded", "completed", "success"):
            return (
                STATUS_CONFIRMED,
                action_id or None,
                "Microsoft Defender machine isolation confirmed successfully.",
            )
        elif mde_status in ("inprogress", "in_progress", "pending", "queued", "requested"):
            return (
                STATUS_REQUESTED,
                action_id or None,
                "Microsoft Defender machine isolation requested and pending.",
            )
        elif mde_status in ("failed", "cancelled", "error"):
            return (
                STATUS_FAILED,
                action_id or None,
                f"Microsoft Defender machine isolation failed: {mde_status}",
            )
        else:
            return (
                STATUS_UNKNOWN,
                action_id or None,
                f"Ambiguous Defender machine action status: '{mde_status}'. Preserving diagnostic data.",
            )

    # 3. Simulated Provider
    elif norm_provider == "simulated":
        action_id = str(response_data.get("action_id") or "sim-action")
        return (
            STATUS_CONFIRMED,
            action_id,
            "Simulated network isolation confirmed.",
        )

    # 4. Fallback / generic provider
    else:
        status_field = str(response_data.get("status", "")).strip().lower()
        action_id = str(response_data.get("id") or response_data.get("action_id") or "")
        if status_field in ("succeeded", "confirmed", "success"):
            return (STATUS_CONFIRMED, action_id or None, f"{provider} isolation confirmed.")
        elif status_field in ("requested", "pending", "in_progress"):
            return (STATUS_REQUESTED, action_id or None, f"{provider} isolation requested.")
        elif status_field in ("failed", "error"):
            return (STATUS_FAILED, action_id or None, f"{provider} isolation failed.")
        return (
            STATUS_UNKNOWN,
            action_id or None,
            f"Ambiguous response from provider '{provider}'.",
        )


def execute_network_containment(
    alert: Union[Dict[str, Any], Any],
    policy: Optional[ContainmentPolicy] = None,
    dry_run: Optional[bool] = None,
    edr_client: Optional[Any] = None,
    comment: Optional[str] = None,
    force: bool = False,
    raise_on_invalid: bool = False,
) -> Dict[str, Any]:
    """
    Executes the complete Week 2 Day 2 EDR Network Containment workflow:
      1. Receives and inspects the incoming security alert.
      2. Validates alert schema and endpoint identification via Day 1 logic.
      3. Evaluates containment policy rules.
      4. If containment is recommended, validates endpoint_id and prepares EDR request.
      5. Enforces execution modes (MODE A: dry-run default, MODE B: live authorized).
      6. Enforces duplicate request suppression safeguards.
      7. Dispatches authorized request to EDR platform (CrowdStrike or Defender).
      8. Parses and audits the provider response (CONFIRMED, REQUESTED, FAILED, UNKNOWN).
      9. Updates incident status to CONTAINED in SQLite if confirmed.
      10. Returns a structured result dictionary.

    Parameters:
        alert: Incoming alert dictionary or model object.
        policy: Optional custom ContainmentPolicy instance.
        dry_run: Explicit dry-run flag. If None, checks EDR_EXECUTION_MODE and EDR_DRY_RUN env vars.
                 Defaults to True (safe dry-run).
        edr_client: Optional pre-configured EDR client. If None in live mode, instantiates via factory.
        comment: Optional administrative rationale for containment request.
        force: If True, bypasses duplicate request suppression.
        raise_on_invalid: If True, re-raises ContainmentValidationError if alert is invalid.

    Returns:
        Dict[str, Any]: Structured result dictionary matching project standards.
    """
    # Determine execution mode (dry-run is default)
    if dry_run is None:
        env_mode = os.environ.get("EDR_EXECUTION_MODE", "").strip().lower()
        env_dry = os.environ.get("EDR_DRY_RUN", "").strip().lower()
        if env_mode == "live" or env_dry in ("false", "0", "no"):
            is_dry_run = False
        else:
            is_dry_run = True  # Default
    else:
        is_dry_run = bool(dry_run)

    mode_str = EXECUTION_MODE_DRY_RUN if is_dry_run else EXECUTION_MODE_LIVE

    # 1. Day 1 Containment Policy Evaluation
    decision = evaluate_containment(
        alert, policy=policy, dry_run=is_dry_run, raise_on_invalid=raise_on_invalid
    )

    # 2. Check validation failure
    if decision["decision"] == DECISION_CONTAINMENT_REJECTED:
        logger.warning(
            "Containment rejected during alert validation for alert_id=%s: %s",
            decision["alert_id"],
            decision["reason"],
        )
        return ContainmentExecutionResult(
            alert_id=decision["alert_id"],
            endpoint_id=decision.get("endpoint_id"),
            hostname=decision.get("hostname"),
            containment_recommended=False,
            execution_mode=mode_str,
            isolation_requested=False,
            status=STATUS_REJECTED,
            message=decision["reason"],
            timestamp=decision.get("timestamp"),
        ).to_dict()

    # 3. Check policy recommendation
    if not decision["containment_recommended"]:
        logger.info(
            "Containment not recommended for alert_id=%s: %s",
            decision["alert_id"],
            decision["reason"],
        )
        return ContainmentExecutionResult(
            alert_id=decision["alert_id"],
            endpoint_id=decision.get("endpoint_id"),
            hostname=decision.get("hostname"),
            containment_recommended=False,
            execution_mode=mode_str,
            isolation_requested=False,
            status=STATUS_NOT_RECOMMENDED,
            message=f"Containment not recommended: {decision['reason']}",
            timestamp=decision.get("timestamp"),
        ).to_dict()

    # 4. Containment is recommended: Validate required endpoint_id
    raw_endpoint_id = decision.get("endpoint_id")
    if not raw_endpoint_id or not str(raw_endpoint_id).strip():
        logger.warning(
            "Containment recommended for alert_id=%s, but endpoint_id is missing. Isolation rejected.",
            decision["alert_id"],
        )
        return ContainmentExecutionResult(
            alert_id=decision["alert_id"],
            endpoint_id=None,
            hostname=decision.get("hostname"),
            containment_recommended=True,
            execution_mode=mode_str,
            isolation_requested=False,
            status=STATUS_REJECTED,
            message="Missing endpoint identifier (endpoint_id); cannot submit EDR isolation request.",
            timestamp=decision.get("timestamp"),
        ).to_dict()

    endpoint_id = str(raw_endpoint_id).strip()

    # 5. Check duplicate / cooldown safeguard
    if not force and _GLOBAL_CONTAINMENT_REGISTRY.is_contained(endpoint_id):
        rec = _GLOBAL_CONTAINMENT_REGISTRY.get_record(endpoint_id) or {}
        prior_status = rec.get("status", STATUS_CONFIRMED)
        action_id = rec.get("action_id")
        provider = rec.get("provider")
        logger.info(
            "Duplicate isolation request suppressed for endpoint_id=%s (current status: %s)",
            endpoint_id,
            prior_status,
        )
        return ContainmentExecutionResult(
            alert_id=decision["alert_id"],
            endpoint_id=endpoint_id,
            hostname=decision.get("hostname"),
            containment_recommended=True,
            execution_mode=mode_str,
            isolation_requested=False,
            status=prior_status,
            message=f"Endpoint '{endpoint_id}' is already contained (duplicate request suppressed).",
            edr_provider=provider,
            action_id=action_id,
            timestamp=decision.get("timestamp"),
        ).to_dict()

    # 6. MODE A: Dry-Run (Default)
    if is_dry_run:
        logger.info(
            "DRY-RUN CONTAINMENT: alert_id=%s, endpoint_id=%s, hostname=%s. No real request sent.",
            decision["alert_id"],
            endpoint_id,
            decision.get("hostname") or "N/A",
        )
        return ContainmentExecutionResult(
            alert_id=decision["alert_id"],
            endpoint_id=endpoint_id,
            hostname=decision.get("hostname"),
            containment_recommended=True,
            execution_mode=EXECUTION_MODE_DRY_RUN,
            isolation_requested=False,
            status=STATUS_SIMULATED,
            message="Dry run completed. No EDR request was sent.",
            edr_provider="simulated",
            action_id=f"sim-action-{endpoint_id}",
            timestamp=decision.get("timestamp"),
        ).to_dict()

    # 7. MODE B: Live Authorized EDR Execution
    logger.info(
        "LIVE AUTHORIZED CONTAINMENT: Initiating isolation for alert_id=%s, endpoint_id=%s",
        decision["alert_id"],
        endpoint_id,
    )
    try:
        client = edr_client or create_edr_client(simulated=False)
    except EDRConfigError as cfg_err:
        logger.error(
            "EDR configuration error during containment request for alert_id=%s: %s",
            decision["alert_id"],
            cfg_err,
        )
        return ContainmentExecutionResult(
            alert_id=decision["alert_id"],
            endpoint_id=endpoint_id,
            hostname=decision.get("hostname"),
            containment_recommended=True,
            execution_mode=EXECUTION_MODE_LIVE,
            isolation_requested=False,
            status=STATUS_FAILED,
            message=f"EDR configuration error: {cfg_err}",
            timestamp=decision.get("timestamp"),
        ).to_dict()
    except Exception as exc:
        logger.error(
            "Failed to initialize EDR client for alert_id=%s: %s",
            decision["alert_id"],
            exc,
        )
        return ContainmentExecutionResult(
            alert_id=decision["alert_id"],
            endpoint_id=endpoint_id,
            hostname=decision.get("hostname"),
            containment_recommended=True,
            execution_mode=EXECUTION_MODE_LIVE,
            isolation_requested=False,
            status=STATUS_FAILED,
            message=f"Client initialization error: {exc}",
            timestamp=decision.get("timestamp"),
        ).to_dict()

    # Safely determine provider name (handle strings, Enum, or mock objects)
    provider_name = getattr(client, "PROVIDER", None)
    if not provider_name or not isinstance(provider_name, str):
        if hasattr(client, "config"):
            cfg = getattr(client, "config")
            if hasattr(cfg, "provider"):
                p_val = getattr(cfg, "provider")
                if hasattr(p_val, "value") and isinstance(p_val.value, str):
                    provider_name = p_val.value
                elif isinstance(p_val, str):
                    provider_name = p_val
    if not isinstance(provider_name, str):
        provider_name = "edr_provider"
    provider_name = provider_name.strip().lower()

    # Submit isolation request
    try:
        isolation_resp = client.isolate_endpoint(
            endpoint_id,
            comment=comment or f"Automated containment for alert {decision['alert_id']}",
        )
    except EDRAuthError as auth_err:
        logger.error(
            "EDR authentication failure during isolation of %s for alert_id=%s: %s",
            endpoint_id,
            decision["alert_id"],
            auth_err,
        )
        return ContainmentExecutionResult(
            alert_id=decision["alert_id"],
            endpoint_id=endpoint_id,
            hostname=decision.get("hostname"),
            containment_recommended=True,
            execution_mode=EXECUTION_MODE_LIVE,
            isolation_requested=True,
            status=STATUS_FAILED,
            message=f"EDR authentication failure: {auth_err}",
            edr_provider=provider_name,
            timestamp=decision.get("timestamp"),
        ).to_dict()
    except EDRTimeoutError as timeout_err:
        logger.error(
            "EDR timeout during isolation of %s for alert_id=%s: %s",
            endpoint_id,
            decision["alert_id"],
            timeout_err,
        )
        return ContainmentExecutionResult(
            alert_id=decision["alert_id"],
            endpoint_id=endpoint_id,
            hostname=decision.get("hostname"),
            containment_recommended=True,
            execution_mode=EXECUTION_MODE_LIVE,
            isolation_requested=True,
            status=STATUS_FAILED,
            message=f"EDR API timeout: {timeout_err}",
            edr_provider=provider_name,
            timestamp=decision.get("timestamp"),
        ).to_dict()
    except (EDRConnectionError, EDRAPIError) as api_err:
        logger.error(
            "EDR API error during isolation of %s for alert_id=%s: %s",
            endpoint_id,
            decision["alert_id"],
            api_err,
        )
        return ContainmentExecutionResult(
            alert_id=decision["alert_id"],
            endpoint_id=endpoint_id,
            hostname=decision.get("hostname"),
            containment_recommended=True,
            execution_mode=EXECUTION_MODE_LIVE,
            isolation_requested=True,
            status=STATUS_FAILED,
            message=f"EDR API error: {api_err}",
            edr_provider=provider_name,
            timestamp=decision.get("timestamp"),
        ).to_dict()
    except Exception as exc:
        logger.error(
            "Unexpected error submitting isolation for %s (alert_id=%s): %s",
            endpoint_id,
            decision["alert_id"],
            exc,
        )
        return ContainmentExecutionResult(
            alert_id=decision["alert_id"],
            endpoint_id=endpoint_id,
            hostname=decision.get("hostname"),
            containment_recommended=True,
            execution_mode=EXECUTION_MODE_LIVE,
            isolation_requested=True,
            status=STATUS_FAILED,
            message=f"Unexpected error submitting isolation: {exc}",
            edr_provider=provider_name,
            timestamp=decision.get("timestamp"),
        ).to_dict()

    # Parse provider response
    try:
        res_status, action_id, res_message = parse_edr_isolation_response(
            provider_name, isolation_resp
        )
    except Exception as exc:
        logger.error(
            "Error parsing EDR response for alert_id=%s: %s",
            decision["alert_id"],
            exc,
        )
        res_status = STATUS_UNKNOWN
        action_id = None
        res_message = f"Failed to parse provider response: {exc}"

    # Record in duplicate tracking registry if confirmed or requested
    if res_status in (STATUS_CONFIRMED, STATUS_REQUESTED):
        _GLOBAL_CONTAINMENT_REGISTRY.record(
            endpoint_id, decision["alert_id"], provider_name, res_status, action_id
        )

    # Advance incident lifecycle status in database
    try:
        from incidents.service import get_incident_by_alert_id, update_incident_status
        from incidents.models import IncidentStatus

        inc = get_incident_by_alert_id(decision["alert_id"])
        if inc:
            if res_status == STATUS_CONFIRMED:
                update_incident_status(decision["alert_id"], IncidentStatus.CONTAINED)
                logger.info(
                    "Incident %s transitioned to %s following confirmed EDR isolation.",
                    decision["alert_id"],
                    IncidentStatus.CONTAINED.value,
                )
            elif res_status == STATUS_REQUESTED and inc.status == IncidentStatus.NEW:
                update_incident_status(decision["alert_id"], IncidentStatus.INVESTIGATING)
                logger.info(
                    "Incident %s transitioned to %s following requested EDR isolation.",
                    decision["alert_id"],
                    IncidentStatus.INVESTIGATING.value,
                )
    except Exception as db_err:
        logger.debug("Database incident status synchronization skipped or failed: %s", db_err)

    logger.info(
        "EDR containment completed: alert_id=%s, endpoint_id=%s, status=%s, provider=%s, action_id=%s",
        decision["alert_id"],
        endpoint_id,
        res_status,
        provider_name,
        action_id or "N/A",
    )

    return ContainmentExecutionResult(
        alert_id=decision["alert_id"],
        endpoint_id=endpoint_id,
        hostname=decision.get("hostname"),
        containment_recommended=True,
        execution_mode=EXECUTION_MODE_LIVE,
        isolation_requested=True,
        status=res_status,
        message=res_message,
        edr_provider=provider_name,
        action_id=action_id,
        timestamp=decision.get("timestamp"),
    ).to_dict()


def process_containment_workflow(
    alert: Union[Dict[str, Any], Any],
    policy: Optional[ContainmentPolicy] = None,
    dry_run: Optional[bool] = None,
    edr_client: Optional[Any] = None,
    comment: Optional[str] = None,
    force: bool = False,
    record_incident: bool = True,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Week 2 Day 3: Complete End-to-End Network Containment Workflow Orchestrator.
    Processes a security alert from ingestion through validation, policy evaluation,
    duplicate check, EDR isolation execution, and incident status recording.

    Workflow Stages:
      1. Receives security alert telemetry.
      2. Parses and validates alert structure (Day 1 schema).
      3. Identifies target endpoint (hostname and endpoint_id).
      4. Stores or reuses incident record in SQLite (initial status: NEW).
      5. Evaluates Day 1 containment policy rules.
      6. Rejects alerts that do not qualify for containment.
      7. Checks duplicate request registry against cooldown.
      8. Dispatches containment execution in dry-run (default) or live mode.
      9. Processes provider response.
      10. Records execution result and updates incident status (CONFIRMED -> CONTAINED, REQUESTED -> INVESTIGATING).
      11. Returns structured execution outcome dictionary including incident_status.
      12. Logs workflow outcome safely without leaking secrets.

    Parameters:
        alert: Incoming alert dictionary or structured model.
        policy: Optional custom ContainmentPolicy instance.
        dry_run: Execution mode toggle. None defaults to EDR_EXECUTION_MODE or True.
        edr_client: Pre-configured or mocked EDR client.
        comment: Administrative containment justification.
        force: If True, bypasses duplicate request suppression.
        record_incident: Whether to store/update the incident in SQLite.
        db_path: Optional override path to the SQLite database.

    Returns:
        Dict[str, Any]: Structured execution result dictionary including incident_status.
    """
    # 1. Log alert received safely
    raw_alert_id = "UNKNOWN"
    if isinstance(alert, dict):
        raw_alert_id = str(alert.get("alert_id") or "UNKNOWN")
    elif hasattr(alert, "alert_id"):
        raw_alert_id = str(getattr(alert, "alert_id") or "UNKNOWN")

    logger.info("Containment workflow initiated for alert_id=%s", raw_alert_id)

    # 2. Record / retrieve incident in database if record_incident is True
    if record_incident:
        try:
            from incidents.service import get_incident_by_alert_id, create_incident
            from incidents.models import IncidentCreate, IncidentStatus

            existing_inc = get_incident_by_alert_id(raw_alert_id, db_path=db_path)
            if not existing_inc:
                # Extract alert fields safely
                a_data = alert if isinstance(alert, dict) else (
                    alert.model_dump() if hasattr(alert, "model_dump") else
                    (alert.dict() if hasattr(alert, "dict") else vars(alert))
                )
                if isinstance(a_data, dict) and a_data.get("alert_id"):
                    raw_sev = a_data.get("severity", 5)
                    try:
                        norm_sev = normalize_severity(raw_sev)
                    except Exception:
                        norm_sev = 5
                    inc_create = IncidentCreate(
                        alert_id=str(a_data.get("alert_id")),
                        threat_type=str(a_data.get("threat_type") or a_data.get("alert_type") or "security_alert"),
                        severity=norm_sev,
                        description=str(a_data.get("description") or f"Incident recorded for alert {raw_alert_id}"),
                        timestamp=str(a_data.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
                        hostname=_clean_string(a_data.get("hostname")),
                        ip_address=_clean_string(a_data.get("ip_address")),
                        username=_clean_string(a_data.get("username")),
                        process_hash=_clean_string(a_data.get("process_hash")),
                        status=IncidentStatus.NEW,
                    )
                    create_incident(inc_create, db_path=db_path)
                    logger.info("Initial incident %s recorded with status NEW in SQLite.", raw_alert_id)
        except Exception as db_err:
            logger.debug("Database incident recording skipped or unavailable: %s", db_err)

    # 3. Execute containment logic
    result = execute_network_containment(
        alert=alert,
        policy=policy,
        dry_run=dry_run,
        edr_client=edr_client,
        comment=comment,
        force=force,
        raise_on_invalid=False,
    )

    # 4. Attach synchronized incident status
    if record_incident:
        try:
            from incidents.service import get_incident_by_alert_id
            inc = get_incident_by_alert_id(result["alert_id"], db_path=db_path)
            result["incident_status"] = inc.status.value if inc else None
        except Exception:
            result["incident_status"] = None
    else:
        result["incident_status"] = None

    logger.info(
        "Containment workflow completed for alert_id=%s: status=%s, incident_status=%s",
        result.get("alert_id"),
        result.get("status"),
        result.get("incident_status") or "N/A",
    )

    return result


def main() -> None:
    """Command-line demonstration of Week 2 Day 1 & Day 2 Network Containment Orchestrator."""
    print("=" * 75)
    print("Automated Ransomware Containment -- Network Containment & EDR Orchestration")
    print("Week 2, Day 1 & Day 2 Integration")
    print("=" * 75)

    # 1. Sample Critical Ransomware Alert
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

    # Day 1 Policy Evaluation Demo
    print("\n[+] Step 1: Evaluating Day 1 Policy Decision...")
    decision = evaluate_containment(sample_alert, dry_run=True)
    print(json.dumps(decision, indent=2))

    # Day 2 EDR Containment Execution (Dry-Run Mode - Default)
    print("\n[+] Step 2: Executing EDR Containment Workflow (Dry-Run Mode - Default)...")
    dry_result = execute_network_containment(sample_alert, dry_run=True)
    print(json.dumps(dry_result, indent=2))

    # Day 2 EDR Containment with Simulated Client
    print("\n[+] Step 3: Executing EDR Containment Workflow with Simulated EDR Client...")
    from integrations.edr_client import SimulatedEDRClient

    sim_client = SimulatedEDRClient()
    sim_result = execute_network_containment(
        sample_alert, dry_run=False, edr_client=sim_client
    )
    print(json.dumps(sim_result, indent=2))

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
    print("\n[+] Step 4: Evaluating Medium Severity Alert (No Isolation):")
    med_result = execute_network_containment(medium_alert, dry_run=True)
    print(json.dumps(med_result, indent=2))

    # Demonstrate Invalid Alert Rejection
    invalid_alert = {
        "alert_id": "ALERT-9999",
        "severity": "unknown_sev",
        "alert_type": "ransomware",
    }
    print("\n[+] Step 5: Evaluating Invalid Alert (Safe Rejection):")
    invalid_result = execute_network_containment(invalid_alert, dry_run=True)
    print(json.dumps(invalid_result, indent=2))

    # Demonstrate Missing Endpoint ID Rejection
    no_endpoint_alert = {
        "alert_id": "ALERT-3003",
        "severity": "critical",
        "alert_type": "ransomware",
        "hostname": "HOST-ONLY-01",
    }
    print("\n[+] Step 6: Missing endpoint_id Rejection:")
    no_ep_result = execute_network_containment(no_endpoint_alert, dry_run=True)
    print(json.dumps(no_ep_result, indent=2))


if __name__ == "__main__":
    main()

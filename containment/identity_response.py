# containment/identity_response.py
"""
Identity Response and Coordinated Incident Response Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Week    : 2
Day     : 4 -- Identity Provider Integration and Account Suspension
Day     : 5 -- Session Revocation and Coordinated Incident Response

PURPOSE
-------
Orchestrates identity-level response actions (account suspension and session revocation)
and coordinates them with EDR network containment and incident management.

KEY ARCHITECTURAL HIGHLIGHTS:
  1. Safe User Identification: Extracts user identity from alert telemetry, prioritizing
     stable directory user IDs, UPNs, or email addresses. Safely rejects IP-only actions.
  2. Account Protection Controls: Enforces hard safeguards shielding emergency administrator
     accounts, break-glass accounts, and orchestrator service accounts from automated modification.
  3. Decoupled Decisions: Evaluates the identity-response policy independently from network
     containment; endpoint isolation does not blindly force account suspension.
  4. Idempotency & Cooldown: Thread-safe tracking suppresses redundant account suspension and
     session revocation requests within a configurable cooldown window.
  5. Multi-Action Coordination: Unifies EDR endpoint isolation, IdP account suspension, and IdP
     session revocation into a single coordinated incident response workflow.
  6. Robust Partial-Success Handling: Preserves individual action outcomes; never masks failures,
     timeouts, or ambiguous responses.
  7. Audit Logging & Sanitization: Persists every attempted, simulated, and executed action in
     the incident audit trail with strict credential scrubbing.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import re
import threading
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from containment.network_containment import (
    DECISION_CONTAINMENT_NOT_RECOMMENDED,
    DECISION_CONTAINMENT_RECOMMENDED,
    DECISION_CONTAINMENT_REJECTED,
    EXECUTION_MODE_DRY_RUN,
    EXECUTION_MODE_LIVE,
    STATUS_CONFIRMED,
    STATUS_FAILED,
    STATUS_NOT_RECOMMENDED,
    STATUS_REJECTED,
    STATUS_REQUESTED,
    STATUS_SIMULATED,
    STATUS_UNKNOWN,
    ContainmentPolicy,
    execute_network_containment,
    validate_alert,
)
from incidents.models import IncidentStatus
from incidents.service import (
    get_incident_by_alert_id,
    record_audit_log,
    update_incident_status,
)
from integrations.identity_client import (
    ACTION_REVOKE_SESSIONS,
    ACTION_SUSPEND_ACCOUNT,
    STATUS_UNSUPPORTED,
    AmbiguousUserError,
    BaseIdentityClient,
    IdentityActionResult,
    IdentityAPIError,
    IdentityAuthError,
    IdentityConfig,
    IdentityConfigError,
    IdentityConnectionError,
    IdentityTimeoutError,
    IneligibleAccountError,
    ProtectedAccountError,
    UnsupportedOperationError,
    UserIdentity,
    UserNotFoundError,
    create_identity_client,
)

logger = logging.getLogger("orchestrator.identity_response")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Policy Definition
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class IdentityResponsePolicy:
    """
    Configurable policy governing automated user account suspension and session revocation.

    Attributes:
        suspend_critical_ransomware: Auto-suspend user on critical ransomware alerts (default: True).
        suspend_critical_hands_on_keyboard: Auto-suspend user on critical hands-on-keyboard alerts (default: True).
        suspend_high_severity: Auto-suspend user on high-severity alerts (default: False).
        revoke_sessions_critical: Revoke user sign-in sessions on critical alerts (default: True).
        revoke_sessions_high: Revoke user sign-in sessions on high-severity alerts (default: False).
        dry_run: Whether dry-run simulation mode is active (default: True).
        protected_accounts: Set of account names, UPNs, or patterns protected from automation.
        allowed_tenants: Optional set of allowed tenant IDs for live execution.
        test_account_allowlist: Optional allowlist of accounts permitted for live modification.
    """

    suspend_critical_ransomware: bool = True
    suspend_critical_hands_on_keyboard: bool = True
    suspend_high_severity: bool = False
    revoke_sessions_critical: bool = True
    revoke_sessions_high: bool = False
    dry_run: bool = True
    protected_accounts: Optional[Set[str]] = None
    allowed_tenants: Optional[Set[str]] = None
    test_account_allowlist: Optional[Set[str]] = None

    def __post_init__(self) -> None:
        defaults = {
            "admin",
            "administrator",
            "breakglass",
            "break-glass",
            "emergency",
            "emergency-admin",
            "orchestrator",
            "svc-orchestrator",
            "orchestrator-svc",
            "root",
        }
        if self.protected_accounts is None:
            self.protected_accounts = defaults
        else:
            self.protected_accounts = {
                a.strip().lower() for a in self.protected_accounts if a and a.strip()
            } | defaults


# ─────────────────────────────────────────────────────────────────────────────
# Idempotency and Duplicate Action Tracking
# ─────────────────────────────────────────────────────────────────────────────


class IdentityActionRegistry:
    """
    Thread-safe in-memory registry tracking recent identity-response actions to prevent
    redundant or duplicate account suspension and session revocation requests.
    """

    def __init__(self, cooldown_seconds: int = 300) -> None:
        self.cooldown_seconds = cooldown_seconds
        self._records: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _key(self, user_id: str, action: str) -> str:
        return f"{user_id.strip().lower()}::{action.strip().upper()}"

    def is_action_active(self, user_id: str, action: str) -> bool:
        """Checks if a confirmed or requested action was executed within the cooldown window."""
        key = self._key(user_id, action)
        with self._lock:
            rec = self._records.get(key)
            if not rec:
                return False
            rec_time = rec.get("time")
            if not rec_time:
                return False
            elapsed = (datetime.now(timezone.utc) - rec_time).total_seconds()
            if elapsed < self.cooldown_seconds and rec.get("status") in (
                STATUS_CONFIRMED,
                STATUS_REQUESTED,
                STATUS_SIMULATED,
            ):
                return True
            return False

    def get_record(self, user_id: str, action: str) -> Optional[Dict[str, Any]]:
        key = self._key(user_id, action)
        with self._lock:
            rec = self._records.get(key)
            return dict(rec) if rec else None

    def record(
        self,
        user_id: str,
        alert_id: str,
        action: str,
        status: str,
        action_id: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> None:
        key = self._key(user_id, action)
        with self._lock:
            self._records[key] = {
                "alert_id": alert_id,
                "user_id": user_id,
                "action": action,
                "status": status,
                "action_id": action_id,
                "provider": provider,
                "time": datetime.now(timezone.utc),
            }

    def clear(self) -> None:
        with self._lock:
            self._records.clear()


_GLOBAL_IDENTITY_REGISTRY = IdentityActionRegistry()


def get_identity_registry() -> IdentityActionRegistry:
    return _GLOBAL_IDENTITY_REGISTRY


def clear_identity_registry() -> None:
    _GLOBAL_IDENTITY_REGISTRY.clear()


# ─────────────────────────────────────────────────────────────────────────────
# User Extraction & Safeguard Helpers
# ─────────────────────────────────────────────────────────────────────────────


def extract_user_identifier(alert: Union[Dict[str, Any], Any]) -> Tuple[Optional[str], str]:
    """
    Extracts the user account identifier from an alert payload following resolution hierarchy.

    Resolution Hierarchy:
      1. 'directory_user_id' or 'user_id' (stable directory UUID)
      2. 'user_principal_name', 'userPrincipalName', or 'upn'
      3. 'email', 'email_address', or 'mail'
      4. 'username'

    IMPORTANT SAFETY RULE:
      Explicitly rejects identity resolution if only an IP address or hostname is present.
      Account suspension is NEVER executed based solely on an IP address.

    Returns:
      Tuple[Optional[str], str]: (identifier, identifier_type)
    """
    data: Dict[str, Any] = {}
    if isinstance(alert, dict):
        data = alert
    elif hasattr(alert, "model_dump"):
        data = alert.model_dump()
    elif hasattr(alert, "dict"):
        data = alert.dict()
    elif hasattr(alert, "__dict__"):
        data = vars(alert)

    # 1. Directory User ID (highest precedence)
    for k in ("directory_user_id", "user_id", "azure_user_id", "entra_id"):
        val = data.get(k)
        if val and str(val).strip():
            return str(val).strip(), "directory_user_id"

    # 2. User Principal Name
    for k in ("user_principal_name", "userPrincipalName", "upn"):
        val = data.get(k)
        if val and str(val).strip():
            return str(val).strip(), "user_principal_name"

    # 3. Email Address
    for k in ("email", "email_address", "mail"):
        val = data.get(k)
        if val and str(val).strip():
            return str(val).strip(), "email"

    # 4. Username
    val = data.get("username")
    if val and str(val).strip():
        return str(val).strip(), "username"

    # Fallback check: alert only has IP address or hostname without user telemetry
    return None, "missing"


def is_account_protected(
    identifier: str,
    policy: Optional[IdentityResponsePolicy] = None,
) -> Tuple[bool, str]:
    """
    Evaluates whether a target user identifier corresponds to a protected administrative,
    emergency break-glass, or service account.

    Returns:
      Tuple[bool, str]: (is_protected, reason)
    """
    if not identifier:
        return False, ""

    clean = identifier.strip().lower()
    active_policy = policy or IdentityResponsePolicy()
    protected_set = active_policy.protected_accounts or set()

    # Exact or substring match in protected accounts set
    for p in protected_set:
        if p == clean or p in clean:
            return True, f"Account '{identifier}' matches protected administrative/emergency account rule '{p}'."

    # Pattern checks for common emergency and admin account naming conventions
    admin_patterns = [
        r"^admin(-|_|\.|$)",
        r"^breakglass(-|_|\.|$)",
        r"^emergency(-|_|\.|$)",
        r"^svc-orchestrator",
        r"^orchestrator(-|_|\.|$)",
        r"^root(-|_|\.|$)",
    ]
    for pat in admin_patterns:
        if re.search(pat, clean):
            return True, f"Account '{identifier}' matches protected administrative pattern '{pat}'."

    # Check test account allowlist (if configured, non-allowlisted accounts are protected from live execution)
    if active_policy.test_account_allowlist is not None:
        allowlist = {a.lower() for a in active_policy.test_account_allowlist}
        if clean not in allowlist:
            return True, f"Account '{identifier}' is not in the configured test-account allowlist."

    return False, ""


def evaluate_identity_policy(
    alert: Dict[str, Any],
    policy: Optional[IdentityResponsePolicy] = None,
) -> Dict[str, Any]:
    """
    Evaluates whether an alert warrants account suspension and/or session revocation.
    Keeps identity decisions logically separated from endpoint network containment.
    """
    active_policy = policy or IdentityResponsePolicy()
    severity = int(alert.get("severity", 1))
    alert_type = str(alert.get("threat_type") or alert.get("alert_type") or "").strip().lower()
    description = str(alert.get("description") or "").strip().lower()

    is_ransomware = (
        "ransomware" in alert_type or "ransom" in description or "encrypt" in description
    )
    is_hands_on_keyboard = (
        "hands-on-keyboard" in alert_type
        or "hands_on_keyboard" in alert_type
        or "hands on keyboard" in alert_type
    )

    suspend_recommended = False
    revoke_recommended = False
    reasons: List[str] = []

    # Level 5 Critical
    if severity >= 5:
        if is_ransomware and active_policy.suspend_critical_ransomware:
            suspend_recommended = True
            reasons.append("Critical ransomware threat detected.")
        if is_hands_on_keyboard and active_policy.suspend_critical_hands_on_keyboard:
            suspend_recommended = True
            reasons.append("Critical hands-on-keyboard threat detected.")
        if active_policy.revoke_sessions_critical:
            revoke_recommended = True
            reasons.append("Critical threat policy mandates session revocation.")
    # Level 4 High
    elif severity == 4:
        if active_policy.suspend_high_severity:
            suspend_recommended = True
            reasons.append("High-severity threat meets configured suspension threshold.")
        if active_policy.revoke_sessions_high:
            revoke_recommended = True
            reasons.append("High-severity threat meets configured session revocation threshold.")

    if not suspend_recommended and not revoke_recommended:
        reasons.append(
            f"Alert severity ({severity}) or threat type '{alert_type}' does not meet automated identity response thresholds."
        )

    return {
        "suspend_recommended": suspend_recommended,
        "revoke_recommended": revoke_recommended,
        "reason": " ".join(reasons),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Day 4: Account Suspension Workflow
# ─────────────────────────────────────────────────────────────────────────────


def execute_account_suspension(
    alert: Union[Dict[str, Any], Any],
    policy: Optional[IdentityResponsePolicy] = None,
    dry_run: Optional[bool] = None,
    identity_client: Optional[BaseIdentityClient] = None,
    reason: Optional[str] = None,
    force: bool = False,
    record_audit: bool = True,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes the Week 2 Day 4 Account Suspension Workflow:
      1. Inspects and validates incoming security alert.
      2. Extracts compromised user identification (rejects IP-only input).
      3. Resolves user identity via Identity Provider.
      4. Evaluates identity response policy.
      5. Enforces account protection and authorization safeguards.
      6. Checks duplicate request registry against cooldown.
      7. Dispatches account suspension (MODE A: Dry-Run default, MODE B: Live authorized).
      8. Parses response and records result in SQLite audit log.
      9. Returns structured result dictionary conforming to project standards.

    Parameters:
      alert: Incoming alert dictionary or structured model.
      policy: Optional custom IdentityResponsePolicy.
      dry_run: Execution mode toggle. None defaults to environment or True.
      identity_client: Pre-configured or mocked BaseIdentityClient.
      reason: Administrative justification.
      force: If True, bypasses duplicate suppression.
      record_audit: Whether to record audit log entry.
      db_path: Optional SQLite database path.

    Returns:
      Dict[str, Any]: Structured result conforming to Step 6 specification.
    """
    # 1. Determine execution mode (dry-run is default)
    if dry_run is None:
        env_mode = os.environ.get("IDENTITY_EXECUTION_MODE", "").strip().lower()
        env_dry = os.environ.get("IDENTITY_DRY_RUN", "").strip().lower()
        if env_mode == "live" or env_dry in ("false", "0", "no"):
            is_dry_run = False
        else:
            is_dry_run = True
    else:
        is_dry_run = bool(dry_run)

    mode_str = EXECUTION_MODE_DRY_RUN if is_dry_run else EXECUTION_MODE_LIVE
    active_policy = policy or IdentityResponsePolicy(dry_run=is_dry_run)
    active_policy.dry_run = is_dry_run

    # Extract alert_id safely
    raw_alert_id = "UNKNOWN"
    if isinstance(alert, dict):
        raw_alert_id = str(alert.get("alert_id") or "UNKNOWN")
    elif hasattr(alert, "alert_id"):
        raw_alert_id = str(getattr(alert, "alert_id") or "UNKNOWN")

    # 2. Validate alert structure
    try:
        validated_alert = validate_alert(alert)
    except Exception as err:
        msg = f"Alert validation failed: {err}"
        logger.warning("Account suspension rejected for alert_id=%s: %s", raw_alert_id, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider="none",
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=mode_str,
            status=STATUS_REJECTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=mode_str,
                status=STATUS_REJECTED,
                message=msg,
                db_path=db_path,
            )
        return res

    # 3. Extract user identification (safeguard: do NOT suspend based only on IP)
    user_identifier, id_type = extract_user_identifier(alert)
    if not user_identifier or id_type == "missing":
        msg = "Missing user identification: No user identification found in alert telemetry. Cannot suspend account based only on IP or hostname."
        logger.warning("Account suspension rejected for alert_id=%s: %s", raw_alert_id, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider="none",
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=mode_str,
            status=STATUS_REJECTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=mode_str,
                status=STATUS_REJECTED,
                message=msg,
                db_path=db_path,
            )
        return res

    # 4. Initialize Identity Provider Client
    client = identity_client
    if client is None:
        try:
            client = create_identity_client(simulated=is_dry_run)
        except IdentityConfigError as cfg_err:
            msg = f"Identity provider configuration error: {cfg_err}"
            logger.error("Identity client initialization failed for alert_id=%s: %s", raw_alert_id, msg)
            res = IdentityActionResult(
                alert_id=raw_alert_id,
                user_id=None,
                identity_provider="entra_id",
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=mode_str,
                status=STATUS_FAILED,
                message=msg,
            ).to_dict()
            if record_audit:
                record_audit_log(
                    alert_id=raw_alert_id,
                    action=ACTION_SUSPEND_ACCOUNT,
                    execution_mode=mode_str,
                    status=STATUS_FAILED,
                    message=msg,
                    db_path=db_path,
                )
            return res

    provider_name = getattr(client, "PROVIDER_NAME", "identity_provider")

    # 5. Resolve user through IdP
    try:
        user_identity = client.resolve_user(user_identifier)
    except AmbiguousUserError as amb_err:
        msg = f"Ambiguous user identity: {amb_err}"
        logger.warning("Account suspension rejected for alert_id=%s: %s", raw_alert_id, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=mode_str,
            status=STATUS_REJECTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=mode_str,
                status=STATUS_REJECTED,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except IdentityAuthError as auth_err:
        msg = f"Identity provider authentication failure: {auth_err}"
        logger.error("Authentication failure during user resolution for alert_id=%s: %s", raw_alert_id, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=mode_str,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=mode_str,
                status=STATUS_FAILED,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except IdentityTimeoutError as time_err:
        msg = f"Identity provider timeout during user resolution: {time_err}"
        logger.error("Timeout for alert_id=%s: %s", raw_alert_id, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=mode_str,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=mode_str,
                status=STATUS_FAILED,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except (IdentityConnectionError, IdentityAPIError) as api_err:
        msg = f"Identity provider API error during user resolution: {api_err}"
        logger.error("API error for alert_id=%s: %s", raw_alert_id, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=mode_str,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=mode_str,
                status=STATUS_FAILED,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res

    if not user_identity:
        msg = f"User identifier '{user_identifier}' could not be resolved in the directory."
        logger.warning("Account suspension rejected for alert_id=%s: %s", raw_alert_id, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=mode_str,
            status=STATUS_REJECTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=mode_str,
                status=STATUS_REJECTED,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res

    target_user_id = user_identity.user_id
    target_upn = user_identity.user_principal_name

    # 6. Check duplicate / cooldown safeguard
    if not force and _GLOBAL_IDENTITY_REGISTRY.is_action_active(target_user_id, ACTION_SUSPEND_ACCOUNT):
        prior = _GLOBAL_IDENTITY_REGISTRY.get_record(target_user_id, ACTION_SUSPEND_ACCOUNT) or {}
        prior_status = prior.get("status", STATUS_CONFIRMED)
        action_id = prior.get("action_id")
        msg = f"Account '{target_upn}' is already suspended or pending (duplicate request suppressed)."
        logger.info("Duplicate account suspension suppressed for user_id=%s", target_user_id)
        return IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=mode_str,
            status=prior_status,
            message=msg,
            action_id=action_id,
        ).to_dict()

    # 7. Check if account is ineligible (e.g. already disabled)
    if not user_identity.account_enabled:
        msg = f"Account '{target_upn}' ({target_user_id}) is already disabled/ineligible."
        logger.info("Account suspension skipped: %s", msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=mode_str,
            status=STATUS_REJECTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=mode_str,
                status=STATUS_REJECTED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res

    # 8. Evaluate identity-response policy
    eval_res = evaluate_identity_policy(validated_alert, active_policy)
    if not eval_res["suspend_recommended"]:
        msg = f"Account suspension not recommended by policy: {eval_res['reason']}"
        logger.info("Account suspension skipped for alert_id=%s: %s", raw_alert_id, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=mode_str,
            status=STATUS_NOT_RECOMMENDED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=mode_str,
                status=STATUS_NOT_RECOMMENDED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res

    # 8. Check account protection safeguards (emergency admin, break-glass, service account)
    is_protected, prot_reason = is_account_protected(target_upn, active_policy)
    if not is_protected:
        is_protected, prot_reason = is_account_protected(target_user_id, active_policy)

    if is_protected:
        msg = f"Account suspension rejected: {prot_reason}"
        logger.warning("PROTECTED ACCOUNT SAFEGUARD: alert_id=%s, target=%s. %s", raw_alert_id, target_upn, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=mode_str,
            status=STATUS_REJECTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=mode_str,
                status=STATUS_REJECTED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res

    # 10. MODE A: Dry-Run (Default)
    if is_dry_run:
        msg = "Account suspension simulated; no account modified."
        action_id = f"sim-susp-{target_user_id}"
        logger.info(
            "DRY-RUN ACCOUNT SUSPENSION: alert_id=%s, user_id=%s, upn=%s. No real accounts modified.",
            raw_alert_id,
            target_user_id,
            target_upn,
        )
        _GLOBAL_IDENTITY_REGISTRY.record(
            target_user_id, raw_alert_id, ACTION_SUSPEND_ACCOUNT, STATUS_SIMULATED, action_id, provider_name
        )
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=EXECUTION_MODE_DRY_RUN,
            status=STATUS_SIMULATED,
            message=msg,
            action_id=action_id,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=EXECUTION_MODE_DRY_RUN,
                status=STATUS_SIMULATED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                correlation_id=action_id,
                db_path=db_path,
            )
        return res

    # 11. MODE B: Live Authorized Execution
    logger.info(
        "LIVE AUTHORIZED ACCOUNT SUSPENSION: Executing for user_id=%s, upn=%s",
        target_user_id,
        target_upn,
    )
    try:
        susp_resp = client.suspend_account(
            target_user_id,
            reason=reason or f"Automated containment for alert {raw_alert_id}",
        )
    except UnsupportedOperationError as unsup_err:
        msg = f"Account suspension is unsupported by provider '{provider_name}': {unsup_err}"
        logger.warning("Account suspension unsupported for alert_id=%s: %s", raw_alert_id, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=EXECUTION_MODE_LIVE,
            status=STATUS_UNSUPPORTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=EXECUTION_MODE_LIVE,
                status=STATUS_UNSUPPORTED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except IdentityAuthError as auth_err:
        msg = f"Identity provider authorization/authentication failed: {auth_err}"
        logger.error("Account suspension failed for alert_id=%s: %s", raw_alert_id, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=EXECUTION_MODE_LIVE,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=EXECUTION_MODE_LIVE,
                status=STATUS_FAILED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except IdentityTimeoutError as time_err:
        msg = f"Identity provider timeout during account suspension: {time_err}"
        logger.error("Account suspension timeout for alert_id=%s: %s", raw_alert_id, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=EXECUTION_MODE_LIVE,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=EXECUTION_MODE_LIVE,
                status=STATUS_FAILED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except (IdentityConnectionError, IdentityAPIError) as api_err:
        msg = f"Identity provider API error: {api_err}"
        logger.error("Account suspension API error for alert_id=%s: %s", raw_alert_id, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=EXECUTION_MODE_LIVE,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=EXECUTION_MODE_LIVE,
                status=STATUS_FAILED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except Exception as exc:
        msg = f"Unexpected error executing account suspension: {exc}"
        logger.error("Unexpected error for alert_id=%s: %s", raw_alert_id, msg)
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=EXECUTION_MODE_LIVE,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_SUSPEND_ACCOUNT,
                execution_mode=EXECUTION_MODE_LIVE,
                status=STATUS_FAILED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res

    # Parse and normalize provider response
    if not isinstance(susp_resp, dict):
        status_val = STATUS_UNKNOWN
        action_id = None
        message_val = "Provider returned malformed non-dictionary response."
    else:
        status_val = susp_resp.get("status") or (
            STATUS_CONFIRMED if susp_resp.get("complete") is True else STATUS_UNKNOWN
        )
        action_id = susp_resp.get("action_id")
        message_val = susp_resp.get("message") or f"Account suspension outcome: {status_val}"

    # Track in registry
    _GLOBAL_IDENTITY_REGISTRY.record(
        target_user_id, raw_alert_id, ACTION_SUSPEND_ACCOUNT, status_val, action_id, provider_name
    )

    res = IdentityActionResult(
        alert_id=raw_alert_id,
        user_id=target_user_id,
        user_principal_name=target_upn,
        identity_provider=provider_name,
        action=ACTION_SUSPEND_ACCOUNT,
        execution_mode=EXECUTION_MODE_LIVE,
        status=status_val,
        message=message_val,
        action_id=action_id,
    ).to_dict()

    if record_audit:
        record_audit_log(
            alert_id=raw_alert_id,
            action=ACTION_SUSPEND_ACCOUNT,
            execution_mode=EXECUTION_MODE_LIVE,
            status=status_val,
            user_id=target_user_id,
            message=message_val,
            identity_provider=provider_name,
            correlation_id=action_id,
            db_path=db_path,
        )

    return res


# ─────────────────────────────────────────────────────────────────────────────
# Day 5: Session Revocation Workflow
# ─────────────────────────────────────────────────────────────────────────────


def execute_session_revocation(
    alert: Union[Dict[str, Any], Any],
    policy: Optional[IdentityResponsePolicy] = None,
    dry_run: Optional[bool] = None,
    identity_client: Optional[BaseIdentityClient] = None,
    force: bool = False,
    record_audit: bool = True,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes the Week 2 Day 5 Session Revocation Workflow:
      1. Inspects and validates incoming security alert / user telemetry.
      2. Extracts compromised user identification.
      3. Resolves user identity via Identity Provider.
      4. Evaluates identity response policy for session revocation.
      5. Enforces account protection and authorization safeguards.
      6. Checks duplicate request registry against cooldown.
      7. Dispatches session revocation (MODE A: Dry-Run default, MODE B: Live authorized).
      8. Parses response and records result in SQLite audit log.
      9. Returns structured result dictionary conforming to project standards.

    Parameters:
      alert: Incoming alert dictionary or structured model.
      policy: Optional custom IdentityResponsePolicy.
      dry_run: Execution mode toggle. None defaults to environment or True.
      identity_client: Pre-configured or mocked BaseIdentityClient.
      force: If True, bypasses duplicate suppression.
      record_audit: Whether to record audit log entry.
      db_path: Optional SQLite database path.

    Returns:
      Dict[str, Any]: Structured result conforming to Step 7 specification.
    """
    if dry_run is None:
        env_mode = os.environ.get("IDENTITY_EXECUTION_MODE", "").strip().lower()
        env_dry = os.environ.get("IDENTITY_DRY_RUN", "").strip().lower()
        if env_mode == "live" or env_dry in ("false", "0", "no"):
            is_dry_run = False
        else:
            is_dry_run = True
    else:
        is_dry_run = bool(dry_run)

    mode_str = EXECUTION_MODE_DRY_RUN if is_dry_run else EXECUTION_MODE_LIVE
    active_policy = policy or IdentityResponsePolicy(dry_run=is_dry_run)
    active_policy.dry_run = is_dry_run

    raw_alert_id = "UNKNOWN"
    if isinstance(alert, dict):
        raw_alert_id = str(alert.get("alert_id") or "UNKNOWN")
    elif hasattr(alert, "alert_id"):
        raw_alert_id = str(getattr(alert, "alert_id") or "UNKNOWN")

    # 1. Validate alert
    try:
        validated_alert = validate_alert(alert)
    except Exception as err:
        msg = f"Alert validation failed: {err}"
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider="none",
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=mode_str,
            status=STATUS_REJECTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=mode_str,
                status=STATUS_REJECTED,
                message=msg,
                db_path=db_path,
            )
        return res

    # 2. Extract user identifier
    user_identifier, id_type = extract_user_identifier(alert)
    if not user_identifier or id_type == "missing":
        msg = "Missing user identification: No user identification found in alert telemetry. Cannot revoke sessions based only on IP or hostname."
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider="none",
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=mode_str,
            status=STATUS_REJECTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=mode_str,
                status=STATUS_REJECTED,
                message=msg,
                db_path=db_path,
            )
        return res

    # 3. Initialize IdP Client
    client = identity_client
    if client is None:
        try:
            client = create_identity_client(simulated=is_dry_run)
        except IdentityConfigError as cfg_err:
            msg = f"Identity provider configuration error: {cfg_err}"
            res = IdentityActionResult(
                alert_id=raw_alert_id,
                user_id=None,
                identity_provider="entra_id",
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=mode_str,
                status=STATUS_FAILED,
                message=msg,
            ).to_dict()
            if record_audit:
                record_audit_log(
                    alert_id=raw_alert_id,
                    action=ACTION_REVOKE_SESSIONS,
                    execution_mode=mode_str,
                    status=STATUS_FAILED,
                    message=msg,
                    db_path=db_path,
                )
            return res

    provider_name = getattr(client, "PROVIDER_NAME", "identity_provider")

    # 4. Resolve User
    try:
        user_identity = client.resolve_user(user_identifier)
    except AmbiguousUserError as amb_err:
        msg = f"Ambiguous user identity: {amb_err}"
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=mode_str,
            status=STATUS_REJECTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=mode_str,
                status=STATUS_REJECTED,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except IdentityAuthError as auth_err:
        msg = f"Identity provider authentication failure: {auth_err}"
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=mode_str,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=mode_str,
                status=STATUS_FAILED,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except IdentityTimeoutError as time_err:
        msg = f"Identity provider timeout during user resolution: {time_err}"
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=mode_str,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=mode_str,
                status=STATUS_FAILED,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except (IdentityConnectionError, IdentityAPIError) as api_err:
        msg = f"Identity provider API error during user resolution: {api_err}"
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=mode_str,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=mode_str,
                status=STATUS_FAILED,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except UnsupportedOperationError as unsup_err:
        msg = f"Session revocation is unsupported by provider '{provider_name}': {unsup_err}"
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=mode_str,
            status=STATUS_UNSUPPORTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=mode_str,
                status=STATUS_UNSUPPORTED,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res

    if not user_identity:
        msg = f"User identifier '{user_identifier}' could not be resolved in the directory."
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=None,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=mode_str,
            status=STATUS_REJECTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=mode_str,
                status=STATUS_REJECTED,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res

    target_user_id = user_identity.user_id
    target_upn = user_identity.user_principal_name

    # 5. Duplicate request protection
    if not force and _GLOBAL_IDENTITY_REGISTRY.is_action_active(target_user_id, ACTION_REVOKE_SESSIONS):
        prior = _GLOBAL_IDENTITY_REGISTRY.get_record(target_user_id, ACTION_REVOKE_SESSIONS) or {}
        prior_status = prior.get("status", STATUS_CONFIRMED)
        action_id = prior.get("action_id")
        msg = f"Sign-in sessions for '{target_upn}' have already been revoked (duplicate request suppressed)."
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=mode_str,
            status=prior_status,
            message=msg,
            action_id=action_id,
        ).to_dict()
        return res

    # 6. Evaluate policy
    eval_res = evaluate_identity_policy(validated_alert, active_policy)
    if not eval_res["revoke_recommended"]:
        msg = f"Session revocation not recommended by policy: {eval_res['reason']}"
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=mode_str,
            status=STATUS_NOT_RECOMMENDED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=mode_str,
                status=STATUS_NOT_RECOMMENDED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res

    # 7. Check protection safeguards
    is_protected, prot_reason = is_account_protected(target_upn, active_policy)
    if not is_protected:
        is_protected, prot_reason = is_account_protected(target_user_id, active_policy)

    if is_protected:
        msg = f"Session revocation rejected: {prot_reason}"
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=mode_str,
            status=STATUS_REJECTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=mode_str,
                status=STATUS_REJECTED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res

    # 8. MODE A: Dry-Run (Default)
    if is_dry_run:
        msg = "User session revocation simulated; no real sessions revoked."
        action_id = f"sim-revoke-{target_user_id}"
        logger.info(
            "DRY-RUN SESSION REVOCATION: alert_id=%s, user_id=%s, upn=%s. No real sessions revoked.",
            raw_alert_id,
            target_user_id,
            target_upn,
        )
        _GLOBAL_IDENTITY_REGISTRY.record(
            target_user_id, raw_alert_id, ACTION_REVOKE_SESSIONS, STATUS_SIMULATED, action_id, provider_name
        )
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=EXECUTION_MODE_DRY_RUN,
            status=STATUS_SIMULATED,
            message=msg,
            action_id=action_id,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=EXECUTION_MODE_DRY_RUN,
                status=STATUS_SIMULATED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                correlation_id=action_id,
                db_path=db_path,
            )
        return res

    # 9. MODE B: Live Authorized Execution
    logger.info("LIVE AUTHORIZED SESSION REVOCATION: Executing for user_id=%s (%s)", target_user_id, target_upn)
    try:
        rev_resp = client.revoke_user_sessions(target_user_id)
    except UnsupportedOperationError as unsup_err:
        msg = f"Session revocation is unsupported by provider '{provider_name}': {unsup_err}"
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=EXECUTION_MODE_LIVE,
            status=STATUS_UNSUPPORTED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=EXECUTION_MODE_LIVE,
                status=STATUS_UNSUPPORTED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except IdentityAuthError as auth_err:
        msg = f"Identity provider authorization/authentication failed: {auth_err}"
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=EXECUTION_MODE_LIVE,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=EXECUTION_MODE_LIVE,
                status=STATUS_FAILED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except IdentityTimeoutError as time_err:
        msg = f"Identity provider timeout during session revocation: {time_err}"
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=EXECUTION_MODE_LIVE,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=EXECUTION_MODE_LIVE,
                status=STATUS_FAILED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except (IdentityConnectionError, IdentityAPIError) as api_err:
        msg = f"Identity provider API error: {api_err}"
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=EXECUTION_MODE_LIVE,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=EXECUTION_MODE_LIVE,
                status=STATUS_FAILED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res
    except Exception as exc:
        msg = f"Unexpected error during session revocation: {exc}"
        res = IdentityActionResult(
            alert_id=raw_alert_id,
            user_id=target_user_id,
            user_principal_name=target_upn,
            identity_provider=provider_name,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=EXECUTION_MODE_LIVE,
            status=STATUS_FAILED,
            message=msg,
        ).to_dict()
        if record_audit:
            record_audit_log(
                alert_id=raw_alert_id,
                action=ACTION_REVOKE_SESSIONS,
                execution_mode=EXECUTION_MODE_LIVE,
                status=STATUS_FAILED,
                user_id=target_user_id,
                message=msg,
                identity_provider=provider_name,
                db_path=db_path,
            )
        return res

    # Normalize response
    if not isinstance(rev_resp, dict):
        status_val = STATUS_UNKNOWN
        action_id = None
        message_val = "Provider returned non-dictionary session revocation response."
    else:
        status_val = rev_resp.get("status") or (
            STATUS_CONFIRMED if rev_resp.get("complete") is True else STATUS_UNKNOWN
        )
        action_id = rev_resp.get("action_id")
        message_val = rev_resp.get("message") or f"Session revocation outcome: {status_val}"

    _GLOBAL_IDENTITY_REGISTRY.record(
        target_user_id, raw_alert_id, ACTION_REVOKE_SESSIONS, status_val, action_id, provider_name
    )

    res = IdentityActionResult(
        alert_id=raw_alert_id,
        user_id=target_user_id,
        user_principal_name=target_upn,
        identity_provider=provider_name,
        action=ACTION_REVOKE_SESSIONS,
        execution_mode=EXECUTION_MODE_LIVE,
        status=status_val,
        message=message_val,
        action_id=action_id,
    ).to_dict()

    if record_audit:
        record_audit_log(
            alert_id=raw_alert_id,
            action=ACTION_REVOKE_SESSIONS,
            execution_mode=EXECUTION_MODE_LIVE,
            status=status_val,
            user_id=target_user_id,
            message=message_val,
            identity_provider=provider_name,
            correlation_id=action_id,
            db_path=db_path,
        )

    return res


# ─────────────────────────────────────────────────────────────────────────────
# Day 5: Coordinated Incident Response Orchestrator
# ─────────────────────────────────────────────────────────────────────────────


def process_coordinated_response_workflow(
    alert: Union[Dict[str, Any], Any],
    containment_policy: Optional[ContainmentPolicy] = None,
    identity_policy: Optional[IdentityResponsePolicy] = None,
    dry_run: Optional[bool] = None,
    edr_client: Optional[Any] = None,
    identity_client: Optional[BaseIdentityClient] = None,
    comment: Optional[str] = None,
    force: bool = False,
    record_incident: bool = True,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Week 2 Day 5: Coordinated Incident Response Workflow Orchestrator.
    Coordinates across all three remediation operations:
      A. Network containment through the existing EDR client.
      B. Account suspension through the Identity Provider.
      C. Session revocation through the Identity Provider.
      D. Synchronized Incident lifecycle progression in SQLite.
      E. Granular audit trail records for each operation.

    Handles partial success and ambiguous outcomes explicitly:
      - If EDR isolation succeeds but account suspension fails, isolation is preserved.
      - If account suspension succeeds but session revocation fails, suspension is preserved.
      - Individual statuses are NEVER artificially masked or overwritten.
      - An incident is only marked CONTAINED when endpoint isolation is confirmed.

    Returns:
      Dict[str, Any]: Structured coordinated response conforming to Step 10 specification.
    """
    # Execution mode resolution
    if dry_run is None:
        edr_mode = os.environ.get("EDR_EXECUTION_MODE", "").strip().lower()
        id_mode = os.environ.get("IDENTITY_EXECUTION_MODE", "").strip().lower()
        edr_dry = os.environ.get("EDR_DRY_RUN", "").strip().lower()
        id_dry = os.environ.get("IDENTITY_DRY_RUN", "").strip().lower()

        # Both must explicitly demand live mode to exit dry-run safety
        if (edr_mode == "live" or edr_dry in ("false", "0", "no")) and (
            id_mode == "live" or id_dry in ("false", "0", "no")
        ):
            is_dry_run = False
        else:
            is_dry_run = True
    else:
        is_dry_run = bool(dry_run)

    raw_alert_id = "UNKNOWN"
    if isinstance(alert, dict):
        raw_alert_id = str(alert.get("alert_id") or "UNKNOWN")
    elif hasattr(alert, "alert_id"):
        raw_alert_id = str(getattr(alert, "alert_id") or "UNKNOWN")

    logger.info(
        "COORDINATED INCIDENT RESPONSE INITIATED: alert_id=%s, dry_run=%s",
        raw_alert_id,
        is_dry_run,
    )

    # 1. Operation A: Network Containment (EDR)
    edr_result = execute_network_containment(
        alert=alert,
        policy=containment_policy,
        dry_run=is_dry_run,
        edr_client=edr_client,
        comment=comment or f"Coordinated response for alert {raw_alert_id}",
        force=force,
        raise_on_invalid=False,
    )

    # 2. Operation B: Account Suspension (IdP)
    suspension_result = execute_account_suspension(
        alert=alert,
        policy=identity_policy,
        dry_run=is_dry_run,
        identity_client=identity_client,
        reason=comment or f"Coordinated response for alert {raw_alert_id}",
        force=force,
        record_audit=True,
        db_path=db_path,
    )

    # 3. Operation C: Session Revocation (IdP)
    revocation_result = execute_session_revocation(
        alert=alert,
        policy=identity_policy,
        dry_run=is_dry_run,
        identity_client=identity_client,
        force=force,
        record_audit=True,
        db_path=db_path,
    )

    # 4. Compute Overall Workflow Status
    ec_status = edr_result.get("status")
    as_status = suspension_result.get("status")
    sr_status = revocation_result.get("status")

    if is_dry_run:
        overall_status = STATUS_SIMULATED
        overall_message = "Response workflow simulated; no real actions executed."
    else:
        # Evaluate live statuses
        active_statuses = [ec_status, as_status, sr_status]
        confirmed_count = sum(1 for s in active_statuses if s == STATUS_CONFIRMED)
        failed_count = sum(1 for s in active_statuses if s in (STATUS_FAILED, STATUS_UNKNOWN))
        rejected_count = sum(1 for s in active_statuses if s in (STATUS_REJECTED, STATUS_NOT_RECOMMENDED, STATUS_UNSUPPORTED))

        if confirmed_count == 3:
            overall_status = STATUS_CONFIRMED
            overall_message = "Coordinated response fully confirmed across all endpoints and identity actions."
        elif confirmed_count > 0 and (failed_count > 0 or rejected_count > 0):
            overall_status = "PARTIAL_SUCCESS"
            overall_message = f"Coordinated response completed with partial success ({confirmed_count} confirmed, {failed_count} failed/unknown, {rejected_count} rejected/unsupported)."
        elif failed_count > 0 and confirmed_count == 0:
            overall_status = STATUS_FAILED
            overall_message = "All attempted coordinated response actions failed."
        elif all(s in (STATUS_REJECTED, STATUS_NOT_RECOMMENDED) for s in active_statuses):
            overall_status = STATUS_NOT_RECOMMENDED
            overall_message = "No response actions recommended or permitted by policy."
        else:
            overall_status = STATUS_UNKNOWN
            overall_message = "Coordinated response finished with mixed or ambiguous outcomes."

    # 5. Synchronize Incident Lifecycle Status in SQLite
    incident_status_val = None
    if record_incident:
        try:
            inc = get_incident_by_alert_id(raw_alert_id, db_path=db_path)
            if inc:
                if ec_status == STATUS_CONFIRMED:
                    update_incident_status(raw_alert_id, IncidentStatus.CONTAINED, db_path=db_path)
                    incident_status_val = IncidentStatus.CONTAINED.value
                elif as_status == STATUS_CONFIRMED and inc.status == IncidentStatus.NEW:
                    update_incident_status(raw_alert_id, IncidentStatus.INVESTIGATING, db_path=db_path)
                    incident_status_val = IncidentStatus.INVESTIGATING.value
                else:
                    incident_status_val = inc.status.value
        except Exception as db_err:
            logger.debug("Database incident synchronization skipped or unavailable: %s", db_err)

    # 6. Assemble Structured Output conforming to Step 10
    response_payload = {
        "alert_id": raw_alert_id,
        "incident_id": raw_alert_id,
        "endpoint_containment": {
            "status": ec_status,
            "action": "ISOLATE_ENDPOINT",
            "endpoint_id": edr_result.get("endpoint_id"),
            "provider": edr_result.get("edr_provider"),
            "action_id": edr_result.get("action_id"),
            "message": edr_result.get("message"),
        },
        "account_suspension": {
            "status": as_status,
            "action": ACTION_SUSPEND_ACCOUNT,
            "user_id": suspension_result.get("user_id"),
            "user_principal_name": suspension_result.get("user_principal_name"),
            "provider": suspension_result.get("identity_provider"),
            "action_id": suspension_result.get("action_id"),
            "message": suspension_result.get("message"),
        },
        "session_revocation": {
            "status": sr_status,
            "action": ACTION_REVOKE_SESSIONS,
            "user_id": revocation_result.get("user_id"),
            "user_principal_name": revocation_result.get("user_principal_name"),
            "provider": revocation_result.get("identity_provider"),
            "action_id": revocation_result.get("action_id"),
            "message": revocation_result.get("message"),
        },
        "overall_status": overall_status,
        "message": overall_message,
    }

    if incident_status_val is not None:
        response_payload["incident_status"] = incident_status_val

    # 7. Coordinated Audit Entry
    if record_incident:
        record_audit_log(
            alert_id=raw_alert_id,
            action="COORDINATED_RESPONSE",
            execution_mode=EXECUTION_MODE_DRY_RUN if is_dry_run else EXECUTION_MODE_LIVE,
            status=overall_status,
            message=overall_message,
            details={
                "endpoint_containment": ec_status,
                "account_suspension": as_status,
                "session_revocation": sr_status,
            },
            db_path=db_path,
        )

    logger.info(
        "COORDINATED INCIDENT RESPONSE COMPLETED: alert_id=%s, overall_status=%s, incident_status=%s",
        raw_alert_id,
        overall_status,
        incident_status_val or "N/A",
    )

    return response_payload

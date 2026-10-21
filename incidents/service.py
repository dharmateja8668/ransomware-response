# incidents/service.py
"""
Business logic and service layer for managing incident records.
Decoupled from HTTP routes and directly interacts with the SQLite database.
"""

from datetime import datetime, timezone
import json
import logging
import re
import sqlite3
from typing import Any, Dict, List, Optional

from incidents.database import get_db, init_db
from incidents.models import (
    IncidentAuditLogResponse,
    IncidentCreate,
    IncidentResponse,
    IncidentStatus,
)

logger = logging.getLogger("orchestrator.audit")


class IncidentDuplicateError(Exception):
    """Raised when an incident with the given alert_id already exists."""


class IncidentNotFoundError(Exception):
    """Raised when an incident with the given alert_id cannot be found."""


class IncidentValidationError(Exception):
    """Raised when an incident payload or field fails business validation."""


def _row_to_incident(row: sqlite3.Row) -> IncidentResponse:
    """Helper to convert an SQLite Row into an IncidentResponse model."""
    return IncidentResponse(
        alert_id=row["alert_id"],
        threat_type=row["threat_type"],
        severity=row["severity"],
        description=row["description"],
        hostname=row["hostname"],
        ip_address=row["ip_address"],
        username=row["username"],
        process_hash=row["process_hash"],
        timestamp=row["timestamp"],
        status=IncidentStatus(row["status"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def create_incident(data: IncidentCreate, db_path: Optional[str] = None) -> IncidentResponse:
    """
    Creates and stores a new incident record.
    Enforces uniqueness of alert_id to prevent duplicates.
    """
    init_db(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    status_val = data.status.value if isinstance(data.status, IncidentStatus) else (data.status or IncidentStatus.NEW.value)

    with get_db(db_path) as conn:
        cursor = conn.execute(
            "SELECT alert_id FROM incidents WHERE alert_id = ?",
            (data.alert_id,),
        )
        if cursor.fetchone():
            raise IncidentDuplicateError(f"Incident with alert_id '{data.alert_id}' already exists.")

        conn.execute(
            """
            INSERT INTO incidents (
                alert_id, threat_type, severity, description,
                hostname, ip_address, username, process_hash,
                timestamp, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data.alert_id,
                data.threat_type,
                data.severity,
                data.description,
                data.hostname,
                data.ip_address,
                data.username,
                data.process_hash,
                data.timestamp,
                status_val,
                now_iso,
                now_iso,
            ),
        )

    return IncidentResponse(
        alert_id=data.alert_id,
        threat_type=data.threat_type,
        severity=data.severity,
        description=data.description,
        hostname=data.hostname,
        ip_address=data.ip_address,
        username=data.username,
        process_hash=data.process_hash,
        timestamp=data.timestamp,
        status=IncidentStatus(status_val),
        created_at=now_iso,
        updated_at=now_iso,
    )


def get_incident_by_alert_id(alert_id: str, db_path: Optional[str] = None) -> Optional[IncidentResponse]:
    """
    Retrieves a single incident by its alert_id.
    Returns None if no matching incident exists.
    """
    init_db(db_path)
    with get_db(db_path) as conn:
        cursor = conn.execute(
            "SELECT * FROM incidents WHERE alert_id = ?",
            (alert_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return _row_to_incident(row)


def list_incidents(
    status: Optional[str] = None,
    severity: Optional[int] = None,
    limit: int = 100,
    db_path: Optional[str] = None,
) -> List[IncidentResponse]:
    """
    Retrieves a list of incidents with optional filtering by status and severity.
    Results are ordered by creation timestamp descending.
    """
    init_db(db_path)
    query = "SELECT * FROM incidents"
    conditions = []
    params = []

    if status:
        # Normalize status comparison
        conditions.append("status = ?")
        params.append(status.upper())

    if severity is not None:
        conditions.append("severity = ?")
        params.append(severity)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with get_db(db_path) as conn:
        cursor = conn.execute(query, tuple(params))
        rows = cursor.fetchall()
        return [_row_to_incident(r) for r in rows]


def update_incident_status(
    alert_id: str,
    new_status: IncidentStatus,
    db_path: Optional[str] = None,
) -> IncidentResponse:
    """
    Updates the lifecycle status and updated_at timestamp of an existing incident.
    Raises IncidentNotFoundError if the incident does not exist.
    """
    init_db(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    status_val = new_status.value if isinstance(new_status, IncidentStatus) else str(new_status)

    with get_db(db_path) as conn:
        cursor = conn.execute(
            "SELECT alert_id FROM incidents WHERE alert_id = ?",
            (alert_id,),
        )
        if not cursor.fetchone():
            raise IncidentNotFoundError(f"Incident with alert_id '{alert_id}' was not found.")

        conn.execute(
            "UPDATE incidents SET status = ?, updated_at = ? WHERE alert_id = ?",
            (status_val, now_iso, alert_id),
        )

    # Return the updated record
    record = get_incident_by_alert_id(alert_id, db_path)
    if not record:
        raise IncidentNotFoundError(f"Incident with alert_id '{alert_id}' was not found.")
    return record


_SENSITIVE_KEY_PATTERN = re.compile(
    r"(secret|password|token|bearer|authorization|api[-_]?key|credential)",
    re.IGNORECASE,
)
_BEARER_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]+", re.IGNORECASE)


def sanitize_audit_data(val: Any) -> Any:
    """
    Recursively scrubs credentials, secrets, tokens, and authorization headers
    from data before recording in logs or persistent audit storage.
    """
    if isinstance(val, dict):
        sanitized = {}
        for k, v in val.items():
            if _SENSITIVE_KEY_PATTERN.search(str(k)):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_audit_data(v)
        return sanitized
    elif isinstance(val, list):
        return [sanitize_audit_data(item) for item in val]
    elif isinstance(val, str):
        # Scrub inline bearer tokens or auth headers
        scrubbed = _BEARER_PATTERN.sub("Bearer [REDACTED]", val)
        return scrubbed
    return val


def record_audit_log(
    alert_id: str,
    action: str,
    execution_mode: str,
    status: str,
    incident_id: Optional[str] = None,
    identity_provider: Optional[str] = None,
    user_id: Optional[str] = None,
    message: Optional[str] = None,
    correlation_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None,
    db_path: Optional[str] = None,
) -> IncidentAuditLogResponse:
    """
    Records an incident audit entry in the SQLite audit log table and emits a safe log line.
    Enforces strict sanitization to guarantee credentials, access tokens, and secrets
    are NEVER persisted or logged.
    """
    init_db(db_path)
    now_iso = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    clean_details = sanitize_audit_data(details) if details else None
    clean_message = sanitize_audit_data(message) if message else None
    details_json = json.dumps(clean_details) if clean_details is not None else None

    # Safe log emission without secrets
    logger.info(
        "AUDIT: alert_id=%s, action=%s, mode=%s, status=%s, provider=%s, user=%s, action_id=%s",
        alert_id,
        action,
        execution_mode,
        status,
        identity_provider or "N/A",
        user_id or "N/A",
        correlation_id or "N/A",
    )

    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO incident_audit_logs (
                alert_id, incident_id, identity_provider, user_id,
                action, execution_mode, status, message,
                correlation_id, details, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                incident_id or alert_id,
                identity_provider,
                user_id,
                action,
                execution_mode,
                status,
                clean_message,
                correlation_id,
                details_json,
                now_iso,
            ),
        )
        row_id = cursor.lastrowid

    return IncidentAuditLogResponse(
        id=row_id,
        alert_id=alert_id,
        incident_id=incident_id or alert_id,
        identity_provider=identity_provider,
        user_id=user_id,
        action=action,
        execution_mode=execution_mode,
        status=status,
        message=clean_message,
        correlation_id=correlation_id,
        details=clean_details,
        timestamp=now_iso,
    )


def get_audit_logs_for_alert(
    alert_id: str,
    db_path: Optional[str] = None,
) -> List[IncidentAuditLogResponse]:
    """
    Retrieves all audit logs recorded for a specific alert_id ordered chronologically.
    """
    init_db(db_path)
    with get_db(db_path) as conn:
        cursor = conn.execute(
            "SELECT * FROM incident_audit_logs WHERE alert_id = ? ORDER BY id ASC",
            (alert_id,),
        )
        rows = cursor.fetchall()
        results: List[IncidentAuditLogResponse] = []
        for r in rows:
            details_dict = None
            if r["details"]:
                try:
                    details_dict = json.loads(r["details"])
                except Exception:
                    details_dict = {"raw": r["details"]}
            results.append(
                IncidentAuditLogResponse(
                    id=r["id"],
                    alert_id=r["alert_id"],
                    incident_id=r["incident_id"],
                    identity_provider=r["identity_provider"],
                    user_id=r["user_id"],
                    action=r["action"],
                    execution_mode=r["execution_mode"],
                    status=r["status"],
                    message=r["message"],
                    correlation_id=r["correlation_id"],
                    details=details_dict,
                    timestamp=r["timestamp"],
                )
            )
        return results

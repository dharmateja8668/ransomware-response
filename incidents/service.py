# incidents/service.py
"""
Business logic and service layer for managing incident records.
Decoupled from HTTP routes and directly interacts with the SQLite database.
"""

from datetime import datetime, timezone
import sqlite3
from typing import List, Optional

from incidents.database import get_db, init_db
from incidents.models import (
    IncidentCreate,
    IncidentResponse,
    IncidentStatus,
)


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

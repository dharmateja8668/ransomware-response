# incidents/coordination.py
"""
Persistent Action Deduplication & Concurrency Coordination Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Purpose : Prevents duplicate containment and identity response actions across
          multiple Uvicorn/FastAPI worker processes.

Features:
  - Database-backed persistence using SQLite with transactional concurrency controls.
  - Multi-worker safe: Leverages database-level PRIMARY KEY integrity constraints and
    atomic conditional updates, avoiding reliance on process-local threading locks.
  - Non-blocking: Acquires lock in an atomic transaction and releases DB locks
    immediately before long-running external EDR or Graph API calls.
  - Crash / stale recovery: Automatically reclaims stale 'IN_PROGRESS' locks.
  - Cooldown enforcement: Suppresses duplicate requests within configurable window.
"""

from datetime import datetime, timezone, timedelta
import json
import logging
import sqlite3
from typing import Any, Dict, Optional, Union

from incidents.database import get_db, init_db

logger = logging.getLogger("orchestrator.coordination")

# Action types
ACTION_TYPE_CONTAINMENT = "containment"
ACTION_TYPE_ACCOUNT_SUSPENSION = "account_suspension"
ACTION_TYPE_SESSION_REVOCATION = "session_revocation"

# Status values
STATUS_IN_PROGRESS = "IN_PROGRESS"
STATUS_CONFIRMED = "CONFIRMED"
STATUS_REQUESTED = "REQUESTED"
STATUS_SIMULATED = "SIMULATED"
STATUS_FAILED = "FAILED"
STATUS_REJECTED = "REJECTED"


class ActionDeduplicationStore:
    """
    Coordinates and persists action execution state to prevent duplicate operations
    across multi-process deployments.
    """

    def __init__(
        self,
        db_path_or_cooldown: Optional[Union[str, int, float]] = None,
        default_cooldown_seconds: int = 300,
        in_progress_timeout_seconds: float = 60.0,
        db_path: Optional[str] = None,
    ) -> None:
        if isinstance(db_path_or_cooldown, str):
            self.db_path: Optional[str] = db_path_or_cooldown
            self.default_cooldown_seconds: int = default_cooldown_seconds
        elif isinstance(db_path_or_cooldown, (int, float)):
            self.default_cooldown_seconds = int(db_path_or_cooldown)
            self.db_path = db_path
        else:
            self.default_cooldown_seconds = default_cooldown_seconds
            self.db_path = db_path
        self.in_progress_timeout_seconds: float = float(in_progress_timeout_seconds)

    @staticmethod
    def _make_key(action_type: str, target_id: str) -> str:
        return f"{action_type.strip().lower()}:{target_id.strip()}"

    def acquire_action_lock(
        self,
        action_type: str,
        target_id: str,
        alert_id: str,
        provider: str = "general",
        cooldown_seconds: Optional[int] = None,
        db_path: Optional[str] = None,
        lock_timeout_seconds: Optional[float] = None,
    ) -> bool:
        """
        Attempts to atomically acquire an execution lock for a given action and target.

        Concurrency & Atomicity Guarantee:
          - Leverages SQLite PRIMARY KEY unique constraint on `action_key`.
          - If row doesn't exist, INSERT succeeds atomically.
          - If row exists, an atomic conditional UPDATE is executed that only updates if the
            prior lock is expired or stale.
          - This eliminates race conditions across multiple worker processes without external locks.

        Returns:
            True if lock was acquired; False if duplicate or active lock is in-progress.
        """
        active_db = db_path or self.db_path
        init_db(active_db)
        timeout = lock_timeout_seconds if lock_timeout_seconds is not None else self.in_progress_timeout_seconds
        key = self._make_key(action_type, target_id)
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()
        in_progress_expires_iso = (now_dt + timedelta(seconds=timeout)).isoformat()

        with get_db(active_db) as conn:
            # 1. Optimistic insert: If the action key is completely new, INSERT will succeed.
            try:
                conn.execute(
                    """
                    INSERT INTO action_deduplication (
                        action_key, action_type, target_id, alert_id, provider,
                        status, action_id, initiated_at, updated_at, expires_at, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key,
                        action_type,
                        target_id,
                        alert_id,
                        provider,
                        STATUS_IN_PROGRESS,
                        None,
                        now_iso,
                        now_iso,
                        in_progress_expires_iso,
                        json.dumps({"attempt_alert_id": alert_id, "lock_timeout": timeout}),
                    ),
                )
                return True
            except sqlite3.IntegrityError:
                # Row already exists; proceed to conditional update check
                pass

            # 2. Atomic Conditional Update: Only acquires if existing action is expired or stale
            cursor = conn.execute(
                """
                UPDATE action_deduplication
                SET alert_id = ?, provider = ?, status = ?, action_id = NULL,
                    initiated_at = ?, updated_at = ?, expires_at = ?, details = ?
                WHERE action_key = ? AND (
                    (status = ? AND expires_at < ?)
                    OR (status IN (?, ?) AND expires_at < ?)
                    OR (status = ?)
                )
                """,
                (
                    alert_id,
                    provider,
                    STATUS_IN_PROGRESS,
                    now_iso,
                    now_iso,
                    in_progress_expires_iso,
                    json.dumps({"attempt_alert_id": alert_id, "lock_timeout": timeout}),
                    key,
                    STATUS_IN_PROGRESS,
                    now_iso,
                    STATUS_CONFIRMED,
                    STATUS_REQUESTED,
                    now_iso,
                    STATUS_FAILED,
                ),
            )
            return cursor.rowcount > 0

    def complete_action(
        self,
        action_type: str,
        target_id: str,
        status: str,
        action_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        cooldown_seconds: Optional[int] = None,
        db_path: Optional[str] = None,
    ) -> None:
        """
        Updates the action record with the final execution result and sets cooldown expiration.
        """
        active_db = db_path or self.db_path
        init_db(active_db)
        cooldown = cooldown_seconds if cooldown_seconds is not None else self.default_cooldown_seconds
        key = self._make_key(action_type, target_id)
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()
        expires_iso = (now_dt + timedelta(seconds=cooldown)).isoformat()
        details_str = json.dumps(details) if details else None

        with get_db(active_db) as conn:
            # Check if record exists; if not, insert it (direct completion)
            cursor = conn.execute(
                """
                UPDATE action_deduplication
                SET status = ?, action_id = ?, updated_at = ?, expires_at = ?, details = ?
                WHERE action_key = ?
                """,
                (status, action_id, now_iso, expires_iso, details_str, key),
            )
            if cursor.rowcount == 0:
                conn.execute(
                    """
                    INSERT INTO action_deduplication (
                        action_key, action_type, target_id, alert_id, provider,
                        status, action_id, initiated_at, updated_at, expires_at, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key,
                        action_type,
                        target_id,
                        action_id or "direct_action",
                        "general",
                        status,
                        action_id,
                        now_iso,
                        now_iso,
                        expires_iso,
                        details_str,
                    ),
                )

    def mark_completed(
        self,
        action_type: str,
        target_id: str,
        alert_id: str,
        status: str,
        telemetry: Optional[Dict[str, Any]] = None,
        cooldown_seconds: Optional[int] = None,
        db_path: Optional[str] = None,
    ) -> None:
        """Convenience method to mark an action completed."""
        self.complete_action(
            action_type=action_type,
            target_id=target_id,
            status=status,
            action_id=alert_id,
            details=telemetry,
            cooldown_seconds=cooldown_seconds,
            db_path=db_path or self.db_path,
        )

    def mark_failure(
        self,
        action_type: str,
        target_id: str,
        alert_id: str,
        error: Optional[str] = None,
        db_path: Optional[str] = None,
    ) -> None:
        """Convenience method to mark an action as failed."""
        self.complete_action(
            action_type=action_type,
            target_id=target_id,
            status=STATUS_FAILED,
            action_id=alert_id,
            details={"error": error or "Action execution failed"},
            cooldown_seconds=0,
            db_path=db_path or self.db_path,
        )

    def is_action_active(
        self,
        action_type: str,
        target_id: str,
        db_path: Optional[str] = None,
    ) -> bool:
        """Checks whether an action on the target is active within its cooldown window."""
        active_db = db_path or self.db_path
        init_db(active_db)
        key = self._make_key(action_type, target_id)
        now_dt = datetime.now(timezone.utc)

        with get_db(active_db) as conn:
            cursor = conn.execute(
                "SELECT status, expires_at FROM action_deduplication WHERE action_key = ?",
                (key,),
            )
            row = cursor.fetchone()
            if not row:
                return False

            status = row["status"]
            expires_at_str = row["expires_at"]
            if status in (STATUS_CONFIRMED, STATUS_REQUESTED, STATUS_SIMULATED):
                try:
                    exp_dt = datetime.fromisoformat(expires_at_str)
                    return now_dt < exp_dt
                except Exception:
                    return False

            return False

    def check_existing_action(
        self,
        action_type: str,
        target_id: str,
        db_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Returns the active record if within cooldown, or None if expired/not found."""
        record = self.get_action_record(action_type, target_id, db_path=db_path or self.db_path)
        if not record:
            return None

        rec_status = record.get("status")
        if rec_status == STATUS_FAILED:
            return record

        if self.is_action_active(action_type, target_id, db_path=db_path or self.db_path):
            return record

        return None

    def release_action(
        self,
        action_type: str,
        target_id: str,
        db_path: Optional[str] = None,
    ) -> bool:
        """Removes a lock or completed entry, allowing immediate re-execution."""
        active_db = db_path or self.db_path
        init_db(active_db)
        key = self._make_key(action_type, target_id)
        with get_db(active_db) as conn:
            cursor = conn.execute(
                "DELETE FROM action_deduplication WHERE action_key = ?",
                (key,),
            )
            return cursor.rowcount > 0

    def get_action_record(
        self,
        action_type: str,
        target_id: str,
        db_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieves raw action coordination record."""
        active_db = db_path or self.db_path
        init_db(active_db)
        key = self._make_key(action_type, target_id)
        with get_db(active_db) as conn:
            cursor = conn.execute(
                "SELECT * FROM action_deduplication WHERE action_key = ?",
                (key,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            if res.get("details"):
                try:
                    res["telemetry"] = json.loads(res["details"])
                except Exception:
                    res["telemetry"] = {}
            else:
                res["telemetry"] = {}
            return res

    def clear(self, db_path: Optional[str] = None) -> None:
        """Clears all deduplication records (for testing)."""
        active_db = db_path or self.db_path
        init_db(active_db)
        with get_db(active_db) as conn:
            conn.execute("DELETE FROM action_deduplication")


# Singleton store instance
_GLOBAL_DEDUP_STORE: Optional[ActionDeduplicationStore] = None


def get_dedup_store(db_path: Optional[str] = None) -> ActionDeduplicationStore:
    global _GLOBAL_DEDUP_STORE
    if db_path:
        return ActionDeduplicationStore(db_path=db_path)
    if _GLOBAL_DEDUP_STORE is None:
        _GLOBAL_DEDUP_STORE = ActionDeduplicationStore()
    return _GLOBAL_DEDUP_STORE

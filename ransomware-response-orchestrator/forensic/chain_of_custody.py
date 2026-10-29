"""
forensic/chain_of_custody.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Forensic Chain-of-Custody & Cryptographic Audit Trail Module.
Automated Ransomware Containment & Incident Response Orchestrator - Day 5.

Provides a tamper-evident, hash-linked cryptographic audit ledger recording
evidence-handling events throughout the digital forensics lifecycle.

Key Capabilities:
  - Append-only event ledger tracking evidence acquisition, verification,
    indexing, cloud archival, analysis, and access.
  - Deterministic serialization and SHA-256 hash chaining (block-linked audit log).
  - Rigorous chain verification detecting tampered, deleted, or reordered records.
  - Concurrency-safe SQLite transactions with Write-Ahead Logging (WAL) and IMMEDIATE locks.
  - SQLite database triggers enforcing record immutability (preventing accidental SQL UPDATE/DELETE).
  - Automated redaction of sensitive secrets (tokens, API keys, passwords, AWS credentials).
  - Explicit differentiation between simulated (MOCK) and production (REAL) operations.
  - Configurable audit failure policies (Strict vs Permissive) for security-critical operations.

Security Architecture & Tamper-Resistance Disclosure:
  A hash chain stored in a writable SQLite database file is not independently
  tamper-proof against an adversary possessing filesystem-level write access who
  could alter historical records and recompute all subsequent event hashes.
  To achieve legal defensibility in judicial proceedings, local hash chains should
  be reinforced with:
    1. Strict OS file ACLs and restricted process ownership.
    2. Real-time streaming to an external, write-once SIEM (e.g., Azure Sentinel, Splunk).
    3. Immutable cloud replication (e.g., AWS S3 Object Lock in Compliance Mode).
    4. Hardware Security Module (HSM) or asymmetric key timestamped signatures.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

logger = logging.getLogger("orchestrator.forensic.chain_of_custody")

DEFAULT_AUDIT_DB = "evidence_catalog.db"
GENESIS_HASH = "0" * 64  # Documented 64-character hex zero genesis hash


# ─────────────────────────────────────────────────────────────────────────────
# Audit Actions & Enums
# ─────────────────────────────────────────────────────────────────────────────

class AuditAction(str, Enum):
    """Standardized lifecycle actions recorded in the chain of custody."""
    # Day 1: Containment Verification
    CONTAINMENT_VERIFIED = "CONTAINMENT_VERIFIED"
    CONTAINMENT_FAILED = "CONTAINMENT_FAILED"

    # Day 2: Evidence Acquisition
    COLLECTION_REQUESTED = "COLLECTION_REQUESTED"
    COLLECTION_STARTED = "COLLECTION_STARTED"
    COLLECTION_COMPLETED = "COLLECTION_COMPLETED"
    COLLECTION_FAILED = "COLLECTION_FAILED"

    # Cryptographic Integrity
    HASH_CALCULATED = "HASH_CALCULATED"
    INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
    INTEGRITY_REJECTED = "INTEGRITY_REJECTED"

    # Day 3: Cloud Storage
    S3_UPLOADED = "S3_UPLOADED"
    S3_UPLOAD_FAILED = "S3_UPLOAD_FAILED"

    # Day 4: Catalog & Analysis
    EVIDENCE_INDEXED = "EVIDENCE_INDEXED"
    INDEXING_FAILED = "INDEXING_FAILED"
    EVIDENCE_RETRIEVED = "EVIDENCE_RETRIEVED"
    RETRIEVAL_FAILED = "RETRIEVAL_FAILED"
    ANALYSIS_COMPLETED = "ANALYSIS_COMPLETED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"

    # Evidence Access & Transfer
    EVIDENCE_ACCESSED = "EVIDENCE_ACCESSED"
    EVIDENCE_EXPORTED = "EVIDENCE_EXPORTED"


class AuditStatus(str, Enum):
    """Standardized outcomes of an audited operation."""
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    WARNING = "WARNING"


class ExecutionMode(str, Enum):
    """Execution environment indicating whether an action was simulated or live."""
    MOCK = "MOCK"
    REAL = "REAL"


class AuditPolicy(str, Enum):
    """Policy for handling audit write failures."""
    STRICT = "STRICT"        # Raises AuditLoggingError to halt unsafe operations
    PERMISSIVE = "PERMISSIVE"  # Logs failure but allows caller to proceed


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class ChainOfCustodyError(Exception):
    """Base exception for all chain-of-custody and audit operations."""


class AuditLoggingError(ChainOfCustodyError):
    """Raised when an audit record fails to persist and strict mode is active."""


class AuditIntegrityError(ChainOfCustodyError):
    """Raised when the cryptographic audit chain verification fails."""


# ─────────────────────────────────────────────────────────────────────────────
# Secret Sanitization
# ─────────────────────────────────────────────────────────────────────────────

# Patterns matching sensitive secrets
BEARER_TOKEN_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{15,}", re.IGNORECASE)
AWS_KEY_PATTERN = re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}")
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:password|secret|token|auth|key|credential|private)", re.IGNORECASE
)


def sanitize_audit_details(data: Any) -> Any:
    """
    Recursively strips or redacts credentials, passwords, Bearer tokens,
    and API secrets from audit record details.
    """
    if isinstance(data, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in data.items():
            if SENSITIVE_KEY_PATTERN.search(str(k)):
                cleaned[str(k)] = "***REDACTED_SECRET***"
            else:
                cleaned[str(k)] = sanitize_audit_details(v)
        return cleaned
    elif isinstance(data, (list, tuple)):
        return [sanitize_audit_details(item) for item in data]
    elif isinstance(data, (int, float, bool, type(None))):
        return data
    elif isinstance(data, str):
        redacted = BEARER_TOKEN_PATTERN.sub("Bearer ***REDACTED_TOKEN***", data)
        redacted = AWS_KEY_PATTERN.sub("***REDACTED_AWS_KEY***", redacted)
        return redacted
    else:
        return str(data)


# ─────────────────────────────────────────────────────────────────────────────
# Audit Event & Verification Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AuditEvent:
    """Represents a single immutable chain-of-custody event."""
    event_id: str
    action: str
    status: str
    timestamp: str
    actor: str
    execution_mode: str
    event_hash: str
    previous_event_hash: str
    sequence_number: Optional[int] = None
    incident_id: Optional[str] = None
    evidence_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    evidence_hash: Optional[str] = None
    source_location: Optional[str] = None
    destination_location: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts audit event to a serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_row(cls, row: Union[sqlite3.Row, Dict[str, Any]]) -> AuditEvent:
        """Constructs an AuditEvent from an SQLite row."""
        raw_details = row["details_json"] if "details_json" in row.keys() else "{}"
        if isinstance(raw_details, str):
            try:
                details = json.loads(raw_details) if raw_details else {}
            except Exception:
                details = {"raw": raw_details}
        elif isinstance(raw_details, dict):
            details = raw_details
        else:
            details = {}

        return cls(
            sequence_number=row["sequence_number"],
            event_id=row["event_id"],
            action=row["action"],
            status=row["status"],
            timestamp=row["timestamp"],
            actor=row["actor"],
            execution_mode=row["execution_mode"],
            event_hash=row["event_hash"],
            previous_event_hash=row["previous_event_hash"],
            incident_id=row["incident_id"],
            evidence_id=row["evidence_id"],
            endpoint_id=row["endpoint_id"],
            evidence_hash=row["evidence_hash"],
            source_location=row["source_location"],
            destination_location=row["destination_location"],
            details=details,
        )


@dataclass
class AuditVerificationResult:
    """Detailed report of an audit chain integrity verification."""
    is_valid: bool
    total_events: int
    verified_events: int
    verified_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    error_message: Optional[str] = None
    compromised_event_id: Optional[str] = None
    compromised_sequence: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Chain of Custody Service
# ─────────────────────────────────────────────────────────────────────────────

class ChainOfCustodyService:
    """
    Manages the cryptographically linked chain-of-custody audit trail.
    Ensures safe concurrent writes, tamper-evident hash validation, and query APIs.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        policy: AuditPolicy = AuditPolicy.STRICT,
        auto_init: bool = True,
    ) -> None:
        """
        Initializes the Chain of Custody Service.

        Args:
            db_path: Path to SQLite DB file or ':memory:'. Defaults to
                     CHAIN_OF_CUSTODY_DB or EVIDENCE_CATALOG_DB or 'evidence_catalog.db'.
            policy: AuditPolicy.STRICT (default) or AuditPolicy.PERMISSIVE.
            auto_init: Whether to initialize database schema immediately.
        """
        env_path = os.getenv("CHAIN_OF_CUSTODY_DB") or os.getenv("EVIDENCE_CATALOG_DB")
        self.db_path = db_path or env_path or DEFAULT_AUDIT_DB
        self.policy = policy
        self._lock = threading.RLock()

        # For :memory: databases, keep a dedicated connection open so data survives
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys = ON;")

        if auto_init:
            self._init_db()

        logger.info(
            "ChainOfCustodyService initialized (DB=%s, Policy=%s)",
            self.db_path,
            self.policy.value,
        )

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provides a managed connection with WAL and Row factory."""
        if self._mem_conn is not None:
            with self._lock:
                try:
                    yield self._mem_conn
                    self._mem_conn.commit()
                except Exception:
                    self._mem_conn.rollback()
                    raise
            return

        conn = sqlite3.connect(self.db_path, timeout=20.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA busy_timeout = 20000;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initializes the SQLite chain_of_custody table, indexes, and immutability triggers."""
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_of_custody (
                    sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    execution_mode TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    previous_event_hash TEXT NOT NULL,
                    incident_id TEXT,
                    evidence_id TEXT,
                    endpoint_id TEXT,
                    evidence_hash TEXT,
                    source_location TEXT,
                    destination_location TEXT,
                    details_json TEXT
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_coc_incident ON chain_of_custody(incident_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_coc_evidence ON chain_of_custody(evidence_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_coc_event_hash ON chain_of_custody(event_hash);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_coc_timestamp ON chain_of_custody(timestamp);"
            )

            # Enforce immutability triggers to block ordinary SQL UPDATE/DELETE attempts
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS prevent_coc_update
                BEFORE UPDATE ON chain_of_custody
                BEGIN
                    SELECT RAISE(ABORT, 'Audit log records are immutable and cannot be updated.');
                END;
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS prevent_coc_delete
                BEFORE DELETE ON chain_of_custody
                BEGIN
                    SELECT RAISE(ABORT, 'Audit log records are immutable and cannot be deleted.');
                END;
                """
            )

    @staticmethod
    def compute_event_hash(
        event_id: str,
        sequence_number: Optional[int],
        action: str,
        status: str,
        timestamp: str,
        actor: str,
        execution_mode: str,
        previous_event_hash: str,
        incident_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
        endpoint_id: Optional[str] = None,
        evidence_hash: Optional[str] = None,
        source_location: Optional[str] = None,
        destination_location: Optional[str] = None,
        details: Optional[Union[Dict[str, Any], str]] = None,
    ) -> str:
        """
        Deterministically serializes audit event fields into a canonical JSON payload
        and computes the resulting SHA-256 hex digest.
        """
        # Ensure details are deterministic and sanitized
        clean_details = sanitize_audit_details(details or {})

        payload: Dict[str, Any] = {
            "action": str(action),
            "actor": str(actor),
            "destination_location": str(destination_location or ""),
            "details": clean_details,
            "endpoint_id": str(endpoint_id or ""),
            "event_id": str(event_id),
            "evidence_hash": str(evidence_hash or ""),
            "evidence_id": str(evidence_id or ""),
            "execution_mode": str(execution_mode),
            "incident_id": str(incident_id or ""),
            "previous_event_hash": str(previous_event_hash),
            "sequence_number": int(sequence_number) if sequence_number is not None else 0,
            "source_location": str(source_location or ""),
            "status": str(status),
            "timestamp": str(timestamp),
        }

        canonical_json = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def record_event(
        self,
        action: Union[AuditAction, str],
        status: Union[AuditStatus, str] = AuditStatus.SUCCESS,
        incident_id: Optional[Union[str, int]] = None,
        evidence_id: Optional[str] = None,
        endpoint_id: Optional[str] = None,
        actor: str = "orchestrator",
        evidence_hash: Optional[str] = None,
        source_location: Optional[str] = None,
        destination_location: Optional[str] = None,
        execution_mode: Optional[Union[ExecutionMode, str]] = None,
        details: Optional[Union[Dict[str, Any], str]] = None,
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> AuditEvent:
        """
        Atomically records a new audit event, linking it to the hash of the preceding event.

        Args:
            action: Lifecycle operation performed.
            status: SUCCESS, FAILURE, or WARNING.
            incident_id: Associated security incident identifier.
            evidence_id: Target evidence ID if applicable.
            endpoint_id: Target machine or endpoint identifier.
            actor: Subsystem, service, or operator identity.
            evidence_hash: SHA-256 hash of the evidence file when available.
            source_location: Original location of evidence.
            destination_location: Target destination (e.g. S3 URI or catalog).
            execution_mode: MOCK or REAL.
            details: Additional sanitized diagnostic details.
            event_id: Optional custom event UUID (generated if None).
            timestamp: Optional UTC timestamp (generated if None).

        Returns:
            AuditEvent recorded in the ledger.

        Raises:
            AuditLoggingError: If write fails and policy is STRICT.
        """
        # Format and validate inputs
        act_str = action.value if isinstance(action, AuditAction) else str(action).strip()
        stat_str = status.value if isinstance(status, AuditStatus) else str(status).strip()
        inc_str = str(incident_id).strip() if incident_id is not None else None
        ev_id_str = str(evidence_id).strip() if evidence_id is not None else None
        ep_id_str = str(endpoint_id).strip() if endpoint_id is not None else None
        evt_id = event_id or f"aud-{uuid.uuid4().hex[:12]}"
        ts = timestamp or datetime.now(timezone.utc).isoformat()

        if execution_mode is not None:
            exec_mode_str = (
                execution_mode.value
                if isinstance(execution_mode, ExecutionMode)
                else str(execution_mode).upper()
            )
        else:
            # Default to MOCK if environment indicates mock mode
            is_mock_env = os.getenv("EDR_MOCK_MODE", "true").lower() in ("true", "1", "yes")
            exec_mode_str = ExecutionMode.MOCK.value if is_mock_env else ExecutionMode.REAL.value

        clean_details = sanitize_audit_details(details or {})
        details_json_str = json.dumps(clean_details, sort_keys=True, ensure_ascii=True)

        max_retries = 5
        base_delay = 0.05

        for attempt in range(max_retries):
            try:
                with self._lock:
                    with self._get_connection() as conn:
                        # Use IMMEDIATE transaction to acquire exclusive write lock when not already in transaction
                        if not conn.in_transaction:
                            try:
                                conn.execute("BEGIN IMMEDIATE")
                            except sqlite3.OperationalError:
                                pass

                        # Determine the last recorded event in the ledger
                        cursor = conn.execute(
                            "SELECT sequence_number, event_hash FROM chain_of_custody "
                            "ORDER BY sequence_number DESC LIMIT 1"
                        )
                        last_row = cursor.fetchone()

                        if last_row is None:
                            prev_hash = GENESIS_HASH
                            next_seq = 1
                        else:
                            prev_hash = last_row["event_hash"]
                            next_seq = last_row["sequence_number"] + 1

                        # Calculate deterministic event hash
                        cur_hash = self.compute_event_hash(
                            event_id=evt_id,
                            sequence_number=next_seq,
                            action=act_str,
                            status=stat_str,
                            timestamp=ts,
                            actor=actor,
                            execution_mode=exec_mode_str,
                            previous_event_hash=prev_hash,
                            incident_id=inc_str,
                            evidence_id=ev_id_str,
                            endpoint_id=ep_id_str,
                            evidence_hash=evidence_hash,
                            source_location=source_location,
                            destination_location=destination_location,
                            details=clean_details,
                        )

                        conn.execute(
                            """
                            INSERT INTO chain_of_custody (
                                sequence_number,
                                event_id,
                                action,
                                status,
                                timestamp,
                                actor,
                                execution_mode,
                                event_hash,
                                previous_event_hash,
                                incident_id,
                                evidence_id,
                                endpoint_id,
                                evidence_hash,
                                source_location,
                                destination_location,
                                details_json
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                next_seq,
                                evt_id,
                                act_str,
                                stat_str,
                                ts,
                                actor,
                                exec_mode_str,
                                cur_hash,
                                prev_hash,
                                inc_str,
                                ev_id_str,
                                ep_id_str,
                                evidence_hash,
                                source_location,
                                destination_location,
                                details_json_str,
                            ),
                        )

                        event = AuditEvent(
                            sequence_number=next_seq,
                            event_id=evt_id,
                            action=act_str,
                            status=stat_str,
                            timestamp=ts,
                            actor=actor,
                            execution_mode=exec_mode_str,
                            event_hash=cur_hash,
                            previous_event_hash=prev_hash,
                            incident_id=inc_str,
                            evidence_id=ev_id_str,
                            endpoint_id=ep_id_str,
                            evidence_hash=evidence_hash,
                            source_location=source_location,
                            destination_location=destination_location,
                            details=clean_details,
                        )

                        logger.debug(
                            "Audit event recorded: seq=%d id=%s action=%s status=%s",
                            next_seq,
                            evt_id,
                            act_str,
                            stat_str,
                        )
                        return event

            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower() and attempt < max_retries - 1:
                    time.sleep(base_delay * (2 ** attempt))
                    continue
                err_msg = f"Database concurrency error recording audit event {act_str}: {exc}"
                logger.error(err_msg)
                if self.policy == AuditPolicy.STRICT:
                    raise AuditLoggingError(err_msg) from exc
                break
            except Exception as exc:
                err_msg = f"Unexpected error recording audit event {act_str}: {exc}"
                logger.exception(err_msg)
                if self.policy == AuditPolicy.STRICT:
                    raise AuditLoggingError(err_msg) from exc
                break

        # If we reach here, recording failed under PERMISSIVE policy
        return AuditEvent(
            sequence_number=None,
            event_id=evt_id,
            action=act_str,
            status=AuditStatus.FAILURE.value,
            timestamp=ts,
            actor=actor,
            execution_mode=exec_mode_str,
            event_hash="",
            previous_event_hash="",
            incident_id=inc_str,
            evidence_id=ev_id_str,
            endpoint_id=ep_id_str,
            details={"error": "Failed to persist audit event"},
        )

    def verify_audit_chain(self) -> AuditVerificationResult:
        """
        Cryptographically validates the entire audit hash chain.

        Verifications performed:
          1. Empty chain: returns is_valid=True.
          2. Genesis block: checks that event 1 points to GENESIS_HASH.
          3. Monotonic sequencing: verifies sequence numbers strictly increment by 1.
          4. Hash integrity: recalculates each event's hash from its fields and compares.
          5. Linkage integrity: verifies each event's previous_event_hash matches the prior event's hash.

        Returns:
            AuditVerificationResult detailing validity and any discovered anomaly.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM chain_of_custody ORDER BY sequence_number ASC"
            )
            rows = cursor.fetchall()

        if not rows:
            return AuditVerificationResult(
                is_valid=True,
                total_events=0,
                verified_events=0,
            )

        expected_prev_hash = GENESIS_HASH
        expected_seq = 1

        for idx, row in enumerate(rows, start=1):
            seq = row["sequence_number"]
            evt_id = row["event_id"]
            stored_hash = row["event_hash"]
            stored_prev_hash = row["previous_event_hash"]

            # 1. Check sequence ordering and gap detection
            if seq != expected_seq:
                err = (
                    f"Sequence discontinuity detected: Expected sequence #{expected_seq}, "
                    f"but encountered #{seq} at event '{evt_id}' (possible record deletion or reordering)."
                )
                logger.error(err)
                return AuditVerificationResult(
                    is_valid=False,
                    total_events=len(rows),
                    verified_events=idx - 1,
                    error_message=err,
                    compromised_event_id=evt_id,
                    compromised_sequence=seq,
                )

            # 2. Check previous hash linkage
            if stored_prev_hash != expected_prev_hash:
                err = (
                    f"Broken hash linkage at event '{evt_id}' (sequence #{seq}): "
                    f"stored previous_event_hash '{stored_prev_hash[:16]}...' does not match "
                    f"expected '{expected_prev_hash[:16]}...'."
                )
                logger.error(err)
                return AuditVerificationResult(
                    is_valid=False,
                    total_events=len(rows),
                    verified_events=idx - 1,
                    error_message=err,
                    compromised_event_id=evt_id,
                    compromised_sequence=seq,
                )

            # 3. Recalculate event hash from record contents
            raw_details = row["details_json"]
            try:
                details_obj = json.loads(raw_details) if raw_details else {}
            except Exception:
                details_obj = {"raw": raw_details}

            recomputed_hash = self.compute_event_hash(
                event_id=evt_id,
                sequence_number=seq,
                action=row["action"],
                status=row["status"],
                timestamp=row["timestamp"],
                actor=row["actor"],
                execution_mode=row["execution_mode"],
                previous_event_hash=stored_prev_hash,
                incident_id=row["incident_id"],
                evidence_id=row["evidence_id"],
                endpoint_id=row["endpoint_id"],
                evidence_hash=row["evidence_hash"],
                source_location=row["source_location"],
                destination_location=row["destination_location"],
                details=details_obj,
            )

            if recomputed_hash != stored_hash:
                err = (
                    f"Cryptographic hash mismatch at event '{evt_id}' (sequence #{seq}): "
                    f"Stored hash '{stored_hash[:16]}...' does not match recomputed '{recomputed_hash[:16]}...'. "
                    f"Record contents have been altered or tampered with."
                )
                logger.error(err)
                return AuditVerificationResult(
                    is_valid=False,
                    total_events=len(rows),
                    verified_events=idx - 1,
                    error_message=err,
                    compromised_event_id=evt_id,
                    compromised_sequence=seq,
                )

            expected_prev_hash = stored_hash
            expected_seq += 1

        logger.info(
            "Audit chain verification succeeded: %d records verified cryptographically intact.",
            len(rows),
        )
        return AuditVerificationResult(
            is_valid=True,
            total_events=len(rows),
            verified_events=len(rows),
        )

    def get_evidence_history(self, evidence_id: str) -> List[AuditEvent]:
        """
        Retrieves the complete chronological chain of custody for a specific evidence item.
        """
        if not evidence_id:
            return []
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM chain_of_custody WHERE evidence_id = ? ORDER BY sequence_number ASC",
                (str(evidence_id).strip(),),
            )
            return [AuditEvent.from_row(r) for r in cursor.fetchall()]

    def get_incident_history(self, incident_id: Union[str, int]) -> List[AuditEvent]:
        """
        Retrieves all audit events associated with a specific incident in chronological order.
        """
        if incident_id is None:
            return []
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM chain_of_custody WHERE incident_id = ? ORDER BY sequence_number ASC",
                (str(incident_id).strip(),),
            )
            return [AuditEvent.from_row(r) for r in cursor.fetchall()]

    def list_recent_events(self, limit: int = 50) -> List[AuditEvent]:
        """
        Returns the most recent audit events ordered by sequence number descending.
        """
        limit = max(1, min(int(limit), 1000))
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM chain_of_custody ORDER BY sequence_number DESC LIMIT ?",
                (limit,),
            )
            return [AuditEvent.from_row(r) for r in cursor.fetchall()]

    def get_event_by_id(self, event_id: str) -> Optional[AuditEvent]:
        """Retrieves a single audit event by its unique event_id."""
        if not event_id:
            return None
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM chain_of_custody WHERE event_id = ?",
                (str(event_id).strip(),),
            )
            row = cursor.fetchone()
            return AuditEvent.from_row(row) if row else None

    def get_last_event(self) -> Optional[AuditEvent]:
        """Retrieves the most recent audit event recorded in the ledger."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM chain_of_custody ORDER BY sequence_number DESC LIMIT 1"
            )
            row = cursor.fetchone()
            return AuditEvent.from_row(row) if row else None

    def count_events(self) -> int:
        """Returns the total number of events in the audit ledger."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) AS total FROM chain_of_custody")
            return cursor.fetchone()["total"]

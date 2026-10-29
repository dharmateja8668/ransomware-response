"""
services/evidence_catalog.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Forensic Evidence Catalog & Indexing Service.
Provides persistent SQLite storage, indexing, search, and cryptographic
integrity verification for digital evidence collected across incident workflows.

Key Features:
  - SQLite metadata catalog with ACID transaction safety and WAL support.
  - Automatic indexing by evidence ID, incident ID, device ID, and SHA-256 hash.
  - Fast multi-parameter search (incident, hostname, hash, evidence type).
  - Standalone and on-demand SHA-256 pre/post cryptographic integrity verification.
  - Seamless ingestion of Day 2/3 EvidenceMetadata objects.
  - Strict preservation of chain-of-custody and simulation indicators.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from forensic.metadata import EvidenceMetadata

logger = logging.getLogger("orchestrator.evidence_catalog")

DEFAULT_DB_PATH = "evidence_catalog.db"


class EvidenceCatalogError(Exception):
    """Base exception for evidence catalog operations."""


class EvidenceNotFoundError(EvidenceCatalogError):
    """Raised when an evidence ID is not found in the catalog."""


class EvidenceIntegrityError(EvidenceCatalogError):
    """Raised when evidence hash does not match the indexed hash."""


@dataclass
class CatalogRecord:
    """Represents a single indexed evidence record in SQLite."""
    evidence_id: str
    incident_id: str
    device_id: str
    device_name: str
    evidence_type: str
    file_name: str
    file_path: str
    file_size_bytes: int
    sha256_hash: str
    s3_bucket: Optional[str] = None
    s3_object_key: Optional[str] = None
    s3_upload_status: Optional[str] = None
    s3_checksum_sha256: Optional[str] = None
    s3_checksum_verified: bool = False
    s3_version_id: Optional[str] = None
    simulation_indicator: bool = False
    collected_at: str = ""
    indexed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata_json: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IntegrityCheckResult:
    """Represents the cryptographic verification result for an evidence file."""
    evidence_id: str
    file_path: str
    indexed_hash: str
    recalculated_hash: str
    is_valid: bool
    verified_at: str
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EvidenceCatalogService:
    """
    Manages SQLite-backed persistence, querying, and verification
    for forensic evidence artifacts.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        audit_service: Optional[Any] = None,
    ) -> None:
        """
        Initializes the Evidence Catalog Service.
        
        Args:
            db_path: Path to the SQLite database file, or ':memory:'.
                     Defaults to EVIDENCE_CATALOG_DB env var or 'evidence_catalog.db'.
            audit_service: Optional ChainOfCustodyService for audit ledger integration.
        """
        env_path = os.getenv("EVIDENCE_CATALOG_DB")
        self.db_path = db_path or env_path or DEFAULT_DB_PATH
        self.audit_service = audit_service
        # For :memory: databases, maintain a single persistent connection so data
        # survives across calls (each new sqlite3.connect(':memory:') creates an
        # isolated, empty database).
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys = ON;")
        self._init_db()
        logger.info(f"EvidenceCatalogService initialized with DB: {self.db_path}")

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provides a managed SQLite connection with Row factory and WAL mode."""
        if self._mem_conn is not None:
            # Re-use the single in-memory connection; do NOT close it.
            try:
                yield self._mem_conn
                self._mem_conn.commit()
            except Exception:
                self._mem_conn.rollback()
                raise
            return

        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initializes database schema and indexes."""
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_catalog (
                    evidence_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    device_name TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size_bytes INTEGER NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    s3_bucket TEXT,
                    s3_object_key TEXT,
                    s3_upload_status TEXT,
                    s3_checksum_sha256 TEXT,
                    s3_checksum_verified INTEGER DEFAULT 0,
                    s3_version_id TEXT,
                    simulation_indicator INTEGER DEFAULT 0,
                    collected_at TEXT NOT NULL,
                    indexed_at TEXT NOT NULL,
                    metadata_json TEXT
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cat_incident ON evidence_catalog(incident_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cat_device ON evidence_catalog(device_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cat_hash ON evidence_catalog(sha256_hash);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cat_type ON evidence_catalog(evidence_type);"
            )

    @staticmethod
    def compute_sha256(file_path: str) -> str:
        """
        Computes the SHA-256 hash of a local file in 64KB chunks.
        
        Args:
            file_path: Path to the target file.
            
        Returns:
            Hex-encoded SHA-256 string.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Cannot compute hash: file not found at {file_path}")

        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest().lower()

    def index_evidence_metadata(self, metadata: EvidenceMetadata) -> CatalogRecord:
        """
        Indexes an EvidenceMetadata record into the SQLite catalog.
        
        Args:
            metadata: EvidenceMetadata instance from Day 2 or Day 3.
            
        Returns:
            CatalogRecord representing the indexed artifact.

        EvidenceMetadata field mapping:
            evidence_id      <- collection_job_id
            device_id        <- endpoint_id
            device_name      <- hostname (or endpoint_id as fallback)
            evidence_type    <- collection_method
            file_path        <- artifact_location
            sha256_hash      <- file_hash_sha256
            collected_at     <- completed_at or requested_at
        """
        # Map EvidenceMetadata fields to catalog record fields
        evidence_id = metadata.collection_job_id
        device_id   = metadata.endpoint_id
        device_name = metadata.hostname or metadata.endpoint_id
        evidence_type = metadata.collection_method
        file_path   = metadata.artifact_location or ""
        raw_hash    = metadata.file_hash_sha256 or ""
        sha256_hash = raw_hash.lower()
        collected_at = metadata.completed_at or metadata.requested_at

        file_name = Path(file_path).name if file_path else f"{evidence_id}.bin"
        now_iso = datetime.now(timezone.utc).isoformat()
        metadata_raw = json.dumps(metadata.to_dict())

        record = CatalogRecord(
            evidence_id=evidence_id,
            incident_id=metadata.incident_id,
            device_id=device_id,
            device_name=device_name,
            evidence_type=evidence_type,
            file_name=file_name,
            file_path=file_path,
            file_size_bytes=metadata.file_size_bytes or 0,
            sha256_hash=sha256_hash,
            s3_bucket=metadata.s3_bucket,
            s3_object_key=metadata.s3_object_key,
            s3_upload_status=metadata.s3_upload_status,
            s3_checksum_sha256=metadata.s3_checksum_sha256,
            s3_checksum_verified=metadata.s3_checksum_verified,
            s3_version_id=metadata.s3_version_id,
            simulation_indicator=metadata.simulation_indicator,
            collected_at=collected_at,
            indexed_at=now_iso,
            metadata_json=metadata_raw,
        )

        query = """
            INSERT INTO evidence_catalog (
                evidence_id, incident_id, device_id, device_name,
                evidence_type, file_name, file_path, file_size_bytes,
                sha256_hash, s3_bucket, s3_object_key, s3_upload_status,
                s3_checksum_sha256, s3_checksum_verified, s3_version_id,
                simulation_indicator, collected_at, indexed_at, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(evidence_id) DO UPDATE SET
                incident_id=excluded.incident_id,
                device_id=excluded.device_id,
                device_name=excluded.device_name,
                evidence_type=excluded.evidence_type,
                file_name=excluded.file_name,
                file_path=excluded.file_path,
                file_size_bytes=excluded.file_size_bytes,
                sha256_hash=excluded.sha256_hash,
                s3_bucket=excluded.s3_bucket,
                s3_object_key=excluded.s3_object_key,
                s3_upload_status=excluded.s3_upload_status,
                s3_checksum_sha256=excluded.s3_checksum_sha256,
                s3_checksum_verified=excluded.s3_checksum_verified,
                s3_version_id=excluded.s3_version_id,
                simulation_indicator=excluded.simulation_indicator,
                collected_at=excluded.collected_at,
                indexed_at=excluded.indexed_at,
                metadata_json=excluded.metadata_json;
        """

        with self._get_connection() as conn:
            conn.execute(
                query,
                (
                    record.evidence_id,
                    record.incident_id,
                    record.device_id,
                    record.device_name,
                    record.evidence_type,
                    record.file_name,
                    record.file_path,
                    record.file_size_bytes,
                    record.sha256_hash,
                    record.s3_bucket,
                    record.s3_object_key,
                    record.s3_upload_status,
                    record.s3_checksum_sha256,
                    1 if record.s3_checksum_verified else 0,
                    record.s3_version_id,
                    1 if record.simulation_indicator else 0,
                    record.collected_at,
                    record.indexed_at,
                    record.metadata_json,
                ),
            )

        if self.audit_service:
            try:
                self.audit_service.record_event(
                    action="EVIDENCE_INDEXED",
                    status="SUCCESS",
                    incident_id=record.incident_id,
                    evidence_id=record.evidence_id,
                    endpoint_id=record.device_id,
                    actor="EvidenceCatalogService",
                    evidence_hash=record.sha256_hash,
                    destination_location=str(self.db_path),
                    execution_mode="MOCK" if record.simulation_indicator else "REAL",
                    details={"file_name": record.file_name, "size_bytes": record.file_size_bytes},
                )
            except Exception as audit_err:
                logger.warning("Failed to record audit event for indexing: %s", audit_err)

        logger.info(
            f"Indexed evidence {record.evidence_id} (Type: {record.evidence_type}, Hash: {record.sha256_hash[:12]}...)"
        )
        return record

    def _row_to_record(self, row: sqlite3.Row) -> CatalogRecord:
        """Converts an SQLite row to a CatalogRecord dataclass."""
        return CatalogRecord(
            evidence_id=row["evidence_id"],
            incident_id=row["incident_id"],
            device_id=row["device_id"],
            device_name=row["device_name"],
            evidence_type=row["evidence_type"],
            file_name=row["file_name"],
            file_path=row["file_path"],
            file_size_bytes=row["file_size_bytes"],
            sha256_hash=row["sha256_hash"],
            s3_bucket=row["s3_bucket"],
            s3_object_key=row["s3_object_key"],
            s3_upload_status=row["s3_upload_status"],
            s3_checksum_sha256=row["s3_checksum_sha256"],
            s3_checksum_verified=bool(row["s3_checksum_verified"]),
            s3_version_id=row["s3_version_id"],
            simulation_indicator=bool(row["simulation_indicator"]),
            collected_at=row["collected_at"],
            indexed_at=row["indexed_at"],
            metadata_json=row["metadata_json"],
        )

    def get_record(self, evidence_id: str) -> Optional[CatalogRecord]:
        """Retrieves an evidence record by its unique evidence ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM evidence_catalog WHERE evidence_id = ?;",
                (evidence_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_record(row)

    def list_records(self, limit: int = 100) -> List[CatalogRecord]:
        """Lists catalog records ordered by most recent collection."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM evidence_catalog ORDER BY indexed_at DESC LIMIT ?;",
                (limit,),
            )
            return [self._row_to_record(r) for r in cursor.fetchall()]

    def find_by_incident(self, incident_id: str) -> List[CatalogRecord]:
        """Finds all evidence records associated with an incident ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM evidence_catalog WHERE incident_id = ? ORDER BY indexed_at DESC;",
                (incident_id,),
            )
            return [self._row_to_record(r) for r in cursor.fetchall()]

    def find_by_device(self, device_id: str) -> List[CatalogRecord]:
        """Finds all evidence records collected from a device ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM evidence_catalog WHERE device_id = ? ORDER BY indexed_at DESC;",
                (device_id,),
            )
            return [self._row_to_record(r) for r in cursor.fetchall()]

    def find_by_hash(self, sha256_hash: str) -> List[CatalogRecord]:
        """Finds evidence records matching a SHA-256 hash."""
        clean_hash = sha256_hash.strip().lower()
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM evidence_catalog WHERE sha256_hash = ? ORDER BY indexed_at DESC;",
                (clean_hash,),
            )
            return [self._row_to_record(r) for r in cursor.fetchall()]

    def search(
        self,
        query: Optional[str] = None,
        incident_id: Optional[str] = None,
        evidence_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[CatalogRecord]:
        """
        Flexible multi-criteria search across the evidence catalog.
        
        Args:
            query: Free-text match against device_name, file_name, or sha256_hash.
            incident_id: Exact filter by incident ID.
            evidence_type: Exact filter by evidence type.
            limit: Maximum records to return.
        """
        clauses = []
        params: List[Any] = []

        if incident_id:
            clauses.append("incident_id = ?")
            params.append(incident_id)

        if evidence_type:
            clauses.append("evidence_type = ?")
            params.append(evidence_type.upper())

        if query:
            q_wild = f"%{query.strip()}%"
            clauses.append(
                "(device_name LIKE ? OR file_name LIKE ? OR sha256_hash LIKE ? OR evidence_id LIKE ?)"
            )
            params.extend([q_wild, q_wild, q_wild, q_wild])

        where_stmt = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM evidence_catalog {where_stmt} ORDER BY indexed_at DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.execute(sql, tuple(params))
            return [self._row_to_record(r) for r in cursor.fetchall()]

    def verify_integrity(
        self,
        evidence_id: str,
        current_file_path: Optional[str] = None,
    ) -> IntegrityCheckResult:
        """
        Verifies the SHA-256 hash of an existing file against the catalog record.
        
        Args:
            evidence_id: Unique identifier of the evidence.
            current_file_path: Optional explicit file path to verify. If omitted,
                               uses file_path recorded in the catalog.
                               
        Returns:
            IntegrityCheckResult detailing whether the file is intact or tampered.
        """
        record = self.get_record(evidence_id)
        now_iso = datetime.now(timezone.utc).isoformat()

        if not record:
            return IntegrityCheckResult(
                evidence_id=evidence_id,
                file_path=current_file_path or "",
                indexed_hash="",
                recalculated_hash="",
                is_valid=False,
                verified_at=now_iso,
                error_message=f"Evidence ID '{evidence_id}' does not exist in catalog.",
            )

        target_path = current_file_path or record.file_path
        if not target_path or not Path(target_path).is_file():
            return IntegrityCheckResult(
                evidence_id=evidence_id,
                file_path=target_path or "",
                indexed_hash=record.sha256_hash,
                recalculated_hash="",
                is_valid=False,
                verified_at=now_iso,
                error_message=f"Target evidence file does not exist on disk: {target_path}",
            )

        try:
            recomputed = self.compute_sha256(target_path)
            is_valid = (recomputed == record.sha256_hash.lower())
            error = None if is_valid else (
                f"Hash mismatch: indexed '{record.sha256_hash}' != calculated '{recomputed}'"
            )
            result = IntegrityCheckResult(
                evidence_id=evidence_id,
                file_path=target_path,
                indexed_hash=record.sha256_hash,
                recalculated_hash=recomputed,
                is_valid=is_valid,
                verified_at=now_iso,
                error_message=error,
            )
            if self.audit_service:
                try:
                    self.audit_service.record_event(
                        action="INTEGRITY_VERIFIED" if is_valid else "INTEGRITY_REJECTED",
                        status="SUCCESS" if is_valid else "FAILURE",
                        incident_id=record.incident_id,
                        evidence_id=record.evidence_id,
                        endpoint_id=record.device_id,
                        actor="EvidenceCatalogService",
                        evidence_hash=recomputed if is_valid else record.sha256_hash,
                        execution_mode="MOCK" if record.simulation_indicator else "REAL",
                        details={"error": error} if error else {"recalculated_hash": recomputed},
                    )
                except Exception as audit_err:
                    logger.warning("Failed to record audit event for integrity check: %s", audit_err)
            return result
        except Exception as exc:
            err_msg = f"Failed to read file for hash computation: {exc}"
            if self.audit_service:
                try:
                    self.audit_service.record_event(
                        action="INTEGRITY_REJECTED",
                        status="FAILURE",
                        incident_id=record.incident_id if record else None,
                        evidence_id=evidence_id,
                        actor="EvidenceCatalogService",
                        details={"error": err_msg},
                    )
                except Exception:
                    pass
            return IntegrityCheckResult(
                evidence_id=evidence_id,
                file_path=target_path,
                indexed_hash=record.sha256_hash,
                recalculated_hash="",
                is_valid=False,
                verified_at=now_iso,
                error_message=err_msg,
            )

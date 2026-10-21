# incidents/database.py
"""
SQLite database management module for incident records.
Uses Python's standard library sqlite3 with connection pooling / context management.
"""

import os
import sqlite3
from contextlib import contextmanager
from typing import Generator, Optional


DEFAULT_DB_PATH = "incidents.db"


def get_db_path(override_path: Optional[str] = None) -> str:
    """
    Resolves the SQLite database file path.
    Precedence:
      1. Explicit override_path argument
      2. INCIDENTS_DB_PATH environment variable
      3. Default: incidents.db in project root
    """
    if override_path:
        return override_path
    return os.environ.get("INCIDENTS_DB_PATH", DEFAULT_DB_PATH).strip() or DEFAULT_DB_PATH


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Creates and returns a new SQLite connection with Row factory enabled.
    """
    path = get_db_path(db_path)
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys and WAL mode for safer concurrency where supported
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def get_db(db_path: Optional[str] = None) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager for database connections ensuring clean commit/rollback and closure.
    """
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initializes the incidents schema and indexes if they do not exist.
    """
    schema_sql = """
    CREATE TABLE IF NOT EXISTS incidents (
        alert_id TEXT PRIMARY KEY,
        threat_type TEXT NOT NULL,
        severity INTEGER NOT NULL,
        description TEXT NOT NULL,
        hostname TEXT,
        ip_address TEXT,
        username TEXT,
        process_hash TEXT,
        timestamp TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'NEW',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
    CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);

    CREATE TABLE IF NOT EXISTS incident_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT NOT NULL,
        incident_id TEXT,
        identity_provider TEXT,
        user_id TEXT,
        action TEXT NOT NULL,
        execution_mode TEXT NOT NULL,
        status TEXT NOT NULL,
        message TEXT,
        correlation_id TEXT,
        details TEXT,
        timestamp TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_alert_id ON incident_audit_logs (alert_id);
    CREATE INDEX IF NOT EXISTS idx_audit_user_id ON incident_audit_logs (user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON incident_audit_logs (action);
    """
    with get_db(db_path) as conn:
        conn.executescript(schema_sql)

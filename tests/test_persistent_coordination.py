# tests/test_persistent_coordination.py
"""
Unit and concurrency tests for Persistent Duplicate Coordination (Phase 5).
Validates:
  1. Atomic deduplication key reservation in SQLite across workers.
  2. Cooldown period enforcement and expiration.
  3. Safe concurrent access with multi-threaded workers (prevents duplicate execution).
  4. Cross-instance synchronization (multiple stores sharing the same SQLite DB).
  5. State preservation across application restarts.
  6. Stale in-progress record recovery after worker crashes.
  7. Proper handling and recording of failed action attempts.
  8. Resiliency against database connectivity or transaction issues.
"""

from concurrent.futures import ThreadPoolExecutor
import time
from unittest.mock import MagicMock, patch

import pytest

from containment.network_containment import (
    STATUS_CONFIRMED,
    STATUS_FAILED,
    STATUS_SIMULATED,
    ContainmentRegistry,
    execute_network_containment,
    get_containment_registry,
    clear_containment_registry,
)
from containment.identity_response import (
    IdentityActionRegistry,
    execute_account_suspension,
    get_identity_registry,
    clear_identity_registry,
)
from incidents.coordination import ActionDeduplicationStore, get_dedup_store
from incidents.database import init_db
from integrations.edr_client import SimulatedEDRClient
from integrations.identity_client import SimulatedIdentityClient


@pytest.fixture(autouse=True)
def coordination_test_db(tmp_path, monkeypatch):
    """Provides a fresh isolated database for each coordination test."""
    db_file = str(tmp_path / "test_coordination.db")
    monkeypatch.setenv("INCIDENTS_DB_PATH", db_file)
    init_db(db_file)
    clear_containment_registry()
    clear_identity_registry()
    yield db_file
    clear_containment_registry()
    clear_identity_registry()


# ── 1. Basic Lock Acquisition and Completion ──────────────────────────────────


def test_lock_acquire_and_complete(coordination_test_db):
    """Acquiring a lock marks it IN_PROGRESS, and mark_completed saves outcome."""
    store = ActionDeduplicationStore(coordination_test_db)
    action_type = "CONTAINMENT_ISOLATE"
    target_id = "HOST-COORD-001"
    alert_id = "ALERT-001"

    # First acquisition succeeds
    acquired = store.acquire_action_lock(action_type, target_id, alert_id)
    assert acquired is True

    # Immediate second acquisition is rejected (in-progress)
    acquired_second = store.acquire_action_lock(action_type, target_id, alert_id)
    assert acquired_second is False

    # Mark as completed
    store.mark_completed(
        action_type=action_type,
        target_id=target_id,
        alert_id=alert_id,
        status="CONFIRMED",
        telemetry={"action": "isolated", "dry_run": False},
        cooldown_seconds=300,
    )

    # Within cooldown, check_existing_action returns cached completed action
    record = store.check_existing_action(action_type, target_id)
    assert record is not None
    assert record["status"] == "CONFIRMED"
    assert record["target_id"] == target_id


# ── 2. Cooldown Expiration ───────────────────────────────────────────────────


def test_cooldown_expiration(coordination_test_db):
    """Actions past their cooldown allow a new lock acquisition."""
    store = ActionDeduplicationStore(coordination_test_db)
    action_type = "CONTAINMENT_ISOLATE"
    target_id = "HOST-EXP-001"
    alert_id = "ALERT-EXP-001"

    # Acquire and complete with 0 second cooldown (immediate expiry)
    assert store.acquire_action_lock(action_type, target_id, alert_id) is True
    store.mark_completed(
        action_type, target_id, alert_id, "CONFIRMED", telemetry={}, cooldown_seconds=0
    )

    # Sleep briefly to ensure time.time() > completed_at
    time.sleep(0.05)

    # Check existing should return None because cooldown expired
    assert store.check_existing_action(action_type, target_id) is None

    # New lock acquisition should succeed for a new alert
    assert store.acquire_action_lock(action_type, target_id, "ALERT-EXP-002") is True


# ── 3. Multi-Worker Concurrency ───────────────────────────────────────────────


def test_concurrent_lock_acquisition(coordination_test_db):
    """Multiple concurrent workers trying to acquire the same lock -> exactly 1 succeeds."""
    store = ActionDeduplicationStore(coordination_test_db)
    action_type = "CONTAINMENT_ISOLATE"
    target_id = "CONCURRENT-HOST-01"
    alert_id = "ALERT-CONCURRENT-01"

    results = []

    def try_acquire(worker_id: int):
        worker_store = ActionDeduplicationStore(coordination_test_db)
        return worker_store.acquire_action_lock(action_type, target_id, alert_id)

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(try_acquire, i) for i in range(8)]
        for f in futures:
            results.append(f.result())

    # Exactly one worker must have acquired the lock
    assert results.count(True) == 1
    assert results.count(False) == 7


# ── 4. Cross-Instance Synchronization ─────────────────────────────────────────


def test_cross_instance_registry_sync(coordination_test_db):
    """Validates that separate registry instances share the exact same SQLite state."""
    registry_a = ContainmentRegistry(cooldown_seconds=300, db_path=coordination_test_db)
    registry_b = ContainmentRegistry(cooldown_seconds=300, db_path=coordination_test_db)

    target_host = "SHARED-DB-HOST"
    alert_id = "ALERT-SYNC-01"

    # Registry A checks duplicate -> False
    assert registry_a.is_duplicate(target_host) is False

    # Registry A records containment
    registry_a.record_containment(
        target=target_host,
        alert_id=alert_id,
        status="CONFIRMED",
        telemetry={"edr": "falcon"},
    )

    # Registry B immediately sees the action recorded in SQLite!
    assert registry_b.is_duplicate(target_host) is True
    duplicate_info = registry_b.get_duplicate_response(target_host)
    assert duplicate_info is not None
    assert duplicate_info["status"] == "duplicate"
    assert duplicate_info["original_status"] == "CONFIRMED"


# ── 5. Application Restart Simulation ─────────────────────────────────────────


def test_application_restart_preserves_state(coordination_test_db):
    """Simulates an application shutdown and restart by instantiating new registries."""
    # Process 1 runs and records identity suspension
    idp_registry_1 = IdentityActionRegistry(cooldown_seconds=600, db_path=coordination_test_db)
    idp_registry_1.record_action(
        action_type="IDENTITY_SUSPEND",
        target="compromised.user@domain.com",
        alert_id="ALERT-REBOOT-001",
        status="CONFIRMED",
        telemetry={"action": "user_disabled"},
    )

    # Process 1 exits (variable deleted)
    del idp_registry_1

    # Process 2 starts up after reboot and loads SQLite store
    idp_registry_2 = IdentityActionRegistry(cooldown_seconds=600, db_path=coordination_test_db)
    assert idp_registry_2.is_duplicate("IDENTITY_SUSPEND", "compromised.user@domain.com") is True

    dup_resp = idp_registry_2.get_duplicate_response("IDENTITY_SUSPEND", "compromised.user@domain.com")
    assert dup_resp is not None
    assert dup_resp["status"] == "duplicate"
    assert dup_resp["action"] == "IDENTITY_SUSPEND"


# ── 6. Stale In-Progress Recovery ─────────────────────────────────────────────


def test_stale_in_progress_lock_reclamation(coordination_test_db):
    """If a worker crashed while holding a lock, a subsequent worker can reclaim it after timeout."""
    store = ActionDeduplicationStore(coordination_test_db)
    action_type = "CONTAINMENT_ISOLATE"
    target_id = "CRASHED-WORKER-HOST"
    alert_id = "ALERT-CRASH-001"

    # Acquire lock with very short lock timeout (0.1 seconds)
    acquired = store.acquire_action_lock(action_type, target_id, alert_id, lock_timeout_seconds=0.1)
    assert acquired is True

    # Immediate attempt fails
    assert store.acquire_action_lock(action_type, target_id, alert_id, lock_timeout_seconds=0.1) is False

    # Wait for the lock to become stale
    time.sleep(0.15)

    # New worker should now be able to reclaim the stale lock!
    reclaimed = store.acquire_action_lock(action_type, target_id, "ALERT-CRASH-RETRY", lock_timeout_seconds=60)
    assert reclaimed is True


# ── 7. Failed Action Handling ─────────────────────────────────────────────────


def test_mark_failure_allows_inspection(coordination_test_db):
    """Failed actions are persisted with FAILED status and error details."""
    store = ActionDeduplicationStore(coordination_test_db)
    action_type = "IDENTITY_SUSPEND"
    target_id = "fail.user@domain.com"
    alert_id = "ALERT-FAIL-01"

    store.acquire_action_lock(action_type, target_id, alert_id)
    store.mark_failure(action_type, target_id, alert_id, error="Graph API 503 Service Unavailable")

    record = store.check_existing_action(action_type, target_id)
    assert record is not None
    assert record["status"] == "FAILED"
    assert "Graph API 503" in record["telemetry"].get("error", "")

    # Failed action does not leave a permanent lock; immediate retry succeeds
    reacquired = store.acquire_action_lock(action_type, target_id, "ALERT-FAIL-RETRY")
    assert reacquired is True


# tests/conftest.py
"""
Pytest global fixtures for test isolation.
Ensures every test runs against a clean, isolated temporary SQLite database
so existing tests (such as test_webhook.py) never collide with persistent state.
"""

import pytest
from incidents.database import init_db


@pytest.fixture(autouse=True)
def isolated_test_db(tmp_path, monkeypatch):
    """
    Directs all database operations during testing to an isolated temporary SQLite file.
    Automatically initializes the schema and cleans up when each test finishes.
    """
    db_file = str(tmp_path / "test_isolated.db")
    monkeypatch.setenv("INCIDENTS_DB_PATH", db_file)
    init_db(db_file)
    yield db_file

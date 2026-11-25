"""
test_s3_object_lock.py - Unit tests for S3 WORM Object Lock & Retention verification.
"""

from pathlib import Path
import sys
from unittest.mock import MagicMock, patch
import pytest

_BACKEND_DIR = Path(__file__).resolve().parent.parent / "zaalima" / "backend"
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.services.s3_service import S3EvidenceStorageService, calculate_sha256


@pytest.fixture
def s3_service_mock():
    return S3EvidenceStorageService()


def test_calculate_sha256_valid_file(tmp_path):
    p = tmp_path / "evidence.bin"
    p.write_bytes(b"TEST FORENSIC BYTES")
    sha = calculate_sha256(str(p))
    assert len(sha) == 64
    assert all(c in "0123456789abcdef" for c in sha)


def test_object_lock_mock_mode(s3_service_mock):
    """In mock mode, Object Lock is configured with WORM compliance in local vault."""
    status = s3_service_mock.get_object_lock_configuration()
    assert status["object_lock_enabled"] is True
    assert status["default_retention_mode"] == "COMPLIANCE"
    assert status["default_retention_days"] == 365


def test_upload_evidence_with_object_lock_mock(s3_service_mock, tmp_path):
    """Verify mock upload records WORM Object Lock metadata and SHA-256."""
    p = tmp_path / "test_artifact.zip"
    p.write_bytes(b"PK\x03\x04MOCK_EVIDENCE")

    res = s3_service_mock.upload_evidence_file(
        local_path=str(p),
        incident_id="INC-LOCK-001",
        hostname="HOST-01",
        evidence_type="kape_artifacts",
        evidence_id="EV-001",
        enable_object_lock=True,
        retention_days=180,
    )

    assert res["success"] is True
    assert res["checksum_verified"] is True
    assert "object_lock" in res
    assert res["object_lock"]["enabled"] is True
    assert res["object_lock"]["mode"] == "COMPLIANCE"
    assert res["object_lock"]["retention_period_days"] == 180
    assert res["object_lock"]["worm_compliant"] is True


def test_verify_evidence_integrity(s3_service_mock, tmp_path):
    """Verify evidence integrity checker catches match and tampering."""
    p = tmp_path / "integrity.raw"
    p.write_bytes(b"EVIDENCE_DATA_123")
    correct_sha = calculate_sha256(str(p))

    assert s3_service_mock.verify_evidence_integrity(str(p), correct_sha) is True
    assert s3_service_mock.verify_evidence_integrity(str(p), "0" * 64) is False

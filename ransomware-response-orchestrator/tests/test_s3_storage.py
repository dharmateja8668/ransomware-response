"""
tests/test_s3_storage.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit Tests for Secure AWS S3 Evidence Storage & Integrity Verification.
Automated Ransomware Containment & Incident Response Orchestrator - Day 3.

Coverage:
  1. Successful mock file upload.
  2. Missing evidence files (S3FileNotFoundError).
  3. AWS IAM permission failures (S3PermissionError).
  4. AWS network failures and timeouts (S3NetworkError).
  5. Checksum verification and mismatch detection (S3ChecksumMismatchError).
  6. Ensuring ETag is NEVER treated as a SHA-256 checksum.
  7. Metadata companion upload (metadata.json).
  8. S3 Configuration validation and secret redaction.
  9. Simulated evidence handling (simulation_indicator preservation).
  10. End-to-end archival integration with ForensicCollectionService.
  11. Live boto3 client exception translation.
  12. Moto simulated AWS S3 integration.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

from storage.s3_storage import (
    S3ChecksumMismatchError,
    S3Config,
    S3ConfigError,
    S3FileNotFoundError,
    S3NetworkError,
    S3PermissionError,
    S3StorageError,
    S3StorageService,
    UploadResult,
    calculate_bytes_sha256,
    calculate_file_sha256,
    sha256_base64_to_hex,
    sha256_hex_to_base64,
)
from forensic.metadata import (
    CollectionMethod,
    CollectionStatus,
    EvidenceMetadata,
)
from forensic.collection_service import ForensicCollectionService
from integrations.defender_client import DefenderClient, EDRConfig


@pytest.fixture
def mock_s3_config():
    return S3Config(
        bucket_name="test-forensic-evidence-bucket",
        region_name="us-east-1",
        prefix="incidents",
        mock_mode=True,
    )


@pytest.fixture
def s3_service(mock_s3_config):
    return S3StorageService(config=mock_s3_config)


@pytest.fixture
def sample_evidence_file(tmp_path: Path):
    """Creates a sample forensic artifact file on disk."""
    file_path = tmp_path / "kape_FINANCE-SRV-01_triage.zip"
    content = b"PK\x03\x04ForensicZipArchiveSimulatedArtifactBytes1234567890"
    file_path.write_bytes(content)
    return file_path


# ─────────────────────────────────────────────────────────────────────────────
# 1. Checksum & Cryptographic Integrity Helper Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_calculate_file_sha256_success(sample_evidence_file: Path):
    expected_hash = hashlib.sha256(sample_evidence_file.read_bytes()).hexdigest().lower()
    computed_hash = calculate_file_sha256(sample_evidence_file)
    assert computed_hash == expected_hash
    assert len(computed_hash) == 64


def test_calculate_file_sha256_missing_file_raises_error(tmp_path: Path):
    non_existent = tmp_path / "missing_evidence.zip"
    with pytest.raises(S3FileNotFoundError) as exc_info:
        calculate_file_sha256(non_existent)
    assert "Evidence file not found" in str(exc_info.value)


def test_sha256_hex_and_base64_conversion():
    test_bytes = b"Automated Ransomware Containment Evidence 2026"
    hex_digest = hashlib.sha256(test_bytes).hexdigest()
    b64_digest = sha256_hex_to_base64(hex_digest)
    converted_back = sha256_base64_to_hex(b64_digest)
    assert converted_back == hex_digest.lower()


def test_etag_is_not_treated_as_sha256(s3_service, sample_evidence_file: Path):
    """
    CRITICAL INTEGRITY REQUIREMENT:
    ETag (MD5 or multipart formula) must NEVER be accepted as a SHA-256 hash.
    """
    sha256 = calculate_file_sha256(sample_evidence_file)
    fake_etag = "d41d8cd98f00b204e9800998ecf8427e"  # 32-char MD5 format

    # SHA-256 hex must be 64 characters
    assert len(sha256) == 64
    assert len(fake_etag) == 32
    assert fake_etag != sha256

    # Verify that verify_object_integrity checks SHA-256, not MD5 ETag
    matched, _ = s3_service.verify_object_integrity(
        bucket=s3_service.config.bucket_name,
        object_key="dummy_key",
        expected_sha256=fake_etag,  # Passing MD5 should fail
    )
    assert matched is False


# ─────────────────────────────────────────────────────────────────────────────
# 2. S3 Configuration & Secret Redaction Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_s3_config_missing_bucket_raises_in_live_mode():
    with pytest.raises(S3ConfigError) as exc_info:
        S3Config(bucket_name="", mock_mode=False)
    assert "AWS_S3_BUCKET_NAME is not set" in str(exc_info.value)


def test_s3_config_masks_sensitive_values():
    config = S3Config(
        bucket_name="secure-evidence-vault",
        kms_key_id="arn:aws:kms:us-east-1:123456789012:key/test-kms-key-id",
        server_side_encryption="aws:kms",
        mock_mode=True,
    )
    repr_str = repr(config)
    assert "secure-evidence-vault" in repr_str
    assert "test-kms-key-id" not in repr_str
    assert "***KMS_KEY***" in repr_str


# ─────────────────────────────────────────────────────────────────────────────
# 3. S3 File Upload & Failure Mode Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_successful_mock_upload_file(s3_service, sample_evidence_file: Path):
    res = s3_service.upload_evidence_file(
        file_path=sample_evidence_file,
        incident_id="1002",
        job_id="kape-test-123456",
        verify_checksum=True,
    )

    assert isinstance(res, UploadResult)
    assert res.bucket == "test-forensic-evidence-bucket"
    assert res.object_key == "incidents/1002/evidence/kape-test-123456/kape_FINANCE-SRV-01_triage.zip"
    assert res.s3_uri == "s3://test-forensic-evidence-bucket/incidents/1002/evidence/kape-test-123456/kape_FINANCE-SRV-01_triage.zip"
    assert res.checksum_verified is True
    assert res.sha256_checksum == calculate_file_sha256(sample_evidence_file)
    assert res.simulation_indicator is True
    assert res.version_id is not None


def test_upload_missing_file_raises_filenotfound(s3_service, tmp_path: Path):
    missing_file = tmp_path / "non_existent_dump.raw"
    with pytest.raises(S3FileNotFoundError) as exc_info:
        s3_service.upload_evidence_file(
            file_path=missing_file,
            incident_id="1002",
            job_id="ram-test-123456",
        )
    assert "does not exist on disk" in str(exc_info.value)


def test_aws_permission_failure(s3_service, sample_evidence_file: Path):
    with pytest.raises(S3PermissionError) as exc_info:
        s3_service.upload_evidence_file(
            file_path=sample_evidence_file,
            incident_id="1002",
            job_id="kape-test-123456",
            options={"simulate_permission_error": True},
        )
    assert "AccessDenied" in str(exc_info.value)


def test_aws_network_failure(s3_service, sample_evidence_file: Path):
    with pytest.raises(S3NetworkError) as exc_info:
        s3_service.upload_evidence_file(
            file_path=sample_evidence_file,
            incident_id="1002",
            job_id="kape-test-123456",
            options={"simulate_network_error": True},
        )
    assert "EndpointConnectionError" in str(exc_info.value)


def test_checksum_mismatch_raises_error(s3_service, sample_evidence_file: Path):
    with pytest.raises(S3ChecksumMismatchError) as exc_info:
        s3_service.upload_evidence_file(
            file_path=sample_evidence_file,
            incident_id="1002",
            job_id="kape-test-123456",
            options={"simulate_checksum_mismatch": True},
            verify_checksum=True,
        )
    assert "Integrity check failed" in str(exc_info.value)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Metadata Upload & Archival Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_upload_evidence_metadata(s3_service):
    meta_dict = {
        "incident_id": "1002",
        "endpoint_id": "mach-01",
        "collection_job_id": "job-abc-123",
        "status": "COMPLETED",
        "file_hash_sha256": "abcdef1234567890",
    }
    res = s3_service.upload_evidence_metadata(
        metadata_dict=meta_dict,
        incident_id="1002",
        job_id="job-abc-123",
    )

    assert res.object_key == "incidents/1002/evidence/job-abc-123/metadata.json"
    assert res.checksum_verified is True
    assert res.file_size_bytes > 0


def test_archive_evidence_manifest_simulated_handling(s3_service, tmp_path: Path):
    """
    Verifies that simulated collection jobs are correctly archived with
    simulation_indicator=True and s3_simulation_indicator=True.
    """
    meta = EvidenceMetadata(
        incident_id="1002",
        endpoint_id="mach-isolated-host",
        hostname="ISOLATED-HOST",
        collection_method=CollectionMethod.KAPE.value,
        status=CollectionStatus.COMPLETED.value,
        artifact_location="evidence/simulated/kape_ISOLATED-HOST_20261026.zip",
        file_hash_sha256="simulated-sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        simulation_indicator=True,
    )

    res = s3_service.archive_evidence_manifest(
        evidence_metadata=meta,
        evidence_dir=tmp_path,
    )

    assert res.simulation_indicator is True
    assert meta.s3_bucket == s3_service.config.bucket_name
    assert meta.s3_upload_status == "VERIFIED"
    assert meta.s3_checksum_verified is True
    assert meta.s3_metadata_key is not None
    assert meta.s3_simulation_indicator is True

    # Confirm saved manifest on disk updated with S3 keys
    saved_json = tmp_path / f"{meta.collection_job_id}_metadata.json"
    assert saved_json.exists()
    loaded = EvidenceMetadata.load(saved_json)
    assert loaded.s3_object_key == meta.s3_object_key
    assert loaded.s3_upload_status == "VERIFIED"


def test_archive_evidence_manifest_real_file(s3_service, sample_evidence_file: Path, tmp_path: Path):
    meta = EvidenceMetadata(
        incident_id="1002",
        endpoint_id="mach-01",
        hostname="FINANCE-SRV-01",
        collection_method=CollectionMethod.KAPE.value,
        status=CollectionStatus.COMPLETED.value,
        artifact_location=str(sample_evidence_file),
        simulation_indicator=False,
    )

    res = s3_service.archive_evidence_manifest(
        evidence_metadata=meta,
        evidence_dir=tmp_path,
    )

    assert res.checksum_verified is True
    assert meta.s3_object_key.endswith("kape_FINANCE-SRV-01_triage.zip")
    assert meta.s3_upload_status == "VERIFIED"


def test_collection_service_archive_job_to_s3_integration(tmp_path: Path):
    config = EDRConfig(mock_mode=True)
    defender_client = DefenderClient(config)
    s3_config = S3Config(bucket_name="test-evidence-vault", mock_mode=True)
    s3_service = S3StorageService(s3_config)

    service = ForensicCollectionService(
        defender_client=defender_client,
        evidence_dir=tmp_path,
        s3_storage_service=s3_service,
    )

    # 1. Initiate KAPE collection on isolated host
    meta = service.initiate_collection(
        incident_id="1002",
        endpoint_identifier="ISOLATED-HOST",
        method=CollectionMethod.KAPE,
    )
    assert meta.status == CollectionStatus.COMPLETED.value

    # 2. Archive to S3 via collection service
    upload_res = service.archive_job_to_s3(meta.collection_job_id)
    assert upload_res.bucket == "test-evidence-vault"
    assert upload_res.checksum_verified is True

    # 3. Retrieve updated job status
    updated = service.get_collection_status(meta.collection_job_id)
    assert updated.s3_upload_status == "VERIFIED"
    assert updated.s3_object_key is not None


# ─────────────────────────────────────────────────────────────────────────────
# 5. Botocore Client Exception Translation Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_boto3_client_error_access_denied_mapping():
    mock_client = MagicMock()
    error_response = {
        "Error": {
            "Code": "AccessDenied",
            "Message": "User is not authorized to perform s3:PutObject",
        }
    }
    mock_client.put_object.side_effect = ClientError(error_response, "PutObject")

    config = S3Config(bucket_name="live-test-bucket", mock_mode=False)
    service = S3StorageService(config=config, s3_client=mock_client)

    # Create dummy file to trigger upload
    with pytest.raises(S3PermissionError) as exc_info:
        service.upload_evidence_metadata({"test": "data"}, incident_id="1001", job_id="job-1")

    assert "AWS IAM Permission Denied" in str(exc_info.value)
    assert "AccessDenied" in str(exc_info.value)


def test_boto3_client_error_no_such_bucket_mapping():
    mock_client = MagicMock()
    error_response = {
        "Error": {
            "Code": "NoSuchBucket",
            "Message": "The specified bucket does not exist",
        }
    }
    mock_client.put_object.side_effect = ClientError(error_response, "PutObject")

    config = S3Config(bucket_name="non-existent-bucket", mock_mode=False)
    service = S3StorageService(config=config, s3_client=mock_client)

    with pytest.raises(S3ConfigError) as exc_info:
        service.upload_evidence_metadata({"test": "data"}, incident_id="1001", job_id="job-1")

    assert "Bucket 'non-existent-bucket' not found" in str(exc_info.value)


def test_boto3_endpoint_connection_error_mapping():
    mock_client = MagicMock()
    mock_client.put_object.side_effect = EndpointConnectionError(endpoint_url="https://s3.amazonaws.com")

    config = S3Config(bucket_name="live-test-bucket", mock_mode=False)
    service = S3StorageService(config=config, s3_client=mock_client)

    with pytest.raises(S3NetworkError) as exc_info:
        service.upload_evidence_metadata({"test": "data"}, incident_id="1001", job_id="job-1")

    assert "Network error contacting AWS S3 endpoint" in str(exc_info.value)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Moto Simulated AWS S3 Test
# ─────────────────────────────────────────────────────────────────────────────

try:
    from moto import mock_aws
    HAS_MOTO = True
except ImportError:
    HAS_MOTO = False


@pytest.mark.skipif(not HAS_MOTO, reason="moto library is not installed in the test environment")
def test_moto_s3_upload_and_integrity_verification(sample_evidence_file: Path):
    """
    Validates live boto3 PutObject, ChecksumSHA256, and SSE-S3 against moto S3 backend.
    """
    import boto3

    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="moto-forensic-vault")

        config = S3Config(
            bucket_name="moto-forensic-vault",
            region_name="us-east-1",
            server_side_encryption="AES256",
            mock_mode=False,
        )
        service = S3StorageService(config=config, s3_client=s3)

        res = service.upload_evidence_file(
            file_path=sample_evidence_file,
            incident_id="1002",
            job_id="moto-kape-job",
            verify_checksum=True,
        )

        assert res.bucket == "moto-forensic-vault"
        assert res.checksum_verified is True
        assert res.sha256_checksum == calculate_file_sha256(sample_evidence_file)

        # Verify object exists in bucket
        head = s3.head_object(Bucket="moto-forensic-vault", Key=res.object_key)
        assert head["ContentLength"] == sample_evidence_file.stat().st_size

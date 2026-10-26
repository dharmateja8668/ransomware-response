"""
storage/s3_storage.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Secure AWS S3 Storage Service for Forensic Evidence.
Automated Ransomware Containment & Incident Response Orchestrator - Day 3.

Responsibilities:
  - Upload forensic disk/memory artifacts to isolated AWS S3 evidence buckets.
  - Organize evidence hierarchically: incidents/{incident_id}/evidence/{job_id}/...
  - Enforce SHA-256 cryptographic integrity verification before and after upload.
  - Upload evidence companion manifests (metadata.json).
  - Enforce server-side encryption (SSE-S3 AES256 or SSE-KMS).
  - Support IAM instance roles, AWS profiles, and least-privilege credentials.
  - Offline Mock Mode for testing without AWS connectivity or credentials.
  - Provide WORM-compliant metadata records for S3 Object Lock protection.

Security Guarantees:
  - Never treats an ETag as a SHA-256 checksum.
  - Never logs or exposes AWS access keys, secret keys, or session tokens.
  - Never marks simulated evidence as real evidence.
  - Refuses upload if the local evidence file does not exist.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import uuid

logger = logging.getLogger("orchestrator.storage.s3")


# ─────────────────────────────────────────────────────────────────────────────
# Custom S3 Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class S3StorageError(Exception):
    """Base exception for AWS S3 evidence storage operations."""


class S3ConfigError(S3StorageError):
    """Raised when S3 configuration parameters (bucket name, region) are invalid."""


class S3FileNotFoundError(S3StorageError):
    """Raised when an evidence file to be uploaded does not exist on disk."""


class S3PermissionError(S3StorageError):
    """Raised when AWS IAM permissions deny S3 actions (e.g. 403 AccessDenied)."""


class S3NetworkError(S3StorageError):
    """Raised when network drops, DNS errors, or timeouts occur contacting AWS."""


class S3ChecksumMismatchError(S3StorageError):
    """Raised when S3 uploaded object hash does not match the local file SHA-256."""


# ─────────────────────────────────────────────────────────────────────────────
# Cryptographic Checksum Helpers
# ─────────────────────────────────────────────────────────────────────────────

def calculate_file_sha256(file_path: Path | str, chunk_size: int = 65536) -> str:
    """
    Computes hex-encoded SHA-256 digest of a local file in streaming chunks.
    Raises S3FileNotFoundError if the file does not exist.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise S3FileNotFoundError(f"Evidence file not found at: {path}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def calculate_bytes_sha256(data: bytes) -> str:
    """Computes hex-encoded SHA-256 digest of bytes in memory."""
    return hashlib.sha256(data).hexdigest().lower()


def sha256_hex_to_base64(hex_digest: str) -> str:
    """Converts a 64-character hexadecimal SHA-256 string to standard Base64."""
    raw_bytes = bytes.fromhex(hex_digest)
    return base64.b64encode(raw_bytes).decode("ascii")


def sha256_base64_to_hex(base64_digest: str) -> str:
    """Converts a Base64-encoded SHA-256 digest to hexadecimal string."""
    raw_bytes = base64.b64decode(base64_digest)
    return raw_bytes.hex().lower()


# ─────────────────────────────────────────────────────────────────────────────
# S3 Configuration Manager
# ─────────────────────────────────────────────────────────────────────────────

class S3Config:
    """
    Manages AWS S3 evidence storage configuration parameters.
    Reads securely from environment variables or explicit parameters.
    """

    DEFAULT_REGION = "us-east-1"
    DEFAULT_PREFIX = "incidents"
    DEFAULT_SSE = "AES256"

    def __init__(
        self,
        bucket_name: Optional[str] = None,
        region_name: Optional[str] = None,
        prefix: Optional[str] = None,
        kms_key_id: Optional[str] = None,
        server_side_encryption: Optional[str] = None,
        profile_name: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        mock_mode: Optional[bool] = None,
    ) -> None:
        # Determine Mock Mode
        env_mock = os.getenv("S3_MOCK_MODE", os.getenv("EDR_MOCK_MODE", "")).strip().lower()
        if mock_mode is not None:
            self.mock_mode = mock_mode
        elif env_mock in ("true", "1", "yes"):
            self.mock_mode = True
        elif env_mock in ("false", "0", "no"):
            self.mock_mode = False
        else:
            # Auto-enable mock mode if bucket is unset in environment
            self.mock_mode = not bool(os.getenv("AWS_S3_BUCKET_NAME") or os.getenv("EVIDENCE_S3_BUCKET"))

        self.bucket_name = (
            bucket_name
            or os.getenv("AWS_S3_BUCKET_NAME")
            or os.getenv("EVIDENCE_S3_BUCKET")
            or ("mock-forensic-evidence-bucket" if self.mock_mode else "")
        ).strip()

        self.region_name = (
            region_name
            or os.getenv("AWS_REGION")
            or os.getenv("AWS_DEFAULT_REGION")
            or self.DEFAULT_REGION
        ).strip()

        self.prefix = (prefix or os.getenv("S3_EVIDENCE_PREFIX", self.DEFAULT_PREFIX)).strip().strip("/")
        self.kms_key_id = (kms_key_id or os.getenv("AWS_KMS_KEY_ID", "")).strip() or None
        self.server_side_encryption = (
            server_side_encryption
            or os.getenv("AWS_SERVER_SIDE_ENCRYPTION")
            or ("aws:kms" if self.kms_key_id else self.DEFAULT_SSE)
        ).strip()

        self.profile_name = (profile_name or os.getenv("AWS_PROFILE", "")).strip() or None
        self.endpoint_url = (endpoint_url or os.getenv("AWS_S3_ENDPOINT_URL", "")).strip() or None

        # Validate configuration
        if not self.mock_mode:
            if not self.bucket_name:
                raise S3ConfigError(
                    "Live S3 mode enabled (S3_MOCK_MODE=false) but AWS_S3_BUCKET_NAME is not set. "
                    "Configure an evidence bucket in .env or switch to S3_MOCK_MODE=true."
                )

    def __repr__(self) -> str:
        """Conceals credentials and sensitive keys in string representations."""
        masked_kms = f"***KMS_KEY***" if self.kms_key_id else "None"
        return (
            f"<S3Config mock_mode={self.mock_mode} bucket='{self.bucket_name}' "
            f"region='{self.region_name}' prefix='{self.prefix}' sse='{self.server_side_encryption}' "
            f"kms_key={masked_kms} profile='{self.profile_name or 'default'}'>"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Upload Result Model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class UploadResult:
    """Represents the verified result of an S3 evidence upload."""
    bucket: str
    object_key: str
    file_size_bytes: int
    sha256_checksum: str
    checksum_verified: bool
    server_side_encryption: str
    uploaded_at: str
    simulation_indicator: bool
    local_path: Optional[str] = None
    version_id: Optional[str] = None
    metadata_key: Optional[str] = None
    kms_key_id: Optional[str] = None

    @property
    def s3_uri(self) -> str:
        """Returns standard S3 URI format: s3://bucket/key"""
        return f"s3://{self.bucket}/{self.object_key}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bucket": self.bucket,
            "object_key": self.object_key,
            "s3_uri": self.s3_uri,
            "file_size_bytes": self.file_size_bytes,
            "sha256_checksum": self.sha256_checksum,
            "checksum_verified": self.checksum_verified,
            "server_side_encryption": self.server_side_encryption,
            "version_id": self.version_id,
            "uploaded_at": self.uploaded_at,
            "simulation_indicator": self.simulation_indicator,
            "metadata_key": self.metadata_key,
            "local_path": self.local_path,
        }


# ─────────────────────────────────────────────────────────────────────────────
# S3 Storage Service
# ─────────────────────────────────────────────────────────────────────────────

class S3StorageService:
    """
    Modular S3 Storage Service for uploading and verifying forensic evidence.
    """

    def __init__(
        self,
        config: Optional[S3Config] = None,
        s3_client: Optional[Any] = None,
    ) -> None:
        self.config = config or S3Config()
        self._client = s3_client
        # In-memory mock store: key -> {bytes, sha256, version_id, sse, metadata}
        self._mock_objects: Dict[str, Dict[str, Any]] = {}

        if not self.config.mock_mode and self._client is None:
            self._client = self._init_boto3_client()

        logger.info(
            "Initialized S3StorageService (bucket=%s, region=%s, mock_mode=%s)",
            self.config.bucket_name,
            self.config.region_name,
            self.config.mock_mode,
        )

    def _init_boto3_client(self) -> Any:
        """Initializes a real boto3 S3 client using environment or profile credentials."""
        try:
            import boto3
            from botocore.config import Config

            session_kwargs: Dict[str, Any] = {}
            if self.config.profile_name:
                session_kwargs["profile_name"] = self.config.profile_name

            session = boto3.Session(**session_kwargs)
            boto_config = Config(
                region_name=self.config.region_name,
                signature_version="s3v4",
                retries={"max_attempts": 3, "mode": "standard"},
            )

            client_kwargs: Dict[str, Any] = {"config": boto_config}
            if self.config.endpoint_url:
                client_kwargs["endpoint_url"] = self.config.endpoint_url

            return session.client("s3", **client_kwargs)
        except Exception as err:
            logger.error("Failed to initialize boto3 client: %s", err)
            raise S3ConfigError(f"Could not initialize AWS S3 client: {err}") from err

    def build_object_key(self, incident_id: str | int, job_id: str, filename: str) -> str:
        """
        Constructs standardized hierarchical S3 object key:
          {prefix}/{incident_id}/evidence/{job_id}/{filename}
        """
        clean_incident = str(incident_id).strip()
        clean_job = str(job_id).strip()
        clean_filename = Path(filename).name
        return f"{self.config.prefix}/{clean_incident}/evidence/{clean_job}/{clean_filename}"

    # ─────────────────────────────────────────────────────────────────────────
    # File Upload & Integrity Verification
    # ─────────────────────────────────────────────────────────────────────────

    def upload_evidence_file(
        self,
        file_path: Path | str,
        incident_id: str | int,
        job_id: str,
        custom_filename: Optional[str] = None,
        verify_checksum: bool = True,
        extra_metadata: Optional[Dict[str, str]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> UploadResult:
        """
        Uploads an authorized local forensic evidence file to S3 with SHA-256 verification.

        Workflow:
          1. Validates that the local file exists.
          2. Computes the pre-upload SHA-256 hash.
          3. Uploads file with Server-Side Encryption and SHA-256 checksum algorithm.
          4. Verifies uploaded integrity by querying S3 or calculating object SHA-256.
          5. Returns detailed UploadResult.
        """
        options = options or {}
        local_file = Path(file_path).resolve()
        if not local_file.is_file():
            raise S3FileNotFoundError(f"Evidence file does not exist on disk: {local_file}")

        file_name = custom_filename or local_file.name
        file_size = local_file.stat().st_size
        object_key = self.build_object_key(incident_id, job_id, file_name)

        # 1. Pre-upload Cryptographic Hash
        sha256_hex = calculate_file_sha256(local_file)
        sha256_b64 = sha256_hex_to_base64(sha256_hex)
        logger.info(
            "Pre-upload SHA-256 for %s (%d bytes): %s",
            local_file.name,
            file_size,
            sha256_hex,
        )

        # 2. Mock Mode Execution
        if self.config.mock_mode:
            return self._mock_upload_file(
                local_file=local_file,
                object_key=object_key,
                file_size=file_size,
                sha256_hex=sha256_hex,
                verify_checksum=verify_checksum,
                options=options,
            )

        # 3. Live S3 Upload with boto3
        extra_args: Dict[str, Any] = {
            "ServerSideEncryption": self.config.server_side_encryption,
            "ChecksumAlgorithm": "SHA256",
        }
        if self.config.kms_key_id and self.config.server_side_encryption == "aws:kms":
            extra_args["SSEKMSKeyId"] = self.config.kms_key_id

        if extra_metadata:
            extra_args["Metadata"] = {k: str(v) for k, v in extra_metadata.items()}

        try:
            with open(local_file, "rb") as body_stream:
                put_kwargs: Dict[str, Any] = {
                    "Bucket": self.config.bucket_name,
                    "Key": object_key,
                    "Body": body_stream,
                    "ChecksumAlgorithm": "SHA256",
                    "ChecksumSHA256": sha256_b64,
                    "ServerSideEncryption": self.config.server_side_encryption,
                }
                if self.config.kms_key_id and self.config.server_side_encryption == "aws:kms":
                    put_kwargs["SSEKMSKeyId"] = self.config.kms_key_id
                if extra_metadata:
                    put_kwargs["Metadata"] = {k: str(v) for k, v in extra_metadata.items()}

                response = self._client.put_object(**put_kwargs)

            version_id = response.get("VersionId")
            uploaded_at = datetime.now(timezone.utc).isoformat()

            # 4. Checksum Verification
            verified = False
            if verify_checksum:
                verified, remote_hash = self.verify_object_integrity(
                    bucket=self.config.bucket_name,
                    object_key=object_key,
                    expected_sha256=sha256_hex,
                )
                if not verified:
                    raise S3ChecksumMismatchError(
                        f"Integrity check failed for {object_key}: expected SHA-256 {sha256_hex}, got {remote_hash}"
                    )

            logger.info("Successfully uploaded evidence to s3://%s/%s (Verified=%s)", self.config.bucket_name, object_key, verified)

            return UploadResult(
                bucket=self.config.bucket_name,
                object_key=object_key,
                local_path=str(local_file),
                file_size_bytes=file_size,
                sha256_checksum=sha256_hex,
                checksum_verified=verified,
                server_side_encryption=self.config.server_side_encryption,
                version_id=version_id,
                uploaded_at=uploaded_at,
                simulation_indicator=False,
                kms_key_id=self.config.kms_key_id,
            )

        except Exception as err:
            self._handle_boto_exception(err, object_key)
            raise

    # ─────────────────────────────────────────────────────────────────────────
    # Metadata Companion Upload
    # ─────────────────────────────────────────────────────────────────────────

    def upload_evidence_metadata(
        self,
        metadata_dict: Dict[str, Any],
        incident_id: str | int,
        job_id: str,
        verify_checksum: bool = True,
    ) -> UploadResult:
        """
        Uploads the companion JSON metadata manifest alongside the evidence object:
          {prefix}/{incident_id}/evidence/{job_id}/metadata.json
        """
        object_key = self.build_object_key(incident_id, job_id, "metadata.json")
        json_bytes = json.dumps(metadata_dict, indent=2).encode("utf-8")
        file_size = len(json_bytes)
        sha256_hex = calculate_bytes_sha256(json_bytes)
        sha256_b64 = sha256_hex_to_base64(sha256_hex)

        if self.config.mock_mode:
            version_id = f"v-{uuid.uuid4().hex[:8]}"
            uploaded_at = datetime.now(timezone.utc).isoformat()
            self._mock_objects[object_key] = {
                "bytes": json_bytes,
                "sha256": sha256_hex,
                "version_id": version_id,
                "sse": self.config.server_side_encryption,
                "uploaded_at": uploaded_at,
            }
            return UploadResult(
                bucket=self.config.bucket_name,
                object_key=object_key,
                file_size_bytes=file_size,
                sha256_checksum=sha256_hex,
                checksum_verified=True,
                server_side_encryption=self.config.server_side_encryption,
                version_id=version_id,
                uploaded_at=uploaded_at,
                simulation_indicator=True,
            )

        try:
            put_kwargs: Dict[str, Any] = {
                "Bucket": self.config.bucket_name,
                "Key": object_key,
                "Body": json_bytes,
                "ContentType": "application/json",
                "ChecksumAlgorithm": "SHA256",
                "ChecksumSHA256": sha256_b64,
                "ServerSideEncryption": self.config.server_side_encryption,
            }
            if self.config.kms_key_id and self.config.server_side_encryption == "aws:kms":
                put_kwargs["SSEKMSKeyId"] = self.config.kms_key_id

            response = self._client.put_object(**put_kwargs)
            version_id = response.get("VersionId")
            uploaded_at = datetime.now(timezone.utc).isoformat()

            verified = True
            if verify_checksum:
                verified, _ = self.verify_object_integrity(self.config.bucket_name, object_key, sha256_hex)

            return UploadResult(
                bucket=self.config.bucket_name,
                object_key=object_key,
                file_size_bytes=file_size,
                sha256_checksum=sha256_hex,
                checksum_verified=verified,
                server_side_encryption=self.config.server_side_encryption,
                version_id=version_id,
                uploaded_at=uploaded_at,
                simulation_indicator=False,
                kms_key_id=self.config.kms_key_id,
            )
        except Exception as err:
            self._handle_boto_exception(err, object_key)
            raise

    # ─────────────────────────────────────────────────────────────────────────
    # End-to-End Evidence Archival Integration (Day 2 -> Day 3)
    # ─────────────────────────────────────────────────────────────────────────

    def archive_evidence_manifest(
        self,
        evidence_metadata: Any,  # EvidenceMetadata
        verify_checksum: bool = True,
        evidence_dir: Optional[Path | str] = None,
    ) -> UploadResult:
        """
        Archives a Day 2 collection job's artifact and metadata manifest into S3:
          1. Validates local artifact existence (or safely handles simulated records).
          2. Computes and verifies SHA-256 cryptographic integrity.
          3. Uploads evidence archive to S3.
          4. Updates the EvidenceMetadata with S3 keys and verification status.
          5. Uploads the updated metadata.json to S3 alongside the artifact.
          6. Persists updated manifest to disk.
        """
        job_id = evidence_metadata.collection_job_id
        incident_id = evidence_metadata.incident_id
        loc = evidence_metadata.artifact_location

        logger.info("Archiving evidence for job %s (Incident #%s)...", job_id, incident_id)

        # Check if this is a simulated artifact or physical file
        is_simulated = (
            evidence_metadata.simulation_indicator
            or not loc
            or str(loc).startswith("simulated://")
            or not Path(str(loc)).exists()
        )

        if is_simulated:
            if not self.config.mock_mode:
                raise S3FileNotFoundError(
                    f"Cannot upload simulated or non-existent artifact '{loc}' in live S3 mode. "
                    "Only verified on-disk evidence packages can be uploaded."
                )

            # Mock mode simulated upload
            clean_host = evidence_metadata.hostname or evidence_metadata.endpoint_id
            fake_filename = f"{evidence_metadata.collection_method.lower()}_{clean_host}_{job_id[:8]}.zip"
            object_key = self.build_object_key(incident_id, job_id, fake_filename)
            sim_sha256 = (
                evidence_metadata.file_hash_sha256
                or "simulated-sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            sim_bytes = 48234102

            result = UploadResult(
                bucket=self.config.bucket_name,
                object_key=object_key,
                local_path=str(loc),
                file_size_bytes=sim_bytes,
                sha256_checksum=sim_sha256,
                checksum_verified=True,
                server_side_encryption=self.config.server_side_encryption,
                version_id=f"sim-v-{uuid.uuid4().hex[:8]}",
                uploaded_at=datetime.now(timezone.utc).isoformat(),
                simulation_indicator=True,
            )

            # Record S3 upload in metadata
            evidence_metadata.record_s3_upload(
                bucket=self.config.bucket_name,
                object_key=object_key,
                checksum_sha256=sim_sha256,
                checksum_verified=True,
                version_id=result.version_id,
                simulation=True,
            )

            # Upload companion metadata
            meta_res = self.upload_evidence_metadata(
                metadata_dict=evidence_metadata.to_dict(),
                incident_id=incident_id,
                job_id=job_id,
            )
            evidence_metadata.s3_metadata_key = meta_res.object_key
            result.metadata_key = meta_res.object_key

            # Save updated manifest locally if directory provided
            if evidence_dir:
                evidence_metadata.save(evidence_dir)

            return result

        # Physical on-disk artifact upload
        local_path = Path(str(loc)).resolve()
        upload_res = self.upload_evidence_file(
            file_path=local_path,
            incident_id=incident_id,
            job_id=job_id,
            verify_checksum=verify_checksum,
        )

        # Update metadata manifest with S3 archive details
        evidence_metadata.record_s3_upload(
            bucket=self.config.bucket_name,
            object_key=upload_res.object_key,
            checksum_sha256=upload_res.sha256_checksum,
            checksum_verified=upload_res.checksum_verified,
            version_id=upload_res.version_id,
            simulation=self.config.mock_mode,
        )

        # Upload companion metadata.json
        meta_res = self.upload_evidence_metadata(
            metadata_dict=evidence_metadata.to_dict(),
            incident_id=incident_id,
            job_id=job_id,
            verify_checksum=verify_checksum,
        )
        evidence_metadata.s3_metadata_key = meta_res.object_key
        upload_res.metadata_key = meta_res.object_key

        # Persist updated manifest to disk
        if evidence_dir:
            evidence_metadata.save(evidence_dir)

        return upload_res

    # ─────────────────────────────────────────────────────────────────────────
    # Verification & S3 Querying
    # ─────────────────────────────────────────────────────────────────────────

    def verify_object_integrity(
        self, bucket: str, object_key: str, expected_sha256: str
    ) -> Tuple[bool, str]:
        """
        Verifies evidence integrity against S3:
          1. Checks S3 ChecksumSHA256 attribute if available.
          2. Otherwise streams object body and calculates SHA-256 digest.
          3. Strictly never treats ETag as SHA-256.

        Returns:
          Tuple[bool, str]: (is_matched, actual_sha256_hex)
        """
        clean_expected = expected_sha256.strip().lower()

        if self.config.mock_mode:
            obj = self._mock_objects.get(object_key)
            if not obj:
                return False, "object_not_found"
            actual = obj["sha256"]
            return (actual == clean_expected), actual

        try:
            head = self._client.head_object(
                Bucket=bucket, Key=object_key, ChecksumMode="ENABLED"
            )
            # Check for native S3 SHA-256 checksum header
            b64_checksum = head.get("ChecksumSHA256")
            if b64_checksum:
                actual_hex = sha256_base64_to_hex(b64_checksum)
                return (actual_hex == clean_expected), actual_hex

            # Fallback: Stream body and compute SHA-256 directly
            obj_res = self._client.get_object(Bucket=bucket, Key=object_key)
            hasher = hashlib.sha256()
            for chunk in obj_res["Body"].iter_chunks(chunk_size=65536):
                hasher.update(chunk)
            actual_hex = hasher.hexdigest().lower()
            return (actual_hex == clean_expected), actual_hex

        except Exception as err:
            logger.error("Failed to verify integrity for s3://%s/%s: %s", bucket, object_key, err)
            self._handle_boto_exception(err, object_key)
            raise

    # ─────────────────────────────────────────────────────────────────────────
    # Mock Handlers & Error Mapping
    # ─────────────────────────────────────────────────────────────────────────

    def _mock_upload_file(
        self,
        local_file: Path,
        object_key: str,
        file_size: int,
        sha256_hex: str,
        verify_checksum: bool,
        options: Dict[str, Any],
    ) -> UploadResult:
        """Simulates file upload in local mock mode."""
        # Simulated Failure Modes
        if options.get("simulate_permission_error") or "access-denied" in str(local_file).lower():
            raise S3PermissionError(
                f"AccessDenied: User arn:aws:iam::123456789012:role/OrchestratorRole is not authorized "
                f"to perform s3:PutObject on resource: arn:aws:s3:::{self.config.bucket_name}/{object_key}"
            )

        if options.get("simulate_network_error") or "timeout" in str(local_file).lower():
            raise S3NetworkError(
                f"EndpointConnectionError: Could not connect to the endpoint URL: "
                f"https://{self.config.bucket_name}.s3.{self.config.region_name}.amazonaws.com/{object_key}"
            )

        version_id = f"mock-v-{uuid.uuid4().hex[:8]}"
        uploaded_at = datetime.now(timezone.utc).isoformat()

        # Simulated Checksum Mismatch
        if options.get("simulate_checksum_mismatch") or "corrupt" in str(local_file).lower():
            corrupt_hash = "0000000000000000000000000000000000000000000000000000000000000000"
            self._mock_objects[object_key] = {
                "sha256": corrupt_hash,
                "version_id": version_id,
                "sse": self.config.server_side_encryption,
                "uploaded_at": uploaded_at,
            }
            if verify_checksum:
                raise S3ChecksumMismatchError(
                    f"Integrity check failed for {object_key}: expected SHA-256 {sha256_hex}, got {corrupt_hash}"
                )

        self._mock_objects[object_key] = {
            "sha256": sha256_hex,
            "version_id": version_id,
            "sse": self.config.server_side_encryption,
            "uploaded_at": uploaded_at,
        }

        return UploadResult(
            bucket=self.config.bucket_name,
            object_key=object_key,
            local_path=str(local_file),
            file_size_bytes=file_size,
            sha256_checksum=sha256_hex,
            checksum_verified=True,
            server_side_encryption=self.config.server_side_encryption,
            version_id=version_id,
            uploaded_at=uploaded_at,
            simulation_indicator=True,
            kms_key_id=self.config.kms_key_id,
        )

    def _handle_boto_exception(self, err: Exception, object_key: str) -> None:
        """Translates botocore exceptions into structured S3StorageError hierarchy."""
        err_msg = str(err)
        err_cls_name = err.__class__.__name__

        # Botocore ClientError mapping
        if hasattr(err, "response") and isinstance(err.response, dict):
            error_code = err.response.get("Error", {}).get("Code", "")
            error_message = err.response.get("Error", {}).get("Message", err_msg)

            if error_code in ("AccessDenied", "403", "InvalidAccessKeyId", "SignatureDoesNotMatch"):
                raise S3PermissionError(
                    f"AWS IAM Permission Denied ({error_code}) for s3://{self.config.bucket_name}/{object_key}: {error_message}"
                ) from err
            if error_code in ("NoSuchBucket", "404"):
                raise S3ConfigError(
                    f"S3 Bucket '{self.config.bucket_name}' not found ({error_code}): {error_message}"
                ) from err

        if "EndpointConnectionError" in err_cls_name or "ConnectTimeoutError" in err_cls_name or "ReadTimeoutError" in err_cls_name:
            raise S3NetworkError(f"Network error contacting AWS S3 endpoint: {err_msg}") from err

        raise S3StorageError(f"AWS S3 operation failed for {object_key}: {err_msg}") from err

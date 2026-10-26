"""
storage package
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Forensic Evidence Storage Package.
Automated Ransomware Containment & Incident Response Orchestrator - Day 3.
"""

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

__all__ = [
    # Configuration & Service
    "S3Config",
    "S3StorageService",
    "UploadResult",
    # Cryptographic Checksum Helpers
    "calculate_file_sha256",
    "calculate_bytes_sha256",
    "sha256_hex_to_base64",
    "sha256_base64_to_hex",
    # Exceptions
    "S3StorageError",
    "S3ConfigError",
    "S3FileNotFoundError",
    "S3PermissionError",
    "S3NetworkError",
    "S3ChecksumMismatchError",
]

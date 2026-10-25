# integrations/validators.py
"""
Indicator Validation Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Purpose : Provides strict, deterministic structural validation for network and host
          indicators of compromise (IP addresses, hostnames, and process hashes).

Prevents malformed, injected, or ambiguous indicator strings from being used in
EDR containment, identity response, or database persistence.
"""

from dataclasses import dataclass
import ipaddress
import logging
import re
from typing import Any, Optional, Tuple

logger = logging.getLogger("orchestrator.validators")

# RFC 1123 / RFC 952 DNS Hostname validation regex
# Label: 1-63 alphanumeric characters or internal hyphens, cannot start or end with hyphen
# Total length: max 253 chars
HOSTNAME_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

# Prohibited dangerous/injection characters in hostnames
FORBIDDEN_HOSTNAME_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\s;'\"><\\/|&`$()\[\]{}]")

# Valid Hash lengths: MD5 (32 hex), SHA-1 (40 hex), SHA-256 (64 hex)
VALID_HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
HEXADECIMAL_REGEX = re.compile(r"^[a-fA-F0-9]+$")


@dataclass
class IndicatorValidationResult:
    """Detailed structural validation result for an indicator."""
    indicator_type: str
    original_value: Optional[str]
    is_valid: bool
    cleaned_value: Optional[str]
    error_message: Optional[str] = None


def validate_ip_address(val: Optional[Any]) -> Optional[str]:
    """
    Validates whether the provided value is a structurally valid IPv4 or IPv6 address.
    Uses Python's standard library `ipaddress` module.

    Returns:
        Canonical string representation of the IP address (e.g. '192.168.1.1' or '2001:db8::1')
        if valid; None if missing, blank, or invalid.
    """
    if val is None:
        return None

    raw_str = str(val).strip()
    if not raw_str:
        return None

    try:
        ip_obj = ipaddress.ip_address(raw_str)
        return str(ip_obj)
    except ValueError as exc:
        logger.warning("Rejected invalid IP address '%s': %s", raw_str, exc)
        return None


def is_valid_ip(val: Optional[Any]) -> bool:
    """Returns True if the value is a valid IPv4 or IPv6 address, False otherwise."""
    return validate_ip_address(val) is not None


def validate_hostname(val: Optional[Any]) -> Optional[str]:
    """
    Validates whether the provided value conforms to RFC 1123 / RFC 952 DNS hostname syntax.

    Requirements:
      - Total length between 1 and 253 characters.
      - Disallows control characters, command injection symbols, whitespace, and special characters.
      - Each dot-separated label must be 1 to 63 characters, containing only alphanumeric characters
        and internal hyphens (cannot begin or end with a hyphen).
      - Supports single-label hostnames (e.g. 'FINANCE-SRV-01', 'DHARMATEJA') and FQDNs.

    Returns:
        Cleaned, normalized hostname string if valid; None if missing or invalid.
    """
    if val is None:
        return None

    raw_str = str(val).strip()
    if not raw_str:
        return None

    # Check for forbidden control/injection characters
    if FORBIDDEN_HOSTNAME_CHARS.search(raw_str):
        logger.warning("Rejected hostname with forbidden/injection characters: '%s'", raw_str)
        return None

    # Check overall length (RFC 1035 / RFC 1123: max 253 characters)
    if raw_str.endswith("."):
        logger.warning("Rejected hostname with trailing dot: '%s'", raw_str)
        return None

    if not (1 <= len(raw_str) <= 253):
        logger.warning("Rejected hostname due to invalid length (%d chars): '%s'", len(raw_str), raw_str)
        return None

    labels = raw_str.split(".")
    for label in labels:
        if not label:
            logger.warning("Rejected hostname with empty label: '%s'", raw_str)
            return None
        if len(label) > 63:
            logger.warning("Rejected hostname with oversized label (%d chars): '%s'", len(label), raw_str)
            return None
        if not HOSTNAME_LABEL_REGEX.match(label):
            logger.warning("Rejected hostname with invalid label syntax '%s' in '%s'", label, raw_str)
            return None

    return raw_str


def is_valid_hostname(val: Optional[Any]) -> bool:
    """Returns True if the value is a valid DNS hostname, False otherwise."""
    return validate_hostname(val) is not None


def validate_process_hash(
    val: Optional[Any],
    expected_algorithm: Optional[str] = None,
    expected_algo: Optional[str] = None,
) -> Optional[str]:
    """
    Validates whether the provided string is a valid cryptographic hash (MD5, SHA-1, or SHA-256).

    Requirements:
      - Contains only valid hexadecimal characters (0-9, a-f, A-F).
      - Matches documented lengths: 32 (MD5), 40 (SHA-1), or 64 (SHA-256).
      - If expected_algorithm is supplied ('sha256', 'md5', 'sha1'), strictly enforces that length.
      - Normalizes valid hashes to lowercase hexadecimal.

    Returns:
        Lowercase hexadecimal hash string if valid; None if missing or invalid.
    """
    if val is None:
        return None

    raw_str = str(val).strip()
    if not raw_str:
        return None

    length = len(raw_str)
    if length not in VALID_HASH_LENGTHS:
        logger.warning("Rejected process hash with unrecognized length (%d chars): '%s'", length, raw_str)
        return None

    if not HEXADECIMAL_REGEX.match(raw_str):
        logger.warning("Rejected process hash containing non-hexadecimal characters: '%s'", raw_str)
        return None

    algo = VALID_HASH_LENGTHS[length]
    algo_filter = expected_algorithm or expected_algo
    if algo_filter:
        norm_expected = algo_filter.strip().upper().replace("-", "")
        norm_algo = algo.replace("-", "")
        if norm_expected != norm_algo:
            logger.warning("Process hash algorithm mismatch: expected %s, got %s for '%s'", algo_filter, algo, raw_str)
            return None

    return raw_str.lower()


def is_valid_process_hash(
    val: Optional[Any],
    expected_algorithm: Optional[str] = None,
    expected_algo: Optional[str] = None,
) -> bool:
    """Returns True if the value is a valid cryptographic hash, False otherwise."""
    return validate_process_hash(val, expected_algorithm=expected_algorithm, expected_algo=expected_algo) is not None

# tests/test_validators.py
"""
Unit tests for IP, Hostname, and Process Hash Validators (Phase 4).
Validates:
  1. IPv4 and IPv6 address validation using standard ipaddress library.
  2. Rejection of invalid, malformed, and injection IP addresses.
  3. RFC 1123 DNS hostname syntax validation.
  4. Rejection of hostnames with injection characters, control chars, or improper labels.
  5. Process hash format, length, and hexadecimal validation (SHA-256, SHA-1, MD5).
  6. Normalization and safe handling of missing / empty inputs.
"""

import pytest

from integrations.validators import (
    is_valid_hostname,
    is_valid_ip,
    is_valid_process_hash,
    validate_hostname,
    validate_ip_address,
    validate_process_hash,
)


# ── 1. IP Address Validation Tests ────────────────────────────────────────────


@pytest.mark.parametrize(
    "ip_str",
    [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.50.12",
        "8.8.8.8",
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
    ],
)
def test_valid_ipv4_addresses(ip_str):
    assert is_valid_ip(ip_str) is True
    assert validate_ip_address(ip_str) == ip_str


@pytest.mark.parametrize(
    "ip_str",
    [
        "::1",
        "2001:db8::1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "fe80::1ff:fe23:4567:890a",
    ],
)
def test_valid_ipv6_addresses(ip_str):
    assert is_valid_ip(ip_str) is True
    assert validate_ip_address(ip_str) is not None


@pytest.mark.parametrize(
    "bad_ip",
    [
        "999.999.999.999",
        "192.168.1",
        "192.168.1.1.1",
        "256.0.0.1",
        "not-an-ip",
        "192.168.1.1; echo hacked",
        "192.168.1.1/24",  # CIDR is not a single endpoint IP
        "fe80:::1",
        "2001::85a3::7334",  # Multiple double-colons
        "",
        "   ",
        None,
    ],
)
def test_invalid_ip_addresses(bad_ip):
    assert is_valid_ip(bad_ip) is False
    assert validate_ip_address(bad_ip) is None


# ── 2. Hostname Validation Tests ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "hostname",
    [
        "workstation-01",
        "FIN-APP-02.corp.local",
        "desktop-def-88.internal.contoso.com",
        "localhost",
        "srv1.sub.domain.tld",
        "my-host-99",
        "a" * 63 + ".example.com",  # 63 char label is valid
    ],
)
def test_valid_hostnames(hostname):
    assert is_valid_hostname(hostname) is True
    assert validate_hostname(hostname) == hostname.strip()


@pytest.mark.parametrize(
    "bad_hostname",
    [
        "-invalid-start",
        "invalid-end-",
        ".starts-with-dot.com",
        "ends-with-dot.",
        "has..double-dot",
        "host;rm -rf /",
        "host|calc.exe",
        "host&cmd.exe",
        "host`id`",
        "host$VAR",
        "<script>alert(1)</script>",
        "host\x00nullbyte",
        "host\nnewline",
        "host name with spaces",
        "a" * 64 + ".com",  # Label > 63 chars
        ("a" * 60 + ".") * 5,  # Total > 253 chars
        "",
        "   ",
        None,
    ],
)
def test_invalid_hostnames(bad_hostname):
    assert is_valid_hostname(bad_hostname) is False
    assert validate_hostname(bad_hostname) is None


# ── 3. Process Hash Validation Tests ──────────────────────────────────────────


@pytest.mark.parametrize(
    "valid_hash,expected_algo",
    [
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
        ("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "sha256"),  # Uppercase
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
        ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
    ],
)
def test_valid_process_hashes(valid_hash, expected_algo):
    assert is_valid_process_hash(valid_hash) is True
    normalized = validate_process_hash(valid_hash)
    assert normalized == valid_hash.lower().strip()


@pytest.mark.parametrize(
    "bad_hash",
    [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",   # 63 chars (too short)
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555", # 65 chars (too long)
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g", # 'g' is non-hex
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", # non-hex
        "not-a-hash",
        "sha256; rm -rf",
        "d41d8cd98f00b204e9800998ecf8427\x00",
        "",
        "   ",
        None,
    ],
)
def test_invalid_process_hashes(bad_hash):
    assert is_valid_process_hash(bad_hash) is False
    assert validate_process_hash(bad_hash) is None


def test_hash_algorithm_restriction():
    """Verify algorithm-specific restriction checks."""
    sha256_sample = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    md5_sample = "d41d8cd98f00b204e9800998ecf8427e"

    assert validate_process_hash(sha256_sample, expected_algo="sha256") is not None
    assert validate_process_hash(md5_sample, expected_algo="sha256") is None  # MD5 rejected when sha256 expected
    assert validate_process_hash(md5_sample, expected_algo="md5") is not None

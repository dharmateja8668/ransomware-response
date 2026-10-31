"""
test_jira.py - Comprehensive Unit and Integration Test Suite for Jira Cloud Integration.

Automated Ransomware Containment & Incident Response Orchestrator
Day 1: Jira Cloud REST API Incident Ticketing Integration.

Tests the following requirements:
1. Jira API authentication (success, 401 unauthorized, 403 forbidden).
2. Jira project retrieval (success, multiple projects, project not found).
3. Successful incident ticket creation (summary format, multiline description format,
   payload structure, returned ticket ID and browse URL).
4. Handling invalid credentials.
5. Handling API connection failures (timeouts, network drop, 500 server error).
6. Security checks (HTTPS protocol enforcement, credential masking in logs).
7. Telemetry input validation (IP address, process hash, missing fields).
"""

from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

import pytest
import requests

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import JiraConfig, mask_secret
from backend.jira_integration import (
    IncidentData,
    IncidentValidationError,
    JiraAuthenticationError,
    JiraClient,
    JiraConnectionError,
    JiraIntegrationError,
    JiraProjectNotFoundError,
    JiraTicketCreationError,
    create_incident_ticket,
    format_ticket_description,
    format_ticket_summary,
    validate_incident_data,
)


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture
def sample_config() -> JiraConfig:
    """Fixture providing valid Jira configuration with simulated credentials."""
    return JiraConfig(
        base_url="https://cybersec-soc.atlassian.net",
        email="analyst@cybersec-soc.org",
        api_token="ATATT3xFfGF0testMockApiToken1234567890",
        project_key="SEC",
        issue_type="Task",
        timeout_seconds=5,
        verify_ssl=True,
    )


@pytest.fixture
def mock_session() -> MagicMock:
    """Fixture providing a mock requests.Session."""
    session = MagicMock()
    session.headers = {}
    return session


@pytest.fixture
def jira_client(sample_config, mock_session) -> JiraClient:
    """Fixture providing a JiraClient initialized with a mock session."""
    return JiraClient(
        base_url=sample_config.base_url,
        email=sample_config.email,
        api_token=sample_config.api_token,
        project_key=sample_config.project_key,
        issue_type=sample_config.issue_type,
        timeout_seconds=sample_config.timeout_seconds,
        verify_ssl=sample_config.verify_ssl,
        session=mock_session,
    )


@pytest.fixture
def sample_incident_payload() -> dict:
    """Fixture providing simulated ransomware alert telemetry data."""
    return {
        "incident_id": "INC-2026-9041",
        "incident_type": "Ransomware (LockBit 3.0)",
        "severity": "CRITICAL",
        "hostname": "WKSTN-FIN-04.corp.local",
        "ip_address": "10.0.4.15",
        "username": "finance_analyst_01",
        "process_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "detection_time": "2026-10-31T14:32:00Z",
        "incident_description": (
            "High-frequency unauthorized file renames with .lockbit extension detected "
            "in C:\\Users\\finance_analyst_01\\Documents. Canary tripwire activated. "
            "Volume Shadow Copies deletion attempted via vssadmin.exe delete shadows /all."
        ),
    }


# ==============================================================================
# 1. Jira API Authentication Tests
# ==============================================================================

def test_jira_authentication_success(jira_client, mock_session):
    """Test successful authentication returns user account details."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "displayName": "SOC Lead Analyst",
        "emailAddress": "analyst@cybersec-soc.org",
        "accountId": "5b10ac8d82e05b22cc7d4ef5",
        "active": True,
    }
    mock_session.get.return_value = mock_resp

    result = jira_client.verify_authentication()

    assert result["authenticated"] is True
    assert result["display_name"] == "SOC Lead Analyst"
    assert result["email"] == "analyst@cybersec-soc.org"
    assert result["account_id"] == "5b10ac8d82e05b22cc7d4ef5"
    assert result["status_code"] == 200

    # Verify endpoint called
    mock_session.get.assert_called_once_with(
        "https://cybersec-soc.atlassian.net/rest/api/3/myself",
        timeout=5,
        verify=True,
    )


def test_jira_authentication_invalid_credentials_401(jira_client, mock_session):
    """Test handling invalid credentials (HTTP 401 Unauthorized)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = "Unauthorized"
    mock_session.get.return_value = mock_resp

    with pytest.raises(JiraAuthenticationError) as exc_info:
        jira_client.verify_authentication()

    assert "401" in str(exc_info.value)
    # Security requirement: API token must NEVER leak in exception message
    assert jira_client.api_token not in str(exc_info.value)


def test_jira_authentication_forbidden_403(jira_client, mock_session):
    """Test handling forbidden access (HTTP 403 Forbidden)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "Forbidden"
    mock_session.get.return_value = mock_resp

    with pytest.raises(JiraAuthenticationError) as exc_info:
        jira_client.verify_authentication()

    assert "403" in str(exc_info.value)
    assert jira_client.api_token not in str(exc_info.value)


def test_jira_authentication_not_found_404(jira_client, mock_session):
    """Test handling 404 Not Found on invalid Jira domain / endpoint."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "Not Found"
    mock_session.get.return_value = mock_resp

    with pytest.raises(JiraIntegrationError) as exc_info:
        jira_client.verify_authentication()

    assert "404" in str(exc_info.value)


# ==============================================================================
# 2. Jira Project Retrieval Tests
# ==============================================================================

def test_jira_project_retrieval_success(jira_client, mock_session):
    """Test retrieving available Jira projects."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"id": "10000", "key": "SEC", "name": "Security Incidents", "projectTypeKey": "software"},
        {"id": "10001", "key": "IT", "name": "IT Service Desk", "projectTypeKey": "service_desk"},
        {"id": "10002", "key": "KAN", "name": "SOC Kanban", "projectTypeKey": "software"},
    ]
    mock_session.get.return_value = mock_resp

    projects = jira_client.get_projects()

    assert len(projects) == 3
    assert projects[0]["key"] == "SEC"
    assert projects[0]["name"] == "Security Incidents"
    assert projects[1]["key"] == "IT"
    assert projects[2]["key"] == "KAN"


def test_identify_incident_project_key_success(jira_client, mock_session):
    """Test identifying and confirming a valid incident project key."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"id": "10000", "key": "SEC", "name": "Security Incidents"},
        {"id": "10001", "key": "IT", "name": "IT Desk"},
    ]
    mock_session.get.return_value = mock_resp

    confirmed_key = jira_client.identify_incident_project_key("SEC")
    assert confirmed_key == "SEC"


def test_identify_incident_project_key_not_found(jira_client, mock_session):
    """Test error handling when requested project key does not exist."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"id": "10000", "key": "IT", "name": "IT Desk"},
        {"id": "10001", "key": "DEV", "name": "Software Development"},
    ]
    mock_session.get.return_value = mock_resp

    with pytest.raises(JiraProjectNotFoundError) as exc_info:
        jira_client.identify_incident_project_key("NON_EXISTENT_KEY")

    assert "NON_EXISTENT_KEY" in str(exc_info.value)
    assert "IT, DEV" in str(exc_info.value)


def test_verify_project_and_issue_type_success(jira_client, mock_session):
    """Test querying project issue types and verifying target issue type exists."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "id": "10000",
        "key": "SEC",
        "name": "Security Incidents",
        "issueTypes": [
            {"id": "1001", "name": "Task"},
            {"id": "1002", "name": "Incident"},
        ],
    }
    mock_session.get.return_value = mock_resp

    result = jira_client.verify_project_and_issue_type("SEC", "Task")
    assert result["issue_type_verified"] is True
    assert "Task" in result["available_issue_types"]


# ==============================================================================
# 3. Incident Ticket Creation Tests
# ==============================================================================

def test_successful_incident_ticket_creation(jira_client, mock_session, sample_incident_payload):
    """
    Test creating a Jira incident ticket with simulated ransomware alert data.
    Verifies Summary format, multiline Description format, and return dictionary.
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {
        "id": "10550",
        "key": "SEC-88",
        "self": "https://cybersec-soc.atlassian.net/rest/api/2/issue/10550",
    }
    mock_session.post.return_value = mock_resp

    result = jira_client.create_incident_ticket(**sample_incident_payload)

    # 1. Verify return structure
    assert result["success"] is True
    assert result["ticket_id"] == "10550"
    assert result["ticket_key"] == "SEC-88"
    assert result["ticket_url"] == "https://cybersec-soc.atlassian.net/browse/SEC-88"
    assert result["summary"] == "[CRITICAL] Ransomware Detected - WKSTN-FIN-04.corp.local"
    assert result["project_key"] == "SEC"
    assert result["status"] == "Created"

    # 2. Verify POST request payload sent to Jira REST API
    mock_session.post.assert_called_once()
    call_args, call_kwargs = mock_session.post.call_args

    assert call_args[0] == "https://cybersec-soc.atlassian.net/rest/api/3/issue"
    payload = call_kwargs["json"]["fields"]

    # Verify Summary format: [CRITICAL] Ransomware Detected - HOSTNAME
    assert payload["summary"] == "[CRITICAL] Ransomware Detected - WKSTN-FIN-04.corp.local"
    assert payload["project"]["key"] == "SEC"
    assert payload["issuetype"]["name"] == "Task"

    # Verify Description contains all required 9 labels and values (supports ADF dict and plain string)
    description_str = str(payload["description"])
    assert "Incident ID: INC-2026-9041" in description_str
    assert "Incident Type: Ransomware (LockBit 3.0)" in description_str
    assert "Severity: CRITICAL" in description_str
    assert "Affected Host: WKSTN-FIN-04.corp.local" in description_str
    assert "IP Address: 10.0.4.15" in description_str
    assert "Compromised User: finance_analyst_01" in description_str
    assert "Process Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in description_str
    assert "Detection Time: 2026-10-31T14:32:00Z" in description_str
    assert "Incident Description: High-frequency unauthorized file renames" in description_str


def test_standalone_create_incident_ticket_function(jira_client, sample_incident_payload):
    """Test the standalone create_incident_ticket() function accepting incident parameters."""
    with patch.object(jira_client, "create_incident_ticket") as mock_create:
        mock_create.return_value = {
            "success": True,
            "ticket_id": "10999",
            "ticket_key": "SEC-99",
            "ticket_url": "https://cybersec-soc.atlassian.net/browse/SEC-99",
            "summary": "[CRITICAL] Ransomware Detected - WKSTN-FIN-04.corp.local",
            "project_key": "SEC",
            "status": "Created",
        }

        result = create_incident_ticket(
            client=jira_client,
            **sample_incident_payload,
        )

        assert result["success"] is True
        assert result["ticket_key"] == "SEC-99"
        mock_create.assert_called_once()


def test_duplicate_incident_ticket_avoidance(jira_client, mock_session, sample_incident_payload):
    """Test that existing incident ticket for host is detected and reused without duplicating."""
    search_resp = MagicMock()
    search_resp.status_code = 200
    search_resp.json.return_value = {
        "total": 1,
        "issues": [
            {
                "id": "10888",
                "key": "SEC-50",
                "fields": {
                    "summary": "[CRITICAL] Ransomware Detected - WKSTN-FIN-04.corp.local",
                    "status": {"name": "In Progress"},
                },
            }
        ],
    }
    mock_session.get.return_value = search_resp

    result = jira_client.create_incident_ticket(check_existing=True, **sample_incident_payload)

    assert result["success"] is True
    assert result["ticket_key"] == "SEC-50"
    assert result["status"] == "Existing (Duplicate Avoided)"
    assert result["is_duplicate"] is True
    # Verify POST was NEVER called because duplicate was detected
    mock_session.post.assert_not_called()


# ==============================================================================
# 4. Handling API Failures & Error Modes
# ==============================================================================

def test_handling_ticket_creation_bad_request_400(jira_client, mock_session, sample_incident_payload):
    """Test handling Jira API 400 Bad Request (e.g., invalid issue type or missing field)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.json.return_value = {
        "errorMessages": [],
        "errors": {"issuetype": "Issue type 'Incident' does not exist in project 'SEC'"},
    }
    mock_session.post.return_value = mock_resp

    with pytest.raises(JiraTicketCreationError) as exc_info:
        jira_client.create_incident_ticket(**sample_incident_payload)

    assert "400" in str(exc_info.value)
    assert "issuetype" in str(exc_info.value)


def test_handling_connection_failure_timeout(jira_client, mock_session):
    """Test handling network timeout during Jira communication."""
    mock_session.get.side_effect = requests.exceptions.Timeout("Connection timed out after 5 seconds")

    with pytest.raises(JiraConnectionError) as exc_info:
        jira_client.verify_authentication()

    assert "Failed to connect to Jira" in str(exc_info.value)


def test_handling_connection_failure_network_error(jira_client, mock_session):
    """Test handling low-level network connection drop or DNS failure."""
    mock_session.get.side_effect = requests.exceptions.ConnectionError("DNS resolution failed")

    with pytest.raises(JiraConnectionError) as exc_info:
        jira_client.get_projects()

    assert "Failed to connect to Jira" in str(exc_info.value)


def test_handling_http_server_error_500(jira_client, mock_session, sample_incident_payload):
    """Test handling Jira Cloud internal server error (HTTP 500)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"
    mock_session.post.return_value = mock_resp

    with pytest.raises(JiraTicketCreationError) as exc_info:
        jira_client.create_incident_ticket(**sample_incident_payload)

    assert "500" in str(exc_info.value)


# ==============================================================================
# 5. Incident Telemetry Validation Tests
# ==============================================================================

def test_validation_missing_required_fields(sample_incident_payload):
    """Test that missing required fields trigger an IncidentValidationError."""
    payload = dict(sample_incident_payload)
    payload["hostname"] = ""  # Empty hostname

    with pytest.raises(IncidentValidationError) as exc_info:
        validate_incident_data(**payload)

    assert "Hostname" in str(exc_info.value)


def test_validation_invalid_ip_address(sample_incident_payload):
    """Test that invalid IP address format triggers validation error."""
    payload = dict(sample_incident_payload)
    payload["ip_address"] = "300.500.700.900"  # Invalid IP

    with pytest.raises(IncidentValidationError) as exc_info:
        validate_incident_data(**payload)

    assert "not a valid IPv4 or IPv6 address" in str(exc_info.value)


def test_validation_invalid_process_hash(sample_incident_payload):
    """Test that invalid process hash triggers validation error."""
    payload = dict(sample_incident_payload)
    payload["process_hash"] = "invalid_hash_xyz_123"

    with pytest.raises(IncidentValidationError) as exc_info:
        validate_incident_data(**payload)

    assert "Process hash" in str(exc_info.value)


def test_validation_accepts_valid_md5_sha1_sha256(sample_incident_payload):
    """Test that valid MD5 (32 hex), SHA-1 (40 hex), and SHA-256 (64 hex) hashes pass."""
    # Test MD5 (32 chars)
    payload = dict(sample_incident_payload)
    payload["process_hash"] = "d41d8cd98f00b204e9800998ecf8427e"
    data = validate_incident_data(**payload)
    assert data.process_hash == "d41d8cd98f00b204e9800998ecf8427e"

    # Test SHA-1 (40 chars)
    payload["process_hash"] = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    data = validate_incident_data(**payload)
    assert data.process_hash == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    # Test SHA-256 (64 chars)
    payload["process_hash"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    data = validate_incident_data(**payload)
    assert data.process_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ==============================================================================
# 6. Security Requirements Tests
# ==============================================================================

def test_security_enforces_https_protocol():
    """Security Requirement: Ensure JiraClient refuses unencrypted HTTP URLs."""
    with pytest.raises(ValueError) as exc_info:
        JiraClient(
            base_url="http://insecure-jira.corp.local",
            email="user@test.org",
            api_token="token123",
        )

    assert "HTTPS" in str(exc_info.value)


def test_security_mask_secret_redacts_tokens():
    """Security Requirement: Ensure API token masking prevents token disclosure."""
    raw_token = "ATATT3xFfGF0SuperSecretJiraToken123456789"
    masked = mask_secret(raw_token)

    assert "ATAT...****" == masked
    assert "SuperSecret" not in masked
    assert mask_secret(None) == "[NOT SET]"
    assert mask_secret("") == "[NOT SET]"


def test_security_safe_dict_masks_api_token(sample_config):
    """Security Requirement: Ensure config.safe_dict() never contains raw secrets."""
    safe = sample_config.safe_dict()
    assert safe["api_token"] != sample_config.api_token
    assert "****" in safe["api_token"]

"""
jira_integration.py - Jira Cloud REST API Integration Module.

Automated Ransomware Containment & Incident Response Orchestrator
Day 1: Jira Cloud REST API Integration.

Capabilities:
- Secure connection establishment with Jira Cloud over HTTPS.
- Authentication verification via Jira Cloud REST API (GET /rest/api/3/myself).
- Project enumeration and project key identification (GET /rest/api/3/project).
- Project issue type verification (GET /rest/api/3/project/{key}).
- Duplicate ticket detection to prevent duplicate issue creation.
- Input validation for ransomware incident telemetry.
- Automated creation of standardized Jira incident tickets (POST /rest/api/3/issue)
  supporting Atlassian Document Format (ADF).
- Comprehensive exception handling without secret leakage in logs.
"""

from dataclasses import dataclass
import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from requests.auth import HTTPBasicAuth

from backend.config import JiraConfig, load_config, mask_secret

# Logger configuration
logger = logging.getLogger("orchestrator.jira")


# ==============================================================================
# Custom Exceptions Hierarchy
# ==============================================================================

class JiraIntegrationError(Exception):
    """Base exception for all Jira integration errors."""
    pass


class JiraAuthenticationError(JiraIntegrationError):
    """Raised when authentication against Jira fails (e.g., HTTP 401/403)."""
    pass


class JiraConnectionError(JiraIntegrationError):
    """Raised when network, DNS, or timeout connection issues occur."""
    pass


class JiraProjectNotFoundError(JiraIntegrationError):
    """Raised when the specified Jira project cannot be found or accessed."""
    pass


class JiraTicketCreationError(JiraIntegrationError):
    """Raised when Jira rejects issue creation (e.g., HTTP 400 bad request)."""
    pass


class IncidentValidationError(JiraIntegrationError):
    """Raised when incident telemetry fails data validation checks."""
    pass


class JiraAssignmentError(JiraIntegrationError):
    """Raised when Jira ticket assignment to an analyst fails."""
    pass


# ==============================================================================
# Incident Telemetry Validation & Formatting
# ==============================================================================

@dataclass
class IncidentData:
    """Container for validated ransomware incident telemetry."""
    incident_id: str
    incident_type: str
    severity: str
    hostname: str
    ip_address: str
    username: str
    process_hash: str
    detection_time: str
    incident_description: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "incident_id": self.incident_id,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "username": self.username,
            "process_hash": self.process_hash,
            "detection_time": self.detection_time,
            "incident_description": self.incident_description,
        }


def validate_incident_data(
    incident_id: str,
    incident_type: str,
    severity: str,
    hostname: str,
    ip_address: str,
    username: str,
    process_hash: str,
    detection_time: str,
    incident_description: str,
) -> IncidentData:
    """
    Validate and sanitize incident parameters before transmitting to Jira.
    
    Enforces SOC security standards:
    - Verifies all required fields are present and non-empty.
    - Validates IPv4 or IPv6 address format.
    - Validates cryptographic process hash (MD5, SHA-1, or SHA-256 hex string).
    - Checks hostname format.
    """
    fields = {
        "Incident ID": incident_id,
        "Incident Type": incident_type,
        "Severity": severity,
        "Hostname": hostname,
        "IP Address": ip_address,
        "Username": username,
        "Process Hash": process_hash,
        "Detection Time": detection_time,
        "Incident Description": incident_description,
    }

    for name, value in fields.items():
        if value is None or not str(value).strip():
            raise IncidentValidationError(f"Validation failed: '{name}' is required and cannot be empty.")

    cleaned_incident_id = str(incident_id).strip()
    cleaned_incident_type = str(incident_type).strip()
    cleaned_severity = str(severity).strip().upper()
    cleaned_hostname = str(hostname).strip()
    cleaned_ip = str(ip_address).strip()
    cleaned_username = str(username).strip()
    cleaned_hash = str(process_hash).strip().lower()
    cleaned_time = str(detection_time).strip()
    cleaned_desc = str(incident_description).strip()

    # Validate IP Address
    try:
        ipaddress.ip_address(cleaned_ip)
    except ValueError:
        raise IncidentValidationError(
            f"Validation failed: '{cleaned_ip}' is not a valid IPv4 or IPv6 address."
        )

    # Validate Process Hash (MD5 = 32 hex, SHA-1 = 40 hex, SHA-256 = 64 hex)
    if not re.fullmatch(r"^[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}$", cleaned_hash):
        raise IncidentValidationError(
            f"Validation failed: Process hash '{cleaned_hash}' must be a valid hex string "
            f"(MD5: 32 chars, SHA-1: 40 chars, or SHA-256: 64 chars)."
        )

    # Validate Hostname (RFC 1123 compliant characters)
    if not re.fullmatch(r"^[a-zA-Z0-9_.-]{1,255}$", cleaned_hostname):
        raise IncidentValidationError(
            f"Validation failed: Hostname '{cleaned_hostname}' contains invalid characters."
        )

    return IncidentData(
        incident_id=cleaned_incident_id,
        incident_type=cleaned_incident_type,
        severity=cleaned_severity,
        hostname=cleaned_hostname,
        ip_address=cleaned_ip,
        username=cleaned_username,
        process_hash=cleaned_hash,
        detection_time=cleaned_time,
        incident_description=cleaned_desc,
    )


def format_ticket_summary(hostname: str, severity: str = "CRITICAL") -> str:
    """
    Format Jira Ticket Summary according to required specification:
    [CRITICAL] Ransomware Detected - HOSTNAME
    """
    clean_severity = severity.strip().upper() if severity else "CRITICAL"
    clean_hostname = hostname.strip()
    return f"[{clean_severity}] Ransomware Detected - {clean_hostname}"


def format_ticket_description(data: IncidentData) -> str:
    """
    Format Jira Ticket Description according to required specification:
    
    Incident ID:
    Incident Type:
    Severity:
    Affected Host:
    IP Address:
    Compromised User:
    Process Hash:
    Detection Time:
    Incident Description:
    """
    description_lines = [
        f"Incident ID: {data.incident_id}",
        f"Incident Type: {data.incident_type}",
        f"Severity: {data.severity}",
        f"Affected Host: {data.hostname}",
        f"IP Address: {data.ip_address}",
        f"Compromised User: {data.username}",
        f"Process Hash: {data.process_hash}",
        f"Detection Time: {data.detection_time}",
        f"Incident Description: {data.incident_description}",
    ]
    return "\n".join(description_lines)


def format_adf_description(description_text: str) -> Dict[str, Any]:
    """
    Format plain text incident description into Jira Cloud REST API v3
    Atlassian Document Format (ADF).
    """
    paragraphs = []
    for line in description_text.splitlines():
        line_str = line.strip()
        if line_str:
            paragraphs.append({
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": line_str,
                    }
                ],
            })
        else:
            paragraphs.append({
                "type": "paragraph",
                "content": [],
            })
    if not paragraphs:
        paragraphs = [{
            "type": "paragraph",
            "content": [{"type": "text", "text": description_text}],
        }]
    return {
        "type": "doc",
        "version": 1,
        "content": paragraphs,
    }


# ==============================================================================
# Jira REST API Client
# ==============================================================================

class JiraClient:
    """
    Jira Cloud REST API Client.
    
    Provides secure, TLS-enforced interaction with Atlassian Jira Cloud:
    - User authentication verification (GET /rest/api/3/myself).
    - Project retrieval and validation (GET /rest/api/3/project).
    - Issue type verification (GET /rest/api/3/project/{key}).
    - Standardized incident issue creation (POST /rest/api/3/issue).
    """

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        project_key: str = "SEC",
        issue_type: str = "Task",
        api_version: str = "3",
        timeout_seconds: int = 10,
        verify_ssl: bool = True,
        session: Optional[requests.Session] = None,
    ):
        """Initialize the JiraClient with credentials and connection settings."""
        self.base_url = base_url.strip().rstrip("/")
        self.email = email.strip()
        self.api_token = api_token.strip()
        self.project_key = project_key.strip().upper()
        self.issue_type = issue_type.strip()
        self.api_version = api_version.strip()
        self.timeout_seconds = timeout_seconds
        self.verify_ssl = verify_ssl

        # Enforce HTTPS security rule
        parsed = urlparse(self.base_url)
        if parsed.scheme.lower() != "https":
            raise ValueError(
                f"Insecure protocol '{parsed.scheme}'. Jira Cloud API requires HTTPS."
            )

        # Setup requests session
        self.session = session or requests.Session()
        self.session.auth = HTTPBasicAuth(self.email, self.api_token)
        if not hasattr(self.session, "headers") or self.session.headers is None:
            self.session.headers = {}
        if hasattr(self.session.headers, "update"):
            self.session.headers.update({
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "Ransomware-Incident-Response-Orchestrator/1.0",
            })

    @classmethod
    def from_config(cls, config: Optional[JiraConfig] = None) -> "JiraClient":
        """Instantiate JiraClient directly from a JiraConfig object or environment."""
        cfg = config or load_config()
        cfg.validate()
        return cls(
            base_url=cfg.base_url,
            email=cfg.email,
            api_token=cfg.api_token,
            project_key=cfg.project_key,
            issue_type=cfg.issue_type,
            api_version=cfg.api_version,
            timeout_seconds=cfg.timeout_seconds,
            verify_ssl=cfg.verify_ssl,
        )

    def verify_authentication(self) -> Dict[str, Any]:
        """
        Verify connection and authentication against Jira Cloud REST API.
        
        Calls Jira endpoint: GET /rest/api/{api_version}/myself
        Returns user account details upon success.
        Raises JiraAuthenticationError on 401/403 or JiraConnectionError on network failure.
        """
        url = f"{self.base_url}/rest/api/{self.api_version}/myself"
        logger.info(
            "Verifying Jira authentication at %s for account %s...",
            url,
            self.email,
        )

        try:
            response = self.session.get(
                url,
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            logger.error("Jira connection failure during authentication: %s", exc)
            raise JiraConnectionError(f"Failed to connect to Jira at {self.base_url}: {exc}") from exc
        except requests.exceptions.RequestException as exc:
            logger.error("Unexpected network error during Jira authentication: %s", exc)
            raise JiraIntegrationError(f"Network error communicating with Jira: {exc}") from exc

        if response.status_code == 200:
            data = response.json()
            display_name = data.get("displayName", "Unknown")
            email = data.get("emailAddress", self.email)
            account_id = data.get("accountId", "Unknown")
            logger.info("Jira authentication successful. User: '%s' (%s)", display_name, email)
            return {
                "authenticated": True,
                "display_name": display_name,
                "email": email,
                "account_id": account_id,
                "status_code": 200,
            }
        elif response.status_code == 401:
            logger.warning("Jira authentication failed (HTTP 401) for account %s.", self.email)
            raise JiraAuthenticationError(
                "Jira authentication failed (HTTP 401 Unauthorized). "
                "Verify your JIRA_EMAIL and JIRA_API_TOKEN in your .env configuration."
            )
        elif response.status_code == 403:
            logger.warning("Jira access forbidden (HTTP 403) for account %s.", self.email)
            raise JiraAuthenticationError(
                "Jira access forbidden (HTTP 403 Forbidden). "
                "The API token lacks necessary permissions or your account is restricted."
            )
        elif response.status_code == 404:
            logger.error("Jira endpoint not found (HTTP 404) at %s", url)
            raise JiraIntegrationError(
                f"Jira endpoint '{url}' not found (HTTP 404). "
                "Verify that JIRA_BASE_URL is your correct Atlassian Cloud domain."
            )
        else:
            logger.error(
                "Jira authentication returned unexpected HTTP %d: %s",
                response.status_code,
                response.text,
            )
            raise JiraIntegrationError(
                f"Jira API returned unexpected status {response.status_code}: {response.text}"
            )

    def get_projects(self) -> List[Dict[str, Any]]:
        """
        Retrieve list of available Jira projects.
        
        Calls Jira endpoint: GET /rest/api/{api_version}/project
        Returns a list of project summaries containing key, name, id, and type.
        """
        url = f"{self.base_url}/rest/api/{self.api_version}/project"
        logger.info("Retrieving available Jira projects from %s...", url)

        try:
            response = self.session.get(
                url,
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            logger.error("Jira connection failure while fetching projects: %s", exc)
            raise JiraConnectionError(f"Failed to connect to Jira at {self.base_url}: {exc}") from exc
        except requests.exceptions.RequestException as exc:
            logger.error("Network error while fetching Jira projects: %s", exc)
            raise JiraIntegrationError(f"Network error fetching projects: {exc}") from exc

        if response.status_code == 200:
            projects = response.json()
            project_list = [
                {
                    "key": p.get("key"),
                    "name": p.get("name"),
                    "id": p.get("id"),
                    "project_type": p.get("projectTypeKey", "software"),
                }
                for p in projects
            ]
            logger.info("Successfully retrieved %d Jira project(s).", len(project_list))
            return project_list
        elif response.status_code in (401, 403):
            raise JiraAuthenticationError(
                f"Access denied retrieving Jira projects (HTTP {response.status_code})."
            )
        else:
            raise JiraIntegrationError(
                f"Failed to retrieve Jira projects (HTTP {response.status_code}): {response.text}"
            )

    def identify_incident_project_key(self, requested_key: Optional[str] = None) -> str:
        """
        Identify and verify the Jira project key where security incidents will be recorded.
        
        - Checks available projects for requested_key (or self.project_key).
        - If the key is not found, raises JiraProjectNotFoundError listing available keys.
        """
        target_key = (requested_key or self.project_key).strip().upper()
        projects = self.get_projects()
        available_keys = [p["key"] for p in projects if p.get("key")]

        if target_key in available_keys:
            logger.info("Verified target incident project key: '%s'", target_key)
            return target_key

        available_str = ", ".join(available_keys) if available_keys else "None found"
        logger.error(
            "Project key '%s' not found in Jira instance. Available project keys: [%s]",
            target_key,
            available_str,
        )
        raise JiraProjectNotFoundError(
            f"Jira project key '{target_key}' not found. Available projects in your Jira: [{available_str}]. "
            f"Please create project '{target_key}' in your Jira workspace or update JIRA_PROJECT_KEY in .env."
        )

    def verify_project_and_issue_type(
        self,
        project_key: Optional[str] = None,
        issue_type_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Query project details and verify whether the configured issue type exists.
        Calls GET /rest/api/{api_version}/project/{key}.
        """
        target_key = (project_key or self.project_key).strip().upper()
        target_type = (issue_type_name or self.issue_type).strip()

        url = f"{self.base_url}/rest/api/{self.api_version}/project/{target_key}"
        try:
            response = self.session.get(
                url,
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
            )
        except Exception as exc:
            raise JiraConnectionError(f"Failed to query project details for '{target_key}': {exc}") from exc

        if response.status_code == 200:
            proj_data = response.json()
            issue_types = [t.get("name") for t in proj_data.get("issueTypes", []) if t.get("name")]
            has_issue_type = target_type in issue_types

            if not has_issue_type:
                logger.warning(
                    "Issue type '%s' not found in project '%s'. Available types: %s",
                    target_type,
                    target_key,
                    issue_types,
                )

            return {
                "project_key": target_key,
                "project_name": proj_data.get("name"),
                "project_id": proj_data.get("id"),
                "available_issue_types": issue_types,
                "issue_type_verified": has_issue_type,
                "target_issue_type": target_type,
            }
        elif response.status_code == 404:
            raise JiraProjectNotFoundError(
                f"Jira project '{target_key}' does not exist or account lacks browse permissions."
            )
        elif response.status_code in (401, 403):
            raise JiraAuthenticationError(
                f"Access denied querying project '{target_key}' (HTTP {response.status_code})."
            )
        else:
            raise JiraIntegrationError(
                f"Failed to query project details (HTTP {response.status_code}): {response.text}"
            )

    def find_existing_incident_ticket(
        self,
        project_key: str,
        hostname: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Check if an open or recent incident ticket already exists for this host in Jira.
        Uses JQL search to avoid creating duplicate test tickets.
        """
        search_url = f"{self.base_url}/rest/api/{self.api_version}/search"
        jql = f'project = "{project_key}" AND summary ~ "Ransomware Detected - {hostname}" ORDER BY created DESC'
        try:
            resp = self.session.get(
                search_url,
                params={"jql": jql, "maxResults": 1, "fields": "summary,status,created"},
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
            )
            if resp.status_code == 200:
                data = resp.json()
                issues = data.get("issues", [])
                if issues:
                    found = issues[0]
                    return {
                        "id": found.get("id"),
                        "key": found.get("key"),
                        "url": f"{self.base_url}/browse/{found.get('key')}",
                        "summary": found.get("fields", {}).get("summary"),
                        "status": found.get("fields", {}).get("status", {}).get("name", "Created"),
                    }
        except Exception as exc:
            logger.debug("JQL search for existing incident ticket failed (non-fatal): %s", exc)
        return None

    def create_incident_ticket(
        self,
        incident_id: str,
        incident_type: str,
        severity: str,
        hostname: str,
        ip_address: str,
        username: str,
        process_hash: str,
        detection_time: str,
        incident_description: str,
        project_key: Optional[str] = None,
        issue_type: Optional[str] = None,
        check_existing: bool = True,
    ) -> Dict[str, Any]:
        """
        Create a standardized Jira incident ticket for a detected ransomware threat.
        Uses POST /rest/api/{api_version}/issue with ADF description support.
        Checks for an existing ticket first to prevent duplicate creation.
        """
        # Step 1: Validate incident data
        validated = validate_incident_data(
            incident_id=incident_id,
            incident_type=incident_type,
            severity=severity,
            hostname=hostname,
            ip_address=ip_address,
            username=username,
            process_hash=process_hash,
            detection_time=detection_time,
            incident_description=incident_description,
        )

        target_project = (project_key or self.project_key).strip().upper()
        target_issue_type = (issue_type or self.issue_type).strip()

        # Step 2: Check for existing test ticket (Task 5 Duplicate Avoidance)
        if check_existing:
            existing = self.find_existing_incident_ticket(target_project, validated.hostname)
            if existing:
                logger.info(
                    "Existing incident ticket '%s' found for host '%s'. Avoiding duplicate.",
                    existing["key"],
                    validated.hostname,
                )
                return {
                    "success": True,
                    "ticket_id": existing["id"],
                    "ticket_key": existing["key"],
                    "ticket_url": existing["url"],
                    "summary": existing["summary"] or format_ticket_summary(validated.hostname, validated.severity),
                    "project_key": target_project,
                    "status": "Existing (Duplicate Avoided)",
                    "severity": validated.severity,
                    "hostname": validated.hostname,
                    "is_duplicate": True,
                }

        # Step 3: Format Summary and Description
        summary = format_ticket_summary(hostname=validated.hostname, severity=validated.severity)
        raw_description = format_ticket_description(validated)

        # Construct Payload (ADF for API v3, plain string for API v2)
        if self.api_version == "3":
            jira_description = format_adf_description(raw_description)
        else:
            jira_description = raw_description

        payload = {
            "fields": {
                "project": {
                    "key": target_project
                },
                "summary": summary,
                "description": jira_description,
                "issuetype": {
                    "name": target_issue_type
                },
                "labels": [
                    "ransomware",
                    "incident-response",
                    validated.severity.lower(),
                ],
            }
        }

        url = f"{self.base_url}/rest/api/{self.api_version}/issue"
        logger.info(
            "Creating Jira ticket in project '%s' with summary: '%s' via %s...",
            target_project,
            summary,
            url,
        )

        # Step 4: Transmit request to Jira
        try:
            response = self.session.post(
                url,
                json=payload,
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            logger.error("Connection failed while creating Jira ticket: %s", exc)
            raise JiraConnectionError(f"Failed to connect to Jira at {self.base_url}: {exc}") from exc
        except requests.exceptions.RequestException as exc:
            logger.error("Network error while creating Jira ticket: %s", exc)
            raise JiraIntegrationError(f"Network error while creating ticket: {exc}") from exc

        # Step 5: Handle responses
        if response.status_code in (200, 201):
            res_data = response.json()
            ticket_id = res_data.get("id")
            ticket_key = res_data.get("key")
            ticket_url = f"{self.base_url}/browse/{ticket_key}"

            logger.info("Successfully created Jira incident ticket: %s (%s)", ticket_key, ticket_url)
            return {
                "success": True,
                "ticket_id": ticket_id,
                "ticket_key": ticket_key,
                "ticket_url": ticket_url,
                "summary": summary,
                "project_key": target_project,
                "status": "Created",
                "severity": validated.severity,
                "hostname": validated.hostname,
                "is_duplicate": False,
            }
        elif response.status_code in (401, 403):
            logger.error("Jira ticket creation unauthorized: HTTP %d", response.status_code)
            raise JiraAuthenticationError(
                f"Unauthorized to create issue in project '{target_project}' (HTTP {response.status_code})."
            )
        elif response.status_code == 400:
            error_data = {}
            try:
                error_data = response.json()
            except Exception:
                pass
            error_msg = error_data.get("errorMessages") or error_data.get("errors") or response.text
            logger.error("Jira rejected ticket creation: %s", error_msg)
            raise JiraTicketCreationError(
                f"Jira rejected ticket creation (HTTP 400): {error_msg}. "
                f"Verify that issue type '{target_issue_type}' exists in project '{target_project}'."
            )
        else:
            logger.error("Unexpected Jira response (HTTP %d): %s", response.status_code, response.text)
            raise JiraTicketCreationError(
                f"Failed to create Jira ticket (HTTP {response.status_code}): {response.text}"
            )

    # ── Day 2: Analyst Assignment Methods ─────────────────────────────────────

    def get_assignable_users(self, project_key: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve the list of users assignable to issues in the given Jira project.

        Calls: GET /rest/api/{api_version}/user/assignable/search?project={key}

        Returns a list of dicts: [{accountId, displayName, emailAddress, active}]
        Returns an empty list if no users are found (non-fatal).
        Raises JiraAuthenticationError on 401/403.
        Raises JiraConnectionError on network failure.
        """
        target_key = (project_key or self.project_key).strip().upper()
        url = f"{self.base_url}/rest/api/{self.api_version}/user/assignable/search"
        logger.info("Retrieving assignable users for project '%s'...", target_key)

        try:
            response = self.session.get(
                url,
                params={"project": target_key},
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            logger.error("Connection failed while fetching assignable users: %s", exc)
            raise JiraConnectionError(f"Failed to connect to Jira at {self.base_url}: {exc}") from exc
        except requests.exceptions.RequestException as exc:
            raise JiraIntegrationError(f"Network error fetching assignable users: {exc}") from exc

        if response.status_code == 200:
            users = response.json()
            if not users:
                logger.warning("No assignable users found for project '%s'.", target_key)
                return []
            result = [
                {
                    "accountId": u.get("accountId", ""),
                    "displayName": u.get("displayName", "Unknown"),
                    "emailAddress": u.get("emailAddress", ""),
                    "active": u.get("active", False),
                }
                for u in users
            ]
            logger.info("Found %d assignable user(s) for project '%s'.", len(result), target_key)
            return result
        elif response.status_code in (401, 403):
            raise JiraAuthenticationError(
                f"Access denied retrieving assignable users (HTTP {response.status_code}). "
                "Verify your API token has 'Browse Projects' permission."
            )
        else:
            raise JiraIntegrationError(
                f"Failed to retrieve assignable users (HTTP {response.status_code}): {response.text}"
            )

    def assign_incident_ticket(self, issue_key: str, account_id: str) -> Dict[str, Any]:
        """
        Assign a Jira incident ticket to a specific SOC analyst by their Jira accountId.

        Calls: PUT /rest/api/{api_version}/issue/{issueKey}/assignee
        Jira returns HTTP 204 No Content on success (no response body).

        Returns a dict: {assigned: bool, issue_key, account_id}
        Raises JiraAssignmentError on 400 (invalid accountId) or 404 (invalid issue key).
        Raises JiraAuthenticationError on 401/403.
        Raises JiraConnectionError on network failure.
        """
        if not issue_key or not issue_key.strip():
            raise JiraAssignmentError("issue_key cannot be empty.")
        if not account_id or not account_id.strip():
            raise JiraAssignmentError("account_id cannot be empty. Cannot assign to anonymous user.")

        url = f"{self.base_url}/rest/api/{self.api_version}/issue/{issue_key.strip()}/assignee"
        logger.info(
            "Assigning ticket '%s' to analyst with accountId '%s'...",
            issue_key,
            mask_secret(account_id, visible_chars=6),
        )

        try:
            response = self.session.put(
                url,
                json={"accountId": account_id.strip()},
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            logger.error("Connection failed while assigning ticket '%s': %s", issue_key, exc)
            raise JiraConnectionError(f"Failed to connect to Jira at {self.base_url}: {exc}") from exc
        except requests.exceptions.RequestException as exc:
            raise JiraIntegrationError(f"Network error while assigning ticket: {exc}") from exc

        if response.status_code == 204:
            logger.info("Ticket '%s' successfully assigned to accountId '%s'.", issue_key, mask_secret(account_id, 6))
            return {
                "assigned": True,
                "issue_key": issue_key,
                "account_id": account_id,
            }
        elif response.status_code == 400:
            error_text = response.text or "Invalid accountId or malformed request."
            logger.error("Assignment rejected (HTTP 400) for ticket '%s': %s", issue_key, error_text)
            raise JiraAssignmentError(
                f"Failed to assign ticket '{issue_key}' (HTTP 400): {error_text}. "
                "Verify the accountId is valid and belongs to an active Jira user."
            )
        elif response.status_code == 404:
            raise JiraAssignmentError(
                f"Issue key '{issue_key}' not found in Jira (HTTP 404). "
                "Verify the ticket key is correct."
            )
        elif response.status_code in (401, 403):
            raise JiraAuthenticationError(
                f"Access denied assigning ticket '{issue_key}' (HTTP {response.status_code}). "
                "Verify your API token has 'Assign Issues' permission."
            )
        else:
            raise JiraAssignmentError(
                f"Unexpected Jira response while assigning ticket (HTTP {response.status_code}): {response.text}"
            )

    def select_analyst_for_severity(
        self,
        severity: str,
        assignee_config: Dict[str, str],
    ) -> Optional[str]:
        """
        Select the appropriate SOC analyst accountId based on incident severity.

        Severity routing:
            CRITICAL → Senior SOC Analyst / Incident Commander
            HIGH     → SOC Analyst (Tier 2)
            MEDIUM   → Junior SOC Analyst (Tier 1)
            LOW      → Monitoring / Tier 1

        Returns the accountId string, or None if no analyst is configured for that severity.
        Never assigns randomly — returns None with a warning instead.
        """
        clean_severity = severity.strip().upper()
        account_id = assignee_config.get(clean_severity, "")

        if not account_id or not account_id.strip():
            logger.warning(
                "No SOC analyst configured for severity '%s'. "
                "Ticket will remain unassigned. Set JIRA_%s_ASSIGNEE_ACCOUNT_ID in .env to enable auto-assignment.",
                clean_severity,
                clean_severity,
            )
            return None

        logger.info(
            "Selected analyst accountId '%s' for severity '%s'.",
            mask_secret(account_id, visible_chars=6),
            clean_severity,
        )
        return account_id.strip()

    def auto_assign_incident(
        self,
        issue_key: str,
        severity: str,
        assignee_config: Dict[str, str],
    ) -> Dict[str, Any]:
        """
        Automatically assign an incident ticket to the appropriate SOC analyst
        based on the severity routing rules.

        Returns a result dict:
            {
                assigned: bool,
                issue_key: str,
                severity: str,
                account_id: str | None,
                reason: str,
            }
        Never raises — failures are captured in the returned dict with assigned=False.
        """
        account_id = self.select_analyst_for_severity(severity, assignee_config)

        if account_id is None:
            return {
                "assigned": False,
                "issue_key": issue_key,
                "severity": severity.upper(),
                "account_id": None,
                "reason": f"No analyst account ID configured for severity '{severity.upper()}'. "
                          f"Set JIRA_{severity.upper()}_ASSIGNEE_ACCOUNT_ID in .env.",
            }

        try:
            self.assign_incident_ticket(issue_key, account_id)
            return {
                "assigned": True,
                "issue_key": issue_key,
                "severity": severity.upper(),
                "account_id": account_id,
                "reason": "Assignment successful.",
            }
        except JiraAssignmentError as exc:
            logger.error("Auto-assignment failed for ticket '%s': %s", issue_key, exc)
            return {
                "assigned": False,
                "issue_key": issue_key,
                "severity": severity.upper(),
                "account_id": account_id,
                "reason": str(exc),
            }
        except (JiraAuthenticationError, JiraConnectionError) as exc:
            logger.error("Auto-assignment failed (infrastructure error) for '%s': %s", issue_key, exc)
            return {
                "assigned": False,
                "issue_key": issue_key,
                "severity": severity.upper(),
                "account_id": account_id,
                "reason": str(exc),
            }


# ==============================================================================
# Standalone create_incident_ticket function (Requirement 3)
# ==============================================================================

def create_incident_ticket(
    incident_id: str,
    incident_type: str,
    severity: str,
    hostname: str,
    ip_address: str,
    username: str,
    process_hash: str,
    detection_time: str,
    incident_description: str,
    client: Optional[JiraClient] = None,
    project_key: Optional[str] = None,
    issue_type: Optional[str] = None,
    check_existing: bool = True,
) -> Dict[str, Any]:
    """
    Standard incident ticket creation function meeting Day 1 Requirement 3.
    """
    active_client = client or JiraClient.from_config()
    return active_client.create_incident_ticket(
        incident_id=incident_id,
        incident_type=incident_type,
        severity=severity,
        hostname=hostname,
        ip_address=ip_address,
        username=username,
        process_hash=process_hash,
        detection_time=detection_time,
        incident_description=incident_description,
        project_key=project_key,
        issue_type=issue_type,
        check_existing=check_existing,
    )

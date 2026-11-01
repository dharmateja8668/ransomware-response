"""
config.py - Configuration management for Jira Cloud integration.

Handles secure loading of environment variables, HTTPS validation,
credential redaction, and configuration auditing.
"""

from dataclasses import dataclass
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

# Setup logger
logger = logging.getLogger("orchestrator.config")


def mask_secret(secret: Optional[str], visible_chars: int = 4) -> str:
    """
    Mask a sensitive secret string so that it can be safely referenced in logs.
    
    Example:
        mask_secret("ATATT3xFfGF0abc123xyz") -> "ATAT...****"
    """
    if not secret:
        return "[NOT SET]"
    if len(secret) <= visible_chars * 2:
        return "****"
    return f"{secret[:visible_chars]}...****"


def _fallback_parse_env(file_path: Path) -> None:
    """Built-in safe parser for .env files when python-dotenv is not installed."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                if key and key not in os.environ:
                    os.environ[key] = val
        logger.debug("Loaded environment variables from %s via fallback parser", file_path)
    except Exception as exc:
        logger.warning("Could not read .env file at %s: %s", file_path, exc)


def load_env_file(env_path: Optional[str] = None) -> None:
    """
    Load environment variables from .env files securely using python-dotenv.
    Searches explicit path, current working directory, and project root.
    Does not overwrite existing environment variables.
    """
    candidate_paths = []
    if env_path:
        candidate_paths.append(Path(env_path).resolve())
    candidate_paths.append((Path.cwd() / ".env").resolve())
    candidate_paths.append((Path(__file__).resolve().parent.parent / ".env").resolve())
    candidate_paths.append((Path(__file__).resolve().parent / ".env").resolve())

    # De-duplicate while preserving order
    seen = set()
    unique_paths = []
    for p in candidate_paths:
        if p not in seen and p.is_file():
            seen.add(p)
            unique_paths.append(p)

    if not unique_paths:
        logger.debug("No .env file found in search paths.")
        return

    # Load from each unique path without overriding already-set environment variables
    for p in unique_paths:
        try:
            from dotenv import load_dotenv
            load_dotenv(dotenv_path=p, override=False)
            logger.debug("Loaded environment variables from %s via python-dotenv", p)
        except ImportError:
            _fallback_parse_env(p)


@dataclass
class JiraConfig:
    """Configuration container for Jira Cloud REST API integration."""
    base_url: str
    email: str
    api_token: str
    project_key: str = "SEC"
    issue_type: str = "Task"
    api_version: str = "3"
    timeout_seconds: int = 10
    verify_ssl: bool = True
    # Day 2: Severity-based SOC analyst assignment account IDs
    critical_assignee_account_id: str = ""
    high_assignee_account_id: str = ""
    medium_assignee_account_id: str = ""
    low_assignee_account_id: str = ""

    def validate(self) -> None:
        """
        Validate configuration parameters.
        Enforces HTTPS and ensures required credentials are non-empty.
        """
        if not self.base_url:
            raise ValueError("JIRA_BASE_URL is required but was not provided.")

        parsed = urlparse(self.base_url)
        if parsed.scheme.lower() != "https":
            raise ValueError(
                f"Insecure protocol detected: '{parsed.scheme}'. Jira Cloud API requires HTTPS."
            )

        if not self.email:
            raise ValueError("JIRA_EMAIL is required for Jira authentication.")

        if not self.api_token:
            raise ValueError("JIRA_API_TOKEN is required for Jira authentication.")

        if not self.project_key:
            raise ValueError("JIRA_PROJECT_KEY must be specified.")

    @property
    def is_placeholder(self) -> bool:
        """Check if any credentials still use default placeholder values."""
        placeholders = {
            "your-domain.atlassian.net",
            "your-email@example.com",
            "your_jira_api_token_here",
            "SEC_OR_PROJECT_KEY",
        }
        return (
            any(ph in self.base_url for ph in placeholders)
            or self.email in placeholders
            or self.api_token in placeholders
            or not self.email
            or not self.api_token
        )

    def safe_dict(self) -> dict:
        """Return a dictionary of configuration with sensitive credentials masked for logging."""
        return {
            "base_url": self.base_url,
            "email": self.email,
            "api_token": mask_secret(self.api_token),
            "project_key": self.project_key,
            "issue_type": self.issue_type,
            "api_version": self.api_version,
            "timeout_seconds": self.timeout_seconds,
            "verify_ssl": self.verify_ssl,
            "critical_assignee_account_id": mask_secret(self.critical_assignee_account_id) if self.critical_assignee_account_id else "[NOT SET]",
            "high_assignee_account_id": mask_secret(self.high_assignee_account_id) if self.high_assignee_account_id else "[NOT SET]",
            "medium_assignee_account_id": mask_secret(self.medium_assignee_account_id) if self.medium_assignee_account_id else "[NOT SET]",
            "low_assignee_account_id": mask_secret(self.low_assignee_account_id) if self.low_assignee_account_id else "[NOT SET]",
        }

    def get_assignee_config(self) -> dict:
        """Return severity-to-account-ID mapping for ticket assignment."""
        return {
            "CRITICAL": self.critical_assignee_account_id,
            "HIGH": self.high_assignee_account_id,
            "MEDIUM": self.medium_assignee_account_id,
            "LOW": self.low_assignee_account_id,
        }


def audit_configuration(config: JiraConfig) -> Dict[str, Dict[str, Any]]:
    """
    Perform a complete audit on all required environment variables.
    Returns status and details for each configuration parameter.
    """
    audit = {}

    # 1. JIRA_BASE_URL
    if not config.base_url:
        audit["JIRA_BASE_URL"] = {"status": "FAIL", "reason": "Missing or empty"}
    elif "your-domain.atlassian.net" in config.base_url or "<" in config.base_url:
        audit["JIRA_BASE_URL"] = {
            "status": "FAIL",
            "reason": f"Placeholder detected ('{config.base_url}'). Update with your real Jira domain (e.g., https://<workspace>.atlassian.net).",
        }
    elif not config.base_url.startswith("https://"):
        audit["JIRA_BASE_URL"] = {"status": "FAIL", "reason": f"Insecure protocol. Jira requires HTTPS."}
    else:
        audit["JIRA_BASE_URL"] = {"status": "PASS", "value": config.base_url}

    # 2. JIRA_EMAIL
    if not config.email:
        audit["JIRA_EMAIL"] = {"status": "FAIL", "reason": "Missing or empty"}
    elif "your-email@example.com" in config.email or "<" in config.email:
        audit["JIRA_EMAIL"] = {"status": "FAIL", "reason": "Placeholder detected"}
    else:
        audit["JIRA_EMAIL"] = {"status": "PASS", "value": config.email}

    # 3. JIRA_API_TOKEN
    if not config.api_token:
        audit["JIRA_API_TOKEN"] = {"status": "FAIL", "reason": "Missing or empty"}
    elif "your_jira_api_token_here" in config.api_token or "<" in config.api_token:
        audit["JIRA_API_TOKEN"] = {"status": "FAIL", "reason": "Placeholder detected"}
    else:
        audit["JIRA_API_TOKEN"] = {
            "status": "PASS",
            "masked_value": mask_secret(config.api_token),
            "length": len(config.api_token),
        }

    # 4. JIRA_PROJECT_KEY
    if not config.project_key:
        audit["JIRA_PROJECT_KEY"] = {"status": "FAIL", "reason": "Missing or empty"}
    elif "SEC_OR_PROJECT_KEY" in config.project_key:
        audit["JIRA_PROJECT_KEY"] = {"status": "FAIL", "reason": "Placeholder detected"}
    else:
        audit["JIRA_PROJECT_KEY"] = {"status": "PASS", "value": config.project_key}

    # 5. JIRA_ISSUE_TYPE
    audit["JIRA_ISSUE_TYPE"] = {
        "status": "PASS" if config.issue_type else "FAIL",
        "value": config.issue_type or "Missing",
    }

    # 6. JIRA_API_VERSION
    audit["JIRA_API_VERSION"] = {
        "status": "PASS" if config.api_version in ("3", "2") else "FAIL",
        "value": f"v{config.api_version}",
    }

    return audit


def load_config(env_file: Optional[str] = None) -> JiraConfig:
    """
    Load Jira configuration from environment variables (loading .env first).
    """
    load_env_file(env_file)

    base_url = os.getenv("JIRA_BASE_URL", "https://your-domain.atlassian.net").strip().rstrip("/")
    email = os.getenv("JIRA_EMAIL", "").strip()
    api_token = os.getenv("JIRA_API_TOKEN", "").strip()
    project_key = os.getenv("JIRA_PROJECT_KEY", "SEC").strip().upper()
    issue_type = os.getenv("JIRA_ISSUE_TYPE", "Task").strip()
    api_version = os.getenv("JIRA_API_VERSION", "3").strip()

    try:
        timeout_seconds = int(os.getenv("JIRA_TIMEOUT_SECONDS", "10"))
    except ValueError:
        timeout_seconds = 10

    verify_ssl_raw = os.getenv("JIRA_VERIFY_SSL", "true").strip().lower()
    verify_ssl = verify_ssl_raw not in ("false", "0", "no")

    config = JiraConfig(
        base_url=base_url,
        email=email,
        api_token=api_token,
        project_key=project_key,
        issue_type=issue_type,
        api_version=api_version,
        timeout_seconds=timeout_seconds,
        verify_ssl=verify_ssl,
        critical_assignee_account_id=os.getenv("JIRA_CRITICAL_ASSIGNEE_ACCOUNT_ID", "").strip(),
        high_assignee_account_id=os.getenv("JIRA_HIGH_ASSIGNEE_ACCOUNT_ID", "").strip(),
        medium_assignee_account_id=os.getenv("JIRA_MEDIUM_ASSIGNEE_ACCOUNT_ID", "").strip(),
        low_assignee_account_id=os.getenv("JIRA_LOW_ASSIGNEE_ACCOUNT_ID", "").strip(),
    )
    return config

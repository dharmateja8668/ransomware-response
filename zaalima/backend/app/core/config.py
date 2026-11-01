from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )

    # App
    app_name: str = "ZAALIMA - Ransomware Containment & IR Orchestrator"
    app_version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"

    # Database
    database_url: str = "postgresql://postgres:password@localhost:5432/zaalima"

    # JWT
    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Jira
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_project_key: str = "RR"
    jira_issue_type: str = "Task"

    # CrowdStrike
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""
    crowdstrike_api_base_url: str = "https://api.us-2.crowdstrike.com"
    edr_client_id: str = ""
    edr_client_secret: str = ""
    edr_api_base_url: str = ""

    @property
    def cs_client_id(self) -> str:
        return self.crowdstrike_client_id or self.edr_client_id

    @property
    def cs_client_secret(self) -> str:
        return self.crowdstrike_client_secret or self.edr_client_secret

    @property
    def cs_api_base_url(self) -> str:
        return self.crowdstrike_api_base_url or self.edr_api_base_url or "https://api.us-2.crowdstrike.com"

    # Microsoft Defender
    defender_tenant_id: str = ""
    defender_client_id: str = ""
    defender_client_secret: str = ""

    # AWS S3
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = "us-east-1"
    s3_evidence_bucket: str = "zaalima-forensic-evidence"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


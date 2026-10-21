# incidents/models.py
"""
Data models for Security Incident Management.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class IncidentStatus(str, Enum):
    """Lifecycle status stages for an incident."""
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"


class IncidentBase(BaseModel):
    """Core incident fields shared across creation and response schemas."""
    model_config = ConfigDict(extra="allow", from_attributes=True)

    alert_id: str = Field(..., description="Unique alert identifier", min_length=1)
    threat_type: str = Field(..., description="Classification of threat, e.g. ransomware", min_length=1)
    severity: int = Field(..., description="Severity level rating (e.g. 1 to 5)", ge=1, le=5)
    description: str = Field(..., description="Detailed description of the incident", min_length=1)
    timestamp: str = Field(..., description="ISO 8601 timestamp of incident occurrence", min_length=1)

    # Optional endpoint telemetry context
    hostname: Optional[str] = Field(None, description="Affected host / computer")
    ip_address: Optional[str] = Field(None, description="IP address of endpoint")
    username: Optional[str] = Field(None, description="User account associated with the incident")
    process_hash: Optional[str] = Field(None, description="Cryptographic hash of offending process or binary")


class IncidentCreate(IncidentBase):
    """Schema for incoming incident creation."""
    status: Optional[IncidentStatus] = Field(
        default=IncidentStatus.NEW,
        description="Initial lifecycle status of the incident",
    )


class IncidentUpdateStatus(BaseModel):
    """Schema for updating incident status."""
    status: IncidentStatus = Field(..., description="Updated lifecycle status")


class IncidentResponse(IncidentBase):
    """Schema for incident query and detail responses."""
    status: IncidentStatus = Field(..., description="Current lifecycle status")
    created_at: str = Field(..., description="Timestamp when the incident record was created in the orchestrator")
    updated_at: str = Field(..., description="Timestamp when the incident record was last modified")


class IncidentAuditLogResponse(BaseModel):
    """Schema for incident audit log records."""
    model_config = ConfigDict(extra="allow", from_attributes=True)

    id: Optional[int] = Field(None, description="Internal audit log sequence ID")
    alert_id: str = Field(..., description="Associated alert ID")
    incident_id: Optional[str] = Field(None, description="Associated incident ID")
    identity_provider: Optional[str] = Field(None, description="Identity provider name if applicable")
    user_id: Optional[str] = Field(None, description="Target user identifier")
    action: str = Field(..., description="Security action executed or requested")
    execution_mode: str = Field(..., description="Execution mode ('dry_run' or 'live')")
    status: str = Field(..., description="Action result status")
    message: Optional[str] = Field(None, description="Explanation or result summary")
    correlation_id: Optional[str] = Field(None, description="Action or trace correlation identifier")
    details: Optional[Dict[str, Any]] = Field(None, description="Sanitized diagnostic metadata")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of the audit entry")

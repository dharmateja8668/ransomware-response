# incidents/models.py
"""
Data models for Security Incident Management.
"""

from enum import Enum
from typing import Optional
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

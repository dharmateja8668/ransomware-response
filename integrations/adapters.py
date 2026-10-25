# integrations/adapters.py
"""
Native EDR Alert Adapters Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project : Automated Ransomware Containment & Incident Response Orchestrator
Purpose : Provides dedicated schema adapters that convert raw, native EDR alert
          payloads (CrowdStrike Falcon and Microsoft Defender for Endpoint) into the
          standardized internal schema accepted by the alert parsing engine.

Keeps vendor-specific schema logic strictly decoupled from core normalization.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import logging

from integrations.validators import (
    validate_hostname,
    validate_ip_address,
    validate_process_hash,
)

logger = logging.getLogger("orchestrator.adapters")


class BaseAlertAdapter(ABC):
    """Abstract base class for provider-specific alert payload adapters."""

    @classmethod
    @abstractmethod
    def can_adapt(cls, payload: Dict[str, Any]) -> bool:
        """Determines whether this adapter can process the given raw payload."""
        pass

    @classmethod
    @abstractmethod
    def adapt(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Converts the provider-specific payload into a dictionary conforming
        to the project's standard alert schema.
        """
        pass


class CrowdStrikeAlertAdapter(BaseAlertAdapter):
    """
    Adapter for raw CrowdStrike Falcon alerts, detections, and webhook payloads.
    Supports:
      - Hostname: device.hostname, device.computer_name
      - IP: device.local_ip, device.external_ip
      - User: user_name, device.user_name, behaviors[].user_name
      - Process hash: behaviors[].sha256, behaviors[].md5, sha256
      - Identifier: composite_id, detection_id, alert_id, id
      - Severity: Falcon numeric score (1-100) or text label
      - Timestamp: created_timestamp, timestamp, first_behavior
    """

    @classmethod
    def can_adapt(cls, payload: Dict[str, Any]) -> bool:
        if not isinstance(payload, dict):
            return False

        # Check for CrowdStrike-specific indicator keys
        if "device" in payload and isinstance(payload.get("device"), dict):
            return True
        if "behaviors" in payload and isinstance(payload.get("behaviors"), list):
            return True
        if any(k in payload for k in ("composite_id", "detection_id", "cid", "falcon")):
            return True
        # Check event wrapper format
        if "event" in payload and isinstance(payload.get("event"), dict):
            event = payload["event"]
            if any(k in event for k in ("ComputerName", "FalconHostLink", "DetectDescription", "SensorId")):
                return True
        return False

    @classmethod
    def adapt(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("Adapting raw CrowdStrike Falcon alert payload.")
        source = payload.get("event", payload) if isinstance(payload.get("event"), dict) else payload

        # 1. Alert Identifier (prefer detection_id if present)
        alert_id = (
            source.get("detection_id")
            or source.get("composite_id")
            or source.get("alert_id")
            or source.get("id")
            or source.get("DetectId")
        )
        if not alert_id:
            alert_id = "cs-alert-unknown"

        # 2. Threat Type
        threat_type = (
            source.get("scenario")
            or source.get("tactic")
            or source.get("technique")
            or source.get("threat_type")
        )
        behaviors = source.get("behaviors", [])
        if not threat_type and isinstance(behaviors, list) and len(behaviors) > 0:
            first_b = behaviors[0]
            if isinstance(first_b, dict):
                threat_type = first_b.get("tactic") or first_b.get("technique")

        if not threat_type:
            threat_type = "ransomware" if "ransom" in str(source).lower() else "suspicious_activity"

        # 3. Severity Mapping (CrowdStrike often uses 1-100 score or textual severity)
        raw_sev = (
            source.get("severity")
            or source.get("max_severity_displayname")
            or source.get("severity_name")
            or source.get("SeverityName")
        )
        sev_text_map = {
            "critical": 5,
            "crit": 5,
            "high": 4,
            "medium": 3,
            "med": 3,
            "low": 2,
            "informational": 1,
            "info": 1,
        }
        if isinstance(raw_sev, (int, float)):
            score = int(raw_sev)
            if score > 5:
                if score >= 80:
                    sev = 5
                elif score >= 60:
                    sev = 4
                elif score >= 40:
                    sev = 3
                elif score >= 20:
                    sev = 2
                else:
                    sev = 1
            else:
                sev = score
        elif isinstance(raw_sev, str):
            clean_sev = raw_sev.strip().lower()
            sev = sev_text_map.get(clean_sev, 3)
        else:
            sev = 3  # Default to Medium if missing

        # 4. Description
        description = (
            source.get("description")
            or source.get("DetectDescription")
            or source.get("name")
        )
        if not description and isinstance(behaviors, list) and len(behaviors) > 0:
            desc_parts = [
                b.get("technique") or b.get("tactic") or b.get("cmdline") or b.get("description", "")
                for b in behaviors
                if isinstance(b, dict) and (b.get("technique") or b.get("tactic") or b.get("cmdline") or b.get("description"))
            ]
            if desc_parts:
                description = " | ".join(desc_parts)

        if not description:
            description = f"CrowdStrike Falcon detection: {threat_type}"

        # 5. Timestamp
        timestamp = (
            source.get("created_timestamp")
            or source.get("timestamp")
            or source.get("first_behavior")
            or source.get("ProcessStartTime")
        )
        if not timestamp:
            from datetime import datetime, timezone
            timestamp = datetime.now(timezone.utc).isoformat()

        # 6. Hostname and Device ID
        device_obj = source.get("device") if isinstance(source.get("device"), dict) else {}
        hostname = (
            device_obj.get("hostname")
            or device_obj.get("computer_name")
            or source.get("ComputerName")
            or source.get("hostname")
        )
        endpoint_id = (
            device_obj.get("device_id")
            or source.get("SensorId")
            or source.get("aid")
            or source.get("endpoint_id")
        )

        # 7. IP Address
        ip_address = (
            device_obj.get("local_ip")
            or device_obj.get("external_ip")
            or source.get("LocalIP")
            or source.get("ip_address")
        )

        # 8. Username
        user_container = source.get("user") if isinstance(source.get("user"), dict) else {}
        username = (
            source.get("user_name")
            or source.get("UserName")
            or user_container.get("username")
            or user_container.get("user_name")
            or device_obj.get("user_name")
        )
        if not username and isinstance(behaviors, list):
            for b in behaviors:
                if isinstance(b, dict) and b.get("user_name"):
                    username = b["user_name"]
                    break

        # 9. Process Hash (Deterministic Strategy: Prioritize latest behavior SHA-256)
        process_hash = source.get("sha256") or source.get("md5")
        if not process_hash and isinstance(behaviors, list) and len(behaviors) > 0:
            # Deterministic: Check behaviors in reverse order (most recent first)
            for b in reversed(behaviors):
                if isinstance(b, dict):
                    h = b.get("sha256") or b.get("sha256_hash")
                    if h:
                        process_hash = h
                        break
            if not process_hash:
                for b in reversed(behaviors):
                    if isinstance(b, dict):
                        h = b.get("md5") or b.get("md5_hash")
                        if h:
                            process_hash = h
                            break

        return {
            "alert_id": str(alert_id),
            "threat_type": str(threat_type),
            "severity": sev,
            "description": str(description),
            "timestamp": str(timestamp),
            "hostname": hostname,
            "endpoint_id": endpoint_id,
            "ip_address": ip_address,
            "username": username,
            "process_hash": process_hash,
            "raw_source_provider": "crowdstrike_falcon",
            "_edr_provider": "crowdstrike",
            "_adapter_applied": "CrowdStrikeAlertAdapter",
        }


class DefenderAlertAdapter(BaseAlertAdapter):
    """
    Adapter for raw Microsoft Defender for Endpoint alerts and incidents.
    Supports:
      - Hostname: computerDnsName, deviceName
      - IP: lastIpAddress, ipAddress, evidence[].ipAddress
      - User: actor, user.accountName, loggedOnUsers[].accountName, evidence[].accountName
      - Process hash: sha256, fileHash, evidence[].sha256
      - Identifier: id, alertId, incidentId
      - Severity: Informational, Low, Medium, High
      - Timestamp: alertCreationTime, createdTime, eventTime
    """

    @classmethod
    def can_adapt(cls, payload: Dict[str, Any]) -> bool:
        if not isinstance(payload, dict):
            return False

        if any(k in payload for k in ("computerDnsName", "alertCreationTime", "machineId", "threatFamilyName")):
            return True
        if "evidence" in payload and isinstance(payload.get("evidence"), list):
            return True
        if "loggedOnUsers" in payload and isinstance(payload.get("loggedOnUsers"), list):
            return True
        return False

    @classmethod
    def adapt(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("Adapting raw Microsoft Defender for Endpoint alert payload.")

        # 1. Alert Identifier
        alert_id = (
            payload.get("id")
            or payload.get("alertId")
            or payload.get("incidentId")
        )
        if not alert_id:
            alert_id = "mde-alert-unknown"

        # 2. Threat Type
        threat_type = (
            payload.get("category")
            or payload.get("threatFamilyName")
            or payload.get("threatType")
        )
        if not threat_type:
            title = str(payload.get("title", "")).lower()
            if "ransom" in title or "encrypt" in title:
                threat_type = "ransomware"
            elif "credential" in title or "mimikatz" in title:
                threat_type = "credential_theft"
            else:
                threat_type = "malware"

        # 3. Severity
        raw_sev = payload.get("severity", "High")
        sev_text_map = {
            "critical": 5,
            "crit": 5,
            "high": 4,
            "medium": 3,
            "med": 3,
            "low": 2,
            "informational": 1,
            "info": 1,
        }
        if isinstance(raw_sev, (int, float)):
            severity = int(raw_sev)
        elif isinstance(raw_sev, str):
            severity = sev_text_map.get(raw_sev.strip().lower(), 3)
        else:
            severity = 3

        # 4. Description
        description = (
            payload.get("description")
            or payload.get("title")
            or f"Microsoft Defender detection: {threat_type}"
        )

        # 5. Timestamp
        timestamp = (
            payload.get("alertCreationTime")
            or payload.get("createdTime")
            or payload.get("eventTime")
            or payload.get("firstEventTime")
        )
        if not timestamp:
            from datetime import datetime, timezone
            timestamp = datetime.now(timezone.utc).isoformat()

        # 6. Hostname and Endpoint ID
        hostname = payload.get("computerDnsName") or payload.get("deviceName")
        endpoint_id = payload.get("machineId")

        # 7. IP Address
        ip_address = payload.get("lastIpAddress") or payload.get("ipAddress")

        # 8. Username
        username = payload.get("actor")
        user_acc = payload.get("userAccount") or payload.get("user")
        if not username and isinstance(user_acc, dict):
            domain = user_acc.get("domainName") or user_acc.get("domain")
            acc = user_acc.get("accountName") or user_acc.get("userPrincipalName") or user_acc.get("userName")
            if domain and acc:
                username = f"{domain}\\{acc}"
            elif acc:
                username = acc

        logged_users = payload.get("loggedOnUsers")
        if not username and isinstance(logged_users, list) and len(logged_users) > 0:
            first_u = logged_users[0]
            if isinstance(first_u, dict):
                username = first_u.get("accountName") or first_u.get("userName")

        # 9. Process Hash
        process_hash = payload.get("sha256") or payload.get("fileHash") or payload.get("sha1")

        # Search Evidence array for missing fields if present
        evidence = payload.get("evidence", [])
        if isinstance(evidence, list):
            for item in evidence:
                if not isinstance(item, dict):
                    continue
                entity_type = str(item.get("entityType", "")).lower()

                # Extract machine evidence
                if not hostname and item.get("computerDnsName"):
                    hostname = item["computerDnsName"]
                if not endpoint_id and item.get("machineId"):
                    endpoint_id = item["machineId"]
                if not ip_address and item.get("ipAddress"):
                    ip_address = item["ipAddress"]

                # Extract user evidence
                if not username and item.get("accountName"):
                    username = item["accountName"]

                # Extract file/process hash evidence (prefer SHA-256)
                if not process_hash:
                    if item.get("sha256"):
                        process_hash = item["sha256"]
                    elif item.get("fileHash"):
                        process_hash = item["fileHash"]

        return {
            "alert_id": str(alert_id),
            "threat_type": str(threat_type),
            "severity": severity,
            "description": str(description),
            "timestamp": str(timestamp),
            "hostname": hostname,
            "endpoint_id": endpoint_id,
            "ip_address": ip_address,
            "username": username,
            "process_hash": process_hash,
            "raw_source_provider": "microsoft_defender",
            "_edr_provider": "defender",
            "_adapter_applied": "DefenderAlertAdapter",
        }


def adapt_raw_alert(raw_payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Inspects an incoming payload and runs the appropriate vendor adapter if
    a native CrowdStrike or Defender schema is detected.
    If the payload is already in normalized format, returns it unmodified.
    """
    if not isinstance(raw_payload, dict):
        return {}

    if CrowdStrikeAlertAdapter.can_adapt(raw_payload):
        return CrowdStrikeAlertAdapter.adapt(raw_payload)

    if DefenderAlertAdapter.can_adapt(raw_payload):
        return DefenderAlertAdapter.adapt(raw_payload)

    # Already standard / normalized or unknown vendor schema
    return raw_payload

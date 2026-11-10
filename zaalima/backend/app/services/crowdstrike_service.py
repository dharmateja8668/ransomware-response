"""CrowdStrike Falcon Real API Service.

Provides real-time OAuth2 authentication, token management,
device querying, alert/detection querying, and containment execution.
Never prints or logs API secrets.
"""

import time
import socket
import logging
from typing import Dict, List, Optional, Any
import requests
from requests.exceptions import Timeout, ConnectionError, HTTPError

from app.core.config import get_settings

logger = logging.getLogger("zaalima.crowdstrike")
settings = get_settings()


class CrowdStrikeService:
    def __init__(self):
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._cached_devices: Dict[str, str] = {}  # hostname -> device_id map
        self._cached_status: Optional[Dict[str, Any]] = None
        self._status_cached_at: float = 0.0

    @property
    def base_url(self) -> str:
        return settings.cs_api_base_url.rstrip("/")

    @property
    def client_id(self) -> str:
        return settings.cs_client_id.strip()

    @property
    def client_secret(self) -> str:
        return settings.cs_client_secret.strip()

    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret and self.base_url)

    def mask_id(self, val: str) -> str:
        if not val or len(val) < 8:
            return "****"
        return f"{val[:4]}...{val[-4:]}"

    def authenticate(self) -> str:
        """Authenticate with CrowdStrike Falcon OAuth2 endpoint.

        Returns bearer access token or raises exception.
        """
        if not self.is_configured():
            raise ValueError("CrowdStrike credentials not configured in environment.")

        # Return cached token if still valid for at least 60 seconds
        if self._access_token and time.time() < (self._token_expires_at - 60):
            return self._access_token

        token_url = f"{self.base_url}/oauth2/token"
        logger.info(f"Authenticating with CrowdStrike Falcon at {self.base_url}...")

        try:
            resp = requests.post(
                token_url,
                data={"client_id": self.client_id, "client_secret": self.client_secret},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=5
            )
        except Timeout:
            raise TimeoutError("CrowdStrike OAuth2 authentication timed out.")
        except ConnectionError as e:
            raise ConnectionError(f"Cannot reach CrowdStrike API at {token_url}: {e}")

        if resp.status_code == 401:
            raise PermissionError("CrowdStrike authentication failed (HTTP 401). Invalid Client ID or Secret.")
        elif resp.status_code == 403:
            raise PermissionError("CrowdStrike authentication forbidden (HTTP 403).")

        try:
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            raise RuntimeError(f"CrowdStrike token request failed: {resp.status_code} - {e}")

        token = data.get("access_token")
        if not token:
            raise ValueError("CrowdStrike token response did not contain 'access_token'.")

        expires_in = data.get("expires_in", 1799)
        self._access_token = token
        self._token_expires_at = time.time() + float(expires_in)
        logger.info("CrowdStrike OAuth2 token obtained successfully.")
        return self._access_token

    def _get_headers(self) -> dict:
        token = self.authenticate()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    def get_connection_status(self, force_refresh: bool = False) -> dict:
        """Checks connection status and permissions without executing destructive actions.
        Caches results for 30 seconds to prevent repeated WAN timeout delays on dashboard polls.
        """
        now = time.time()
        if not force_refresh and self._cached_status and (now - self._status_cached_at < 30):
            return self._cached_status

        if not self.is_configured():
            status_data = {
                "status": "DISCONNECTED",
                "configured": False,
                "message": "CrowdStrike credentials (CROWDSTRIKE_CLIENT_ID / SECRET) are not configured.",
                "base_url": self.base_url,
                "client_id": "",
                "permissions": [],
                "enrolled_hosts_count": 0,
                "alerts_count": 0
            }
            self._cached_status = status_data
            self._status_cached_at = now
            return status_data

        try:
            self.authenticate()
        except PermissionError as e:
            status_data = {
                "status": "AUTHENTICATION FAILED",
                "configured": True,
                "message": str(e),
                "base_url": self.base_url,
                "client_id": self.mask_id(self.client_id),
                "permissions": [],
                "enrolled_hosts_count": 0,
                "alerts_count": 0
            }
            self._cached_status = status_data
            self._status_cached_at = now
            return status_data
        except Exception as e:
            status_data = {
                "status": "API ERROR",
                "configured": True,
                "message": str(e),
                "base_url": self.base_url,
                "client_id": self.mask_id(self.client_id),
                "permissions": [],
                "enrolled_hosts_count": 0,
                "alerts_count": 0
            }
            self._cached_status = status_data
            self._status_cached_at = now
            return status_data

        headers = self._get_headers()
        permissions = ["oauth2:authenticated"]
        device_count = 0
        alert_count = 0

        # Check devices permission
        try:
            r_dev = requests.get(f"{self.base_url}/devices/queries/devices/v1?limit=1", headers=headers, timeout=5)
            if r_dev.status_code == 200:
                permissions.append("devices:read")
                total = r_dev.json().get("meta", {}).get("pagination", {}).get("total")
                if total is not None:
                    device_count = total
                else:
                    device_count = len(r_dev.json().get("resources", []))
        except Exception:
            pass

        # Check alerts permission
        try:
            r_alt = requests.get(f"{self.base_url}/alerts/queries/alerts/v1?limit=1", headers=headers, timeout=5)
            if r_alt.status_code == 200:
                permissions.append("alerts:read")
                total = r_alt.json().get("meta", {}).get("pagination", {}).get("total")
                if total is not None:
                    alert_count = total
                else:
                    alert_count = len(r_alt.json().get("resources", []))
        except Exception:
            pass

        # Check device containment write permission (dry-run probe with dummy ID)
        try:
            r_cont = requests.post(
                f"{self.base_url}/devices/entities/devices-actions/v2?action_name=contain",
                json={"ids": ["00000000000000000000000000000000"]},
                headers=headers,
                timeout=8
            )
            # 404 means the endpoint and write permission are valid (ID simply not found)
            if r_cont.status_code in [200, 400, 404]:
                permissions.append("devices:containment_write")
        except Exception:
            pass

        return {
            "status": "CONNECTED",
            "configured": True,
            "message": "Connected to real CrowdStrike Falcon API.",
            "base_url": self.base_url,
            "client_id": self.mask_id(self.client_id),
            "permissions": permissions,
            "enrolled_hosts_count": device_count,
            "alerts_count": alert_count,
            "token_valid": True
        }

    def get_real_devices(self, limit: int = 50) -> List[dict]:
        """Queries CrowdStrike for actual enrolled hosts/devices."""
        headers = self._get_headers()
        url = f"{self.base_url}/devices/queries/devices/v1?limit={limit}"
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        device_ids = resp.json().get("resources", [])

        if not device_ids:
            return []

        # Query details for devices
        entities_url = f"{self.base_url}/devices/entities/devices/v1"
        r_details = requests.get(entities_url, params={"ids": device_ids}, headers=headers, timeout=10)
        r_details.raise_for_status()

        raw_devices = r_details.json().get("resources", [])
        normalized = []

        for d in raw_devices:
            dev_id = d.get("device_id")
            hostname = d.get("hostname", "UNKNOWN")
            if dev_id and hostname:
                self._cached_devices[hostname.upper()] = dev_id
                self._cached_devices[dev_id] = dev_id

            status_val = d.get("status", "normal")
            is_contained = status_val.lower() == "contained" or d.get("containment_status") == "contained"

            normalized.append({
                "device_id": dev_id,
                "hostname": hostname,
                "ip_address": d.get("connection_ip") or d.get("local_ip") or "N/A",
                "mac_address": d.get("mac_address", ""),
                "operating_system": f"{d.get('platform_name', '')} {d.get('os_version', '')}".strip() or "Windows",
                "connected_user": d.get("last_login_user", "system"),
                "status": "isolated" if is_contained else "healthy",
                "is_isolated": is_contained,
                "edr_provider": "CROWDSTRIKE",
                "last_seen": d.get("last_seen"),
                "source": "CROWDSTRIKE"
            })

        return normalized

    def get_real_alerts(self, limit: int = 50) -> List[dict]:
        """Queries CrowdStrike for actual threat alerts."""
        headers = self._get_headers()
        url = f"{self.base_url}/alerts/queries/alerts/v1?limit={limit}"
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        alert_ids = resp.json().get("resources", [])

        if not alert_ids:
            return []

        # Query details
        detail_url = f"{self.base_url}/alerts/entities/alerts/v2"
        r_detail = requests.post(detail_url, json={"composite_ids": alert_ids}, headers=headers, timeout=12)
        r_detail.raise_for_status()

        raw_alerts = r_detail.json().get("resources", [])
        normalized = []

        for a in raw_alerts:
            comp_id = a.get("composite_id") or a.get("id")
            dev_dict = a.get("device", {}) if isinstance(a.get("device"), dict) else {}
            hostname = dev_dict.get("hostname", "UNKNOWN")
            ip = dev_dict.get("connection_ip") or dev_dict.get("local_ip") or "N/A"

            # Severity mapping
            sev_raw = (a.get("severity_name") or str(a.get("severity") or "")).lower()
            if "crit" in sev_raw:
                severity = "critical"
            elif "high" in sev_raw:
                severity = "high"
            elif "med" in sev_raw:
                severity = "medium"
            else:
                severity = "low"

            name = a.get("name") or a.get("objective") or a.get("tactic") or "CrowdStrike Alert"
            status_raw = a.get("status", "new").lower()
            status = "investigating" if status_raw in ["in_progress", "reopened"] else ("resolved" if status_raw == "closed" else "new")

            normalized.append({
                "threat_id": comp_id,
                "threat_name": name,
                "hostname": hostname,
                "device_id": dev_dict.get("device_id"),
                "ip_address": ip,
                "username": dev_dict.get("last_login_user") or "N/A",
                "severity": severity,
                "status": status,
                "process_name": a.get("filename") or a.get("tactic") or "process",
                "process_hash": a.get("sha256") or a.get("md5") or "",
                "description": f"Real CrowdStrike Falcon alert: {name} on {hostname}. Scenario: {a.get('scenario', 'Detection')}",
                "source": "CROWDSTRIKE",
                "detected_at": a.get("created_timestamp") or a.get("timestamp")
            })

        return normalized

    def resolve_device_id(self, target: str) -> Optional[str]:
        """Resolves a hostname or device ID to a valid CrowdStrike device_id."""
        if target.upper() in self._cached_devices:
            return self._cached_devices[target.upper()]
        if target in self._cached_devices:
            return self._cached_devices[target]

        # Refresh devices cache
        try:
            devices = self.get_real_devices(limit=100)
            for d in devices:
                if d["hostname"].upper() == target.upper():
                    return d["device_id"]
                if d["device_id"] == target:
                    return d["device_id"]
        except Exception as e:
            logger.warning(f"Could not resolve device_id for {target}: {e}")

        return None

    def get_device_containment_status(self, target: str) -> dict:
        """Queries CrowdStrike Falcon directly for current live containment status."""
        device_id = self.resolve_device_id(target) or target
        headers = self._get_headers()
        url = f"{self.base_url}/devices/entities/devices/v1?ids={device_id}"
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        resources = resp.json().get("resources", [])
        if not resources:
            return {"found": False, "target": target, "device_id": device_id}

        d = resources[0]
        status_val = d.get("status", "normal")
        cont_status = d.get("containment_status") or status_val
        is_contained = status_val.lower() == "contained" or cont_status.lower() == "contained"

        return {
            "found": True,
            "target": target,
            "device_id": d.get("device_id"),
            "hostname": d.get("hostname"),
            "status": "contained" if is_contained else "normal",
            "containment_status": cont_status,
            "is_contained": is_contained,
            "platform": d.get("platform_name"),
            "ip_address": d.get("connection_ip") or d.get("local_ip"),
            "last_seen": d.get("last_seen")
        }

    def contain_endpoint(self, target: str, comment: Optional[str] = None, confirm_dev_machine: bool = False) -> dict:
        """Executes actual network containment on CrowdStrike host.

        Target can be a device_id or hostname.
        Enforces safety guard for developer host 'DHARMATEJA'.
        """
        device_id = self.resolve_device_id(target) or target

        # Safety Guard: Never isolate the primary development computer without explicit confirmation
        local_host = socket.gethostname().upper()
        is_dev_machine = (
            target.upper() == local_host
            or target.upper() == "DHARMATEJA"
            or device_id == "57f9317c6e8f4b3dac65e8097a1f0db4"
        )
        if is_dev_machine and not confirm_dev_machine:
            raise PermissionError(
                f"SAFETY GUARD: Target '{target}' is your active primary development computer ({local_host}). "
                "Containment is blocked to protect network access and SSH/IDE sessions. "
                "To explicitly authorize containment on your dev workstation, provide 'confirm_dev_machine: True'."
            )

        headers = self._get_headers()
        url = f"{self.base_url}/devices/entities/devices-actions/v2?action_name=contain"
        payload = {
            "ids": [device_id],
            "comment": comment or "Authorized containment via ZAALIMA Incident Response Orchestrator"
        }

        logger.info(f"Submitting real CrowdStrike network containment for {device_id} ({target})...")
        resp = requests.post(url, json=payload, headers=headers, timeout=12)
        resp_json = resp.json()

        if resp.status_code == 200 or resp.status_code == 201:
            return {
                "success": True,
                "device_id": device_id,
                "target": target,
                "action": "contain",
                "status": "contained",
                "message": f"CrowdStrike network containment successfully initiated for {target} ({device_id}).",
                "raw_response": resp_json
            }
        else:
            errors = resp_json.get("errors", [])
            err_msg = errors[0].get("message") if errors else resp.text
            raise RuntimeError(f"CrowdStrike containment failed (HTTP {resp.status_code}): {err_msg}")

    def lift_containment(self, target: str, comment: Optional[str] = None) -> dict:
        """Lifts network containment on CrowdStrike host."""
        device_id = self.resolve_device_id(target) or target
        headers = self._get_headers()
        url = f"{self.base_url}/devices/entities/devices-actions/v2?action_name=lift_containment"
        payload = {
            "ids": [device_id],
            "comment": comment or "Authorized containment lift via ZAALIMA Incident Response Orchestrator"
        }

        logger.info(f"Submitting real CrowdStrike lift-containment for {device_id} ({target})...")
        resp = requests.post(url, json=payload, headers=headers, timeout=12)
        resp_json = resp.json()

        if resp.status_code == 200 or resp.status_code == 201:
            return {
                "success": True,
                "device_id": device_id,
                "target": target,
                "action": "lift_containment",
                "status": "healthy",
                "message": f"CrowdStrike network containment successfully released for {target} ({device_id}).",
                "raw_response": resp_json
            }
        else:
            errors = resp_json.get("errors", [])
            err_msg = errors[0].get("message") if errors else resp.text
            raise RuntimeError(f"CrowdStrike lift-containment failed (HTTP {resp.status_code}): {err_msg}")


# Global singleton instance
crowdstrike_service = CrowdStrikeService()


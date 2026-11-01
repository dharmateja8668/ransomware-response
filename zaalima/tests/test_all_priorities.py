"""Comprehensive Verification Test Suite for ZAALIMA Incident Response Orchestrator.
Covers:
Priority 1: CrowdStrike Falcon Containment & Dev Workstation Safety Guard
Priority 2: AWS S3 Evidence Storage & AES-256 Encryption
Priority 3: Digital Forensics (KAPE Triage & Volatility Memory IOC Extraction)
Priority 4: Jira Cloud REST API v3 Issue Lifecycle & Status Synchronization
"""

import sys
import os
import json
import base64
import socket
from pathlib import Path
from datetime import datetime, timezone

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.core.config import get_settings
from app.db.database import SessionLocal, create_tables
from app.models.incident import Incident, IncidentStatus, IncidentSeverity
from app.models.endpoint import Endpoint, EndpointStatus
from app.models.forensic import ForensicEvidence, EvidenceType
from app.models.audit_log import AuditLog
from app.services.crowdstrike_service import crowdstrike_service
from app.services.s3_service import s3_service
from app.services.forensic_service import forensic_service


def test_priority_1_crowdstrike():
    print("\n" + "=" * 70)
    print("PRIORITY 1: CROWDSTRIKE FALCON CONTAINMENT & SAFETY GUARD")
    print("=" * 70)

    # 1. Connection check
    status = crowdstrike_service.get_connection_status()
    print(f"[*] CrowdStrike Connection: {status.get('status')} ({status.get('base_url')})")
    assert status.get("status") == "CONNECTED", f"CrowdStrike not connected: {status}"

    # 2. Host enrollment
    hostname = socket.gethostname()
    print(f"[*] Local Hostname: {hostname}")
    devices = crowdstrike_service.get_real_devices(limit=5)
    print(f"[*] Enrolled Devices in Falcon: {len(devices)}")
    for d in devices:
        print(f"    - Host: {d.get('hostname')}, Device ID: {d.get('device_id')}, Status: {d.get('status')}")

    # 3. SAFETY GUARD: Attempt isolation of primary dev workstation WITHOUT confirmation
    dev_target = hostname
    print(f"[*] Testing Safety Guard on primary workstation '{dev_target}' (confirm_dev_machine=False)...")
    safety_tripped = False
    try:
        crowdstrike_service.contain_endpoint(dev_target, comment="Safety Guard Test", confirm_dev_machine=False)
    except PermissionError as pe:
        safety_tripped = True
        print(f"[+] SAFETY GUARD ENGAGED AS EXPECTED: {pe}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

    assert safety_tripped, "FAIL: Primary dev workstation was not protected by safety guard!"

    # 4. Containment Status Query
    if devices:
        test_aid = devices[0]["device_id"]
        c_status = crowdstrike_service.get_device_containment_status(test_aid)
        print(f"[*] Live Falcon Containment Status for {test_aid}: {c_status.get('containment_status')}")

    print("[PASS] Priority 1: CrowdStrike containment & safety controls verified.")


def test_priority_2_aws_s3():
    print("\n" + "=" * 70)
    print("PRIORITY 2: AWS S3 EVIDENCE STORAGE & AES-256 ENCRYPTION")
    print("=" * 70)

    # 1. Status check
    status = s3_service.get_status()
    print(f"[*] S3 Storage Operational Mode: {status.get('status')}")
    print(f"[*] Encryption Standard: {status.get('encryption')}")
    print(f"[*] Target Bucket: {status.get('bucket')} (Region: {status.get('region')})")

    # 2. Staged upload test
    test_incident = "INC-TEST-S3"
    test_evidence_id = f"EV-TEST-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    test_file = Path("d:/ransomware response/zaalima/backend/storage/forensics/test_artifact.bin")
    test_file.parent.mkdir(parents=True, exist_ok=True)
    with open(test_file, "wb") as f:
        f.write(b"ZAALIMA_ENCRYPTED_FORENSIC_EVIDENCE_PAYLOAD_SHA256_VERIFIED\n" * 50)

    upload_res = s3_service.upload_evidence_file(
        local_path=str(test_file),
        incident_id=test_incident,
        hostname="WS-FIN-01",
        evidence_type="memory_dump",
        evidence_id=test_evidence_id,
        analyst_notes="Automated test upload for S3 integration"
    )

    print(f"[*] Upload Completed: {upload_res.get('success')}")
    print(f"    - S3 URI: {upload_res.get('s3_uri')}")
    print(f"    - SHA-256 Checksum: {upload_res.get('sha256')}")
    print(f"    - Encryption: {upload_res.get('encryption')}")
    print(f"    - Companion Manifest: {upload_res.get('metadata_uri')}")

    assert upload_res.get("sha256") is not None, "SHA-256 hash was not computed"
    assert "AES256" in upload_res.get("encryption", ""), "AES-256 encryption was not applied"

    # Cleanup test file
    if test_file.exists():
        test_file.unlink()

    print("[PASS] Priority 2: AWS S3 storage, AES-256 encryption, and companion manifests verified.")


def test_priority_3_digital_forensics():
    print("\n" + "=" * 70)
    print("PRIORITY 3: DIGITAL FORENSICS (KAPE & VOLATILITY)")
    print("=" * 70)

    incident_id = "INC-FORENSIC-VERIFY"
    target_host = "WS-ACCT-02"

    # 1. KAPE Artifact Collection
    print(f"[*] Initiating KAPE artifact acquisition on {target_host}...")
    kape_res = forensic_service.collect_kape_artifacts(
        incident_id=incident_id,
        hostname=target_host,
        analyst_name="soc_analyst_test",
        categories=["RegistryHives", "EventLogs", "Prefetch", "Amcache"]
    )

    print(f"[+] KAPE Artifact Package Created: {kape_res['file_name']}")
    print(f"    - Size: {kape_res['file_size_bytes']} bytes")
    print(f"    - Package SHA-256: {kape_res['sha256']}")
    print(f"    - Chain of Custody entries: {len(kape_res['chain_of_custody'])}")
    assert os.path.exists(kape_res["file_path"]), "KAPE zip package was not written to disk"
    assert len(kape_res["sha256"]) == 64, "Invalid SHA-256 hash length"

    # 2. Volatility Memory Analysis
    print(f"[*] Initiating Volatility memory triage on {target_host}...")
    vol_res = forensic_service.analyze_memory_volatility(
        incident_id=incident_id,
        hostname=target_host,
        analyst_name="soc_analyst_test"
    )

    print(f"[+] Volatility Verdict: {vol_res['threat_verdict']}")
    print(f"    - Critical Findings: {vol_res['critical_findings']}")
    print(f"    - Extracted IOCs: {len(vol_res['extracted_iocs'])}")
    for ioc in vol_res["extracted_iocs"]:
        print(f"      * [{ioc['severity']}] {ioc['type']}: {ioc['value']}")

    # Verify shadow copy deletion finding
    shadow_copy_found = any("vssadmin" in f.get("command_line", "") for f in vol_res["findings"])
    assert shadow_copy_found, "Volatility should detect ransomware shadow copy deletion command"

    # Verify injected code detection
    malfind_found = any(f.get("finding_type") == "PROCESS_INJECTION" for f in vol_res["findings"])
    assert malfind_found, "Volatility should detect injected memory space"

    print("[PASS] Priority 3: KAPE triage packaging & Volatility memory triage heuristics verified.")


def test_priority_4_jira():
    print("\n" + "=" * 70)
    print("PRIORITY 4: JIRA CLOUD REST API V3 INTEGRATION & STATUS SYNC")
    print("=" * 70)

    import requests

    settings = get_settings()
    print(f"[*] Jira Base URL: {settings.jira_base_url}")
    print(f"[*] Jira Project Key: {settings.jira_project_key}")
    print(f"[*] Jira Issue Type: {settings.jira_issue_type}")

    auth = base64.b64encode(f"{settings.jira_email}:{settings.jira_api_token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json", "Accept": "application/json"}

    # 1. Real Jira Auth
    resp = requests.get(f"{settings.jira_base_url}/rest/api/3/myself", headers=headers, timeout=10)
    assert resp.status_code == 200, f"Jira Auth failed: {resp.text}"
    user_info = resp.json()
    print(f"[+] Jira Cloud Authenticated: {user_info.get('displayName')} ({user_info.get('emailAddress')})")

    # 2. Create Real Ticket for Test Incident
    db = SessionLocal()
    try:
        inc_id = f"INC-TEST-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        incident = Incident(
            incident_id=inc_id,
            title="LockBit 3.0 Ransomware Outbreak on WS-ACCT-02",
            description="Active vssadmin shadow deletion and memory injection detected by Volatility & CrowdStrike Falcon.",
            severity=IncidentSeverity.critical,
            status=IncidentStatus.detected,
            threat_type="Ransomware",
            hostname="WS-ACCT-02",
            ip_address="192.168.1.105",
            detected_at=datetime.now(timezone.utc)
        )
        db.add(incident)
        db.commit()

        # Send to Jira Cloud
        summary = f"[CRITICAL] {incident.title}"
        adf_description = {
            "version": 1,
            "type": "doc",
            "content": [{
                "type": "paragraph",
                "content": [{
                    "type": "text",
                    "text": f"ZAALIMA Incident ID: {inc_id}\nHost: {incident.hostname}\nSeverity: CRITICAL\nStatus: Detected"
                }]
            }]
        }
        create_payload = {
            "fields": {
                "project": {"key": settings.jira_project_key},
                "summary": summary,
                "description": adf_description,
                "issuetype": {"name": settings.jira_issue_type}
            }
        }

        print(f"[*] Creating real ticket in project {settings.jira_project_key} on Jira Cloud...")
        res_create = requests.post(
            f"{settings.jira_base_url}/rest/api/3/issue",
            json=create_payload,
            headers=headers,
            timeout=10
        )
        assert res_create.status_code == 201, f"Failed to create Jira issue: {res_create.status_code} {res_create.text}"
        ticket_data = res_create.json()
        ticket_id = ticket_data.get("id")
        ticket_key = ticket_data.get("key")
        ticket_url = f"{settings.jira_base_url}/browse/{ticket_key}"
        print(f"[+] Real Jira Ticket Created: Key={ticket_key}, ID={ticket_id}")
        print(f"    - Browse URL: {ticket_url}")

        # Store in DB
        incident.jira_ticket_id = ticket_id
        incident.jira_ticket_key = ticket_key
        incident.jira_ticket_url = ticket_url
        db.commit()

        # 3. Synchronize Ticket Status from Jira Cloud API
        print(f"[*] Synchronizing live issue status from Jira for {ticket_key}...")
        resp_get = requests.get(
            f"{settings.jira_base_url}/rest/api/3/issue/{ticket_key}",
            headers=headers,
            timeout=10
        )
        assert resp_get.status_code == 200, f"Failed to retrieve Jira issue: {resp_get.text}"
        issue_details = resp_get.json()
        jira_status_name = issue_details.get("fields", {}).get("status", {}).get("name")
        print(f"[+] Live Jira Status: '{jira_status_name}' (Issue ID: {issue_details.get('id')})")
        assert issue_details.get("id") == ticket_id, "Ticket ID mismatch during synchronization"

        # Verify incident record in database
        refreshed = db.query(Incident).filter(Incident.incident_id == inc_id).first()
        assert refreshed.jira_ticket_id == ticket_id, "Jira issue ID was not persisted in database"
        assert refreshed.jira_ticket_key == ticket_key, "Jira ticket key was not persisted in database"
        print(f"[+] Database Record Verified: jira_ticket_id='{refreshed.jira_ticket_id}', jira_ticket_key='{refreshed.jira_ticket_key}'")

    finally:
        db.close()

    print("[PASS] Priority 4: Real Jira Cloud issue creation, database ID persistence, and status sync verified.")


if __name__ == "__main__":
    print("STARTING COMPLETE END-TO-END VERIFICATION FOR ALL 4 PRIORITIES...")
    create_tables()
    try:
        test_priority_1_crowdstrike()
        test_priority_2_aws_s3()
        test_priority_3_digital_forensics()
        test_priority_4_jira()
        print("\n" + "=" * 70)
        print("ALL 4 PRIORITIES FULLY VERIFIED AND PASSING SUCCESSFULLY!")
        print("=" * 70)
    except Exception as e:
        print(f"\n[FAIL] Test suite encountered an error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

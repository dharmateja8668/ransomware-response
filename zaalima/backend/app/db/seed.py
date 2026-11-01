"""Seed the database with realistic simulated security data."""
import random
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.user import User, UserRole
from app.models.threat import Threat, ThreatSeverity, ThreatStatus
from app.models.incident import Incident, IncidentStatus, IncidentSeverity
from app.models.endpoint import Endpoint, EndpointStatus
from app.models.audit_log import AuditLog, AuditAction
from app.models.forensic import ForensicEvidence, EvidenceType


THREAT_NAMES = [
    "WannaCry Ransomware", "LockBit 3.0", "BlackCat/ALPHV", "Conti Ransomware",
    "REvil/Sodinokibi", "DarkSide Ransomware", "Ryuk", "Hive Ransomware",
    "BlackMatter", "CL0P Ransomware", "Play Ransomware", "Royal Ransomware",
]

HOSTNAMES = [
    "WORKSTATION-001", "WORKSTATION-002", "SERVER-DC-01", "LAPTOP-HR-04",
    "FILESERVER-02", "WEBSERVER-01", "DBSERVER-PRIMARY", "DEVBOX-03",
    "ACCOUNTING-PC", "EXEC-LAPTOP-01",
]

USERS = [
    "john.smith", "jane.doe", "alice.johnson", "bob.wilson", "charlie.brown",
    "diana.prince", "evan.rogers", "fiona.green", "george.hall", "helen.troy",
]


def utc_ago(hours=0, minutes=0, days=0):
    return datetime.now(timezone.utc) - timedelta(hours=hours, minutes=minutes, days=days)


def seed_users(db: Session):
    if db.query(User).count() > 0:
        return
    users = [
        User(username="admin", email="admin@zaalima.io",
             hashed_password=hash_password("Admin@123!"), role=UserRole.admin, is_active=True),
        User(username="soc_analyst1", email="analyst1@zaalima.io",
             hashed_password=hash_password("Analyst@123!"), role=UserRole.soc_analyst, is_active=True),
        User(username="soc_analyst2", email="analyst2@zaalima.io",
             hashed_password=hash_password("Analyst@123!"), role=UserRole.soc_analyst, is_active=True),
        User(username="viewer", email="viewer@zaalima.io",
             hashed_password=hash_password("Viewer@123!"), role=UserRole.viewer, is_active=True),
    ]
    db.add_all(users)
    db.commit()


def seed_threats(db: Session):
    if db.query(Threat).count() > 0:
        return
    threats = []
    severities = [ThreatSeverity.critical, ThreatSeverity.critical, ThreatSeverity.high,
                  ThreatSeverity.high, ThreatSeverity.medium, ThreatSeverity.low]
    statuses = [ThreatStatus.new, ThreatStatus.investigating, ThreatStatus.contained, ThreatStatus.resolved]

    for i in range(1, 25):
        host = random.choice(HOSTNAMES)
        threats.append(Threat(
            threat_id=f"THR-2026-{i:04d}",
            threat_name=random.choice(THREAT_NAMES),
            hostname=host,
            ip_address=f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
            username=random.choice(USERS),
            severity=random.choice(severities),
            status=random.choice(statuses),
            process_name=random.choice(["svchost.exe", "cmd.exe", "powershell.exe", "explorer.exe", "malware.exe"]),
            process_hash="e3b0c44298fc1c149afbf4c8996fb924" + f"{i:032x}"[:32],
            description=f"[SIMULATED] Ransomware activity detected on {host}",
            source="SIMULATED",
            detected_at=utc_ago(hours=random.randint(0, 168)),
        ))
    db.add_all(threats)
    db.commit()


def seed_incidents(db: Session):
    if db.query(Incident).count() > 0:
        return
    incidents = [
        Incident(
            incident_id="INC-20261031-001", title="[CRITICAL] Ransomware Detected - WORKSTATION-001",
            description="[SIMULATED] LockBit 3.0 ransomware detected on WORKSTATION-001.",
            severity=IncidentSeverity.critical, status=IncidentStatus.containing,
            threat_type="Ransomware", hostname="WORKSTATION-001",
            ip_address="192.168.1.105", affected_user="john.smith",
            assigned_to="soc_analyst1", detected_at=utc_ago(hours=2),
        ),
        Incident(
            incident_id="INC-20261030-002", title="[HIGH] Suspicious PowerShell Activity - LAPTOP-HR-04",
            description="[SIMULATED] Encoded PowerShell script execution detected.",
            severity=IncidentSeverity.high, status=IncidentStatus.investigating,
            threat_type="Malware", hostname="LAPTOP-HR-04",
            ip_address="192.168.2.88", affected_user="jane.doe",
            assigned_to="soc_analyst2", detected_at=utc_ago(hours=18),
        ),
        Incident(
            incident_id="INC-20261029-003", title="[CRITICAL] BlackCat Ransomware - FILESERVER-02",
            description="[SIMULATED] BlackCat/ALPHV ransomware encrypted files on file server.",
            severity=IncidentSeverity.critical, status=IncidentStatus.resolved,
            threat_type="Ransomware", hostname="FILESERVER-02",
            ip_address="192.168.1.200", affected_user="bob.wilson",
            assigned_to="soc_analyst1", detected_at=utc_ago(days=2),
            resolved_at=utc_ago(hours=36),
        ),
        Incident(
            incident_id="INC-20261028-004", title="[HIGH] Lateral Movement Detected - SERVER-DC-01",
            description="[SIMULATED] Pass-the-Hash attack detected on Domain Controller.",
            severity=IncidentSeverity.high, status=IncidentStatus.evidence_collection,
            threat_type="Lateral Movement", hostname="SERVER-DC-01",
            ip_address="192.168.1.10", affected_user="alice.johnson",
            assigned_to="soc_analyst2", detected_at=utc_ago(days=3),
        ),
    ]
    db.add_all(incidents)
    db.commit()


def seed_endpoints(db: Session):
    if db.query(Endpoint).count() > 0:
        return
    endpoint_data = [
        ("WORKSTATION-001", "192.168.1.105", "Windows 11 Pro", "john.smith", EndpointStatus.isolated, True),
        ("WORKSTATION-002", "192.168.1.106", "Windows 10 Pro", "jane.doe", EndpointStatus.healthy, False),
        ("SERVER-DC-01", "192.168.1.10", "Windows Server 2022", "admin", EndpointStatus.suspicious, False),
        ("LAPTOP-HR-04", "192.168.2.88", "Windows 11 Home", "jane.doe", EndpointStatus.infected, False),
        ("FILESERVER-02", "192.168.1.200", "Windows Server 2019", "bob.wilson", EndpointStatus.healthy, False),
        ("WEBSERVER-01", "192.168.1.80", "Ubuntu 22.04 LTS", None, EndpointStatus.healthy, False),
        ("DBSERVER-PRIMARY", "192.168.1.50", "Red Hat Enterprise Linux 9", None, EndpointStatus.healthy, False),
        ("DEVBOX-03", "192.168.3.15", "Windows 11 Pro", "charlie.brown", EndpointStatus.healthy, False),
        ("ACCOUNTING-PC", "192.168.2.45", "Windows 10 Pro", "diana.prince", EndpointStatus.suspicious, False),
        ("EXEC-LAPTOP-01", "192.168.4.10", "macOS Sonoma", "george.hall", EndpointStatus.healthy, False),
    ]
    endpoints = [
        Endpoint(
            hostname=h, ip_address=ip, operating_system=os_,
            connected_user=user, status=status, is_isolated=isolated,
            edr_provider="SIMULATED",
            last_seen=utc_ago(minutes=random.randint(1, 60)),
        )
        for h, ip, os_, user, status, isolated in endpoint_data
    ]
    db.add_all(endpoints)
    db.commit()


def seed_audit_logs(db: Session):
    if db.query(AuditLog).count() > 0:
        return
    logs = [
        AuditLog(action=AuditAction.threat_detected, actor="system", target="WORKSTATION-001",
                 details="LockBit 3.0 detected", status="success", created_at=utc_ago(hours=2)),
        AuditLog(action=AuditAction.endpoint_isolated, actor="soc_analyst1", target="WORKSTATION-001",
                 details="[SIMULATED] Endpoint isolated via EDR", status="success", created_at=utc_ago(hours=1, minutes=50)),
        AuditLog(action=AuditAction.incident_created, actor="soc_analyst1", target="INC-20261031-001",
                 details="Incident ticket created", status="success", created_at=utc_ago(hours=1, minutes=45)),
        AuditLog(action=AuditAction.user_suspended, actor="soc_analyst1", target="john.smith",
                 details="[SIMULATED] Account suspended - ransomware compromise", status="success", created_at=utc_ago(hours=1, minutes=40)),
        AuditLog(action=AuditAction.evidence_collected, actor="soc_analyst1", target="WORKSTATION-001",
                 details="Memory dump collected via KAPE", status="success", created_at=utc_ago(hours=1, minutes=30)),
        AuditLog(action=AuditAction.jira_ticket_created, actor="system", target="RR-1",
                 details="Jira incident ticket created for INC-20261031-001", status="success", created_at=utc_ago(hours=1, minutes=20)),
        AuditLog(action=AuditAction.playbook_executed, actor="system", target="Ransomware Response Playbook",
                 details="Automated playbook triggered for INC-20261031-001", status="success", created_at=utc_ago(hours=1, minutes=15)),
        AuditLog(action=AuditAction.login, actor="admin", target="admin",
                 details="Admin login from 192.168.1.1", status="success", created_at=utc_ago(hours=3)),
    ]
    db.add_all(logs)
    db.commit()


def seed_all(db: Session):
    seed_users(db)
    seed_threats(db)
    seed_incidents(db)
    seed_endpoints(db)
    seed_audit_logs(db)
    print("[OK] Database seeded with simulated security data.")


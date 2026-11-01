"""Digital Forensics API routes."""
import json
import uuid
import random
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.database import get_db
from app.core.security import get_current_user
from app.models.forensic import ForensicEvidence, EvidenceType
from app.models.audit_log import AuditLog, AuditAction
from app.services.s3_service import s3_service
from app.services.forensic_service import forensic_service

router = APIRouter()


@router.get("/s3/status")
async def get_s3_status(current_user=Depends(get_current_user)):
    """Returns the operational status of AWS S3 evidence storage."""
    return s3_service.get_status()


@router.get("/")
async def list_evidence(
    skip: int = 0, limit: int = 50,
    incident_id: Optional[str] = None,
    hostname: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    q = db.query(ForensicEvidence)
    if incident_id:
        q = q.filter(ForensicEvidence.incident_id == incident_id)
    if hostname:
        q = q.filter(ForensicEvidence.hostname.ilike(f"%{hostname}%"))
    total = q.count()
    items = q.order_by(ForensicEvidence.created_at.desc()).offset(skip).limit(limit).all()
    return {
        "total": total,
        "items": [
            {
                "evidence_id": e.evidence_id,
                "incident_id": e.incident_id,
                "hostname": e.hostname,
                "evidence_type": e.evidence_type.value if hasattr(e.evidence_type, "value") else str(e.evidence_type),
                "file_name": e.file_name,
                "file_size_bytes": e.file_size_bytes,
                "file_hash_sha256": e.file_hash_sha256,
                "s3_bucket": e.s3_bucket,
                "s3_key": e.s3_key,
                "collection_status": e.collection_status,
                "collected_by": e.collected_by,
                "collected_at": e.collected_at,
                "uploaded_at": e.uploaded_at,
                "notes": e.notes,
                "has_chain_of_custody": bool(e.chain_of_custody)
            }
            for e in items
        ]
    }


class KapeCollectRequest(BaseModel):
    incident_id: str
    hostname: str
    categories: Optional[List[str]] = None
    notes: Optional[str] = None


@router.post("/kape/collect")
async def collect_kape(
    body: KapeCollectRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Executes KAPE triage collection and stores evidence record with SHA-256."""
    res = forensic_service.collect_kape_artifacts(
        incident_id=body.incident_id,
        hostname=body.hostname,
        analyst_name=current_user.username,
        categories=body.categories
    )

    ev_id = f"EV-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:6].upper()}"
    ev = ForensicEvidence(
        evidence_id=ev_id,
        incident_id=body.incident_id,
        hostname=body.hostname,
        evidence_type=EvidenceType.kape_artifacts,
        file_name=res["file_name"],
        file_size_bytes=res["file_size_bytes"],
        file_hash_sha256=res["sha256"],
        chain_of_custody=json.dumps(res["chain_of_custody"]),
        collection_status="collected",
        collected_by=current_user.username,
        collected_at=datetime.now(timezone.utc),
        notes=body.notes or f"KAPE Acquisition job {res['job_id']}"
    )
    db.add(ev)
    db.add(AuditLog(
        action=AuditAction.evidence_collected,
        actor=current_user.username,
        target=body.hostname,
        details=f"KAPE artifacts acquired (SHA-256: {res['sha256'][:16]}...) for {body.incident_id}",
        status="success"
    ))
    db.commit()

    return {
        "status": "success",
        "evidence_id": ev_id,
        "job_id": res["job_id"],
        "file_name": res["file_name"],
        "file_size_bytes": res["file_size_bytes"],
        "sha256": res["sha256"],
        "real_tool_executed": res["real_tool"],
        "categories": res["categories"],
        "chain_of_custody": res["chain_of_custody"]
    }


class VolatilityAnalyzeRequest(BaseModel):
    incident_id: str
    hostname: str
    memory_dump_path: Optional[str] = None


@router.post("/volatility/analyze")
async def analyze_volatility(
    body: VolatilityAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Performs Volatility memory triage and extracts ransomware IOCs."""
    analysis = forensic_service.analyze_memory_volatility(
        incident_id=body.incident_id,
        hostname=body.hostname,
        analyst_name=current_user.username,
        memory_dump_path=body.memory_dump_path
    )

    res_json = json.dumps(analysis)
    res_hash = __import__("hashlib").sha256(res_json.encode()).hexdigest()

    ev_id = f"EV-VOL-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:6].upper()}"
    ev = ForensicEvidence(
        evidence_id=ev_id,
        incident_id=body.incident_id,
        hostname=body.hostname,
        evidence_type=EvidenceType.volatility_report,
        file_name=f"{body.hostname}_volatility_triage.json",
        file_size_bytes=len(res_json),
        file_hash_sha256=res_hash,
        chain_of_custody=json.dumps([
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "MEMORY_TRIAGE_EXECUTED",
                "actor": current_user.username,
                "tool": "Volatility 3 Framework",
                "verification_hash_sha256": res_hash
            }
        ]),
        collection_status="analyzed",
        collected_by=current_user.username,
        collected_at=datetime.now(timezone.utc),
        notes=f"Verdict: {analysis['threat_verdict']} ({analysis['critical_findings']} critical findings)"
    )
    db.add(ev)
    db.add(AuditLog(
        action=AuditAction.evidence_collected,
        actor=current_user.username,
        target=body.hostname,
        details=f"Volatility memory analysis on {body.hostname}: {analysis['threat_verdict']}",
        status="success"
    ))
    db.commit()

    return {
        "status": "success",
        "evidence_id": ev_id,
        "analysis": analysis
    }


@router.post("/{evidence_id}/upload-s3")
async def upload_evidence_to_s3(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Uploads evidence artifact to AWS S3 with AES-256 SSE and SHA-256 checksum."""
    ev = db.query(ForensicEvidence).filter(ForensicEvidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Forensic evidence record not found")

    # Find or stage artifact file
    from pathlib import Path
    storage_dir = Path("d:/ransomware response/zaalima/backend/storage/forensics")
    candidate = None
    if ev.incident_id:
        inc_dir = storage_dir / ev.incident_id
        if inc_dir.exists():
            for f in inc_dir.rglob(ev.file_name or "*"):
                if f.is_file():
                    candidate = str(f)
                    break

    if not candidate:
        candidate = str(storage_dir / (ev.file_name or f"{evidence_id}.bin"))

    upload_result = s3_service.upload_evidence_file(
        local_path=candidate,
        incident_id=ev.incident_id or "INC-GENERAL",
        hostname=ev.hostname,
        evidence_type=ev.evidence_type.value if hasattr(ev.evidence_type, "value") else str(ev.evidence_type),
        evidence_id=ev.evidence_id,
        analyst_notes=ev.notes
    )

    ev.s3_bucket = upload_result.get("s3_bucket")
    ev.s3_key = upload_result.get("s3_key")
    ev.file_hash_sha256 = upload_result.get("sha256")
    ev.uploaded_at = datetime.now(timezone.utc)
    ev.collection_status = "uploaded_to_s3"

    # Append to chain of custody
    custody_list = []
    if ev.chain_of_custody:
        try:
            custody_list = json.loads(ev.chain_of_custody)
        except Exception:
            custody_list = []
    custody_list.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "UPLOADED_TO_AWS_S3",
        "actor": current_user.username,
        "destination": f"s3://{ev.s3_bucket}/{ev.s3_key}",
        "server_side_encryption": upload_result.get("encryption"),
        "verification_hash_sha256": upload_result.get("sha256")
    })
    ev.chain_of_custody = json.dumps(custody_list)

    db.add(AuditLog(
        action=AuditAction.evidence_collected,
        actor=current_user.username,
        target=ev.hostname,
        details=f"Evidence {ev.evidence_id} uploaded to AWS S3 ({upload_result.get('s3_uri')}) with AES256 encryption",
        status="success"
    ))
    db.commit()

    return {
        "status": "success",
        "evidence_id": ev.evidence_id,
        "s3_upload": upload_result
    }


@router.get("/{evidence_id}/custody")
async def get_chain_of_custody(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    ev = db.query(ForensicEvidence).filter(ForensicEvidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    ledger = []
    if ev.chain_of_custody:
        try:
            ledger = json.loads(ev.chain_of_custody)
        except Exception:
            pass
    return {
        "evidence_id": ev.evidence_id,
        "hostname": ev.hostname,
        "file_hash_sha256": ev.file_hash_sha256,
        "chain_of_custody": ledger
    }


class CollectEvidenceRequest(BaseModel):
    incident_id: str
    hostname: str
    evidence_type: str
    notes: Optional[str] = None


@router.post("/collect")
async def collect_evidence(
    body: CollectEvidenceRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    ev_id = f"EV-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8].upper()}"
    ev = ForensicEvidence(
        evidence_id=ev_id, incident_id=body.incident_id,
        hostname=body.hostname, evidence_type=body.evidence_type,
        collection_status="collected", collected_by=current_user.username,
        collected_at=datetime.now(timezone.utc), notes=body.notes,
        file_name=f"{body.hostname}_{body.evidence_type}_{ev_id}.bin",
        file_size_bytes=1024 * 1024 * random.randint(50, 4096),
    )
    db.add(ev)
    db.add(AuditLog(action=AuditAction.evidence_collected, actor=current_user.username,
                    target=body.hostname,
                    details=f"[SIMULATED] {body.evidence_type} collected from {body.hostname}",
                    status="success"))
    db.commit()
    return {"evidence_id": ev_id, "message": "[SIMULATED] Evidence collected successfully"}

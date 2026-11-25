"""
test_aws_orchestration.py - Unit tests for AWS Step Functions definition and Lambda handlers.
"""

import json
from pathlib import Path
import pytest

from orchestration.aws.lambda_handlers import (
    lambda_handler_containment,
    lambda_handler_forensics,
    lambda_handler_ingest_alert,
    lambda_handler_orchestrator,
    lambda_handler_s3_upload,
)
from orchestration.aws.step_functions_service import StepFunctionsService


def test_step_functions_definition_valid_json():
    """Verify that the Amazon States Language definition is valid JSON and well-structured."""
    asl_path = Path(__file__).resolve().parent.parent / "orchestration" / "aws" / "step_functions_definition.json"
    assert asl_path.is_file()

    with open(asl_path, "r", encoding="utf-8") as f:
        definition = json.load(f)

    assert "StartAt" in definition
    assert "States" in definition
    assert definition["StartAt"] == "IngestAndValidateAlert"
    assert "ExecuteNetworkContainment" in definition["States"]
    assert "UploadEvidenceToS3" in definition["States"]
    assert "WorkflowComplete" in definition["States"]


def test_lambda_handler_ingest_alert():
    """Verify ingestion lambda validates alert telemetry."""
    event = {
        "alert_id": "ALERT-LAMBDA-001",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Lambda test event",
        "timestamp": "2026-11-20T17:00:00Z",
        "hostname": "HOST-LAMBDA-01",
        "endpoint_id": "EP-001",
    }
    result = lambda_handler_ingest_alert(event, None)
    assert result["alert_id"] == "ALERT-LAMBDA-001"
    assert result["hostname"] == "HOST-LAMBDA-01"


def test_lambda_handler_containment_dry_run():
    """Verify containment lambda executes safely in dry-run mode."""
    event = {
        "alert_id": "ALERT-LAMBDA-002",
        "threat_type": "ransomware",
        "severity": 5,
        "hostname": "HOST-LAMBDA-02",
        "endpoint_id": "EP-002",
        "dry_run": True,
    }
    result = lambda_handler_containment(event, None)
    assert "containment" in result
    assert result["containment"]["status"] == "SIMULATED"


def test_step_functions_service_fallback_when_offline():
    """Verify step functions service falls back seamlessly to Python orchestrator."""
    service = StepFunctionsService()
    alert = {
        "alert_id": "ALERT-SFN-003",
        "threat_type": "ransomware",
        "severity": 5,
        "description": "Step Functions fallback verification",
        "timestamp": "2026-11-20T17:00:00Z",
        "hostname": "HOST-SFN-03",
        "endpoint_id": "EP-003",
    }
    res = service.start_workflow_execution(alert)
    assert res["success"] is True
    assert res["execution_mode"] == "LOCAL_PYTHON_FALLBACK"

"""
test_ransomware_simulator.py - Comprehensive Unit & Integration Test Suite.

Automated Ransomware Containment & Incident Response Orchestrator
Week 4 Day 4: Ransomware Simulation and End-to-End Testing.

Tests the following required capabilities:
1. Simulated incident generation.
2. CRITICAL severity incident.
3. HIGH severity incident.
4. MEDIUM severity incident.
5. LOW severity incident.
6. Invalid severity rejection.
7. Missing incident information.
8. Successful mocked workflow.
9. Jira failure handling (auth, ticket creation, assignment).
10. Slack failure handling (HTTP 500, network error, missing webhook).
11. Duplicate incident handling.
12. Response time calculation (time.perf_counter).
13. JSON simulation report generation in reports/simulations/.
14. Secret masking in reports (zero credential leakage).
15. Safe live mode safeguards and execution.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import JiraConfig, SlackConfig, mask_secret, mask_webhook_url
from backend.jira_integration import IncidentValidationError
from backend.ransomware_simulator import (
    RansomwareSimulator,
    SEVERITY_INCIDENT_TEMPLATES,
    mask_report_secrets,
    run_ransomware_simulation,
)


@pytest.fixture
def simulator(tmp_path):
    """Provide a RansomwareSimulator instance configured with temporary reports directory."""
    reports_dir = tmp_path / "reports" / "simulations"
    return RansomwareSimulator(reports_dir=reports_dir)


# ==============================================================================
# 1. Incident Generation & Severity Level Tests
# ==============================================================================

def test_simulated_incident_generation(simulator):
    """Test standard simulated incident generation contains all required fields."""
    incident = simulator.generate_simulated_incident(severity="CRITICAL")

    required_keys = [
        "incident_id",
        "incident_type",
        "severity",
        "hostname",
        "ip_address",
        "username",
        "process_hash",
        "detection_time",
        "incident_description",
        "source",
        "telemetry",
    ]
    for key in required_keys:
        assert key in incident, f"Missing required incident field: {key}"

    # Verify it passes core telemetry validation
    validated = simulator.validate_incident(incident)
    assert validated.incident_id == incident["incident_id"]
    assert validated.severity == "CRITICAL"
    assert validated.hostname == incident["hostname"]


def test_critical_severity_incident(simulator):
    """Test CRITICAL severity incident generates ransomware telemetry."""
    incident = simulator.generate_simulated_incident(severity="CRITICAL")

    assert incident["severity"] == "CRITICAL"
    assert incident["incident_type"] == "Ransomware"
    assert incident["hostname"] == "TEST-WORKSTATION-01"
    assert incident["ip_address"] == "192.168.56.101"
    assert "Canary file tripwire" in incident["incident_description"]

    telemetry = incident["telemetry"]
    assert telemetry["canary_file_tripped"] is True
    assert telemetry["shadow_copies_deleted"] is True
    assert telemetry["encrypted_files_count"] > 0
    assert "winlogin_update.exe" in telemetry["process_name"]


def test_high_severity_incident(simulator):
    """Test HIGH severity incident generates mass file modification telemetry."""
    incident = simulator.generate_simulated_incident(severity="HIGH")

    assert incident["severity"] == "HIGH"
    assert incident["incident_type"] == "Mass File Modification"
    assert incident["hostname"] == "TEST-WORKSTATION-02"
    assert incident["ip_address"] == "192.168.56.102"

    telemetry = incident["telemetry"]
    assert telemetry["modified_files_count"] == 85
    assert telemetry["canary_file_tripped"] is False


def test_medium_severity_incident(simulator):
    """Test MEDIUM severity incident generates suspicious process telemetry."""
    incident = simulator.generate_simulated_incident(severity="MEDIUM")

    assert incident["severity"] == "MEDIUM"
    assert incident["incident_type"] == "Suspicious Process Execution"
    assert incident["hostname"] == "TEST-WORKSTATION-03"
    assert incident["ip_address"] == "192.168.56.103"

    telemetry = incident["telemetry"]
    assert "powershell" in telemetry["process_name"]
    assert telemetry["certutil_decoded"] is True


def test_low_severity_incident(simulator):
    """Test LOW severity incident generates network beaconing telemetry."""
    incident = simulator.generate_simulated_incident(severity="LOW")

    assert incident["severity"] == "LOW"
    assert incident["incident_type"] == "Unusual Network Activity"
    assert incident["hostname"] == "TEST-WORKSTATION-04"
    assert incident["ip_address"] == "192.168.56.104"

    telemetry = incident["telemetry"]
    assert telemetry["beacon_interval_seconds"] == 60
    assert telemetry["destination_port"] == 8088


def test_invalid_severity_rejection(simulator):
    """Test that invalid severity levels are strictly rejected with ValueError."""
    invalid_levels = ["EXTREME", "SUPER_CRITICAL", "UNKNOWN", "", "123"]
    for level in invalid_levels:
        with pytest.raises(ValueError) as excinfo:
            simulator.generate_simulated_incident(severity=level)
        assert "Invalid severity level" in str(excinfo.value)

        with pytest.raises(ValueError):
            simulator.generate_test_telemetry(severity=level)


# ==============================================================================
# 2. Validation & Missing Information Tests
# ==============================================================================

def test_missing_incident_information(simulator):
    """Test that missing required fields fail telemetry validation and halt workflow."""
    # Test missing hostname
    bad_incident = simulator.generate_simulated_incident(severity="CRITICAL")
    bad_incident["hostname"] = ""
    with pytest.raises(IncidentValidationError):
        simulator.validate_incident(bad_incident)

    # Test invalid IP address
    bad_ip_incident = simulator.generate_simulated_incident(severity="CRITICAL")
    bad_ip_incident["ip_address"] = "999.999.999.999"
    with pytest.raises(IncidentValidationError):
        simulator.validate_incident(bad_ip_incident)

    # Test invalid process hash
    bad_hash_incident = simulator.generate_simulated_incident(severity="CRITICAL")
    bad_hash_incident["process_hash"] = "not_a_valid_hex_hash"
    with pytest.raises(IncidentValidationError):
        simulator.validate_incident(bad_hash_incident)

    # Execute simulation with invalid incident: workflow must fail gracefully
    result = simulator.run_simulation(incident_data=bad_incident)
    assert result["overall_workflow_status"] == "FAILED"
    assert result["incident_validation"]["valid"] is False
    assert result["jira_ticket"]["status"] == "SKIPPED"
    assert result["slack_notification"]["status"] == "SKIPPED"


# ==============================================================================
# 3. Successful Workflow & End-to-End Simulation Tests
# ==============================================================================

def test_successful_mocked_workflow(simulator):
    """Test complete successful mocked simulation workflow through all 8 stages."""
    result = simulator.run_simulation(severity="CRITICAL", live=False)

    assert result["overall_workflow_status"] == "SUCCESS"
    assert result["mode"] == "MOCKED"
    assert result["severity"] == "CRITICAL"
    assert result["incident_id"] == "INC-2026-001"
    assert result["hostname"] == "TEST-WORKSTATION-01"

    # Validation stage
    assert result["incident_validation"]["valid"] is True
    assert result["incident_validation"]["status"] == "VALID"

    # Jira stage
    assert result["jira_ticket"]["status"] == "Created"
    assert result["jira_ticket"]["ticket_key"] is not None
    assert "https://" in result["jira_ticket"]["ticket_url"]

    # Analyst assignment stage
    assert result["analyst_assignment"]["assigned"] is True
    assert result["analyst_assignment"]["status"] == "ASSIGNED"
    assert result["analyst_assignment"]["role"] == "Senior SOC Lead / Incident Commander"

    # Slack notification stage
    assert result["slack_notification"]["delivered"] is True
    assert result["slack_notification"]["status"] == "DELIVERED"
    assert "🔴 Critical Alert" in result["slack_notification"]["message"]

    # Performance stage
    metrics = result["performance_metrics"]
    assert metrics["total_response_time_seconds"] >= 0.0
    assert metrics["jira_ticket_creation_seconds"] >= 0.0
    assert metrics["analyst_assignment_seconds"] >= 0.0
    assert metrics["slack_notification_seconds"] >= 0.0


def test_simulate_ransomware_detection(simulator):
    """Test simulate_ransomware_detection returns valid detection payload."""
    detection = simulator.simulate_ransomware_detection(severity="HIGH")
    assert detection["status"] == "DETECTED"
    assert detection["source"] == "Simulated EDR"
    assert detection["severity"] == "HIGH"
    assert detection["incident"]["incident_id"] == "INC-2026-002"


# ==============================================================================
# 4. Failure Scenarios Handling Tests
# ==============================================================================

def test_jira_auth_failure_handling(simulator):
    """Test Jira authentication failure aborts ticket creation and Slack notification."""
    result = simulator.run_simulation(severity="CRITICAL", fail_jira="auth")

    assert result["overall_workflow_status"] == "FAILED"
    assert result["jira_ticket"]["status"] == "FAILED"
    assert "HTTP 401" in result["jira_ticket"]["error"]
    # Slack notification must be aborted because Jira failed
    assert result["slack_notification"]["status"] == "JIRA_FAILED"
    assert result["slack_notification"]["delivered"] is False
    assert result["analyst_assignment"]["assigned"] is False


def test_jira_ticket_creation_failure(simulator):
    """Test Jira HTTP 400 rejection correctly reports workflow as FAILED."""
    result = simulator.run_simulation(severity="CRITICAL", fail_jira="create")

    assert result["overall_workflow_status"] == "FAILED"
    assert result["jira_ticket"]["status"] == "FAILED"
    assert "HTTP 400" in result["jira_ticket"]["error"]
    assert result["slack_notification"]["status"] == "JIRA_FAILED"


def test_jira_connection_failure(simulator):
    """Test Jira network timeout error correctly reports workflow as FAILED."""
    result = simulator.run_simulation(severity="CRITICAL", fail_jira="connection")

    assert result["overall_workflow_status"] == "FAILED"
    assert result["jira_ticket"]["status"] == "FAILED"
    assert "timed out" in result["jira_ticket"]["error"]


def test_jira_analyst_assignment_failure(simulator):
    """Test analyst assignment failure: Jira ticket preserved, workflow is PARTIAL_SUCCESS."""
    result = simulator.run_simulation(severity="CRITICAL", fail_assignment=True)

    assert result["overall_workflow_status"] == "PARTIAL_SUCCESS"
    assert result["jira_ticket"]["status"] == "Created"
    assert result["analyst_assignment"]["assigned"] is False
    assert result["analyst_assignment"]["status"] == "UNASSIGNED"
    # Slack still notifies with unassigned status
    assert result["slack_notification"]["delivered"] is True


def test_slack_http500_failure_handling(simulator):
    """Test Slack HTTP 500 error: Jira preserved, workflow is PARTIAL_SUCCESS."""
    result = simulator.run_simulation(severity="CRITICAL", fail_slack="http500")

    assert result["overall_workflow_status"] == "PARTIAL_SUCCESS"
    assert result["jira_ticket"]["status"] == "Created"
    assert result["analyst_assignment"]["assigned"] is True
    assert result["slack_notification"]["status"] == "FAILED"
    assert result["slack_notification"]["delivered"] is False
    assert "HTTP 500" in result["slack_notification"]["error"]


def test_slack_network_connection_failure(simulator):
    """Test Slack connection error: Jira preserved, workflow is PARTIAL_SUCCESS."""
    result = simulator.run_simulation(severity="CRITICAL", fail_slack="connection")

    assert result["overall_workflow_status"] == "PARTIAL_SUCCESS"
    assert result["jira_ticket"]["status"] == "Created"
    assert result["slack_notification"]["status"] == "FAILED"
    assert result["slack_notification"]["delivered"] is False


def test_slack_missing_webhook_handling(simulator):
    """Test unconfigured Slack webhook: status recorded as NOT_CONFIGURED."""
    result = simulator.run_simulation(severity="CRITICAL", fail_slack="missing_webhook")

    assert result["overall_workflow_status"] == "PARTIAL_SUCCESS"
    assert result["jira_ticket"]["status"] == "Created"
    assert result["slack_notification"]["status"] == "NOT_CONFIGURED"
    assert result["slack_notification"]["delivered"] is False


def test_duplicate_incident_handling(simulator):
    """Test duplicate incident handling: avoids redundant ticket and suppresses notification."""
    result = simulator.run_simulation(severity="CRITICAL", is_duplicate=True)

    assert result["overall_workflow_status"] == "SUCCESS"
    assert result["jira_ticket"]["is_duplicate"] is True
    assert "Duplicate Avoided" in result["jira_ticket"]["status"]
    assert result["slack_notification"]["status"] == "SKIPPED_DUPLICATE"


# ==============================================================================
# 5. Performance Measurement Tests
# ==============================================================================

def test_response_time_calculation(simulator):
    """Test duration measurement using time.perf_counter for all workflow stages."""
    result = simulator.run_simulation(severity="CRITICAL")

    metrics = result["performance_metrics"]
    assert "jira_ticket_creation_seconds" in metrics
    assert "analyst_assignment_seconds" in metrics
    assert "slack_notification_seconds" in metrics
    assert "total_response_time_seconds" in metrics

    assert isinstance(metrics["jira_ticket_creation_seconds"], float)
    assert isinstance(metrics["analyst_assignment_seconds"], float)
    assert isinstance(metrics["slack_notification_seconds"], float)
    assert isinstance(metrics["total_response_time_seconds"], float)

    # Verify detection and start timestamps
    assert metrics["detection_time"] is not None
    assert metrics["processing_start_time"] is not None


# ==============================================================================
# 6. Report Generation & Zero-Secret Leakage Tests
# ==============================================================================

def test_json_simulation_report_generation(simulator):
    """Test JSON audit report generation in reports/simulations/ directory."""
    result = simulator.run_simulation(severity="HIGH", save_report=True)

    # Verify file was created in simulator.reports_dir
    report_files = list(simulator.reports_dir.glob("simulation_report_*.json"))
    assert len(report_files) >= 1

    report_path = report_files[-1]
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Verify 12 required sections
    assert data["simulation_id"] == result["simulation_id"]
    assert data["incident_id"] == "INC-2026-002"
    assert data["threat_type"] == "Mass File Modification"
    assert data["severity"] == "HIGH"
    assert data["hostname"] == "TEST-WORKSTATION-02"
    assert "detection_timestamp" in data
    assert "incident_validation" in data
    assert "jira_ticket" in data
    assert "analyst_assignment" in data
    assert "slack_notification" in data
    assert "performance_metrics" in data
    assert "overall_workflow_status" in data


def test_secret_masking_in_reports():
    """Test that report serializer masks API tokens, Slack webhooks, and passwords."""
    raw_data = {
        "simulation_id": "SIM-TEST-001",
        "ticket_key": "RR-102",  # Should NOT be masked
        "project_key": "RR",     # Should NOT be masked
        "api_token": "ATATT3xFfGF0UdWqGgYtgrVqDwV0NHssKvtq9",
        "secret_key": "super_secret_jwt_key",
        "slack_webhook": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
        "nested": {
            "password": "production_database_password",
            "token": "ghp_1234567890abcdef",
            "normal_field": "public_data",
        },
    }

    sanitized = mask_report_secrets(raw_data)

    # Ensure Jira keys remain intact
    assert sanitized["ticket_key"] == "RR-102"
    assert sanitized["project_key"] == "RR"

    # Ensure secrets are masked
    assert sanitized["api_token"] != raw_data["api_token"]
    assert "...****" in sanitized["api_token"]

    assert sanitized["secret_key"] != raw_data["secret_key"]
    assert "...****" in sanitized["secret_key"]

    assert sanitized["slack_webhook"] != raw_data["slack_webhook"]
    assert "https://hooks.slack.com/services/...****" in sanitized["slack_webhook"]

    assert sanitized["nested"]["password"] != raw_data["nested"]["password"]
    assert sanitized["nested"]["token"] != raw_data["nested"]["token"]
    assert sanitized["nested"]["normal_field"] == "public_data"


# ==============================================================================
# 7. CLI Runner & Live Safeguard Tests
# ==============================================================================

def test_cli_runner_mocked(tmp_path):
    """Test run_ransomware_simulation entrypoint executes cleanly in mocked mode."""
    with patch("backend.ransomware_simulator.RansomwareSimulator.save_simulation_report") as mock_save:
        mock_save.return_value = str(tmp_path / "mock_report.json")
        exit_code = run_ransomware_simulation(severity="CRITICAL", live=False)
        assert exit_code == 0

        exit_code_high = run_ransomware_simulation(severity="HIGH", live=False)
        assert exit_code_high == 0


def test_live_simulation_requires_confirmation():
    """Test that live simulation aborts if user declines or fails confirmation."""
    with patch("builtins.input", return_value="no"):
        exit_code = run_ransomware_simulation(severity="CRITICAL", live=True, confirm_live=False)
        assert exit_code == 1


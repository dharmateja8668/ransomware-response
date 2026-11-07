"""
test_performance_evaluator.py - Test Suite for Day 5 Performance Evaluation Engine.

Automated Ransomware Containment & Incident Response Orchestrator
Week 4 Day 5: Performance Evaluation and Final Documentation.
"""

import json
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.performance_evaluator import (
    PerformanceEvaluator,
    calculate_p95,
    calculate_statistics,
)
from backend.ransomware_simulator import RansomwareSimulator


@pytest.fixture
def evaluator(tmp_path):
    """Provide a PerformanceEvaluator configured with temporary reports directory."""
    reports_dir = tmp_path / "reports" / "performance"
    simulator = RansomwareSimulator(reports_dir=tmp_path / "reports" / "simulations")
    return PerformanceEvaluator(simulator=simulator, reports_dir=reports_dir)


def test_calculate_p95():
    """Verify 95th percentile calculation with known array."""
    data = [float(i) for i in range(1, 101)]
    p95 = calculate_p95(data)
    assert 94.0 <= p95 <= 96.0

    assert calculate_p95([]) == 0.0
    assert calculate_p95([5.0]) == 5.0


def test_calculate_statistics():
    """Verify statistics calculation: min, max, average, median, p95, stdev."""
    data = [1.0, 2.0, 3.0, 4.0, 5.0]
    stats = calculate_statistics(data)
    assert stats["min_seconds"] == 1.0
    assert stats["max_seconds"] == 5.0
    assert stats["average_seconds"] == 3.0
    assert stats["median_seconds"] == 3.0
    assert stats["std_dev_seconds"] > 0.0

    empty_stats = calculate_statistics([])
    assert empty_stats["average_seconds"] == 0.0


def test_run_stage_benchmarks_metrics(evaluator):
    """Verify benchmark run collects all required 5 workflow stages across severities."""
    summary = evaluator.run_stage_benchmarks(iterations_per_severity=3)

    assert summary["total_iterations"] == 12  # 3 * 4 severities
    assert summary["overall_success_rate_percent"] == 100.0
    assert "by_severity" in summary

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        assert sev in summary["by_severity"]
        sev_stats = summary["by_severity"][sev]
        assert sev_stats["iteration_count"] == 3
        assert sev_stats["successful_workflow_count"] == 3
        assert sev_stats["failed_workflow_count"] == 0
        assert "complete_workflow_stats" in sev_stats
        assert "stage1_detection_validation_stats" in sev_stats
        assert "stage2_jira_ticket_creation_stats" in sev_stats
        assert "stage3_analyst_assignment_stats" in sev_stats
        assert "stage4_slack_notification_stats" in sev_stats


def test_run_reliability_analysis_9_scenarios(evaluator):
    """Verify all 9 failure scenarios are executed and pass expected checks."""
    records = evaluator.run_reliability_analysis()

    assert len(records) == 9
    for rec in records:
        assert rec["passed"] is True, f"Scenario failed: {rec['test_scenario']}"
        assert rec["test_scenario"]
        assert rec["expected_result"]
        assert rec["actual_result"]
        assert rec["impact_on_overall_workflow"]


def test_slack_failure_does_not_interrupt_jira(evaluator):
    """Verify that Slack failures (missing webhook, HTTP 500, network error) preserve Jira ticket."""
    records = evaluator.run_reliability_analysis()

    slack_scenarios = [r for r in records if r["scenario_id"] in ("SCENARIO-4", "SCENARIO-5", "SCENARIO-6")]
    assert len(slack_scenarios) == 3

    for sc in slack_scenarios:
        assert sc["passed"] is True
        assert sc["jira_ticket_status"] in ("Created", "Existing (Duplicate Avoided)")
        assert sc["workflow_status"] == "PARTIAL_SUCCESS"
        assert sc["slack_isolation_verified"] is True


def test_save_json_and_csv_reports(evaluator, tmp_path):
    """Verify performance_summary.json and performance_results.csv serialization."""
    evaluator.run_stage_benchmarks(iterations_per_severity=2)
    evaluator.run_reliability_analysis()

    summary_file = evaluator.save_performance_summary_json()
    assert summary_file.exists()
    with open(summary_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["total_iterations"] == 8
    assert "production_timing_notes" in data

    csv_file = evaluator.save_performance_results_csv()
    assert csv_file.exists()
    content = csv_file.read_text(encoding="utf-8")
    assert "stage1_detection_validation_seconds" in content
    assert "stage5_total_workflow_seconds" in content

    rel_file = evaluator.save_reliability_analysis_json()
    assert rel_file.exists()
    with open(rel_file, "r", encoding="utf-8") as f:
        rel_data = json.load(f)
    assert rel_data["total_scenarios_tested"] == 9
    assert rel_data["scenarios_passed"] == 9


def test_generate_charts_and_markdown_report(evaluator):
    """Verify generation of all 4 Matplotlib chart files and performance_report.md."""
    evaluator.run_stage_benchmarks(iterations_per_severity=2)
    evaluator.run_reliability_analysis()

    charts = evaluator.generate_performance_charts()
    assert len(charts) == 4
    for chart in charts:
        assert chart.exists()
        assert chart.stat().st_size > 1000  # Non-empty image file

    report_file = evaluator.generate_performance_report_markdown()
    assert report_file.exists()
    text = report_file.read_text(encoding="utf-8")
    assert "Performance Evaluation & Reliability Analysis Report" in text
    assert "Mocked vs Live Performance" in text
    assert "Stage 1: Incident Detection & Validation" in text


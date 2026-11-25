"""
test_forensics_reality.py - Forensic separation of real tool vs simulation tests.
"""

from pathlib import Path
import sys
import pytest

_BACKEND_DIR = Path(__file__).resolve().parent.parent / "zaalima" / "backend"
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.services.forensic_service import ForensicService


@pytest.fixture
def forensic_svc():
    return ForensicService()


def test_kape_artifacts_classification(forensic_svc):
    """Verify KAPE artifact package has explicit evidence_classification and is_simulated flag."""
    res = forensic_svc.collect_kape_artifacts(
        incident_id="INC-FOR-001",
        hostname="SEC-WORKSTATION-01",
        analyst_name="Test SOC Lead",
    )
    assert "evidence_classification" in res
    assert "is_simulated" in res
    assert res["is_simulated"] == (not res["real_tool"])
    assert res["sha256"]
    assert Path(res["file_path"]).is_file()


def test_physical_memory_acquisition_reality_check(forensic_svc):
    """Verify that memory acquisition explicitly marks simulated data and documents real requirements."""
    res = forensic_svc.acquire_physical_memory(
        incident_id="INC-RAM-002",
        hostname="DC-SERVER-01",
        analyst_name="Senior Forensic Investigator",
    )
    assert "evidence_classification" in res
    assert "is_simulated" in res
    assert "hardware_prerequisites" in res
    assert len(res["hardware_prerequisites"]) >= 4
    if not res["real_driver_loaded"]:
        assert res["evidence_classification"] == "SIMULATED_MEMORY_DUMP"
        assert res["is_simulated"] is True
        assert "Simulated RAM package generated" in res["message"]


def test_volatility_analysis_simulation_indicator(forensic_svc):
    """Verify that volatility triage separates real dump analysis from simulated triage."""
    res = forensic_svc.analyze_memory_volatility(
        incident_id="INC-VOL-003",
        hostname="WEB-SRV-01",
        analyst_name="Incident Responder",
        memory_dump_path=None,
    )
    assert res["is_simulated"] is True
    assert res["evidence_classification"] == "SIMULATED_MEMORY_TRIAGE"
    assert res["real_dump_provided"] is False

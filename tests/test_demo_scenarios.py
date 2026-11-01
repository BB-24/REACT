"""Automated tests for REACT mid-semester demo scenarios, safety boundaries, and offline execution.

Verifies:
- Scenario 1 (High Severity / Full Containment & Capture)
- Scenario 2 (Critical Infrastructure Bypass Policy)
- Scenario 3 (Simulated Failure & Safety Cutoff)
- Deterministic estate reset
- Fail-closed mock safety guard
- Bearer secret & SAS token sanitization
"""

import os
from unittest.mock import patch

import pytest

from src.demo import SIMULATION_LABEL, get_orchestrator
from src.demo.orchestrator import (
    MOCK_SETTINGS,
    SafetyError,
    enforce_mock_safety,
    sanitize_value,
)


@pytest.fixture
def fresh_demo_estate(monkeypatch):
    """Ensure clean simulated estate with isolated environment before and after each test."""
    for key, val in MOCK_SETTINGS.items():
        monkeypatch.setenv(key, val)
    orch = get_orchestrator()
    orch.reset_estate()
    yield orch
    orch.reset_estate()


def test_prerequisites_verification(fresh_demo_estate):
    """Demo prerequisites pass completely in mock mode."""
    res = fresh_demo_estate.check_prerequisites()
    assert res["allPassed"] is True
    assert res["simulationLabel"] == SIMULATION_LABEL
    assert res["checks"]["mockModeActive"]["passed"] is True
    assert res["checks"]["sampleEvidence"]["passed"] is True


def test_scenario_1_high_severity_flow(fresh_demo_estate):
    """Scenario 1: Full end-to-end containment, RAM dump, custody ledger, and disk capture."""
    result = fresh_demo_estate.run_scenario(1)

    assert result.status == "succeeded"
    assert result.scenario_id == "1"
    assert result.incident_id == "INC-2026-DEMO-01"
    assert result.simulation_label == SIMULATION_LABEL

    # Check 6 pipeline stages
    stage_ids = [s.stage_id for s in result.stages]
    assert stage_ids == [
        "ingestion",
        "containment",
        "memory_acquisition",
        "custody_ledger",
        "disk_snapshot",
        "forensic_analysis",
    ]

    # Stage 2: Network Containment
    containment = next(s for s in result.stages if s.stage_id == "containment")
    assert containment.status == "completed"
    assert "Forensic-Isolation-NSG-INC-2026-DEMO-01" in containment.details["isolationNsg"]

    # Stage 3: Live Memory Acquisition
    memory = next(s for s in result.stages if s.stage_id == "memory_acquisition")
    assert memory.status == "completed"
    assert memory.details["targetPlatform"] == "windows"
    assert memory.details["tool"] == "winpmem.exe"

    # Stage 4: Chain of Custody & Ledger
    custody = next(s for s in result.stages if s.stage_id == "custody_ledger")
    assert custody.status == "completed"
    assert len(custody.details["sha256"]) == 64
    assert custody.details["witnessHashMatch"] is True
    assert custody.details["ledgerEntryId"] >= 1

    # Stage 5: Disk Snapshotting
    disk = next(s for s in result.stages if s.stage_id == "disk_snapshot")
    assert disk.status == "completed"
    assert disk.details["memoryGate"] == "satisfied"
    assert disk.details["snapshotCount"] >= 2
    assert "snapshot.json" in disk.details["manifestBlob"]

    # Stage 6: Forensic Analysis
    analysis = next(s for s in result.stages if s.stage_id == "forensic_analysis")
    assert analysis.status == "completed"
    assert analysis.details["timelineEventsCount"] > 0

    # Verify Sanitized Evidence Dossier
    dossier = result.sanitized_evidence
    assert dossier["incidentId"] == "INC-2026-DEMO-01"
    assert dossier["ledgerIntegrity"]["chainIntact"] is True
    # Ensure no raw SAS query strings exist
    dumped = str(dossier)
    assert "?sv=" not in dumped
    assert "cmVhY3Qt" not in dumped


def test_scenario_2_critical_infrastructure_bypass(fresh_demo_estate):
    """Scenario 2: Critical Infrastructure tag bypasses network containment while acquisition proceeds."""
    result = fresh_demo_estate.run_scenario(2)

    assert result.status == "succeeded"
    assert result.scenario_id == "2"
    assert result.incident_id == "INC-2026-DEMO-02"

    # Stage 2: Containment must be bypassed
    containment = next(s for s in result.stages if s.stage_id == "containment")
    assert containment.status == "bypassed"
    assert containment.details["status"] == "bypassed"
    assert "Critical-Infrastructure tag" in containment.details["reason"]
    assert containment.details["networkInterfaceTouched"] is False

    # Downstream acquisition must still succeed
    memory = next(s for s in result.stages if s.stage_id == "memory_acquisition")
    assert memory.status == "completed"
    assert memory.details["targetPlatform"] == "linux"
    assert memory.details["tool"] == "avml"

    disk = next(s for s in result.stages if s.stage_id == "disk_snapshot")
    assert disk.status == "completed"
    assert disk.details["snapshotCount"] >= 3  # OS disk + 2 data disks for db-02

    custody = next(s for s in result.stages if s.stage_id == "custody_ledger")
    assert custody.status == "completed"
    assert len(custody.details["sha256"]) == 64


def test_scenario_3_simulated_failure_handling(fresh_demo_estate):
    """Scenario 3: Non-existent target VM halts pipeline safely without generating false evidence."""
    result = fresh_demo_estate.run_scenario(3)

    assert result.status == "failed"
    assert result.scenario_id == "3"

    containment = next(s for s in result.stages if s.stage_id == "containment")
    assert containment.status == "failed"
    assert containment.details["statusCode"] == 500

    # Downstream stages must be safely skipped
    memory = next(s for s in result.stages if s.stage_id == "memory_acquisition")
    assert memory.status == "skipped"

    disk = next(s for s in result.stages if s.stage_id == "disk_snapshot")
    assert disk.status == "skipped"

    assert "Pipeline Halted at Containment" in result.sanitized_evidence["status"]


def test_deterministic_estate_reset(fresh_demo_estate):
    """Reset restores in-memory estate to pristine baseline."""
    # Run scenario 1 to populate blobs and ledger rows
    fresh_demo_estate.run_scenario(1)
    state_after_run = fresh_demo_estate.get_estate_state()
    assert len(state_after_run["blobs"]) > 0
    assert len(state_after_run["ledger"]["rows"]) > 0

    # Reset estate
    reset_res = fresh_demo_estate.reset_estate()
    assert reset_res["status"] == "reset"

    state_after_reset = fresh_demo_estate.get_estate_state()
    # Ledger must be reset
    assert len(state_after_reset["ledger"]["rows"]) == 0
    # Pre-seeded VMs remain intact
    assert state_after_reset["virtualMachines"] == ["db-02", "web-01"]


def test_mock_safety_guard_fail_closed():
    """Setting REACT_MOCK_MODE=false raises SafetyError and blocks demo execution."""
    with patch.dict(os.environ, {"REACT_MOCK_MODE": "false"}):
        with pytest.raises(SafetyError) as exc_info:
            enforce_mock_safety()
        assert "REACT_MOCK_MODE is set to 'false'" in str(exc_info.value)


def test_data_sanitization():
    """Sanitizer scrubs SAS tokens and key material from nested objects."""
    raw_output = {
        "uploadUrl": "https://reactenclave01.blob.core.windows.net/evidence/INC-1/mem.raw?sv=2024-01-01&sig=secret123",
        "nested": {
            "key": "cmVhY3QtbW9jay1hY2NvdW50LWtleQ==",
            "url": "https://storage.azure.com/blob?sp=rw&sig=abc456",
        },
        "safeString": "web-01",
    }
    sanitized = sanitize_value(raw_output)

    assert "secret123" not in str(sanitized)
    assert "abc456" not in str(sanitized)
    assert "cmVhY3Qt" not in str(sanitized)
    assert sanitized["safeString"] == "web-01"


def test_function_app_blueprints_and_mock_routes(fresh_demo_estate):
    """Verify function_app.py exposes health, mock state, and mock reset."""
    import azure.functions as func

    from src.functions.function_app import health, mock_reset, mock_state

    req = func.HttpRequest(method="GET", url="/api/health", body=b"")
    h_resp = health(req)
    assert h_resp.status_code == 200
    assert "SIMULATED" in h_resp.get_body().decode("utf-8")

    s_resp = mock_state(req)
    assert s_resp.status_code == 200

    r_req = func.HttpRequest(method="POST", url="/api/mock/reset", body=b"")
    r_resp = mock_reset(r_req)
    assert r_resp.status_code == 200

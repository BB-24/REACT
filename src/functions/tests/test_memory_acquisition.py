"""Unit tests for Phase 2 live-response acquisition (REQ-3.3.1 - REQ-3.3.4).

The Azure side is the mock estate, so the Run Command really does reach a
simulated VM and really does produce a blob in the enclave container.
"""

import pytest
from MemoryAcquisition import (
    LINUX,
    PARAMETER_ORDER,
    WINDOWS,
    AcquisitionError,
    build_bootstrap_script,
    build_run_command,
    handle_acquisition,
    target_platform,
)
from shared import mocks
from shared.mocks import Model

WINDOWS_VM = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourceGroups/rg-victims"
    "/providers/Microsoft.Compute/virtualMachines/web-01"
)
LINUX_VM = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourceGroups/rg-victims"
    "/providers/Microsoft.Compute/virtualMachines/db-02"
)


def _vm(os_type):
    return Model(
        name="target",
        location="eastus",
        storage_profile=Model(os_disk=Model(os_type=os_type), data_disks=[]),
    )


# --- Platform resolution -----------------------------------------------------


def test_platform_is_read_from_the_os_disk():
    assert target_platform(_vm("Windows")) == WINDOWS
    assert target_platform(_vm("Linux")) == LINUX


def test_platform_override_is_honoured():
    assert target_platform(_vm("Windows"), {"platform": "Linux"}) == LINUX


def test_unknown_platform_override_is_rejected():
    with pytest.raises(AcquisitionError):
        target_platform(_vm("Windows"), {"platform": "solaris"})


def test_missing_os_type_is_rejected_rather_than_guessed():
    """Guessing wrong ships PowerShell to a Linux box and burns the one clean
    shot at volatile memory."""
    with pytest.raises(AcquisitionError):
        target_platform(_vm(None))


# --- Generated script (REQ-3.3.1, REQ-3.3.2) ---------------------------------


def test_windows_bootstrap_fetches_tool_and_script_from_the_repository():
    script = build_bootstrap_script(WINDOWS)
    assert "$ToolUrl" in script and "$ScriptUrl" in script
    assert script.count("Invoke-WebRequest") == 2


def test_windows_bootstrap_invokes_the_acquisition_script_with_the_sas():
    script = build_bootstrap_script(WINDOWS)
    assert "-SasUrl $SasUrl" in script
    assert "-WinPmemPath $toolPath" in script


def test_windows_bootstrap_cleans_up_after_itself():
    assert "Remove-Item" in build_bootstrap_script(WINDOWS)


def test_linux_bootstrap_stages_everything_in_tmpfs():
    """Nothing, not even the tool binary, may reach the target's block device."""
    script = build_bootstrap_script(LINUX)
    assert "/dev/shm" in script
    assert "--stage-dir /dev/shm" in script


def test_linux_bootstrap_reads_parameters_positionally():
    script = build_bootstrap_script(LINUX)
    for index, _name in enumerate(PARAMETER_ORDER[:4], start=1):
        assert f'"${index}"' in script


def test_unsupported_platform_is_rejected():
    with pytest.raises(AcquisitionError):
        build_bootstrap_script("solaris")


# --- Run Command assembly ----------------------------------------------------


def test_every_parameter_is_protected():
    """All five carry or accompany a SAS; none may be readable off the VM."""
    command = build_run_command(WINDOWS, "eastus", {"SasUrl": "https://x/y?sig=z"})
    assert "parameters" not in command
    assert [item["name"] for item in command["protected_parameters"]] == list(PARAMETER_ORDER)


def test_parameter_order_is_stable():
    """Linux binds these positionally, so the order is a contract."""
    command = build_run_command(LINUX, "eastus", {name: name for name in PARAMETER_ORDER})
    assert [item["value"] for item in command["protected_parameters"]] == list(PARAMETER_ORDER)


def test_missing_parameters_become_empty_strings_not_none():
    command = build_run_command(WINDOWS, "eastus", {})
    assert all(item["value"] == "" for item in command["protected_parameters"])


def test_failure_is_treated_as_deployment_failure():
    command = build_run_command(WINDOWS, "eastus", {})
    assert command["treat_failure_as_deployment_failure"] is True
    assert command["async_execution"] is False


# --- End to end through the mock estate --------------------------------------


def test_acquisition_uploads_an_image_to_the_enclave(mock_estate, post, body):
    response = handle_acquisition(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    assert response.status_code == 200
    payload = body(response)

    assert payload["status"] == "acquired"
    assert payload["platform"] == WINDOWS
    assert payload["toolBlob"] == "winpmem.exe"

    stored = mock_estate.get_blob(
        mocks.EVIDENCE_ACCOUNT, mocks.EVIDENCE_CONTAINER, payload["blobName"]
    )
    assert stored.size > 0
    assert stored.metadata["incidentid"] == "INC-1"
    assert stored.metadata["witnesssha256"] == stored.sha256()


def test_linux_target_gets_avml_and_the_shell_script(mock_estate, post, body):
    payload = body(handle_acquisition(post({"IncidentId": "INC-2", "TargetVM": LINUX_VM})))
    assert payload["platform"] == LINUX
    assert payload["toolBlob"] == "avml"
    assert payload["scriptBlob"] == "acquire-memory.sh"


def test_response_never_carries_the_sas(mock_estate, post, body):
    """The function invokes Run Command itself, so no caller needs the token.

    Only the expiry is returned, so the Logic App can reason about the window
    without ever holding the credential.
    """
    response = handle_acquisition(post({"IncidentId": "INC-3", "TargetVM": WINDOWS_VM}))
    assert b"sig=" not in response.get_body()

    payload = body(response)
    assert "uploadUrl" not in payload
    assert "uploadUrlExpiresOn" in payload


def test_run_command_record_logs_names_but_never_values(mock_estate, post):
    handle_acquisition(post({"IncidentId": "INC-4", "TargetVM": WINDOWS_VM}))
    record = mock_estate.run_commands[-1]
    assert record["parameterNames"] == sorted(PARAMETER_ORDER)
    assert "SasUrl" not in str(record.get("parameterValues", ""))


def test_custody_is_recorded_once_event_grid_delivers(mock_estate, post, body):
    payload = body(handle_acquisition(post({"IncidentId": "INC-5", "TargetVM": WINDOWS_VM})))
    assert payload["custody"] == "pending-event-grid"
    assert mock_estate.ledger_rows == []

    delivered = mocks.drain_events()
    assert delivered[0]["status"] == "recorded"
    assert delivered[0]["witnessMatch"] is True
    assert mock_estate.ledger_rows[0]["ArtifactType"] == "memory-image"


def test_missing_incident_id_returns_400(mock_estate, post, body):
    response = handle_acquisition(post({"TargetVM": WINDOWS_VM}))
    assert response.status_code == 400
    assert "IncidentId" in body(response)["error"]


def test_unresolvable_target_returns_400(mock_estate, post):
    assert handle_acquisition(post({"IncidentId": "INC-6"})).status_code == 400

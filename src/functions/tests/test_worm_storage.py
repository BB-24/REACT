"""Unit and integration tests for P2-5: Deploy WORM Blob Storage with Legal Hold.

Covers:
- REQ-3.5.1: Immutable WORM storage with 7-year time-based retention (2555 days).
- Legal hold applied and verified on all required evidence containers.
- Required containers: memory-dumps, disk-snapshots, analysis-output, reports.
- Secure storage account defaults: allowBlobPublicAccess=False, minimumTlsVersion=TLS1_2.
- Private endpoint and private DNS infrastructure declarations.
"""

import json
from pathlib import Path

import pytest
from shared.mocks import (
    ANALYSIS_OUTPUT_CONTAINER,
    DISK_SNAPSHOTS_CONTAINER,
    EVIDENCE_ACCOUNT,
    EVIDENCE_CONTAINER,
    MEMORY_DUMPS_CONTAINER,
    REPORTS_CONTAINER,
    TOOLS_CONTAINER,
    ImmutabilityError,
)

IAC_MAIN_BICEP = Path(__file__).resolve().parents[3] / "iac" / "main.bicep"
IAC_MAIN_JSON = Path(__file__).resolve().parents[3] / "iac" / "main.json"


# --- Mock Estate WORM & Legal Hold Tests -------------------------------------


def test_required_worm_containers_are_present(mock_estate):
    """Verify that all four required containers plus evidence container are provisioned."""
    expected_containers = {
        "memory-dumps",
        "disk-snapshots",
        "analysis-output",
        "reports",
        "evidence",
    }
    present = {c.name for (acc, _), c in mock_estate.containers.items() if acc == EVIDENCE_ACCOUNT}
    assert expected_containers.issubset(present)


@pytest.mark.parametrize(
    "container_name",
    [
        MEMORY_DUMPS_CONTAINER,
        DISK_SNAPSHOTS_CONTAINER,
        ANALYSIS_OUTPUT_CONTAINER,
        REPORTS_CONTAINER,
        EVIDENCE_CONTAINER,
    ],
)
def test_worm_containers_have_seven_year_retention_and_legal_hold(mock_estate, container_name):
    """Verify 7-year retention (2555 days) and active legal hold tag on each evidence container."""
    container = mock_estate.container(EVIDENCE_ACCOUNT, container_name)
    assert container.retention_days == 2555
    assert container.legal_hold is True
    assert "react-active-investigation" in container.legal_hold_tags
    assert container.policy_locked is True


@pytest.mark.parametrize(
    "container_name",
    [
        MEMORY_DUMPS_CONTAINER,
        DISK_SNAPSHOTS_CONTAINER,
        ANALYSIS_OUTPUT_CONTAINER,
        REPORTS_CONTAINER,
        EVIDENCE_CONTAINER,
    ],
)
def test_worm_containers_prevent_overwrite_under_legal_hold_and_retention(
    mock_estate, container_name
):
    """An attacker or compromised component cannot overwrite evidence under WORM/Legal Hold."""
    blob_name = f"INC-2026-TEST/{container_name}-artifact.raw"
    mock_estate.put_blob(EVIDENCE_ACCOUNT, container_name, blob_name, b"initial-authentic-data")

    with pytest.raises(ImmutabilityError) as exc_info:
        mock_estate.put_blob(EVIDENCE_ACCOUNT, container_name, blob_name, b"tampered-data")

    assert "legal hold" in str(exc_info.value).lower() or "retention" in str(exc_info.value).lower()


@pytest.mark.parametrize(
    "container_name",
    [
        MEMORY_DUMPS_CONTAINER,
        DISK_SNAPSHOTS_CONTAINER,
        ANALYSIS_OUTPUT_CONTAINER,
        REPORTS_CONTAINER,
        EVIDENCE_CONTAINER,
    ],
)
def test_worm_containers_prevent_delete_under_legal_hold_and_retention(mock_estate, container_name):
    """An attacker or compromised component cannot delete evidence under WORM/Legal Hold."""
    blob_name = f"INC-2026-TEST/{container_name}-artifact.raw"
    mock_estate.put_blob(EVIDENCE_ACCOUNT, container_name, blob_name, b"initial-authentic-data")

    with pytest.raises(ImmutabilityError) as exc_info:
        mock_estate.delete_blob(EVIDENCE_ACCOUNT, container_name, blob_name)

    assert "legal hold" in str(exc_info.value).lower() or "retention" in str(exc_info.value).lower()


def test_tool_repository_remains_mutable(mock_estate):
    """Verify tool repository does not block updates as tool binaries rotate."""
    mock_estate.put_blob(EVIDENCE_ACCOUNT, TOOLS_CONTAINER, "winpmem.exe", b"v2")
    assert mock_estate.get_blob(EVIDENCE_ACCOUNT, TOOLS_CONTAINER, "winpmem.exe").data == b"v2"


# --- Infrastructure Bicep / ARM Template Validation --------------------------


def test_iac_bicep_exists():
    assert IAC_MAIN_BICEP.exists(), "iac/main.bicep must exist"


def test_iac_bicep_storage_account_security_configuration():
    """Verify security configurations on the evidence storage account in Bicep."""
    content = IAC_MAIN_BICEP.read_text(encoding="utf-8")

    assert "allowBlobPublicAccess: false" in content
    assert "minimumTlsVersion: 'TLS1_2'" in content
    assert "supportsHttpsTrafficOnly: true" in content
    assert "publicNetworkAccess: storagePublicNetworkAccess" in content
    assert "immutableStorageWithVersioning:" in content


def test_iac_bicep_provisions_all_required_containers():
    """Verify all four required containers are declared in Bicep."""
    content = IAC_MAIN_BICEP.read_text(encoding="utf-8")

    for container in ["memory-dumps", "disk-snapshots", "analysis-output", "reports"]:
        assert f"name: '{container}'" in content, f"Container {container} not found in main.bicep"


def test_iac_bicep_immutability_and_legal_hold_verification():
    """Verify retention policy days default to 2555 (7 years) and legal hold verification check exists."""
    content = IAC_MAIN_BICEP.read_text(encoding="utf-8")

    # 7-year retention policy parameter default
    assert "param retentionDays int = 2555" in content

    # Legal hold script includes verification check
    assert "hasLegalHold" in content
    assert "ERROR: Legal hold verification failed" in content


def test_iac_bicep_private_endpoints_and_dns():
    """Verify Private Endpoint, Subnet, and Private DNS resources in Bicep."""
    content = IAC_MAIN_BICEP.read_text(encoding="utf-8")

    assert "Microsoft.Network/privateEndpoints" in content
    assert "Microsoft.Network/privateDnsZones" in content
    assert "privatelink.blob" in content
    assert "Forensic-Enclave-Subnet" in content
    assert "storagePrivateEndpoint" in content


def test_iac_arm_template_json_contains_worm_and_private_endpoints():
    """Verify compiled main.json contains the expected WORM and Private Endpoint resources."""
    assert IAC_MAIN_JSON.exists(), "iac/main.json must exist"
    data = json.loads(IAC_MAIN_JSON.read_text(encoding="utf-8"))

    resources = data.get("resources", [])
    resource_types = [r.get("type") for r in resources]

    assert "Microsoft.Storage/storageAccounts" in resource_types
    assert "Microsoft.Network/privateEndpoints" in resource_types
    assert "Microsoft.Network/privateDnsZones" in resource_types

    # Find storage account and verify security defaults
    storage_account = next(
        r for r in resources if r.get("type") == "Microsoft.Storage/storageAccounts"
    )
    props = storage_account.get("properties", {})
    assert props.get("allowBlobPublicAccess") is False
    assert props.get("minimumTlsVersion") == "TLS1_2"
    assert props.get("supportsHttpsTrafficOnly") is True
    assert props.get("immutableStorageWithVersioning", {}).get("enabled") is True

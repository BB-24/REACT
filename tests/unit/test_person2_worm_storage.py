"""Unit tests for Person 2: Deploy WORM Blob Storage with Legal Hold (Issue #28 / P2-5).

Requirements covered:
- REQ-3.5.1: WORM Blob Storage with 7-year time-based retention policy (2555 days).
- Legal hold applied and verified on all evidence containers.
- Required containers: memory-dumps, disk-snapshots, analysis-output, reports.
- Secure storage account: allowBlobPublicAccess=False, minimumTlsVersion=TLS1_2.
- Private endpoints and private DNS for forensic enclave storage.
"""

import json
import unittest
from pathlib import Path

from src.functions.shared import mocks
from src.functions.shared.mocks import (
    ANALYSIS_OUTPUT_CONTAINER,
    DISK_SNAPSHOTS_CONTAINER,
    EVIDENCE_ACCOUNT,
    EVIDENCE_CONTAINER,
    MEMORY_DUMPS_CONTAINER,
    REPORTS_CONTAINER,
    TOOLS_CONTAINER,
    ImmutabilityError,
)

IAC_BICEP_PATH = Path(__file__).resolve().parents[2] / "iac" / "main.bicep"
IAC_JSON_PATH = Path(__file__).resolve().parents[2] / "iac" / "main.json"


class TestPerson2WormStorage(unittest.TestCase):
    """Test suite for P2-5 WORM storage, legal hold, and network isolation."""

    def setUp(self):
        mocks.reset()

    def test_task_2_5_all_required_containers_provisioned(self):
        """P2-5 Acceptance Criteria: memory-dumps, disk-snapshots, analysis-output, reports are provisioned."""
        estate = mocks.world()
        required = [
            "memory-dumps",
            "disk-snapshots",
            "analysis-output",
            "reports",
            "evidence",
        ]
        for name in required:
            self.assertIn(
                (EVIDENCE_ACCOUNT, name),
                estate.containers,
                f"Container '{name}' was not provisioned in evidence account.",
            )

    def test_task_2_5_seven_year_retention_and_legal_hold_on_containers(self):
        """REQ-3.5.1: 7-year (2555 days) immutability and legal hold active on all evidence containers."""
        estate = mocks.world()
        evidence_containers = [
            MEMORY_DUMPS_CONTAINER,
            DISK_SNAPSHOTS_CONTAINER,
            ANALYSIS_OUTPUT_CONTAINER,
            REPORTS_CONTAINER,
            EVIDENCE_CONTAINER,
        ]
        for name in evidence_containers:
            container = estate.container(EVIDENCE_ACCOUNT, name)
            self.assertEqual(container.retention_days, 2555)
            self.assertTrue(container.legal_hold)
            self.assertIn("react-active-investigation", container.legal_hold_tags)
            self.assertTrue(container.policy_locked)

    def test_task_2_5_immutability_blocks_overwriting_and_deleting(self):
        """REQ-3.5.1: Immutability / legal hold blocks any modification or deletion of evidence."""
        estate = mocks.world()
        for name in [MEMORY_DUMPS_CONTAINER, DISK_SNAPSHOTS_CONTAINER, ANALYSIS_OUTPUT_CONTAINER, REPORTS_CONTAINER]:
            blob_path = f"INC-2026-P2-05/{name}/test-data.bin"
            estate.put_blob(EVIDENCE_ACCOUNT, name, blob_path, b"authentic-evidence-content")

            # Overwrite must raise ImmutabilityError
            with self.assertRaises(ImmutabilityError):
                estate.put_blob(EVIDENCE_ACCOUNT, name, blob_path, b"tampered-evidence-content")

            # Delete must raise ImmutabilityError
            with self.assertRaises(ImmutabilityError):
                estate.delete_blob(EVIDENCE_ACCOUNT, name, blob_path)

    def test_task_2_5_tool_repository_remains_mutable(self):
        """Tool repository is explicitly mutable so tool binaries can be updated."""
        estate = mocks.world()
        estate.put_blob(EVIDENCE_ACCOUNT, TOOLS_CONTAINER, "avml", b"avml-v2.0")
        self.assertEqual(
            estate.get_blob(EVIDENCE_ACCOUNT, TOOLS_CONTAINER, "avml").data,
            b"avml-v2.0",
        )

    def test_task_2_5_bicep_storage_account_security_and_containers(self):
        """Bicep infrastructure satisfies all secure storage account and container requirements."""
        self.assertTrue(IAC_BICEP_PATH.exists())
        bicep_text = IAC_BICEP_PATH.read_text(encoding="utf-8")

        # Security defaults
        self.assertIn("allowBlobPublicAccess: false", bicep_text)
        self.assertIn("minimumTlsVersion: 'TLS1_2'", bicep_text)
        self.assertIn("supportsHttpsTrafficOnly: true", bicep_text)
        self.assertIn("publicNetworkAccess: storagePublicNetworkAccess", bicep_text)
        self.assertIn("param storagePublicNetworkAccess string = 'Disabled'", bicep_text)

        # 7-year retention
        self.assertIn("param retentionDays int = 2555", bicep_text)

        # Containers
        for c in ["memory-dumps", "disk-snapshots", "analysis-output", "reports"]:
            self.assertIn(f"name: '{c}'", bicep_text)

        # Legal hold verification
        self.assertIn("hasLegalHold", bicep_text)
        self.assertIn("ERROR: Legal hold verification failed", bicep_text)

        # Private endpoint and DNS
        self.assertIn("Microsoft.Network/privateEndpoints", bicep_text)
        self.assertIn("Microsoft.Network/privateDnsZones", bicep_text)
        self.assertIn("privatelink.blob", bicep_text)
        self.assertIn("storagePrivateEndpoint", bicep_text)

    def test_task_2_5_compiled_arm_template_validity(self):
        """Compiled ARM template iac/main.json reflects P2-5 resources correctly."""
        self.assertTrue(IAC_JSON_PATH.exists())
        arm_data = json.loads(IAC_JSON_PATH.read_text(encoding="utf-8"))

        resource_types = [r.get("type") for r in arm_data.get("resources", [])]
        self.assertIn("Microsoft.Storage/storageAccounts", resource_types)
        self.assertIn("Microsoft.Network/privateEndpoints", resource_types)
        self.assertIn("Microsoft.Network/privateDnsZones", resource_types)

        # Verify storage account parameters
        storage_account = next(
            r for r in arm_data["resources"] if r.get("type") == "Microsoft.Storage/storageAccounts"
        )
        props = storage_account.get("properties", {})
        self.assertFalse(props.get("allowBlobPublicAccess"))
        self.assertEqual(props.get("minimumTlsVersion"), "TLS1_2")
        self.assertTrue(props.get("supportsHttpsTrafficOnly"))


if __name__ == "__main__":
    unittest.main()

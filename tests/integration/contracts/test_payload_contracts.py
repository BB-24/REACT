"""Contract integration tests for incident payloads across P1, P2, and P3."""

import json
import re
import unittest
from pathlib import Path

RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/(?P<subscription>[0-9a-fA-F-]{36})/resourceGroups/(?P<resource_group>[^/]+)/"
    r"providers/Microsoft\.Compute/virtualMachines/(?P<name>[^/]+)$"
)
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class TestPayloadContracts(unittest.TestCase):
    """Verifies that payload contracts adhere to the JSON schema in docs/payload-contract.json."""

    def setUp(self):
        contract_path = Path(__file__).resolve().parents[3] / "docs" / "payload-contract.json"
        with open(contract_path, encoding="utf-8") as f:
            self.schema = json.load(f)

        self.valid_sentinel_payload = {
            "IncidentID": "INC-2026-0001",
            "TargetVM": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Compute/virtualMachines/suspicious-vm-01",
            "IPAddress": "203.0.113.25",
            "SubscriptionID": "11111111-1111-1111-1111-111111111111",
            "IncidentSeverity": "High",
            "ResourceGroupName": "Compromised-Environment-RG",
        }

    def _validate_contract(self, payload: dict) -> list[str]:
        """Validate payload against schema rules without third-party dependencies."""
        errors = []
        required_fields = self.schema.get("required", [])
        for field in required_fields:
            if field not in payload:
                errors.append(f"Missing required field: {field}")
            elif not isinstance(payload[field], str) or not payload[field].strip():
                errors.append(f"Field {field} must be a non-empty string")

        if "TargetVM" in payload:
            if not RESOURCE_ID_PATTERN.fullmatch(payload["TargetVM"]):
                errors.append(
                    "TargetVM is not a valid Microsoft.Compute/virtualMachines resource ID"
                )

        if "SubscriptionID" in payload:
            if not UUID_PATTERN.fullmatch(payload["SubscriptionID"]):
                errors.append("SubscriptionID is not a valid UUID")

        if "IncidentSeverity" in payload:
            allowed = self.schema["properties"]["IncidentSeverity"]["enum"]
            if payload["IncidentSeverity"] not in allowed:
                errors.append(f"IncidentSeverity must be one of {allowed}")

        # Consistency check between TargetVM and SubscriptionID
        if "TargetVM" in payload and "SubscriptionID" in payload:
            match = RESOURCE_ID_PATTERN.fullmatch(payload["TargetVM"])
            if match and match.group("subscription").lower() != payload["SubscriptionID"].lower():
                errors.append("TargetVM subscription does not match SubscriptionID")

        return errors

    def test_valid_high_severity_payload(self):
        """Test that a standard High severity Sentinel payload satisfies contract."""
        errors = self._validate_contract(self.valid_sentinel_payload)
        self.assertEqual(errors, [])

    def test_valid_critical_severity_payload(self):
        """Test that Critical severity payload satisfies contract."""
        payload = dict(self.valid_sentinel_payload)
        payload["IncidentSeverity"] = "Critical"
        errors = self._validate_contract(payload)
        self.assertEqual(errors, [])

    def test_missing_required_fields_rejected(self):
        """Test that omitting required fields produces contract errors."""
        for field in ["IncidentID", "TargetVM", "IPAddress", "SubscriptionID", "IncidentSeverity"]:
            payload = dict(self.valid_sentinel_payload)
            del payload[field]
            errors = self._validate_contract(payload)
            self.assertTrue(any(f"Missing required field: {field}" in e for e in errors))

    def test_invalid_subscription_uuid_rejected(self):
        """Test that a non-UUID SubscriptionID is caught."""
        payload = dict(self.valid_sentinel_payload)
        payload["SubscriptionID"] = "invalid-subscription-id"
        errors = self._validate_contract(payload)
        self.assertIn("SubscriptionID is not a valid UUID", errors)

    def test_invalid_target_vm_format_rejected(self):
        """Test that an ill-formed TargetVM ARM ID is caught."""
        payload = dict(self.valid_sentinel_payload)
        payload["TargetVM"] = "/subscriptions/not/a/valid/vm/id"
        errors = self._validate_contract(payload)
        self.assertIn(
            "TargetVM is not a valid Microsoft.Compute/virtualMachines resource ID", errors
        )

    def test_subscription_mismatch_rejected(self):
        """Test that a mismatch between TargetVM URI and SubscriptionID fails."""
        payload = dict(self.valid_sentinel_payload)
        payload["SubscriptionID"] = "22222222-2222-2222-2222-222222222222"
        errors = self._validate_contract(payload)
        self.assertIn("TargetVM subscription does not match SubscriptionID", errors)

    def test_p1_to_p2_acquisition_contract_payload(self):
        """Validate structure of payload generated by P1 for P2 Start_Acquisition_Workflow."""
        incident_id = self.valid_sentinel_payload["IncidentID"]
        target_vm = self.valid_sentinel_payload["TargetVM"]
        vm_name = target_vm.split("/")[-1]
        uri_template = "https://forensicevidence.blob.core.windows.net/evidence/{0}/{1}.raw"
        evidence_uri = uri_template.format(incident_id, vm_name)

        p1_to_p2_payload = {
            "IncidentID": incident_id,
            "TargetVM": target_vm,
            "EvidenceBlobUri": evidence_uri,
        }

        self.assertEqual(p1_to_p2_payload["IncidentID"], "INC-2026-0001")
        self.assertTrue(
            p1_to_p2_payload["EvidenceBlobUri"].endswith("INC-2026-0001/suspicious-vm-01.raw")
        )

    def test_p1_to_p3_analysis_contract_payload(self):
        """Validate structure of payload forwarded by P1 to P3 Start_Analysis_Pipeline."""
        incident_id = self.valid_sentinel_payload["IncidentID"]
        target_vm = self.valid_sentinel_payload["TargetVM"]
        vm_name = target_vm.split("/")[-1]
        uri_template = "https://forensicevidence.blob.core.windows.net/evidence/{0}/{1}.raw"
        evidence_uri = uri_template.format(incident_id, vm_name)

        containment_response = {
            "status": "Contained",
            "IncidentID": incident_id,
            "TargetVM": target_vm,
            "NetworkInterface": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/networkInterfaces/suspicious-vm-01VMNic",
            "IsolationNSG": "Forensic-Isolation-NSG-INC-2026-0001",
            "PreviousNSGId": None,
            "CriticalInfrastructureBypass": False,
        }

        p1_to_p3_payload = {
            "IncidentID": incident_id,
            "TargetVM": target_vm,
            "IPAddress": self.valid_sentinel_payload["IPAddress"],
            "SubscriptionID": self.valid_sentinel_payload["SubscriptionID"],
            "IncidentSeverity": self.valid_sentinel_payload["IncidentSeverity"],
            "EvidenceBlobUri": evidence_uri,
            "ContainmentDetails": containment_response,
            "PipelineStatus": "AcquisitionCompleted",
            "Timestamp": "2026-10-08T00:00:00Z",
        }

        self.assertEqual(p1_to_p3_payload["PipelineStatus"], "AcquisitionCompleted")
        self.assertEqual(p1_to_p3_payload["ContainmentDetails"]["status"], "Contained")
        self.assertIn("EvidenceBlobUri", p1_to_p3_payload)


if __name__ == "__main__":
    unittest.main()

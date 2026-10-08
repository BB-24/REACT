"""Unit tests for Person 1: Cloud Orchestration & Infrastructure Security.

Covers:
- REQ-3.1 (Triggering & Ingestion, Webhook payload parsing)
- REQ-3.2 (Network Containment, Isolation NSG, Service Endpoint exception, NIC Swap, Tag Bypass)
- Logic App Playbook parameterization and workflow routing
"""

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import azure.functions as func

from src.functions.NetworkContainment import (
    ValidationError,
    _nsg_name,
    _parse_incident,
    _primary_nic_id,
    _private_endpoint_prefixes,
    _resource_parts,
    _rule_payload,
)
from src.functions.NetworkContainment import (
    main as containment_main,
)


class TestPerson1Orchestration(unittest.TestCase):
    """Unit tests for Person 1 tasks (Webhook ingestion, containment logic, workflow definitions)."""

    def setUp(self):
        self.sample_payload = {
            "IncidentID": "INC-2026-P1-001",
            "TargetVM": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Compute/virtualMachines/victim-srv-01",
            "IPAddress": "192.168.10.50",
            "SubscriptionID": "11111111-1111-1111-1111-111111111111",
            "IncidentSeverity": "High",
            "ResourceGroupName": "Compromised-Environment-RG",
        }

    def _make_req(self, payload: dict) -> func.HttpRequest:
        return func.HttpRequest(
            method="POST",
            url="/api/NetworkContainment",
            body=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

    # --------------------------------------------------------------------------
    # Task 1.1: Webhook Trigger & Ingestion Parsing (REQ-3.1)
    # --------------------------------------------------------------------------

    def test_task_1_1_payload_parsing_extracts_entities(self):
        """REQ-3.1.2/3: Ingestion logic parses IncidentID, TargetVM, IPAddress, SubscriptionID."""
        req = self._make_req(self.sample_payload)
        incident = _parse_incident(req)

        self.assertEqual(incident.incident_id, "INC-2026-P1-001")
        self.assertEqual(incident.target_vm, self.sample_payload["TargetVM"])
        self.assertEqual(incident.ip_address, "192.168.10.50")
        self.assertEqual(incident.subscription_id, "11111111-1111-1111-1111-111111111111")
        self.assertEqual(incident.severity, "High")
        self.assertEqual(incident.resource_group, "Compromised-Environment-RG")

    def test_task_1_1_non_json_body_raises_validation_error(self):
        """REQ-3.1: Malformed JSON body is rejected with 400 ValidationError."""
        bad_req = func.HttpRequest(
            method="POST",
            url="/api/NetworkContainment",
            body=b"INVALID_JSON_DATA",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(ValidationError) as ctx:
            _parse_incident(bad_req)
        self.assertIn("valid JSON", str(ctx.exception))

    def test_task_1_1_missing_required_fields_rejected(self):
        """REQ-3.1: Missing required fields in webhook payload are rejected."""
        required_fields = [
            "IncidentID",
            "TargetVM",
            "IPAddress",
            "SubscriptionID",
            "IncidentSeverity",
        ]
        for field in required_fields:
            payload = dict(self.sample_payload)
            del payload[field]
            with self.assertRaises(ValidationError):
                _parse_incident(self._make_req(payload))

    def test_task_1_1_severity_filtering(self):
        """REQ-3.1: NetworkContainment only accepts High or Critical severity."""
        for disallowed in ["Low", "Medium", "Informational"]:
            payload = dict(self.sample_payload)
            payload["IncidentSeverity"] = disallowed
            with self.assertRaises(ValidationError) as ctx:
                _parse_incident(self._make_req(payload))
            self.assertIn("IncidentSeverity", str(ctx.exception))

    def test_task_1_1_logic_app_workflow_json_schema(self):
        """Verify workflow.json contains valid Trigger and Action definitions."""
        workflow_path = Path(__file__).resolve().parents[2] / "src" / "logic-apps" / "workflow.json"
        with open(workflow_path, encoding="utf-8") as f:
            workflow = json.load(f)

        self.assertIn("Incident_Webhook", workflow["triggers"])
        actions = workflow["actions"]
        self.assertIn("Parse_Incident", actions)
        self.assertIn("High_Or_Critical_Severity_Only", actions)

    # --------------------------------------------------------------------------
    # Task 1.2: Network Containment Azure Function (REQ-3.2)
    # --------------------------------------------------------------------------

    def test_task_1_2_nsg_naming_sanitization_and_length(self):
        """REQ-3.2.1: NSG name is sanitized and does not exceed 80 characters."""
        long_incident_id = "INC-" + "A" * 100 + "@#$%^&*"
        name = _nsg_name(long_incident_id)
        self.assertTrue(name.startswith("Forensic-Isolation-NSG-"))
        self.assertLessEqual(len(name), 80)
        self.assertNotIn("@", name)
        self.assertNotIn("$", name)

    def test_task_1_2_isolation_nsg_rule_payloads(self):
        """REQ-3.2.2/3: Rule definitions enforce Allow Storage and Deny All Inbound/Outbound."""
        storage_rule = _rule_payload(
            "Allow-Azure-Storage-Egress", 100, "Outbound", "Allow", "Storage"
        )
        self.assertEqual(storage_rule["priority"], 100)
        self.assertEqual(storage_rule["access"], "Allow")
        self.assertEqual(storage_rule["destination_address_prefix"], "Storage")

        deny_in = _rule_payload("Deny-All-Inbound", 4095, "Inbound", "Deny", "*")
        self.assertEqual(deny_in["priority"], 4095)
        self.assertEqual(deny_in["access"], "Deny")
        self.assertEqual(deny_in["direction"], "Inbound")

        deny_out = _rule_payload("Deny-All-Outbound", 4096, "Outbound", "Deny", "*")
        self.assertEqual(deny_out["priority"], 4096)
        self.assertEqual(deny_out["access"], "Deny")
        self.assertEqual(deny_out["direction"], "Outbound")

    def test_task_1_2_private_endpoint_prefixes_parsing(self):
        """REQ-3.2.3: Parses comma-separated private endpoint CIDR prefixes from environment."""
        with patch.dict(
            "os.environ",
            {"EVIDENCE_STORAGE_PRIVATE_ENDPOINT_PREFIXES": "10.0.1.0/24, 10.0.2.15/32"},
        ):
            prefixes = _private_endpoint_prefixes()
            self.assertEqual(prefixes, ["10.0.1.0/24", "10.0.2.15/32"])

    def test_task_1_2_primary_nic_resolution(self):
        """REQ-3.2.4: Identifies primary NIC from VM network profile."""
        fake_vm = MagicMock()
        nic1 = MagicMock(primary=False, id="/sub/rg/nic1")
        nic2 = MagicMock(primary=True, id="/sub/rg/nic2")
        fake_vm.network_profile.network_interfaces = [nic1, nic2]

        resolved_id = _primary_nic_id(fake_vm)
        self.assertEqual(resolved_id, "/sub/rg/nic2")

    def test_task_1_2_resource_parts_extraction(self):
        """Extracts subscription, resource group, and resource name from full ARM ID."""
        arm_id = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Test-RG/providers/Microsoft.Compute/virtualMachines/vm-01"
        sub, rg, name = _resource_parts(arm_id, "providers/Microsoft.Compute/virtualMachines")
        self.assertEqual(sub, "11111111-1111-1111-1111-111111111111")
        self.assertEqual(rg, "Test-RG")
        self.assertEqual(name, "vm-01")

    @patch("src.functions.NetworkContainment.DefaultAzureCredential")
    @patch("src.functions.NetworkContainment.NetworkManagementClient")
    @patch("azure.mgmt.compute.ComputeManagementClient")
    def test_task_1_2_critical_infrastructure_tag_bypass_execution(
        self, mock_compute, mock_network, mock_cred
    ):
        """VM with Critical-Infrastructure tag returns Bypassed status without changing NSG."""
        fake_vm = MagicMock()
        fake_vm.tags = {"Critical-Infrastructure": "true"}
        fake_vm.network_profile.network_interfaces = [
            MagicMock(
                primary=True,
                id="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/networkInterfaces/test-nic",
            )
        ]
        mock_compute.return_value.virtual_machines.get.return_value = fake_vm

        resp = containment_main(self._make_req(self.sample_payload))
        self.assertEqual(resp.status_code, 200)

        data = json.loads(resp.body)
        self.assertEqual(data["status"], "Bypassed")
        self.assertIn("Critical-Infrastructure", data["Reason"])
        mock_network.return_value.network_security_groups.begin_create_or_update.assert_not_called()

    # --------------------------------------------------------------------------
    # Task 1.3: Workflow State Management & Handoff URLs
    # --------------------------------------------------------------------------

    def test_task_1_3_arm_template_parameters_integrity(self):
        """Verify incident-response-playbook.json includes all required handoff URLs."""
        playbook_path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "logic-apps"
            / "incident-response-playbook.json"
        )
        with open(playbook_path, encoding="utf-8") as f:
            playbook = json.load(f)

        params = playbook["parameters"]
        self.assertIn("containmentFunctionUrl", params)
        self.assertIn("acquisitionArmRequestUrl", params)
        self.assertIn("acquisitionStatusUrl", params)
        self.assertIn("analysisPipelineUrl", params)
        self.assertIn("evidenceBlobUriTemplate", params)


if __name__ == "__main__":
    unittest.main()

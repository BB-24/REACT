"""Unit tests for NetworkContainment Azure Function logic."""

import json
import unittest
import unittest.mock
from unittest.mock import MagicMock

import azure.functions as func

from src.functions.NetworkContainment import (
    ValidationError,
    _nsg_name,
    _parse_incident,
    _rule_payload,
)


class TestNetworkContainment(unittest.TestCase):
    def setUp(self):
        self.valid_payload = {
            "IncidentID": "INC-2026-0001",
            "TargetVM": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Compute/virtualMachines/test-vm",
            "IPAddress": "203.0.113.25",
            "SubscriptionID": "11111111-1111-1111-1111-111111111111",
            "IncidentSeverity": "High",
            "ResourceGroupName": "Compromised-Environment-RG",
        }

    def _make_request(self, body: dict) -> func.HttpRequest:
        return func.HttpRequest(
            method="POST",
            url="/api/NetworkContainment",
            body=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

    def test_parse_incident_success(self):
        req = self._make_request(self.valid_payload)
        incident = _parse_incident(req)
        self.assertEqual(incident.incident_id, "INC-2026-0001")
        self.assertEqual(incident.subscription_id, "11111111-1111-1111-1111-111111111111")
        self.assertEqual(incident.severity, "High")
        self.assertEqual(incident.resource_group, "Compromised-Environment-RG")

    def test_parse_incident_critical_severity_allowed(self):
        payload = dict(self.valid_payload)
        payload["IncidentSeverity"] = "Critical"
        req = self._make_request(payload)
        incident = _parse_incident(req)
        self.assertEqual(incident.severity, "Critical")

    def test_parse_incident_low_severity_rejected(self):
        payload = dict(self.valid_payload)
        payload["IncidentSeverity"] = "Low"
        req = self._make_request(payload)
        with self.assertRaises(ValidationError) as ctx:
            _parse_incident(req)
        self.assertIn("IncidentSeverity", str(ctx.exception))

    def test_parse_incident_mismatched_subscription(self):
        payload = dict(self.valid_payload)
        payload["SubscriptionID"] = "22222222-2222-2222-2222-222222222222"
        req = self._make_request(payload)
        with self.assertRaises(ValidationError) as ctx:
            _parse_incident(req)
        self.assertIn("SubscriptionID does not match", str(ctx.exception))

    def test_parse_incident_mismatched_resource_group(self):
        payload = dict(self.valid_payload)
        payload["ResourceGroupName"] = "Wrong-RG"
        req = self._make_request(payload)
        with self.assertRaises(ValidationError) as ctx:
            _parse_incident(req)
        self.assertIn("ResourceGroupName does not match", str(ctx.exception))

    def test_nsg_naming_and_sanitization(self):
        name = _nsg_name("INC#2026@TEST!01")
        self.assertTrue(name.startswith("Forensic-Isolation-NSG-"))
        self.assertNotIn("#", name)
        self.assertNotIn("@", name)
        self.assertNotIn("!", name)
        self.assertLessEqual(len(name), 80)

    def test_containment_rejects_resource_group_outside_configured_scope(self):
        from src.functions.NetworkContainment import main

        with (
            unittest.mock.patch.dict(
                "os.environ",
                {
                    "AZURE_SUBSCRIPTION_ID": "11111111-1111-1111-1111-111111111111",
                    "TARGET_RESOURCE_GROUP": "approved-demo-rg",
                },
            ),
            unittest.mock.patch(
                "src.functions.NetworkContainment.clients.credential"
            ) as credential,
        ):
            response = main(self._make_request(self.valid_payload))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            json.loads(response.get_body())["error"],
            "Target VM is outside the configured resource-group boundary.",
        )
        credential.assert_not_called()

    def test_rule_payload_structure(self):
        allow_rule = _rule_payload("Allow-Storage", 100, "Outbound", "Allow", "Storage")
        self.assertEqual(allow_rule["priority"], 100)
        self.assertEqual(allow_rule["access"], "Allow")
        self.assertEqual(allow_rule["destination_address_prefix"], "Storage")

        deny_rule = _rule_payload("Deny-All-Inbound", 4095, "Inbound", "Deny", "*")
        self.assertEqual(deny_rule["priority"], 4095)
        self.assertEqual(deny_rule["access"], "Deny")
        self.assertEqual(deny_rule["direction"], "Inbound")

    # ------------------------------------------------------------------
    # Critical-infrastructure tag bypass (TDD – feature not yet in main)
    # ------------------------------------------------------------------

    @unittest.mock.patch("src.functions.NetworkContainment.clients.credential")
    @unittest.mock.patch("src.functions.NetworkContainment.clients.network_client")
    @unittest.mock.patch("src.functions.NetworkContainment.clients.compute_client")
    def test_critical_infrastructure_tag_bypass(
        self, mock_compute_cls, mock_network_cls, mock_credential_cls
    ):
        """VM tagged CriticalInfrastructure should be bypassed, not contained."""
        from src.functions.NetworkContainment import main

        # Build a fake VM object whose tags include the critical marker.
        fake_vm = MagicMock()
        fake_vm.tags = {"critical-infrastructure": "TRUE"}
        fake_vm.network_profile.network_interfaces = [
            MagicMock(
                primary=True,
                id="/subscriptions/11111111-1111-1111-1111-111111111111/"
                "resourceGroups/Compromised-Environment-RG/"
                "providers/Microsoft.Network/networkInterfaces/test-nic",
            )
        ]
        mock_compute_cls.return_value.virtual_machines.get.return_value = fake_vm

        req = self._make_request(self.valid_payload)
        resp = main(req)
        body = json.loads(resp.get_body())

        self.assertEqual(body["status"], "Bypassed")
        self.assertIn("Critical-Infrastructure", body.get("Reason", ""))
        # NSG should *not* have been created.
        mock_network_cls.return_value.network_security_groups.begin_create_or_update.assert_not_called()

    @unittest.mock.patch("src.functions.NetworkContainment.clients.credential")
    @unittest.mock.patch("src.functions.NetworkContainment.clients.network_client")
    @unittest.mock.patch("src.functions.NetworkContainment.clients.compute_client")
    def test_no_critical_infrastructure_tag_proceeds(
        self, mock_compute_cls, mock_network_cls, mock_credential_cls
    ):
        """VM without CriticalInfrastructure tag should be contained normally."""
        from src.functions.NetworkContainment import main

        # Build a fake VM *without* the critical-infra tag.
        fake_vm = MagicMock()
        fake_vm.tags = {"Environment": "Production"}
        fake_vm.location = "eastus"
        fake_vm.network_profile.network_interfaces = [
            MagicMock(
                primary=True,
                id="/subscriptions/11111111-1111-1111-1111-111111111111/"
                "resourceGroups/Compromised-Environment-RG/"
                "providers/Microsoft.Network/networkInterfaces/test-nic",
            ),
            MagicMock(
                primary=False,
                id="/subscriptions/11111111-1111-1111-1111-111111111111/"
                "resourceGroups/Compromised-Environment-RG/"
                "providers/Microsoft.Network/networkInterfaces/secondary-nic",
            ),
        ]
        mock_compute_cls.return_value.virtual_machines.get.return_value = fake_vm

        original_primary_nsg = (
            "/subscriptions/11111111-1111-1111-1111-111111111111/"
            "resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/networkSecurityGroups/original-primary"
        )
        primary_nic = MagicMock()
        primary_nic.network_security_group = MagicMock(id=original_primary_nsg)
        secondary_nic = MagicMock()
        secondary_nic.network_security_group = None
        network_client = mock_network_cls.return_value
        network_client.network_interfaces.get.side_effect = [primary_nic, secondary_nic]
        network_client.network_security_groups.get.return_value.id = (
            "/subscriptions/11111111-1111-1111-1111-111111111111/"
            "resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/"
            "networkSecurityGroups/Forensic-Isolation-NSG-INC-2026-0001"
        )

        req = self._make_request(self.valid_payload)
        resp = main(req)
        body = json.loads(resp.get_body())

        self.assertEqual(body["status"], "Contained")
        self.assertFalse(body["CriticalInfrastructureBypass"])
        self.assertEqual(body["PreviousNSGId"], original_primary_nsg)
        self.assertEqual(len(body["NICContainment"]), 2)
        # NSG *should* have been created and attached.
        network_client.network_security_groups.begin_create_or_update.assert_called_once()
        self.assertEqual(network_client.network_interfaces.begin_create_or_update.call_count, 2)
        created_nsg = network_client.network_security_groups.begin_create_or_update.call_args.args[
            2
        ]
        rule_names = {rule["name"] for rule in created_nsg["security_rules"]}
        self.assertIn("Allow-Evidence-Storage-Outbound", rule_names)
        self.assertIn("Deny-All-Inbound", rule_names)
        self.assertIn("Deny-All-Outbound", rule_names)


if __name__ == "__main__":
    unittest.main()

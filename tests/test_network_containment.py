"""Unit tests for NetworkContainment Azure Function logic."""

import importlib.util
import json
import sys
import unittest
import unittest.mock
from types import ModuleType
from unittest.mock import MagicMock


def _azure_sdk_missing() -> bool:
    """True when the real azure-functions SDK is not importable here.

    ``sys.modules`` is empty before anything imports azure, so checking it
    alone would let these stubs shadow an installed SDK and break submodule
    imports such as ``azure.mgmt.network.models``.
    """
    try:
        return importlib.util.find_spec("azure.functions") is None
    except ImportError:
        return True


# Stub azure modules only if the real SDK is not installed in this environment.
if _azure_sdk_missing():
    azure_mod = ModuleType("azure")
    func_mod = ModuleType("azure.functions")

    class FakeHttpRequest:
        def __init__(self, method: str, url: str, body: bytes, headers: dict):
            self.method = method
            self.url = url
            self._body = body
            self.headers = headers

        def get_json(self):
            return json.loads(self._body.decode("utf-8"))

    class FakeHttpResponse:
        def __init__(
            self, body: str, *, status_code: int = 200, mimetype: str = "application/json"
        ):
            self.body = body
            self.status_code = status_code
            self.mimetype = mimetype

        def get_body(self):
            # Mirrors the real azure.functions API, which returns bytes.
            return self.body.encode("utf-8") if isinstance(self.body, str) else self.body

    class FakeBlueprint:
        """Stand-in for azure.functions.Blueprint supporting @bp.route(...)."""

        def __init__(self, *args, **kwargs):
            self.routes = []

        def route(self, *args, **kwargs):
            def decorator(func):
                self.routes.append((args, kwargs))
                return func

            return decorator

    func_mod.HttpRequest = FakeHttpRequest
    func_mod.HttpResponse = FakeHttpResponse
    func_mod.Blueprint = FakeBlueprint
    azure_mod.functions = func_mod

    sys.modules["azure"] = azure_mod
    sys.modules["azure.functions"] = func_mod
    sys.modules["azure.identity"] = MagicMock()
    sys.modules["azure.mgmt"] = MagicMock()
    sys.modules["azure.mgmt.network"] = MagicMock()
    # ``azure.mgmt.network`` is a MagicMock (not a package), so submodule imports
    # like ``from azure.mgmt.network.models import NetworkSecurityGroup`` fail
    # unless the submodule is registered explicitly. Same for compute.models.
    sys.modules["azure.mgmt.network.models"] = MagicMock()
    sys.modules["azure.mgmt.compute"] = MagicMock()
    sys.modules["azure.mgmt.compute.models"] = MagicMock()

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

    @unittest.mock.patch("src.functions.NetworkContainment.DefaultAzureCredential", autospec=False)
    @unittest.mock.patch("src.functions.NetworkContainment.NetworkManagementClient", autospec=False)
    @unittest.mock.patch("azure.mgmt.compute.ComputeManagementClient", autospec=False)
    def test_critical_infrastructure_tag_bypass(
        self, mock_compute_cls, mock_network_cls, mock_credential_cls
    ):
        """VM tagged CriticalInfrastructure should be bypassed, not contained."""
        from src.functions.NetworkContainment import main

        # Build a fake VM object whose tags include the critical marker.
        fake_vm = MagicMock()
        fake_vm.tags = {"Critical-Infrastructure": "true"}
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

    @unittest.mock.patch("src.functions.NetworkContainment.DefaultAzureCredential", autospec=False)
    @unittest.mock.patch("src.functions.NetworkContainment.NetworkManagementClient", autospec=False)
    @unittest.mock.patch("azure.mgmt.compute.ComputeManagementClient", autospec=False)
    def test_no_critical_infrastructure_tag_proceeds(
        self, mock_compute_cls, mock_network_cls, mock_credential_cls
    ):
        """VM without CriticalInfrastructure tag should be contained normally."""
        from src.functions.NetworkContainment import main

        # Build a fake VM *without* the critical-infra tag.
        fake_vm = MagicMock()
        fake_vm.tags = {"Environment": "Production"}
        fake_vm.network_profile.network_interfaces = [
            MagicMock(
                primary=True,
                id="/subscriptions/11111111-1111-1111-1111-111111111111/"
                "resourceGroups/Compromised-Environment-RG/"
                "providers/Microsoft.Network/networkInterfaces/test-nic",
            )
        ]
        mock_compute_cls.return_value.virtual_machines.get.return_value = fake_vm

        fake_nic = MagicMock()
        fake_nic.network_security_group = None
        mock_network_cls.return_value.network_interfaces.get.return_value = fake_nic
        mock_network_cls.return_value.network_security_groups.get.return_value = MagicMock(
            id="/subscriptions/11111111-1111-1111-1111-111111111111/"
            "resourceGroups/Compromised-Environment-RG/"
            "providers/Microsoft.Network/networkSecurityGroups/Forensic-Isolation-NSG-INC-2026-0001"
        )

        req = self._make_request(self.valid_payload)
        resp = main(req)
        body = json.loads(resp.get_body())

        self.assertEqual(body["status"], "Contained")
        self.assertFalse(body["CriticalInfrastructureBypass"])
        # NSG *should* have been created and attached.
        mock_network_cls.return_value.network_security_groups.begin_create_or_update.assert_called()
        mock_network_cls.return_value.network_interfaces.begin_create_or_update.assert_called()


if __name__ == "__main__":
    unittest.main()

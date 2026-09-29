"""Unit tests for NetworkContainment Azure Function logic."""

import json
import sys
import unittest
from types import ModuleType
from unittest.mock import MagicMock

# Stub azure modules if not installed in local environment
if "azure" not in sys.modules:
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

    func_mod.HttpRequest = FakeHttpRequest
    func_mod.HttpResponse = MagicMock
    azure_mod.functions = func_mod

    sys.modules["azure"] = azure_mod
    sys.modules["azure.functions"] = func_mod
    sys.modules["azure.identity"] = MagicMock()
    sys.modules["azure.mgmt"] = MagicMock()
    sys.modules["azure.mgmt.network"] = MagicMock()
    sys.modules["azure.mgmt.compute"] = MagicMock()

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


if __name__ == "__main__":
    unittest.main()

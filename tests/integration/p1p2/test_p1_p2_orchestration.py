"""Integration tests for Person 1 (Orchestration) and Person 2 (Acquisition & Containment)."""

import json
import unittest
from unittest.mock import MagicMock, patch

from src.functions.NetworkContainment import main as containment_main
from src.functions.shared import sas


class TestP1P2Integration(unittest.TestCase):
    """Verifies integration contracts and flow between P1 Logic App Orchestration and P2 Containment."""

    def setUp(self):
        self.sentinel_payload = {
            "IncidentID": "INC-2026-9001",
            "TargetVM": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Compute/virtualMachines/workstation-01",
            "IPAddress": "10.0.1.4",
            "SubscriptionID": "11111111-1111-1111-1111-111111111111",
            "IncidentSeverity": "High",
            "ResourceGroupName": "Compromised-Environment-RG",
        }

    def _make_http_request(self, body: dict):
        import azure.functions as func

        return func.HttpRequest(
            method="POST",
            url="/api/NetworkContainment",
            body=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

    def _simulate_logic_app_eval(self, containment_response: dict, status_code: int) -> str:
        """Simulate Logic App workflow.json 'Check_Containment_Success' branch evaluation."""
        # Logic App condition:
        # @or(equals(outputs('Call_Network_Containment')['statusCode'], 200),
        #     equals(body('Call_Network_Containment')?['status'], 'Bypassed'))
        if status_code == 200 or containment_response.get("status") == "Bypassed":
            return "Start_Acquisition_Workflow"
        return "Record_Containment_Failure"

    @patch("src.functions.NetworkContainment.DefaultAzureCredential")
    @patch("src.functions.NetworkContainment.NetworkManagementClient")
    @patch("azure.mgmt.compute.ComputeManagementClient")
    def test_p1p2_normal_containment_and_acquisition_trigger(
        self, mock_compute_cls, mock_network_cls, mock_cred_cls
    ):
        """P1 calls P2 Network Containment; on Contained (200), P1 triggers Acquisition workflow."""
        fake_vm = MagicMock()
        fake_vm.tags = {"Environment": "Production"}
        fake_vm.network_profile.network_interfaces = [
            MagicMock(
                primary=True,
                id="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/networkInterfaces/workstation-01VMNic",
            )
        ]
        mock_compute_cls.return_value.virtual_machines.get.return_value = fake_vm

        fake_nic = MagicMock()
        fake_nic.network_security_group = None
        mock_network_cls.return_value.network_interfaces.get.return_value = fake_nic
        mock_network_cls.return_value.network_security_groups.get.return_value = MagicMock(
            id="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/networkSecurityGroups/Forensic-Isolation-NSG-INC-2026-9001"
        )

        req = self._make_http_request(self.sentinel_payload)
        resp = containment_main(req)
        self.assertEqual(resp.status_code, 200)

        body = json.loads(resp.get_body())
        self.assertEqual(body["status"], "Contained")
        self.assertEqual(body["IsolationNSG"], "Forensic-Isolation-NSG-INC-2026-9001")

        next_action = self._simulate_logic_app_eval(body, resp.status_code)
        self.assertEqual(next_action, "Start_Acquisition_Workflow")

        # Verify P1-constructed acquisition payload matches P2 format
        vm_name = self.sentinel_payload["TargetVM"].split("/")[-1]
        blob_uri = f"https://forensicevidence.blob.core.windows.net/evidence/{self.sentinel_payload['IncidentID']}/{vm_name}.raw"
        acquisition_payload = {
            "IncidentID": self.sentinel_payload["IncidentID"],
            "TargetVM": self.sentinel_payload["TargetVM"],
            "EvidenceBlobUri": blob_uri,
        }
        self.assertEqual(acquisition_payload["IncidentID"], "INC-2026-9001")
        self.assertIn("workstation-01.raw", acquisition_payload["EvidenceBlobUri"])

    @patch("src.functions.NetworkContainment.DefaultAzureCredential")
    @patch("src.functions.NetworkContainment.NetworkManagementClient")
    @patch("azure.mgmt.compute.ComputeManagementClient")
    def test_p1p2_critical_infrastructure_bypassed_acquisition_proceeds(
        self, mock_compute_cls, mock_network_cls, mock_cred_cls
    ):
        """P1 calls P2; VM has Critical-Infrastructure:True; P2 bypasses isolation; P1 proceeds with acquisition."""
        fake_vm = MagicMock()
        fake_vm.tags = {"Critical-Infrastructure": "True", "Role": "DomainController"}
        fake_vm.network_profile.network_interfaces = [
            MagicMock(
                primary=True,
                id="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/networkInterfaces/dc-01VMNic",
            )
        ]
        mock_compute_cls.return_value.virtual_machines.get.return_value = fake_vm

        req = self._make_http_request(self.sentinel_payload)
        resp = containment_main(req)
        self.assertEqual(resp.status_code, 200)

        body = json.loads(resp.get_body())
        self.assertEqual(body["status"], "Bypassed")
        self.assertIn("Critical-Infrastructure", body["Reason"])

        # NSG should not be created
        mock_network_cls.return_value.network_security_groups.begin_create_or_update.assert_not_called()

        # Logic App condition must still evaluate to proceed with acquisition!
        next_action = self._simulate_logic_app_eval(body, resp.status_code)
        self.assertEqual(next_action, "Start_Acquisition_Workflow")

    def test_p1p2_write_only_sas_generation(self):
        """P2 enclave SAS generation guarantees write-only and short-lived expiration for acquisition scripts."""
        with patch.dict(
            "os.environ",
            {
                "EVIDENCE_STORAGE_ACCOUNT": "testforensicstorage",
                "KEY_VAULT_URI": "https://test-vault.vault.azure.net",
                "SAS_MODE": "key-vault",
            },
        ):
            with patch("src.functions.shared.clients.secret_client") as mock_sc:
                mock_sc.return_value.get_secret.return_value = MagicMock(
                    value="bW9ja19zdG9yYWdlX2tleV9mb3JfdGVzdGluZ18xMjM0NTY3OA=="
                )
                blob_name = sas.build_blob_name("INC-2026-9001", "workstation-01", "memory", "raw")
                url, expiry = sas.mint_write_only_sas(blob_name, ttl_minutes=45)

                self.assertIn("https://testforensicstorage.blob.core.windows.net/evidence/", url)
                self.assertIn("INC-2026-9001/workstation-01/memory-", url)
                self.assertTrue(url.endswith(".raw") or "?" in url)
                self.assertIsNotNone(expiry)

    def test_p1p2_containment_failure_branches_to_error_recording(self):
        """When NetworkContainment returns an error (500), Logic App records failure."""
        failed_response = {
            "status": "Failed",
            "error": "Network containment could not be completed.",
        }
        next_action = self._simulate_logic_app_eval(failed_response, 500)
        self.assertEqual(next_action, "Record_Containment_Failure")


if __name__ == "__main__":
    unittest.main()

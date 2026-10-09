"""End-to-End integration tests for the REACT Forensic Automation Pipeline."""

import json
import unittest
from unittest.mock import MagicMock, patch

from src.functions.NetworkContainment import main as containment_main


class MockLogicAppEngine:
    """Simulates execution flow of src/logic-apps/workflow.json."""

    def __init__(self, containment_func, acquisition_delay_polls=1, acquisition_fail=False):
        self.containment_func = containment_func
        self.acquisition_delay_polls = acquisition_delay_polls
        self.acquisition_fail = acquisition_fail
        self.execution_log = []

    def execute(self, trigger_payload: dict) -> dict:
        self.execution_log.append(("Trigger_Received", trigger_payload))

        # Action: Parse_Incident
        incident_id = trigger_payload.get("IncidentID")
        severity = trigger_payload.get("IncidentSeverity")

        # Action: High_Or_Critical_Severity_Only condition
        if severity not in ("High", "Critical"):
            msg = f"Incident {incident_id} was not contained because its severity is neither High nor Critical."
            self.execution_log.append(("Ignored_Non_Severe_Incident", msg))
            return {"status": "Ignored", "reason": msg, "log": self.execution_log}

        # Action: Call_Network_Containment
        import azure.functions as func

        req = func.HttpRequest(
            method="POST",
            url="/api/NetworkContainment",
            body=json.dumps(trigger_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        containment_resp = self.containment_func(req)
        containment_data = json.loads(containment_resp.get_body())
        self.execution_log.append(
            (
                "Call_Network_Containment",
                {"code": containment_resp.status_code, "data": containment_data},
            )
        )

        # Action: Check_Containment_Success
        # Condition: (statusCode == 200 OR status == 'Bypassed')
        if containment_resp.status_code != 200 and containment_data.get("status") != "Bypassed":
            self.execution_log.append(("Record_Containment_Failure", containment_data))
            return {
                "status": "Failed_At_Containment",
                "data": containment_data,
                "log": self.execution_log,
            }

        # Action: Start_Acquisition_Workflow
        vm_name = trigger_payload["TargetVM"].split("/")[-1]
        evidence_uri = (
            f"https://forensicevidence.blob.core.windows.net/evidence/{incident_id}/{vm_name}.raw"
        )
        self.execution_log.append(("Start_Acquisition_Workflow", {"EvidenceBlobUri": evidence_uri}))

        # Action: Wait_For_Evidence_Acquisition (Polling loop)
        for poll_idx in range(self.acquisition_delay_polls):
            if self.acquisition_fail and poll_idx == self.acquisition_delay_polls - 1:
                self.execution_log.append(("Get_Acquisition_Status", "Failed"))
                return {"status": "Acquisition_Failed", "log": self.execution_log}
            status = "Completed" if poll_idx == self.acquisition_delay_polls - 1 else "Running"
            self.execution_log.append(("Get_Acquisition_Status", status))

        # Action: Start_Analysis_Pipeline
        analysis_payload = {
            "IncidentID": incident_id,
            "TargetVM": trigger_payload["TargetVM"],
            "IPAddress": trigger_payload["IPAddress"],
            "SubscriptionID": trigger_payload["SubscriptionID"],
            "IncidentSeverity": trigger_payload["IncidentSeverity"],
            "EvidenceBlobUri": evidence_uri,
            "ContainmentDetails": containment_data,
            "PipelineStatus": "AcquisitionCompleted",
            "Timestamp": "2026-10-08T01:00:00Z",
        }
        self.execution_log.append(("Start_Analysis_Pipeline", analysis_payload))

        return {"status": "Succeeded", "incident_id": incident_id, "log": self.execution_log}


class TestE2EPipeline(unittest.TestCase):
    """End-to-end integration scenarios verifying P1 + P2 + P3 pipeline coordination."""

    def setUp(self):
        self.valid_payload = {
            "IncidentID": "INC-2026-9999",
            "TargetVM": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Compute/virtualMachines/victim-01",
            "IPAddress": "198.51.100.12",
            "SubscriptionID": "11111111-1111-1111-1111-111111111111",
            "IncidentSeverity": "High",
            "ResourceGroupName": "Compromised-Environment-RG",
        }

    @patch("src.functions.NetworkContainment.DefaultAzureCredential")
    @patch("src.functions.NetworkContainment.NetworkManagementClient")
    @patch("azure.mgmt.compute.ComputeManagementClient")
    def test_e2e_1_happy_path_complete_incident_response(
        self, mock_compute_cls, mock_network_cls, mock_cred_cls
    ):
        """E2E-1: Happy Path - High Severity Incident -> Containment (Contained) -> Acquisition -> Analysis."""
        fake_vm = MagicMock()
        fake_vm.tags = {"Role": "WebFrontend"}
        fake_vm.network_profile.network_interfaces = [
            MagicMock(
                primary=True,
                id="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/networkInterfaces/victim-01VMNic",
            )
        ]
        mock_compute_cls.return_value.virtual_machines.get.return_value = fake_vm

        fake_nic = MagicMock()
        fake_nic.network_security_group = None
        mock_network_cls.return_value.network_interfaces.get.return_value = fake_nic
        mock_network_cls.return_value.network_security_groups.get.return_value = MagicMock(
            id="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/networkSecurityGroups/Forensic-Isolation-NSG-INC-2026-9999"
        )

        engine = MockLogicAppEngine(containment_main, acquisition_delay_polls=2)
        result = engine.execute(self.valid_payload)

        self.assertEqual(result["status"], "Succeeded")
        action_names = [entry[0] for entry in result["log"]]
        self.assertIn("Call_Network_Containment", action_names)
        self.assertIn("Start_Acquisition_Workflow", action_names)
        self.assertIn("Start_Analysis_Pipeline", action_names)

    @patch("src.functions.NetworkContainment.DefaultAzureCredential")
    @patch("src.functions.NetworkContainment.NetworkManagementClient")
    @patch("azure.mgmt.compute.ComputeManagementClient")
    def test_e2e_2_critical_infrastructure_vm_full_pipeline(
        self, mock_compute_cls, mock_network_cls, mock_cred_cls
    ):
        """E2E-2: Critical-Infrastructure VM -> Isolation Bypassed -> Acquisition & Analysis still succeed."""
        fake_vm = MagicMock()
        fake_vm.tags = {"Critical-Infrastructure": "True", "System": "SCADA-Controller"}
        fake_vm.network_profile.network_interfaces = [
            MagicMock(
                primary=True,
                id="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/networkInterfaces/scada-nic",
            )
        ]
        mock_compute_cls.return_value.virtual_machines.get.return_value = fake_vm

        engine = MockLogicAppEngine(containment_main, acquisition_delay_polls=1)
        result = engine.execute(self.valid_payload)

        self.assertEqual(result["status"], "Succeeded")
        # NSG should not be created
        mock_network_cls.return_value.network_security_groups.begin_create_or_update.assert_not_called()

        action_names = [entry[0] for entry in result["log"]]
        self.assertIn("Start_Acquisition_Workflow", action_names)
        self.assertIn("Start_Analysis_Pipeline", action_names)

    def test_e2e_3_medium_severity_skips_containment_and_acquisition(self):
        """E2E-3: Non-Severe Incident (Medium/Low) terminates early without calling containment/acquisition."""
        payload = dict(self.valid_payload)
        payload["IncidentSeverity"] = "Medium"

        engine = MockLogicAppEngine(containment_main)
        result = engine.execute(payload)

        self.assertEqual(result["status"], "Ignored")
        action_names = [entry[0] for entry in result["log"]]
        self.assertIn("Ignored_Non_Severe_Incident", action_names)
        self.assertNotIn("Call_Network_Containment", action_names)
        self.assertNotIn("Start_Acquisition_Workflow", action_names)


if __name__ == "__main__":
    unittest.main()

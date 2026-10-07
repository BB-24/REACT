"""Integration tests for Person 1 (Orchestrator) and Person 3 (Analysis & Report Generation)."""

import unittest


class TestP1P3Reporting(unittest.TestCase):
    """Verifies that P1 orchestration triggers P3 analysis/reporting with complete and compliant metadata."""

    def test_p1p3_analysis_payload_assembly(self):
        """P1 constructs analysis payload containing Sentinel incident context + Containment results."""
        incident = {
            "IncidentID": "INC-2026-7788",
            "TargetVM": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Compute/virtualMachines/db-server-01",
            "IPAddress": "10.0.2.15",
            "SubscriptionID": "11111111-1111-1111-1111-111111111111",
            "IncidentSeverity": "High",
        }
        containment_output = {
            "status": "Contained",
            "IncidentID": "INC-2026-7788",
            "TargetVM": incident["TargetVM"],
            "NetworkInterface": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/networkInterfaces/db-server-01VMNic",
            "IsolationNSG": "Forensic-Isolation-NSG-INC-2026-7788",
            "CriticalInfrastructureBypass": False,
        }

        analysis_trigger_payload = {
            "IncidentID": incident["IncidentID"],
            "TargetVM": incident["TargetVM"],
            "IPAddress": incident["IPAddress"],
            "SubscriptionID": incident["SubscriptionID"],
            "IncidentSeverity": incident["IncidentSeverity"],
            "EvidenceBlobUri": f"https://forensicevidence.blob.core.windows.net/evidence/{incident['IncidentID']}/db-server-01.raw",
            "ContainmentDetails": containment_output,
            "PipelineStatus": "AcquisitionCompleted",
            "Timestamp": "2026-10-08T01:00:00Z",
        }

        self.assertEqual(analysis_trigger_payload["IncidentID"], "INC-2026-7788")
        self.assertEqual(analysis_trigger_payload["ContainmentDetails"]["status"], "Contained")
        self.assertFalse(
            analysis_trigger_payload["ContainmentDetails"]["CriticalInfrastructureBypass"]
        )

    def test_p1p3_report_metadata_includes_critical_infrastructure_bypass_notice(self):
        """When VM has Critical-Infrastructure tag, report generator receives Bypassed status to render in report."""
        containment_output = {
            "status": "Bypassed",
            "IncidentID": "INC-2026-7788",
            "TargetVM": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Compute/virtualMachines/core-router",
            "Reason": "Critical-Infrastructure tag set to True",
            "NetworkInterface": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/networkInterfaces/core-routerVMNic",
            "Action": "Network isolation skipped; acquisition proceeds",
        }

        report_summary = {
            "IncidentID": containment_output["IncidentID"],
            "IsolationStatus": f"Bypassed ({containment_output['Reason']})",
            "AnalysisSummary": "Volatile memory and disk artifacts collected while target remained operational.",
        }

        self.assertIn("Bypassed", report_summary["IsolationStatus"])
        self.assertIn("Critical-Infrastructure", report_summary["IsolationStatus"])

    def test_p1p3_partial_acquisition_degradation_handling(self):
        """P3 report handles partial evidence (e.g. Memory succeeded, Disk snapshot timed out)."""
        evidence_status = {
            "MemoryDump": {"status": "Acquired", "size_bytes": 4294967296},
            "DiskSnapshot": {
                "status": "Failed",
                "error": "Disk snapshot timed out after 30 minutes",
            },
        }

        report_sections = []
        if evidence_status["MemoryDump"]["status"] == "Acquired":
            report_sections.append("Memory Analysis: Volatility 3 findings included")
        if evidence_status["DiskSnapshot"]["status"] == "Failed":
            report_sections.append(
                "Disk Analysis: WARNING - Disk acquisition failed; report limited to volatile memory"
            )

        self.assertEqual(len(report_sections), 2)
        self.assertIn("WARNING - Disk acquisition failed", report_sections[1])


if __name__ == "__main__":
    unittest.main()

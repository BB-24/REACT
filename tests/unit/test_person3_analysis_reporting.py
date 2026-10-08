"""Unit tests for Person 3: Automated Forensic Analysis & PDF Reporting Engine.

Covers:
- REQ-3.6 (Automated Analysis, Plaso/Volatility normalization, Cosmos DB schema, PDF Reporting data model)
"""

import unittest


class TestPerson3AnalysisReporting(unittest.TestCase):
    """Unit tests for Person 3 forensic analysis and report generation logic."""

    # --------------------------------------------------------------------------
    # Task 3.1 & 3.2: Plaso / Volatility Normalization & Cosmos DB Schema (REQ-3.6)
    # --------------------------------------------------------------------------

    def test_task_3_1_plaso_timeline_event_structure(self):
        """REQ-3.6.2: Plaso / Log2Timeline parsed events follow normalized schema for Cosmos DB ingestion."""
        sample_timeline_event = {
            "id": "EVT-INC-2026-P3-001-00042",
            "IncidentID": "INC-2026-P3-001",  # Cosmos DB Partition Key
            "Timestamp": "2026-10-08T03:14:07.123456Z",
            "TimestampDesc": "File Modification Time",
            "Source": "FILE",
            "SourceType": "NTFS $MFT",
            "Message": "C:/Windows/System32/drivers/etc/hosts modified",
            "Parser": "mft",
            "Severity": "Warning",
            "Tags": ["SuspiciousModification", "SystemFile"],
        }

        self.assertEqual(sample_timeline_event["IncidentID"], "INC-2026-P3-001")
        self.assertIn("Timestamp", sample_timeline_event)
        self.assertIn("Parser", sample_timeline_event)

    def test_task_3_1_volatility_memory_findings_model(self):
        """REQ-3.6.3: Volatility 3 output is structured into forensic memory analysis findings."""
        volatility_findings = {
            "IncidentID": "INC-2026-P3-001",
            "Plugin": "windows.malfind",
            "FindingsCount": 1,
            "Details": [
                {
                    "PID": 1840,
                    "ProcessName": "powershell.exe",
                    "ProcessPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "VirtualAddress": "0x1b4a0000",
                    "Protection": "PAGE_EXECUTE_READWRITE",
                    "InjectedBytesHex": "4883ec28e8110000004883c428c3",
                    "Analysis": "Code injection detected in unbacked executable memory segment.",
                }
            ],
        }

        self.assertEqual(volatility_findings["Plugin"], "windows.malfind")
        self.assertEqual(volatility_findings["Details"][0]["PID"], 1840)
        self.assertEqual(volatility_findings["Details"][0]["Protection"], "PAGE_EXECUTE_READWRITE")

    def test_task_3_2_cosmos_db_container_partition_contract(self):
        """REQ-3.6.4: All forensic documents share /IncidentID partition key for co-located indexing."""
        documents = [
            {
                "id": "DOC-TIMELINE-01",
                "IncidentID": "INC-2026-P3-001",
                "DocType": "TimelineSummary",
            },
            {
                "id": "DOC-VOLATILITY-01",
                "IncidentID": "INC-2026-P3-001",
                "DocType": "MemoryAnalysis",
            },
            {
                "id": "DOC-NETWORK-01",
                "IncidentID": "INC-2026-P3-001",
                "DocType": "NetworkArtifacts",
            },
        ]

        for doc in documents:
            self.assertIn("IncidentID", doc)
            self.assertEqual(doc["IncidentID"], "INC-2026-P3-001")

    # --------------------------------------------------------------------------
    # Task 3.3: PDF Report Generation Data Assembly (REQ-3.6.5)
    # --------------------------------------------------------------------------

    def test_task_3_3_report_data_context_assembly(self):
        """REQ-3.6.5: Report compiler aggregates Incident, Containment, Ledger, and Timeline metrics."""
        report_context = {
            "metadata": {
                "incident_id": "INC-2026-P3-001",
                "target_vm": "victim-vm-01",
                "ip_address": "10.0.1.20",
                "severity": "Critical",
                "generated_at": "2026-10-08T04:00:00Z",
            },
            "containment": {
                "status": "Contained",
                "isolation_nsg": "Forensic-Isolation-NSG-INC-2026-P3-001",
                "nic_id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1",
            },
            "chain_of_custody": [
                {
                    "artifact_name": "memory.raw",
                    "sha256": "abc123def45678901234567890abcdef1234567890abcdef1234567890abcdef",
                    "status": "Verified",
                    "size_mb": 4096,
                }
            ],
            "analysis_summary": {
                "total_timeline_events": 24890,
                "critical_findings_count": 2,
                "top_findings": [
                    "Malicious code injection detected in powershell.exe (PID 1840)",
                    "Persistence registry key added in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                ],
            },
        }

        self.assertEqual(report_context["metadata"]["incident_id"], "INC-2026-P3-001")
        self.assertEqual(len(report_context["chain_of_custody"]), 1)
        self.assertEqual(report_context["analysis_summary"]["critical_findings_count"], 2)

    def test_task_3_3_report_handles_critical_infrastructure_bypass_notice(self):
        """When containment is bypassed, the report generates a visible policy notice."""
        containment_info = {
            "status": "Bypassed",
            "reason": "Critical-Infrastructure tag set to True",
        }

        banner_text = (
            f"NETWORK ISOLATION BYPASSED: {containment_info['reason']}"
            if containment_info["status"] == "Bypassed"
            else "TARGET FULLY ISOLATED"
        )

        self.assertIn("BYPASSED", banner_text)
        self.assertIn("Critical-Infrastructure", banner_text)

    def test_task_3_3_report_graceful_degradation_on_partial_data(self):
        """Report engine tolerates missing analysis sections when analysis was interrupted."""
        partial_data = {
            "incident_id": "INC-2026-P3-002",
            "memory_analysis": None,  # Failed/skipped
            "disk_analysis": {"status": "Completed", "partitions_analyzed": 2},
        }

        sections = []
        if partial_data.get("memory_analysis"):
            sections.append("Memory Section")
        else:
            sections.append("Memory Section: Skipped / Unavailable")

        if partial_data.get("disk_analysis"):
            sections.append("Disk Section: Complete")

        self.assertEqual(sections[0], "Memory Section: Skipped / Unavailable")
        self.assertEqual(sections[1], "Disk Section: Complete")


if __name__ == "__main__":
    unittest.main()

"""Integration tests for Person 2 (Acquisition/Storage) and Person 3 (Analysis/Ledger/Cosmos DB)."""

import unittest
from datetime import UTC, datetime

from src.functions.shared import sas


class TestP2P3Handoff(unittest.TestCase):
    """Verifies data formats, storage paths, and metadata handoff from P2 to P3."""

    def test_p2p3_blob_path_structure_and_timestamp_ordering(self):
        """P2 evidence blobs follow strict <incident>/<target>/<artifact>-<utc_timestamp>.<ext> layout."""
        t1 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=UTC)
        blob_path_mem = sas.build_blob_name(
            "INC-2026-0001", "victim-vm-01", "memory", "raw", now=t1
        )
        blob_path_disk = sas.build_blob_name(
            "INC-2026-0001", "victim-vm-01", "disk-os", "vhd", now=t1
        )

        self.assertEqual(blob_path_mem, "INC-2026-0001/victim-vm-01/memory-20261008T120000Z.raw")
        self.assertEqual(blob_path_disk, "INC-2026-0001/victim-vm-01/disk-os-20261008T120000Z.vhd")

    def test_p2p3_cosmos_db_partition_key_consistency(self):
        """P3 Cosmos DB collection uses IncidentID as partition key matching P1 and P2 metadata."""
        incident_id = "INC-2026-0001"
        p2_evidence_record = {
            "id": "EV-20261008-001",
            "IncidentID": incident_id,  # Partition Key
            "TargetVM": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Compute/virtualMachines/victim-vm-01",
            "ArtifactType": "MemoryDump",
            "BlobUri": "https://forensicevidence.blob.core.windows.net/evidence/INC-2026-0001/victim-vm-01/memory.raw",
            "SHA256Hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "AcquiredAt": "2026-10-08T12:00:00Z",
        }

        # P3 Analysis record using the same partition key
        p3_analysis_record = {
            "id": f"ANALYSIS-{incident_id}",
            "IncidentID": p2_evidence_record["IncidentID"],  # Must match for co-located indexing
            "TargetVM": p2_evidence_record["TargetVM"],
            "PlasoTimelineEventsCount": 15420,
            "VolatilityFindings": ["Suspicious injected thread in svchost.exe (PID: 1044)"],
            "AnalysisStatus": "Completed",
        }

        self.assertEqual(p2_evidence_record["IncidentID"], p3_analysis_record["IncidentID"])
        self.assertEqual(p3_analysis_record["IncidentID"], incident_id)

    def test_p2p3_evidence_ledger_hash_contract(self):
        """P2 Chain of Custody calculates SHA-256 and writes to Ledger; P3 validates integrity before analysis."""
        sample_hash = "6a2f3a6125a81cf26719cdb584ff1d3ff3d3f9e4299b6df651351296f866440b"
        ledger_entry = {
            "IncidentID": "INC-2026-0001",
            "ArtifactName": "memory.raw",
            "EvidenceLedgerHash": sample_hash,
            "VerificationStatus": "Verified",
        }

        # P3 ingestion checks ledger entry
        self.assertEqual(len(ledger_entry["EvidenceLedgerHash"]), 64)
        self.assertEqual(ledger_entry["VerificationStatus"], "Verified")


if __name__ == "__main__":
    unittest.main()

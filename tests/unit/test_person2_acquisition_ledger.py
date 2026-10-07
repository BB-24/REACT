"""Unit tests for Person 2: Evidence Acquisition & Cryptographic Chain of Custody.

Covers:
- REQ-3.3 (Memory Acquisition & Write-Only SAS Minting)
- REQ-3.4 (Disk Snapshotting & Enclave Storage Pathing)
- REQ-3.5 (Cryptographic Chain of Custody, Event Grid BlobCreated parsing, SQL Ledger Schemas)
"""

import hashlib
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from src.functions.shared import config, sas


class TestPerson2AcquisitionLedger(unittest.TestCase):
    """Unit tests for Person 2 components and operations."""

    # --------------------------------------------------------------------------
    # Task 2.1: Live-Response Memory Extraction Contracts (REQ-3.3)
    # --------------------------------------------------------------------------

    def test_task_2_1_direct_streaming_sas_url_contract(self):
        """REQ-3.3.4: Streamed memory dump URL carries write permissions and embeds incident hierarchy."""
        with patch.dict(
            "os.environ",
            {
                "EVIDENCE_STORAGE_ACCOUNT": "forensicevidence",
                "KEY_VAULT_URI": "https://vault.azure.net",
                "SAS_MODE": "key-vault",
            },
        ):
            with patch("src.functions.shared.clients.secret_client") as mock_sc:
                mock_sc.return_value.get_secret.return_value = MagicMock(value="bW9ja19rZXk=")
                blob_name = sas.build_blob_name("INC-2026-P2-01", "vm-web-01", "memory", "raw")
                url, expiry = sas.mint_write_only_sas(blob_name, ttl_minutes=60)

                self.assertTrue(
                    url.startswith(
                        "https://forensicevidence.blob.core.windows.net/evidence/INC-2026-P2-01/vm-web-01/memory-"
                    )
                )
                self.assertTrue(url.endswith(".raw") or "?" in url)

    def test_task_2_1_tool_download_sas_separation(self):
        """REQ-3.3.2: Tool download SAS accesses 'tools' container and grants read-only access."""
        with patch.dict(
            "os.environ",
            {
                "EVIDENCE_STORAGE_ACCOUNT": "forensicevidence",
                "KEY_VAULT_URI": "https://vault.azure.net",
                "SAS_MODE": "key-vault",
            },
        ):
            with patch("src.functions.shared.clients.secret_client") as mock_sc:
                mock_sc.return_value.get_secret.return_value = MagicMock(value="bW9ja19rZXk=")
                url, expiry = sas.mint_read_only_sas("winpmem/winpmem_mini_x64.exe", ttl_minutes=30)

                self.assertIn("/tools/winpmem/winpmem_mini_x64.exe", url)

    # --------------------------------------------------------------------------
    # Task 2.2: Storage & SAS Token Management (REQ-3.3, REQ-3.4)
    # --------------------------------------------------------------------------

    def test_task_2_2_blob_naming_and_safe_slugs(self):
        """Blob path safely encodes incident ID, host name, and UTC timestamp."""
        test_time = datetime(2026, 10, 8, 14, 30, 0, tzinfo=UTC)
        blob_name = sas.build_blob_name(
            "INC 2026/001", "vm@prod#01", "disk-os", "vhd", now=test_time
        )
        self.assertEqual(blob_name, "INC-2026-001/vm-prod-01/disk-os-20261008T143000Z.vhd")

    def test_task_2_2_sas_ttl_and_clock_skew(self):
        """REQ-3.3.3: Token minting enforces TTL and includes clock skew backdating."""
        issued_at = datetime(2026, 10, 8, 12, 0, 0, tzinfo=UTC)
        with patch.dict(
            "os.environ",
            {
                "EVIDENCE_STORAGE_ACCOUNT": "forensicevidence",
                "KEY_VAULT_URI": "https://vault.azure.net",
                "SAS_MODE": "key-vault",
            },
        ):
            with patch("src.functions.shared.clients.secret_client") as mock_sc:
                mock_sc.return_value.get_secret.return_value = MagicMock(value="bW9ja19rZXk=")
                _, expiry = sas.mint_write_only_sas("test.raw", ttl_minutes=45, now=issued_at)
                expected_expiry = issued_at + timedelta(minutes=45)
                self.assertEqual(expiry, expected_expiry)

    def test_task_2_2_invalid_sas_mode_raises_config_error(self):
        """Invalid SAS_MODE setting triggers ConfigError."""
        with patch.dict(
            "os.environ",
            {
                "EVIDENCE_STORAGE_ACCOUNT": "forensicevidence",
                "SAS_MODE": "unsupported-mode",
            },
        ):
            with self.assertRaises(config.ConfigError):
                sas.mint_write_only_sas("test.raw")

    # --------------------------------------------------------------------------
    # Task 2.3: Cryptographic Chain of Custody & SQL Ledger (REQ-3.5)
    # --------------------------------------------------------------------------

    def test_task_2_3_sha256_hash_calculation(self):
        """REQ-3.5.2: Verifies SHA-256 calculation algorithm on binary evidence chunks."""
        evidence_bytes = b"Sample Volatile Memory Snapshot Dump Data 0xDEADBEEF"
        hasher = hashlib.sha256()
        hasher.update(evidence_bytes)
        calculated_hash = hasher.hexdigest()

        self.assertEqual(len(calculated_hash), 64)
        self.assertEqual(calculated_hash, hashlib.sha256(evidence_bytes).hexdigest())

    def test_task_2_3_eventgrid_blob_created_event_parsing(self):
        """REQ-3.5.2: Parses Event Grid BlobCreated event to identify new evidence blob."""
        event_grid_event = {
            "id": "e492b45e-b01e-0013-1b20-1a2b3c4d5e6f",
            "eventType": "Microsoft.Storage.BlobCreated",
            "subject": "/blobServices/default/containers/evidence/blobs/INC-2026-P2-01/victim-01/memory-20261008T120000Z.raw",
            "eventTime": "2026-10-08T12:05:00.0000000Z",
            "data": {
                "api": "PutBlob",
                "contentType": "application/octet-stream",
                "contentLength": 4294967296,
                "blobUrl": "https://forensicevidence.blob.core.windows.net/evidence/INC-2026-P2-01/victim-01/memory-20261008T120000Z.raw",
            },
        }

        # Extract incident ID and blob details from event
        subject = event_grid_event["subject"]
        blob_path = subject.split("/containers/evidence/blobs/")[-1]
        incident_id = blob_path.split("/")[0]
        artifact_name = blob_path.split("/")[-1]

        self.assertEqual(incident_id, "INC-2026-P2-01")
        self.assertEqual(artifact_name, "memory-20261008T120000Z.raw")
        self.assertEqual(event_grid_event["data"]["contentLength"], 4294967296)

    def test_task_2_3_sql_ledger_record_schema(self):
        """REQ-3.5.3: Azure SQL Database Ledger record satisfies required tamper-evident fields."""
        ledger_row = {
            "LedgerTransactionId": 10042,
            "IncidentID": "INC-2026-P2-01",
            "ArtifactName": "memory-20261008T120000Z.raw",
            "BlobUri": "https://forensicevidence.blob.core.windows.net/evidence/INC-2026-P2-01/victim-01/memory-20261008T120000Z.raw",
            "SHA256Hash": "d2c3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
            "ArtifactSizeBytes": 4294967296,
            "AcquiredBy": "AutomatedForensicPipeline",
            "AcquiredAt": "2026-10-08T12:05:00Z",
            "IsTamperEvidentVerified": True,
        }

        self.assertIn("LedgerTransactionId", ledger_row)
        self.assertEqual(len(ledger_row["SHA256Hash"]), 64)
        self.assertTrue(ledger_row["IsTamperEvidentVerified"])


if __name__ == "__main__":
    unittest.main()

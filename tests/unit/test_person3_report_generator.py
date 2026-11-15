"""Unit tests for Person 3 / Issue #34: [P3-4] Implement ReportGenerator Azure Function.

Covers:
- HTTP Function endpoint (POST /api/GenerateReport, /api/ReportGenerator, /api/report/generate)
- IncidentID request validation (missing, empty, non-dict, invalid JSON)
- Data retrieval from Cosmos DB (timeline, process listings, network connections, evidence)
- Data retrieval from SQL Ledger and cryptographic chain of custody verification
- Jinja2 template rendering containing all 6 required forensic sections
- Safe data escaping and empty section degradation
- PDF generation (WeasyPrint and standard PDF generator)
- Upload to immutable WORM 'reports' container with legal hold metadata
- Tampered ledger detection and graceful failure handling
"""

import json
from unittest.mock import MagicMock

import pytest
from ReportGenerator import (
    generate_report_http,
    report_generate_path_alias,
    report_generator_alias,
)
from shared import ledger, mocks
from shared.mocks import (
    MockCosmosClient,
)
from shared.reporting import (
    collect_report_data,
    format_bytes,
    render_pdf,
    render_report_html,
    upload_report_pdf,
)


@pytest.fixture(autouse=True)
def reset_environment(monkeypatch):
    """Ensure mock mode is active and state is clean for each test."""
    monkeypatch.setenv("REACT_MOCK_MODE", "true")
    mocks.reset()


class TestReportDataCollection:
    """Tests for aggregating data from Cosmos DB and SQL Ledger."""

    def test_collect_data_from_cosmos_and_ledger(self):
        """Verify data is collected from both Cosmos DB and SQL Ledger."""
        incident_id = "INC-2026-REPORT-001"

        # Populate Cosmos DB container
        client = MockCosmosClient()
        db = client.get_database_client("react-forensic-db")
        container = db.get_container_client("timeline-artifacts")

        container.upsert_item(
            {
                "id": "EVT-01",
                "incidentId": incident_id,
                "artifactType": "syslog:line",
                "timestamp": "2026-10-24T00:01:00.000000Z",
                "source": "/var/log/syslog",
                "data": {"message": "sshd accepted connection for azureuser"},
            }
        )
        container.upsert_item(
            {
                "id": "EVT-02",
                "incidentId": incident_id,
                "artifactType": "process:listing",
                "timestamp": "2026-10-24T00:02:00.000000Z",
                "source": "volatility3",
                "data": {
                    "pid": 1840,
                    "ppid": 4,
                    "process_name": "powershell.exe",
                    "command_line": "powershell -enc JAB4...",
                    "finding": "Injected code detected in unbacked memory segment",
                },
            }
        )
        container.upsert_item(
            {
                "id": "EVT-03",
                "incidentId": incident_id,
                "artifactType": "network:connection",
                "timestamp": "2026-10-24T00:03:00.000000Z",
                "source": "pcap",
                "data": {
                    "source_ip": "10.0.1.20",
                    "source_port": 49152,
                    "destination_ip": "198.51.100.42",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                    "threat": "C2 beaconing observed",
                },
            }
        )

        # Record evidence in SQL Ledger
        ledger.record_evidence(
            {
                "IncidentId": incident_id,
                "BlobUri": f"https://mock.blob.core.windows.net/evidence/{incident_id}/memdump.raw",
                "BlobName": "memdump.raw",
                "ArtifactType": "MemoryDump",
                "SizeBytes": 4294967296,
                "Sha256Hash": "a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123",
                "AcquiredUtc": "2026-10-24T00:00:30Z",
                "RecordedUtc": "2026-10-24T00:00:35Z",
                "InitiatorObjectId": "test-initiator",
                "SourceHost": "victim-vm-01",
            }
        )

        data = collect_report_data(incident_id, cosmos_container=container)

        # Metadata
        assert data["metadata"]["incident_id"] == incident_id
        assert data["metadata"]["status"] == "Contained / Analysis Completed"

        # Evidence Inventory
        assert len(data["evidence_items"]) == 1
        assert data["evidence_items"][0]["blob_name"] == "memdump.raw"
        assert "a1b2c3d4e5f6" in data["evidence_items"][0]["sha256"]

        # Process Listings
        assert len(data["process_listings"]) >= 1
        assert data["process_listings"][0]["pid"] == 1840
        assert data["process_listings"][0]["process_name"] == "powershell.exe"

        # Network Connections
        assert len(data["network_connections"]) >= 1
        assert data["network_connections"][0]["destination_ip"] == "198.51.100.42"

        # Timeline Events
        assert len(data["timeline_events"]) == 3
        # Sorted chronologically
        assert data["timeline_events"][0]["timestamp"] <= data["timeline_events"][1]["timestamp"]

        # Chain of Custody
        assert len(data["custody_records"]) == 1
        assert data["custody_verification"]["verified"] is True
        assert data["custody_verification"]["status"] == "Verified"

    def test_collect_data_empty_incident(self):
        """Collecting data for an incident with zero records returns empty sections without error."""
        data = collect_report_data("INC-EMPTY-999")
        assert data["metadata"]["incident_id"] == "INC-EMPTY-999"
        assert len(data["evidence_items"]) == 0
        assert len(data["process_listings"]) == 0
        assert len(data["network_connections"]) == 0
        assert len(data["timeline_events"]) == 0
        assert len(data["custody_records"]) == 0

    def test_collect_data_rejects_empty_id(self):
        """Invalid or empty IncidentID raises ValueError."""
        with pytest.raises(ValueError, match="non-empty"):
            collect_report_data("")

        with pytest.raises(ValueError, match="non-empty"):
            collect_report_data("   ")


class TestReportTemplateRendering:
    """Tests for Jinja2 HTML report template rendering."""

    def test_all_six_sections_present_in_rendered_html(self):
        """Verify all 6 required sections are rendered into HTML."""
        report_data = {
            "report_id": "RPT-INC-TEST-001",
            "metadata": {
                "incident_id": "INC-TEST-001",
                "generated_at": "2026-10-24T01:00:00Z",
                "status": "Contained / Analysis Completed",
                "target_vm": "victim-vm-01",
                "ip_address": "10.0.1.20",
                "severity": "Critical",
                "containment_status": "Contained",
            },
            "evidence_items": [
                {
                    "blob_name": "disk-snapshot-01.vhd",
                    "artifact_type": "DiskSnapshot",
                    "size_formatted": "32.00 GB",
                    "acquired_utc": "2026-10-24T00:30:00Z",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "integrity_status": "Verified",
                }
            ],
            "process_listings": [
                {
                    "pid": 404,
                    "ppid": 1,
                    "process_name": "malicious_beacon.exe",
                    "command_line": "/bin/beacon -c2 198.51.100.5",
                    "timestamp": "2026-10-24T00:15:00Z",
                    "finding": "Known C2 backdoor",
                }
            ],
            "network_connections": [
                {
                    "timestamp": "2026-10-24T00:16:00Z",
                    "protocol": "TCP",
                    "source_ip": "10.0.1.20",
                    "source_port": 54321,
                    "destination_ip": "198.51.100.5",
                    "destination_port": 8443,
                    "state": "ESTABLISHED",
                    "threat": "Malicious C2 communication",
                }
            ],
            "timeline_events": [
                {
                    "id": "EVT-1",
                    "timestamp": "2026-10-24T00:00:01Z",
                    "artifactType": "auth:failure",
                    "source": "/var/log/auth.log",
                    "message": "Repeated SSH login failures from 198.51.100.5",
                    "data": {},
                }
            ],
            "custody_records": [
                {
                    "RecordedUtc": "2026-10-24T00:31:00Z",
                    "BlobName": "disk-snapshot-01.vhd",
                    "ArtifactType": "DiskSnapshot",
                    "Sha256Hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                }
            ],
            "custody_verification": {
                "status": "Verified",
                "verified": True,
                "details": "Azure SQL Ledger cryptographically verified. Hash chain is intact.",
            },
        }

        html = render_report_html(report_data)

        # 1. Incident metadata
        assert "Incident Metadata" in html
        assert "INC-TEST-001" in html
        assert "victim-vm-01" in html

        # 2. Evidence inventory (including hashes)
        assert "Evidence Inventory" in html
        assert "disk-snapshot-01.vhd" in html
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in html

        # 3. Process listings
        assert "Process Listings" in html
        assert "malicious_beacon.exe" in html
        assert "404" in html

        # 4. Network connections
        assert "Network Connections" in html
        assert "198.51.100.5" in html
        assert "8443" in html

        # 5. Timeline events
        assert "Timeline Events" in html
        assert "auth:failure" in html
        assert "Repeated SSH login failures" in html

        # 6. Chain of custody verification
        assert "Chain of Custody Verification" in html
        assert "CHAIN OF CUSTODY VERIFIED" in html
        assert "Hash chain is intact" in html

        # Forensic disclaimer
        assert (
            "Forensic Evidence &amp; Integrity Disclaimer" in html
            or "Forensic Evidence & Integrity Disclaimer" in html
        )

    def test_template_handles_empty_sections_gracefully(self):
        """When sections have no records, clean placeholder notices are rendered."""
        report_data = {
            "report_id": "RPT-EMPTY-001",
            "metadata": {
                "incident_id": "INC-EMPTY-001",
                "generated_at": "2026-10-24T01:00:00Z",
                "status": "Contained",
                "target_vm": "victim-vm-01",
                "ip_address": "10.0.1.20",
                "severity": "Low",
                "containment_status": "Contained",
            },
            "evidence_items": [],
            "process_listings": [],
            "network_connections": [],
            "timeline_events": [],
            "custody_records": [],
            "custody_verification": {
                "status": "Verification Unavailable",
                "verified": False,
                "details": "No ledger records to verify.",
            },
        }

        html = render_report_html(report_data)
        assert "No physical evidence blobs recorded" in html
        assert "No process listings or memory execution artifacts" in html
        assert "No active or persistent network connections" in html
        assert "No parsed Plaso timeline events" in html
        assert "No chain of custody records found" in html

    def test_untrusted_data_is_escaped(self):
        """XSS payloads in evidence or process names are safely HTML-escaped."""
        report_data = {
            "report_id": "RPT-XSS-001",
            "metadata": {
                "incident_id": "<script>alert('xss')</script>",
                "generated_at": "2026-10-24T01:00:00Z",
                "status": "Contained",
                "target_vm": "<b>bold-vm</b>",
                "ip_address": "10.0.1.20",
                "severity": "Medium",
                "containment_status": "Contained",
            },
            "evidence_items": [],
            "process_listings": [
                {
                    "pid": 999,
                    "ppid": 1,
                    "process_name": "<img src=x onerror=alert(1)>",
                    "command_line": "cmd.exe <bad>",
                    "timestamp": "2026-10-24T00:00:00Z",
                    "finding": None,
                }
            ],
            "network_connections": [],
            "timeline_events": [],
            "custody_records": [],
            "custody_verification": {
                "status": "Verified",
                "verified": True,
                "details": "ok",
            },
        }

        html = render_report_html(report_data)
        assert "<script>" not in html
        assert (
            "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in html or "&lt;script&gt;" in html
        )
        assert "<img src=x" not in html


class TestPdfGeneration:
    """Tests for PDF compilation and output validation."""

    def test_render_pdf_returns_valid_non_empty_bytes(self):
        """render_pdf produces valid standard PDF-1.4 bytes starting with %PDF."""
        html = "<html><body><h1>Forensic Report Test</h1><p>Sample report content</p></body></html>"
        pdf = render_pdf(html, title="Test Report")

        assert isinstance(pdf, bytes)
        assert len(pdf) > 200
        assert pdf.startswith(b"%PDF")
        assert b"%%EOF" in pdf

    def test_format_bytes_helper(self):
        """format_bytes formats numbers into readable byte/KB/MB/GB/TB strings."""
        assert format_bytes(500) == "500 B"
        assert format_bytes(1024) == "1.00 KB"
        assert format_bytes(1048576) == "1.00 MB"
        assert format_bytes(1073741824) == "1.00 GB"
        assert format_bytes(None) == "Unknown"


class TestReportStorageAndWORM:
    """Tests for storing generated PDF reports into WORM storage."""

    def test_upload_report_pdf_to_reports_container(self):
        """PDF report is stored in the 'reports' container with correct metadata."""
        incident_id = "INC-STORE-001"
        pdf_bytes = b"%PDF-1.4\n...fake pdf content...\n%%EOF\n"

        result = upload_report_pdf(incident_id, pdf_bytes, report_id="RPT-STORE-001")

        assert result["incidentId"] == incident_id
        assert result["reportId"] == "RPT-STORE-001"
        assert result["container"] == "reports"
        assert result["blobName"] == f"{incident_id}/RPT-STORE-001.pdf"
        assert "reports" in result["blobUri"]
        assert result["sizeBytes"] == len(pdf_bytes)
        assert len(result["sha256"]) == 64

        # Verify blob actually exists in mock storage
        estate = mocks.world()
        blob_key = (mocks.EVIDENCE_ACCOUNT, "reports", f"{incident_id}/RPT-STORE-001.pdf")
        assert blob_key in estate.blobs

        stored_blob = estate.blobs[blob_key]
        assert stored_blob.metadata["IncidentID"] == incident_id
        assert stored_blob.metadata["ReportId"] == "RPT-STORE-001"
        assert stored_blob.metadata["WORM"] == "true"

    def test_reports_container_worm_immutability_rejects_overwrite(self):
        """Attempting to overwrite a report in the WORM reports container is rejected."""
        incident_id = "INC-WORM-OVERWRITE"
        pdf_bytes = b"%PDF-1.4\n...original report...\n%%EOF\n"

        upload_report_pdf(incident_id, pdf_bytes, report_id="RPT-WORM-01")

        # Second upload with same name and overwrite=False should fail
        with pytest.raises(mocks.MockAzureError):
            upload_report_pdf(
                incident_id, b"%PDF-1.4\n...tampered...\n%%EOF\n", report_id="RPT-WORM-01"
            )

    def test_upload_rejects_empty_bytes(self):
        """Uploading empty bytes raises ValueError."""
        with pytest.raises(ValueError, match="empty"):
            upload_report_pdf("INC-ERR", b"")


class TestChainOfCustodyIntegrityVerification:
    """Tests for cryptographic verification of the SQL Ledger."""

    def test_tampered_ledger_fails_verification(self):
        """Tampering with an in-memory ledger entry causes verification to report Failed."""
        incident_id = "INC-TAMPER-001"
        ledger.record_evidence(
            {
                "IncidentId": incident_id,
                "BlobUri": f"https://mock.blob.core.windows.net/evidence/{incident_id}/evidence.raw",
                "BlobName": "evidence.raw",
                "ArtifactType": "MemoryDump",
                "SizeBytes": 1024,
                "Sha256Hash": "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
                "AcquiredUtc": "2026-10-24T00:00:00Z",
                "RecordedUtc": "2026-10-24T00:00:01Z",
                "InitiatorObjectId": "agent-007",
                "SourceHost": "host-1",
            }
        )

        # Before tampering
        v_clean = ledger.verify_custody_integrity()
        assert v_clean["verified"] is True
        assert v_clean["status"] == "Verified"

        # Tamper with the ledger row
        estate = mocks.world()
        estate.ledger_rows[0]["Sha256Hash"] = "TAMPERED_HASH_99999999999999999999999999999999"

        # After tampering
        v_tampered = ledger.verify_custody_integrity()
        assert v_tampered["verified"] is False
        assert v_tampered["status"] == "Failed"
        assert "tampering detected" in v_tampered["details"]


class TestReportGeneratorHttpBlueprint:
    """Tests for the Azure Functions HTTP trigger blueprint."""

    def test_http_trigger_success_canonical_route(self):
        """POST /api/GenerateReport returns 202 Accepted with report details."""
        fake_req = MagicMock()
        fake_req.get_json.return_value = {"IncidentID": "INC-HTTP-2026-001"}

        resp = generate_report_http(fake_req)
        assert resp.status_code == 202
        body = json.loads(resp.get_body().decode("utf-8"))

        assert body["status"] == "Accepted"
        assert body["incidentId"] == "INC-HTTP-2026-001"
        assert body["container"] == "reports"
        assert body["format"] == "pdf"
        assert "blobUri" in body
        assert "reportId" in body
        assert body["sizeBytes"] > 0

    def test_http_trigger_camel_case_param(self):
        """POST /api/GenerateReport accepts lowercase 'incidentId'."""
        fake_req = MagicMock()
        fake_req.get_json.return_value = {"incidentId": "INC-CAMEL-002"}

        resp = generate_report_http(fake_req)
        assert resp.status_code == 202
        body = json.loads(resp.get_body().decode("utf-8"))
        assert body["incidentId"] == "INC-CAMEL-002"

    def test_http_trigger_html_format(self):
        """POST /api/GenerateReport with format='html' returns rendered HTML."""
        fake_req = MagicMock()
        fake_req.get_json.return_value = {"IncidentID": "INC-HTML-003", "format": "html"}

        resp = generate_report_http(fake_req)
        assert resp.status_code == 202
        body = json.loads(resp.get_body().decode("utf-8"))
        assert body["format"] == "html"
        assert "<html" in body["content"].lower()
        assert "INC-HTML-003" in body["content"]

    def test_http_trigger_missing_incident_id(self):
        """Request missing 'IncidentID' returns HTTP 400."""
        fake_req = MagicMock()
        fake_req.get_json.return_value = {"other": "param"}

        resp = generate_report_http(fake_req)
        assert resp.status_code == 400
        body = json.loads(resp.get_body().decode("utf-8"))
        assert "IncidentID" in body["error"]

    def test_http_trigger_empty_incident_id(self):
        """Request with empty 'IncidentID' returns HTTP 400."""
        fake_req = MagicMock()
        fake_req.get_json.return_value = {"IncidentID": "   "}

        resp = generate_report_http(fake_req)
        assert resp.status_code == 400
        body = json.loads(resp.get_body().decode("utf-8"))
        assert "empty" in body["error"].lower() or "missing" in body["error"].lower()

    def test_http_trigger_invalid_json(self):
        """Malformed JSON payload returns HTTP 400."""
        fake_req = MagicMock()
        fake_req.get_json.side_effect = ValueError("Invalid JSON token")

        resp = generate_report_http(fake_req)
        assert resp.status_code == 400
        body = json.loads(resp.get_body().decode("utf-8"))
        assert "Invalid JSON" in body["error"]

    def test_http_trigger_unsupported_format(self):
        """Request with unsupported format returns HTTP 400."""
        fake_req = MagicMock()
        fake_req.get_json.return_value = {"IncidentID": "INC-BAD-FMT", "format": "docx"}

        resp = generate_report_http(fake_req)
        assert resp.status_code == 400
        body = json.loads(resp.get_body().decode("utf-8"))
        assert "Unsupported" in body["error"]

    def test_http_trigger_route_aliases(self):
        """All route aliases produce consistent 202 responses."""
        fake_req = MagicMock()
        fake_req.get_json.return_value = {"IncidentID": "INC-ALIAS-001"}

        r1 = generate_report_http(fake_req)
        r2 = report_generator_alias(fake_req)
        r3 = report_generate_path_alias(fake_req)

        assert r1.status_code == 202
        assert r2.status_code == 202
        assert r3.status_code == 202

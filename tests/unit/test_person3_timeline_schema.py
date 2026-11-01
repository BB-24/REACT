"""Unit tests for Person 3: Cosmos DB Serverless + Timeline Schema & Ingestion (Issue #33).

Covers:
- Acceptance Criteria 1: Cosmos DB Core (SQL) API Serverless
- Acceptance Criteria 2: Container timeline-artifacts with /incidentId partition key
- Acceptance Criteria 3: Schema: incidentId, artifactType, timestamp, source, data (JSON)
- Acceptance Criteria 4: Ingestion code writes parsed Plaso output to Cosmos DB
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from src.functions.shared.mocks._cosmos import (
    CosmosResourceNotFoundError,
    MockCosmosClient,
)
from src.functions.shared.timeline import (
    SchemaValidationError,
    TimelineArtifact,
    convert_plaso_event,
    generate_artifact_id,
    normalize_timestamp,
    validate_timeline_artifact,
)
from src.functions.shared.timeline_ingestion import (
    ingest_timeline,
    parse_timeline_content,
)
from src.functions.TimelineIngestion import ingest_timeline_http


class TestTimelineSchemaAndValidation:
    """Tests covering artifact schema contract and validation."""

    def test_valid_artifact_schema_creation_and_dict(self):
        """Valid artifact builds cleanly and produces required Cosmos DB schema."""
        artifact = TimelineArtifact(
            id="art-INC-2026-001-0001",
            incident_id="INC-2026-001",
            artifact_type="plaso:syslog",
            timestamp="2026-10-24T00:01:05Z",
            source="/var/log/syslog",
            data={"message": "sshd accepted publickey", "pid": 1234},
        )

        doc = artifact.to_dict()
        assert doc["id"] == "art-INC-2026-001-0001"
        assert doc["incidentId"] == "INC-2026-001"
        assert doc["IncidentID"] == "INC-2026-001"
        assert doc["artifactType"] == "plaso:syslog"
        assert doc["timestamp"] == "2026-10-24T00:01:05Z"
        assert doc["source"] == "/var/log/syslog"
        assert doc["data"]["pid"] == 1234

        validated = validate_timeline_artifact(doc)
        assert validated.incident_id == "INC-2026-001"
        assert validated.artifact_type == "plaso:syslog"

    @pytest.mark.parametrize("bad_incident_id", ["", "   ", None, 12345])
    def test_missing_or_invalid_incident_id(self, bad_incident_id):
        """Field 'incidentId' must be a non-empty string."""
        payload = {
            "id": "art-01",
            "incidentId": bad_incident_id,
            "artifactType": "plaso:syslog",
            "timestamp": "2026-10-24T00:00:00Z",
            "source": "syslog",
            "data": {"test": 1},
        }
        with pytest.raises(SchemaValidationError, match="incidentId"):
            validate_timeline_artifact(payload)

    @pytest.mark.parametrize("missing_field", ["artifactType", "source", "timestamp", "data"])
    def test_missing_required_fields(self, missing_field):
        """Missing artifactType, source, timestamp, or data raises SchemaValidationError."""
        payload = {
            "id": "art-01",
            "incidentId": "INC-2026-001",
            "artifactType": "plaso:syslog",
            "timestamp": "2026-10-24T00:00:00Z",
            "source": "/var/log/syslog",
            "data": {"msg": "hello"},
        }
        del payload[missing_field]

        with pytest.raises(SchemaValidationError, match=missing_field):
            validate_timeline_artifact(payload)

    def test_invalid_or_non_json_data(self):
        """Field 'data' must be a JSON-serializable dictionary."""
        # Non-dict data
        with pytest.raises(SchemaValidationError, match="must be a JSON object"):
            validate_timeline_artifact(
                {
                    "id": "art-01",
                    "incidentId": "INC-2026-001",
                    "artifactType": "plaso:syslog",
                    "timestamp": "2026-10-24T00:00:00Z",
                    "source": "syslog",
                    "data": "not a dict",
                }
            )

        # Dict with non-JSON serializable value (e.g. set or custom object)
        with pytest.raises(SchemaValidationError, match="non-JSON-serializable"):
            validate_timeline_artifact(
                {
                    "id": "art-01",
                    "incidentId": "INC-2026-001",
                    "artifactType": "plaso:syslog",
                    "timestamp": "2026-10-24T00:00:00Z",
                    "source": "syslog",
                    "data": {"bad_set": {1, 2, 3}},
                }
            )

    def test_timestamp_normalization_formats(self):
        """Timestamps are normalized consistently to UTC ISO-8601 strings."""
        # Microseconds (standard Plaso timestamp: e.g. 1729728000000000 us = 2024-10-24T00:00:00Z)
        us_ts = 1729728000000000
        norm_us = normalize_timestamp(us_ts)
        assert norm_us.startswith("2024-10-24T00:00:00")
        assert norm_us.endswith("Z")

        # ISO string with UTC offset
        iso_offset = "2026-10-24T05:30:00+05:30"
        norm_iso = normalize_timestamp(iso_offset)
        assert norm_iso == "2026-10-24T00:00:00Z"

        # Invalid timestamp string
        with pytest.raises(SchemaValidationError, match="Malformed ISO-8601"):
            normalize_timestamp("invalid-date-string")

        # Negative numeric timestamp
        with pytest.raises(SchemaValidationError, match="greater than zero"):
            normalize_timestamp(-100)

    def test_stable_and_unique_artifact_id_behavior(self):
        """Artifact ID generation is deterministic and stable across identical inputs."""
        incident = "INC-TEST-01"
        ts = "2026-10-24T00:00:00Z"
        source = "/var/log/auth.log"
        art_type = "plaso:syslog"
        data = {"event": "login", "user": "root"}

        id1 = generate_artifact_id(incident, ts, source, art_type, data)
        id2 = generate_artifact_id(incident, ts, source, art_type, data)
        assert id1 == id2
        assert id1.startswith("art-INC-TEST-01-")

        # Differing data yields differing ID
        id_diff = generate_artifact_id(incident, ts, source, art_type, {"event": "logout"})
        assert id1 != id_diff

        # Seed ID preservation
        assert (
            generate_artifact_id(incident, ts, source, art_type, data, seed_id="CUSTOM-ID-99")
            == "CUSTOM-ID-99"
        )

    def test_convert_representative_plaso_events(self):
        """Plaso parsed events (both JSON Lines and array entries) convert accurately."""
        # 1. Microsecond Plaso event
        plaso_evt_1 = {
            "timestamp": 1729728065123456,
            "data_type": "syslog:line",
            "source_long": "/var/log/syslog",
            "message": "CRON started job",
            "parser": "syslog",
            "pid": 4321,
        }
        converted_1 = convert_plaso_event(plaso_evt_1, incident_id="INC-2026-002")
        assert converted_1.incident_id == "INC-2026-002"
        assert converted_1.artifact_type == "syslog:line"
        assert converted_1.source == "/var/log/syslog"
        assert converted_1.data["message"] == "CRON started job"
        assert converted_1.data["pid"] == 4321

        # 2. ISO timestamped event
        plaso_evt_2 = {
            "Timestamp": "2026-10-08T03:14:07.123456Z",
            "DocType": "TimelineSummary",
            "Source": "FILE:NTFS $MFT",
            "message": "drivers/etc/hosts modified",
        }
        converted_2 = convert_plaso_event(plaso_evt_2, incident_id="INC-2026-002")
        assert converted_2.artifact_type == "TimelineSummary"
        assert converted_2.source == "FILE:NTFS $MFT"
        assert converted_2.timestamp == "2026-10-08T03:14:07.123456Z"


class TestTimelineIngestionEngine:
    """Tests for the Cosmos DB ingestion engine."""

    def test_parse_timeline_content_formats(self, tmp_path):
        """Engine parses both JSON Lines and JSON array formats cleanly."""
        # JSON Lines format
        json_lines = (
            '{"timestamp": "2026-10-24T00:00:01Z", "message": "event 1"}\n'
            '{"timestamp": "2026-10-24T00:00:02Z", "message": "event 2"}\n'
        )
        records, errs = parse_timeline_content(json_lines)
        assert len(records) == 2
        assert len(errs) == 0

        # JSON array format
        json_array = '[{"timestamp": "2026-10-24T00:00:01Z", "msg": "array event"}]'
        records_arr, errs_arr = parse_timeline_content(json_array)
        assert len(records_arr) == 1
        assert len(errs_arr) == 0

        # File path
        file_path = tmp_path / "timeline.json"
        file_path.write_text(json_lines, encoding="utf-8")
        records_file, _ = parse_timeline_content(file_path)
        assert len(records_file) == 2

    def test_successful_ingestion_with_mock_cosmos(self):
        """Timeline events are successfully converted and persisted to Cosmos DB."""
        client = MockCosmosClient()
        db = client.get_database_client("react-forensic-db")
        container = db.get_container_client("timeline-artifacts")

        json_lines = (
            '{"id": "EVT-1", "timestamp": "2026-10-24T00:00:01Z", "data_type": "syslog", "source": "/var/log/syslog", "message": "boot"}\n'
            '{"id": "EVT-2", "timestamp": "2026-10-24T00:00:02Z", "data_type": "auth", "source": "/var/log/auth.log", "message": "login"}\n'
        )

        summary = ingest_timeline(
            timeline_source=json_lines,
            incident_id="INC-2026-003",
            container_client=container,
        )

        assert summary.total_records == 2
        assert summary.written_records == 2
        assert summary.rejected_records == 0
        assert summary.is_success is True

        # Verify items stored in Cosmos DB container under partition key
        stored_item = container.read_item("EVT-1", "INC-2026-003")
        assert stored_item["incidentId"] == "INC-2026-003"
        assert stored_item["artifactType"] == "syslog"
        assert stored_item["data"]["message"] == "boot"

    def test_partition_key_consistency(self):
        """Partition key /incidentId is strictly enforced in container operations."""
        client = MockCosmosClient()
        container = client.get_database_client("react-forensic-db").get_container_client(
            "timeline-artifacts"
        )

        evt = [{"id": "EVT-PKEY-1", "timestamp": "2026-10-24T01:00:00Z", "msg": "test"}]
        ingest_timeline(evt, incident_id="INC-PKEY-999", container_client=container)

        # Confirm stored under INC-PKEY-999
        test_inc = "INC-PKEY-999"
        doc = container.read_item("EVT-PKEY-1", test_inc)
        assert doc["incidentId"] == "INC-PKEY-999"

        # Reading with incorrect partition key fails
        with pytest.raises(CosmosResourceNotFoundError):
            wrong_inc = "WRONG-INCIDENT"
            container.read_item("EVT-PKEY-1", wrong_inc)

    def test_empty_timeline_input(self):
        """Empty input produces zero written records without failure."""
        client = MockCosmosClient()
        container = client.get_database_client("db").get_container_client("timeline-artifacts")

        summary = ingest_timeline("", incident_id="INC-EMPTY", container_client=container)
        assert summary.total_records == 0
        assert summary.written_records == 0
        assert summary.rejected_records == 0

    def test_malformed_json_lines_handling(self):
        """Malformed JSON lines are safely rejected and counted without crashing valid lines."""
        client = MockCosmosClient()
        container = client.get_database_client("db").get_container_client("timeline-artifacts")

        mixed_content = (
            '{"id": "V1", "timestamp": "2026-10-24T00:00:01Z", "msg": "valid 1"}\n'
            "THIS IS CORRUPT NOT JSON\n"
            '{"id": "V2", "timestamp": "2026-10-24T00:00:02Z", "msg": "valid 2"}\n'
            '{"timestamp": null, "msg": "missing timestamp"}\n'
        )

        summary = ingest_timeline(
            mixed_content, incident_id="INC-MIXED", container_client=container
        )
        assert summary.written_records == 2
        assert summary.rejected_records == 2
        assert len(summary.errors) == 2

    def test_database_write_failure_handling(self):
        """Database write errors are recorded and do not falsely report success."""
        failing_container = MagicMock()
        failing_container.upsert_item.side_effect = RuntimeError("Cosmos DB throttled 429")

        events = [{"timestamp": "2026-10-24T00:00:01Z", "msg": "event"}]

        summary = ingest_timeline(
            events,
            incident_id="INC-FAIL",
            container_client=failing_container,
        )

        assert summary.written_records == 0
        assert summary.rejected_records == 1
        assert "Cosmos DB throttled 429" in summary.errors[0]

    def test_idempotent_duplicate_reingestion(self):
        """Re-ingesting the exact same timeline produces identical upserts without duplicate items."""
        client = MockCosmosClient()
        container = client.get_database_client("db").get_container_client("timeline-artifacts")

        content = '{"id": "IDEM-1", "timestamp": "2026-10-24T00:00:01Z", "msg": "first run"}\n'

        # First run
        s1 = ingest_timeline(content, incident_id="INC-IDEM", container_client=container)
        assert s1.written_records == 1
        assert container.count("INC-IDEM") == 1

        # Second run with exact same id
        s2 = ingest_timeline(content, incident_id="INC-IDEM", container_client=container)
        assert s2.written_records == 1
        assert container.count("INC-IDEM") == 1


class TestTimelineIngestionHttpBlueprint:
    """Tests for the Azure Functions HTTP trigger blueprint."""

    def test_http_trigger_success(self, monkeypatch):
        """HTTP trigger ingests timeline and returns 200 with summary."""
        monkeypatch.setenv("REACT_MOCK_MODE", "true")

        fake_req = MagicMock()
        fake_req.get_json.return_value = {
            "incidentId": "INC-HTTP-001",
            "events": [{"id": "H1", "timestamp": "2026-10-24T00:00:01Z", "msg": "http test"}],
        }

        resp = ingest_timeline_http(fake_req)
        assert resp.status_code == 200
        data = json.loads(resp.get_body().decode("utf-8"))
        assert data["incidentId"] == "INC-HTTP-001"
        assert data["writtenRecords"] == 1

    def test_http_trigger_missing_incident_id(self):
        """HTTP trigger returns 400 when incidentId is absent."""
        fake_req = MagicMock()
        fake_req.get_json.return_value = {"events": []}

        resp = ingest_timeline_http(fake_req)
        assert resp.status_code == 400
        assert "incidentId" in resp.get_body().decode("utf-8")

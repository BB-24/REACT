"""Unit tests for the Phase 3 hashing and ledger logic.

The blob client and SQL connection are both replaced with doubles, so these run
with no Azure dependency and no network.
"""
import hashlib
import json

import azure.functions as func
import pytest

from ChainOfCustody import (
    BLOB_CREATED_EVENT,
    VALIDATION_EVENT,
    handle_custody,
    process_blob_created,
    sha256_stream,
    split_blob_url,
)
from shared import config, ledger

BLOB_URL = "https://enclave.blob.core.windows.net/evidence/INC-1/web-01/memory.raw"


# --- URL parsing -------------------------------------------------------------


def test_splits_container_and_nested_blob_name():
    assert split_blob_url(BLOB_URL) == ("evidence", "INC-1/web-01/memory.raw")


def test_percent_encoding_is_decoded():
    url = "https://a.blob.core.windows.net/evidence/INC%2D1/mem%20dump.raw"
    assert split_blob_url(url) == ("evidence", "INC-1/mem dump.raw")


def test_url_without_blob_name_is_rejected():
    with pytest.raises(ValueError):
        split_blob_url("https://a.blob.core.windows.net/evidence")


# --- Streaming hash ----------------------------------------------------------


class _FakeDownloader:
    def __init__(self, chunks):
        self._chunks = chunks

    def chunks(self):
        return iter(self._chunks)


class _FakeProperties:
    def __init__(self, size, metadata=None):
        self.size = size
        self.metadata = metadata or {}
        self.creation_time = None


class _FakeBlobClient:
    def __init__(self, payload, metadata=None, declared_size=None, chunk=4):
        self._chunks = [
            payload[i:i + chunk] for i in range(0, len(payload), chunk)
        ] or [b""]
        self._size = declared_size if declared_size is not None else len(payload)
        self._metadata = metadata or {}

    def get_blob_properties(self):
        return _FakeProperties(self._size, self._metadata)

    def download_blob(self, **kwargs):
        return _FakeDownloader(self._chunks)


def test_chunked_hash_matches_whole_file_hash():
    payload = b"volatile memory contents" * 500
    digest, size = sha256_stream(_FakeBlobClient(payload))
    assert digest == hashlib.sha256(payload).hexdigest()
    assert size == len(payload)


# --- Event handling ----------------------------------------------------------


class _FakeCursor:
    def __init__(self, rowcount):
        self.rowcount = rowcount
        self.statements = []

    def execute(self, statement, values):
        self.statements.append((statement, values))


class _FakeConnection:
    def __init__(self, rowcount=1):
        self.cursor_obj = _FakeCursor(rowcount)
        self.committed = False
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


def _blob_created(url=BLOB_URL):
    return {"eventType": BLOB_CREATED_EVENT, "data": {"url": url}}


def _env(monkeypatch):
    monkeypatch.setenv("EVIDENCE_CONTAINER", "evidence")
    monkeypatch.setenv("LEDGER_TABLE", "dbo.EvidenceLedger")
    monkeypatch.setenv("LOGIC_APP_PRINCIPAL_ID", "aad-object-id")


def test_records_hash_size_and_incident(monkeypatch):
    _env(monkeypatch)
    payload = b"memory image bytes"
    connection = _FakeConnection()
    result = process_blob_created(
        _blob_created(),
        blob_client_factory=lambda url: _FakeBlobClient(payload),
        connection_factory=lambda: connection,
    )
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()
    assert result["sizeBytes"] == len(payload)
    assert result["status"] == "recorded"
    assert connection.committed

    _statement, values = connection.cursor_obj.statements[0]
    recorded = dict(zip(ledger.COLUMNS, values))
    assert recorded["IncidentId"] == "INC-1"
    assert recorded["ArtifactType"] == "memory-image"
    assert recorded["InitiatorObjectId"] == "aad-object-id"


def test_metadata_overrides_the_fallback_initiator(monkeypatch):
    _env(monkeypatch)
    connection = _FakeConnection()
    metadata = {
        "IncidentId": "INC-9",
        "initiatorobjectid": "logic-app-oid",
        "sourcehost": "web-01",
        "acquiredutc": "2024-01-01T00:00:00Z",
    }
    process_blob_created(
        _blob_created(),
        blob_client_factory=lambda url: _FakeBlobClient(b"abc", metadata),
        connection_factory=lambda: connection,
    )
    _statement, values = connection.cursor_obj.statements[0]
    recorded = dict(zip(ledger.COLUMNS, values))
    assert recorded["InitiatorObjectId"] == "logic-app-oid"
    assert recorded["IncidentId"] == "INC-9"
    assert recorded["SourceHost"] == "web-01"
    assert recorded["AcquiredUtc"] == "2024-01-01T00:00:00Z"


def test_witness_hash_mismatch_is_reported(monkeypatch):
    """A hash computed on the target that differs means transit tampering."""
    _env(monkeypatch)
    metadata = {"witnesssha256": "0" * 64}
    result = process_blob_created(
        _blob_created(),
        blob_client_factory=lambda url: _FakeBlobClient(b"abc", metadata),
        connection_factory=lambda: _FakeConnection(),
    )
    assert result["witnessMatch"] is False


def test_witness_hash_match_is_reported(monkeypatch):
    _env(monkeypatch)
    payload = b"abc"
    metadata = {"witnesssha256": hashlib.sha256(payload).hexdigest().upper()}
    result = process_blob_created(
        _blob_created(),
        blob_client_factory=lambda url: _FakeBlobClient(payload, metadata),
        connection_factory=lambda: _FakeConnection(),
    )
    assert result["witnessMatch"] is True


def test_size_mismatch_refuses_to_record(monkeypatch):
    _env(monkeypatch)
    connection = _FakeConnection()
    with pytest.raises(RuntimeError):
        process_blob_created(
            _blob_created(),
            blob_client_factory=lambda url: _FakeBlobClient(
                b"abc", declared_size=999
            ),
            connection_factory=lambda: connection,
        )
    assert connection.cursor_obj.statements == []


def test_blob_outside_enclave_container_is_skipped(monkeypatch):
    _env(monkeypatch)
    url = "https://enclave.blob.core.windows.net/scratch/INC-1/notes.txt"
    result = process_blob_created(
        _blob_created(url),
        blob_client_factory=lambda u: _FakeBlobClient(b"abc"),
        connection_factory=lambda: _FakeConnection(),
    )
    assert result["status"] == "skipped"


def test_duplicate_delivery_reports_duplicate_not_error(monkeypatch):
    """Event Grid delivers at least once; a replay must not be a failure."""
    _env(monkeypatch)
    result = process_blob_created(
        _blob_created(),
        blob_client_factory=lambda url: _FakeBlobClient(b"abc"),
        connection_factory=lambda: _FakeConnection(rowcount=0),
    )
    assert result["status"] == "duplicate"


# --- HTTP handler ------------------------------------------------------------


def _request(body):
    return func.HttpRequest(
        method="POST",
        url="/api/custody",
        headers={"Content-Type": "application/json"},
        body=json.dumps(body).encode("utf-8"),
    )


def test_answers_the_event_grid_validation_handshake():
    events = [{
        "eventType": VALIDATION_EVENT,
        "data": {"validationCode": "ABC-123"},
    }]
    response = handle_custody(_request(events))
    assert response.status_code == 200
    assert json.loads(response.get_body())["validationResponse"] == "ABC-123"


def test_validation_handshake_short_circuits_a_mixed_batch():
    events = [_blob_created(), {
        "eventType": VALIDATION_EVENT, "data": {"validationCode": "X"},
    }]
    response = handle_custody(
        _request(events),
        blob_client_factory=lambda url: pytest.fail("must not hash during handshake"),
    )
    assert json.loads(response.get_body())["validationResponse"] == "X"


def test_unrelated_event_types_are_ignored(monkeypatch):
    _env(monkeypatch)
    response = handle_custody(_request([{"eventType": "Microsoft.Storage.BlobDeleted"}]))
    assert response.status_code == 200
    assert json.loads(response.get_body())["processed"][0]["status"] == "ignored"


def test_malformed_json_returns_400():
    request = func.HttpRequest(
        method="POST", url="/api/custody",
        headers={"Content-Type": "application/json"}, body=b"{{{",
    )
    assert handle_custody(request).status_code == 400


# --- Ledger SQL --------------------------------------------------------------


def test_insert_is_guarded_against_duplicate_deliveries():
    statement = ledger.build_insert("dbo.EvidenceLedger")
    assert statement.count("?") == len(ledger.COLUMNS) + 2
    assert "WHERE NOT EXISTS" in statement
    assert "BlobUri = ? AND Sha256Hash = ?" in statement
    # A ledger table rejects UPDATE and DELETE by design.
    assert "UPDATE" not in statement.upper()
    assert "DELETE" not in statement.upper()


def test_table_name_from_config_is_validated(monkeypatch):
    monkeypatch.setenv("LEDGER_TABLE", "dbo.Evidence; DROP TABLE dbo.Ledger--")
    with pytest.raises(config.ConfigError):
        ledger.table_name()


def test_incomplete_entry_is_rejected():
    with pytest.raises(ValueError):
        ledger.record_evidence({"IncidentId": "INC-1"},
                               connection_factory=lambda: _FakeConnection())

"""Append-only chain-of-custody writes into Person 3's Azure SQL ledger table.

The target is an Azure SQL *ledger* table: rows can be inserted but never
updated or deleted, and the database maintains a cryptographically verifiable
digest of the insert history. That is what makes this table admissible as a
chain of custody rather than just an audit log -- so this module only ever
issues INSERTs.

Event Grid delivers *at least once*. Because we cannot delete a duplicate row
out of a ledger table after the fact, the insert is guarded with a
``WHERE NOT EXISTS`` on ``(BlobUri, Sha256Hash)`` and is therefore idempotent.

The expected schema is documented in
``src/functions/ChainOfCustody/LEDGER_CONTRACT.md``.
"""
import logging
import re

from . import clients, config

DEFAULT_TABLE = "dbo.EvidenceLedger"

# Column order is the INSERT order; ``record_evidence`` reads the entry dict
# using exactly these keys.
COLUMNS = (
    "IncidentId",
    "BlobUri",
    "BlobName",
    "ArtifactType",
    "SizeBytes",
    "Sha256Hash",
    "AcquiredUtc",
    "RecordedUtc",
    "InitiatorObjectId",
    "SourceHost",
)

# A table name cannot be parameterised, so it is interpolated into the SQL text.
# Validating it here stops a tampered application setting from becoming an
# injection point.
_TABLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")


def table_name():
    """Return the validated ledger table name from configuration."""
    name = config.get("LEDGER_TABLE", DEFAULT_TABLE)
    if not _TABLE_NAME.match(name):
        raise config.ConfigError(
            "LEDGER_TABLE must be a bare or schema-qualified identifier, got "
            "'{0}'.".format(name)
        )
    return name


def build_insert(table):
    """Return the idempotent INSERT statement for ``table``."""
    placeholders = ", ".join(["?"] * len(COLUMNS))
    return (
        "INSERT INTO {table} ({columns}) "
        "SELECT {placeholders} "
        "WHERE NOT EXISTS ("
        "SELECT 1 FROM {table} WHERE BlobUri = ? AND Sha256Hash = ?"
        ")".format(table=table, columns=", ".join(COLUMNS),
                   placeholders=placeholders)
    )


def build_lookup(table, columns):
    """Return the statement behind ``find_evidence``."""
    return (
        "SELECT TOP 1 {columns} FROM {table} "
        "WHERE IncidentId = ? AND ArtifactType = ? "
        "ORDER BY LedgerEntryId DESC".format(
            columns=", ".join(columns), table=table
        )
    )


LOOKUP_COLUMNS = ("BlobName", "Sha256Hash", "SizeBytes", "RecordedUtc")


def find_evidence(incident_id, artifact_type, connection_factory=None):
    """Return the most recent custody record of ``artifact_type``, or ``None``.

    This is the gate REQ-3.4.1 describes: disk snapshotting must not begin until
    the RAM dump is confirmed in the enclave, and the ledger row is the only
    confirmation that actually proves the bytes arrived and hashed cleanly.
    """
    statement = build_lookup(table_name(), LOOKUP_COLUMNS)
    factory = connection_factory or _connect
    connection = factory()
    try:
        cursor = connection.cursor()
        cursor.execute(statement, [incident_id, artifact_type])
        row = cursor.fetchone()
    finally:
        connection.close()

    if not row:
        return None
    return dict(zip(LOOKUP_COLUMNS, row))


def _connect():
    """Open a connection to the ledger database through the client seam."""
    return clients.sql_connection()


def record_evidence(entry, connection_factory=None):
    """Insert one custody record. Returns the number of rows actually written.

    A return value of ``0`` means the record was already present -- a replayed
    Event Grid delivery -- which is a success, not an error.
    """
    missing = [column for column in COLUMNS if column not in entry]
    if missing:
        raise ValueError(
            "Custody entry is missing required fields: {0}".format(
                ", ".join(missing)
            )
        )

    statement = build_insert(table_name())
    values = [entry[column] for column in COLUMNS]
    values.extend([entry["BlobUri"], entry["Sha256Hash"]])

    factory = connection_factory or _connect
    connection = factory()
    try:
        cursor = connection.cursor()
        cursor.execute(statement, values)
        written = cursor.rowcount
        connection.commit()
    finally:
        connection.close()

    if written == 0:
        logging.info(
            "Custody record for %s already present; duplicate Event Grid "
            "delivery ignored.", entry["BlobName"]
        )
    return written

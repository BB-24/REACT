"""Stand-in for the ``pyodbc`` connection to the Azure SQL Ledger database.

This is not a SQL engine. It understands exactly the two statement shapes
``shared.ledger`` issues -- the guarded append and the artifact lookup -- and
refuses everything else loudly, so a new query cannot silently return empty
results and be mistaken for "no evidence recorded".

Two behaviours of a real ledger table are reproduced deliberately, because they
are the behaviours the design leans on:

* **UPDATE and DELETE are rejected.** A ledger table is append-only, which is
  why ``record_evidence`` deduplicates at insert time instead of cleaning up
  after a replayed Event Grid delivery.
* **Every row extends a hash chain.** Azure SQL maintains a cryptographically
  verifiable digest of the insert history; ``World.verify_ledger`` recomputes
  the mock's equivalent, so tampering with a row in memory is detectable.
"""

import re

from . import _world
from ._world import MockAzureError

_INSERT = re.compile(
    r"^\s*INSERT\s+INTO\s+(?P<table>[A-Za-z0-9_.]+)\s*\((?P<columns>[^)]*)\)",
    re.IGNORECASE,
)
_LOOKUP = re.compile(
    r"^\s*SELECT\s+(?:TOP\s+\d+\s+)?(?P<columns>.+?)\s+FROM\s+"
    r"(?P<table>[A-Za-z0-9_.]+)\s+WHERE\s+IncidentId\s*=\s*\?\s+AND\s+"
    r"ArtifactType\s*=\s*\?",
    re.IGNORECASE | re.DOTALL,
)
_FORBIDDEN = re.compile(r"^\s*(UPDATE|DELETE|DROP|TRUNCATE|ALTER)\b", re.IGNORECASE)


class MockCursor:
    def __init__(self, world):
        self._world = world
        self.rowcount = -1
        self._results = []

    def execute(self, statement, parameters=None):
        parameters = list(parameters or [])

        if _FORBIDDEN.match(statement):
            raise MockAzureError(
                "Azure SQL Ledger tables reject UPDATE and DELETE. Statement: "
                f"{statement.strip()[:80]}"
            )

        insert = _INSERT.match(statement)
        if insert:
            self._execute_insert(insert, parameters)
            return self

        lookup = _LOOKUP.match(statement)
        if lookup:
            self._execute_lookup(lookup, parameters)
            return self

        raise MockAzureError(
            "The mock ledger does not understand this statement, so it will "
            f"not guess at a result: {statement.strip()[:120]}"
        )

    def _execute_insert(self, match, parameters):
        columns = [name.strip() for name in match.group("columns").split(",")]
        values = parameters[: len(columns)]
        guard = parameters[len(columns) :]

        row = dict(zip(columns, values, strict=False))

        # `... WHERE NOT EXISTS (SELECT 1 ... WHERE BlobUri = ? AND
        # Sha256Hash = ?)` -- the idempotency guard against Event Grid's
        # at-least-once delivery.
        if len(guard) == 2:
            blob_uri, digest = guard
            for existing in self._world.ledger_rows:
                if existing.get("BlobUri") == blob_uri and existing.get("Sha256Hash") == digest:
                    self.rowcount = 0
                    self._results = []
                    return

        self._world.append_ledger_row(row)
        self.rowcount = 1
        self._results = []

    def _execute_lookup(self, match, parameters):
        columns = [name.strip() for name in match.group("columns").split(",")]
        incident_id, artifact_type = parameters[0], parameters[1]
        matched = [
            row
            for row in self._world.ledger_rows
            if row.get("IncidentId") == incident_id and row.get("ArtifactType") == artifact_type
        ]
        matched.sort(key=lambda row: row["LedgerEntryId"], reverse=True)
        self._results = [tuple(row.get(column) for column in columns) for row in matched]
        self.rowcount = len(self._results)

    def fetchall(self):
        return list(self._results)

    def fetchone(self):
        return self._results[0] if self._results else None

    def close(self):
        self._results = []


class MockSqlConnection:
    def __init__(self):
        self._world = _world.world()
        self.closed = False

    def cursor(self):
        return MockCursor(self._world)

    def commit(self):
        return None

    def rollback(self):
        return None

    def close(self):
        self.closed = True


def connect(*args, **kwargs):
    return MockSqlConnection()

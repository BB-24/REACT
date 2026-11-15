"""Stand-in for ``azure.cosmos.CosmosClient`` and related database/container clients.

Covers:
- Person 3 / Issue #33 / REQ-3.6: Cosmos DB Core (SQL) API Serverless
- Provides an in-memory document store matching Azure Cosmos DB SDK semantics
  allowing offline unit and integration tests without touching cloud resources.
"""

from __future__ import annotations

import copy
from typing import Any


class CosmosError(Exception):
    """Base exception for mock Cosmos DB operations."""


class CosmosResourceNotFoundError(CosmosError):
    """Raised when an item, container, or database is not found."""


class CosmosResourceExistsError(CosmosError):
    """Raised when attempting to create an item that already exists."""


class CosmosHttpResponseError(CosmosError):
    """Raised when an HTTP-level error occurs against Cosmos DB."""


class MockContainerClient:
    """In-memory stand-in for ``azure.cosmos.ContainerProxy``."""

    def __init__(self, name: str, database: MockDatabaseClient) -> None:
        self.name = name
        self.database = database
        self._items: dict[tuple[str, str], dict[str, Any]] = {}

    def _extract_partition_key(self, doc: dict[str, Any]) -> str:
        val = doc.get("incidentId") or doc.get("IncidentID")
        if val is None or not str(val).strip():
            return "default"
        return str(val).strip()

    def upsert_item(self, body: dict[str, Any]) -> dict[str, Any]:
        """Create or update an item in the container (idempotent)."""
        if not isinstance(body, dict):
            raise TypeError("Item body must be a dictionary")

        doc = copy.deepcopy(body)
        if "id" not in doc or not str(doc["id"]).strip():
            raise ValueError("Item body missing required 'id' attribute.")

        item_id = str(doc["id"]).strip()
        partition_val = self._extract_partition_key(doc)
        key = (partition_val, item_id)

        self._items[key] = doc
        return copy.deepcopy(doc)

    def read_item(self, item: str, partition_key: str) -> dict[str, Any]:
        """Read a single item by id and partition key."""
        key = (str(partition_key).strip(), str(item).strip())
        if key not in self._items:
            raise CosmosResourceNotFoundError(
                f"Item '{item}' with partition key '{partition_key}' not found."
            )
        return copy.deepcopy(self._items[key])

    def delete_item(self, item: str, partition_key: str) -> None:
        """Delete an item by id and partition key."""
        key = (str(partition_key).strip(), str(item).strip())
        if key not in self._items:
            raise CosmosResourceNotFoundError(
                f"Item '{item}' with partition key '{partition_key}' not found."
            )
        del self._items[key]

    def query_items(
        self,
        query: str,
        parameters: list[dict[str, Any]] | None = None,
        partition_key: str | None = None,
        enable_cross_partition_query: bool = False,
    ) -> list[dict[str, Any]]:
        """Query items in the container matching partition key or query filter."""
        target_incident = str(partition_key).strip() if partition_key is not None else None
        if target_incident is None and parameters:
            for p in parameters:
                name = str(p.get("name", "")).lower().lstrip("@")
                if name in ("incidentid", "incident_id", "pk"):
                    target_incident = str(p.get("value", "")).strip()
                    break

        results = []
        for doc in self._items.values():
            doc_inc = str(doc.get("incidentId") or doc.get("IncidentID") or "").strip()
            if target_incident is not None:
                if doc_inc == target_incident:
                    results.append(copy.deepcopy(doc))
            else:
                results.append(copy.deepcopy(doc))
        return results

    def count(self, partition_key: str | None = None) -> int:
        """Helper to count items in container."""
        return len(self.query_items("", partition_key=partition_key))


class MockDatabaseClient:
    """In-memory stand-in for ``azure.cosmos.DatabaseClient``."""

    def __init__(self, name: str, client: MockCosmosClient) -> None:
        self.name = name
        self.client = client
        self._containers: dict[str, MockContainerClient] = {}

    def get_container_client(self, container: str) -> MockContainerClient:
        """Get or create mock container client."""
        if container not in self._containers:
            self._containers[container] = MockContainerClient(container, self)
        return self._containers[container]

    def create_container_if_not_exists(
        self, id: str, partition_key: Any = None, **kwargs: Any
    ) -> MockContainerClient:
        return self.get_container_client(id)


class MockCosmosClient:
    """In-memory stand-in for ``azure.cosmos.CosmosClient``."""

    _shared_instances: dict[str, MockCosmosClient] = {}

    def __init__(self, url: str | None = None, credential: Any = None, **kwargs: Any) -> None:
        self.url = url or "https://mock-react-cosmos.documents.azure.com:443/"
        self.credential = credential
        self._databases: dict[str, MockDatabaseClient] = {}

    def get_database_client(self, database: str) -> MockDatabaseClient:
        """Get or create mock database client."""
        if database not in self._databases:
            self._databases[database] = MockDatabaseClient(database, self)
        return self._databases[database]

    def create_database_if_not_exists(self, id: str, **kwargs: Any) -> MockDatabaseClient:
        return self.get_database_client(id)

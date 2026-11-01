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
    """In-memory stand-in for ``azure.cosmos.ContainerClient``."""

    def __init__(
        self, name: str, database: MockDatabaseClient, partition_key_path: str = "/incidentId"
    ) -> None:
        self.name = name
        self.database = database
        self.partition_key_path = partition_key_path
        # Key: (partition_key_value, item_id) -> document dict
        self._items: dict[tuple[str, str], dict[str, Any]] = {}

    def _extract_partition_key(self, body: dict[str, Any]) -> str:
        key_name = self.partition_key_path.lstrip("/")
        val = body.get(key_name)
        if val is None and key_name == "incidentId":
            val = body.get("IncidentID")
        if val is None or not str(val).strip():
            raise ValueError(f"Document missing required partition key '{self.partition_key_path}'")
        return str(val).strip()

    def create_item(
        self, body: dict[str, Any], enable_automatic_id_generation: bool = False
    ) -> dict[str, Any]:
        """Create a new item in the container."""
        if not isinstance(body, dict):
            raise TypeError("Item body must be a dictionary")

        doc = copy.deepcopy(body)
        if "id" not in doc or not str(doc["id"]).strip():
            if enable_automatic_id_generation:
                import uuid

                doc["id"] = str(uuid.uuid4())
            else:
                raise ValueError("Item body missing required 'id' attribute.")

        item_id = str(doc["id"]).strip()
        partition_val = self._extract_partition_key(doc)
        key = (partition_val, item_id)

        if key in self._items:
            raise CosmosResourceExistsError(
                f"Item with id '{item_id}' and partition key '{partition_val}' already exists."
            )

        self._items[key] = doc
        return copy.deepcopy(doc)

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
        """Query items in the container."""
        if partition_key is not None:
            pkey = str(partition_key).strip()
            return [copy.deepcopy(v) for k, v in self._items.items() if k[0] == pkey]
        return [copy.deepcopy(v) for v in self._items.values()]

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
        """Get or initialize a container client by name."""
        if container not in self._containers:
            self._containers[container] = MockContainerClient(container, self)
        return self._containers[container]

    def create_container_if_not_exists(
        self,
        id: str,
        partition_key: Any = None,
        **kwargs: Any,
    ) -> MockContainerClient:
        """Create or retrieve container."""
        return self.get_container_client(id)


class MockCosmosClient:
    """In-memory stand-in for ``azure.cosmos.CosmosClient``."""

    def __init__(
        self,
        url: str = "https://mock-cosmos.documents.azure.com:443/",
        credential: Any = None,
        **kwargs: Any,
    ) -> None:
        self.url = url
        self.credential = credential
        self._databases: dict[str, MockDatabaseClient] = {}

    def get_database_client(self, database: str) -> MockDatabaseClient:
        """Get or initialize a database client by name."""
        if database not in self._databases:
            self._databases[database] = MockDatabaseClient(database, self)
        return self._databases[database]

    def create_database_if_not_exists(self, id: str, **kwargs: Any) -> MockDatabaseClient:
        """Create or retrieve database."""
        return self.get_database_client(id)

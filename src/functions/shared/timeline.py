"""Timeline artifact schema and normalization for Azure Cosmos DB ingestion.

Covers:
- Person 3 / Issue #33 / REQ-3.6:
  - Cosmos DB timeline artifact schema:
    {
      "id": "<stable-unique-artifact-id>",
      "incidentId": "<incident-identifier>",
      "artifactType": "<artifact-type>",
      "timestamp": "<normalized-timestamp>",
      "source": "<source-tool-or-evidence-reference>",
      "data": { ... }
    }
  - Partition key: /incidentId
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import datetime, timezone
from typing import Any


class SchemaValidationError(ValueError):
    """Raised when an artifact does not conform to the timeline schema."""


def normalize_timestamp(ts: Any) -> str:
    """Normalize a timestamp into an ISO-8601 UTC string.

    Supports:
    - Microseconds since epoch (standard Plaso timestamp format)
    - Milliseconds since epoch
    - Seconds since epoch
    - ISO-8601 formatted strings (e.g. '2026-10-24T00:00:01Z')
    - datetime instances
    """
    if ts is None or ts == "":
        raise SchemaValidationError("Timestamp cannot be empty or None")

    if isinstance(ts, (int, float)):
        if ts <= 0:
            raise SchemaValidationError(f"Numeric timestamp must be greater than zero, got: {ts}")
        # Plaso timestamps are typically integer microseconds since Unix epoch
        if ts >= 1e14:  # microseconds (e.g. 1729728000000000)
            seconds = ts / 1_000_000.0
        elif ts >= 1e11:  # milliseconds (e.g. 1729728000000)
            seconds = ts / 1_000.0
        else:  # seconds (e.g. 1729728000)
            seconds = float(ts)

        try:
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (ValueError, OverflowError, OSError) as err:
            raise SchemaValidationError(f"Invalid numeric timestamp value: {ts}") from err

        iso = dt.isoformat()
        if iso.endswith("+00:00"):
            iso = iso[:-6] + "Z"
        return iso

    if isinstance(ts, str):
        cleaned = ts.strip()
        if not cleaned:
            raise SchemaValidationError("Timestamp string cannot be empty")
        # Try parsing ISO formatted string
        # Replace Z with +00:00 for standard fromisoformat if needed
        iso_candidate = cleaned
        if iso_candidate.endswith("Z"):
            iso_candidate = iso_candidate[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(iso_candidate)
        except ValueError as err:
            raise SchemaValidationError(
                f"Malformed ISO-8601 timestamp string: '{cleaned}'"
            ) from err

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)

        iso = dt.isoformat()
        if iso.endswith("+00:00"):
            iso = iso[:-6] + "Z"
        return iso

    if isinstance(ts, datetime):
        dt = ts
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        iso = dt.isoformat()
        if iso.endswith("+00:00"):
            iso = iso[:-6] + "Z"
        return iso

    raise SchemaValidationError(f"Unsupported timestamp type: {type(ts).__name__}")


def generate_artifact_id(
    incident_id: str,
    timestamp: str,
    source: str,
    artifact_type: str,
    data: dict[str, Any],
    seed_id: str | None = None,
) -> str:
    """Generate a stable, unique artifact identifier.

    If a non-empty seed_id is provided, it is sanitized and returned.
    Otherwise, a deterministic SHA-256 prefix hash is produced.
    """
    if seed_id and str(seed_id).strip():
        return str(seed_id).strip()

    try:
        data_serialized = json.dumps(data, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        data_serialized = str(sorted(str(k) for k in data.keys()))

    hasher = hashlib.sha256()
    hasher.update(incident_id.encode("utf-8"))
    hasher.update(b":")
    hasher.update(timestamp.encode("utf-8"))
    hasher.update(b":")
    hasher.update(source.encode("utf-8"))
    hasher.update(b":")
    hasher.update(artifact_type.encode("utf-8"))
    hasher.update(b":")
    hasher.update(data_serialized.encode("utf-8"))
    digest = hasher.hexdigest()[:16]

    return f"art-{incident_id}-{digest}"


@dataclasses.dataclass(frozen=True)
class TimelineArtifact:
    """Immutable data model representing a timeline artifact stored in Cosmos DB."""

    id: str
    incident_id: str
    artifact_type: str
    timestamp: str
    source: str
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert the artifact to a Cosmos DB document with required schema keys."""
        return {
            "id": self.id,
            "incidentId": self.incident_id,
            "IncidentID": self.incident_id,  # Compatibility alias for co-located partitioning
            "artifactType": self.artifact_type,
            "timestamp": self.timestamp,
            "source": self.source,
            "data": self.data,
        }


def validate_timeline_artifact(payload: dict[str, Any] | TimelineArtifact) -> TimelineArtifact:
    """Validate that a dict or model satisfies the timeline artifact schema.

    Returns the validated TimelineArtifact instance, or raises SchemaValidationError.
    """
    if isinstance(payload, TimelineArtifact):
        # Validate internal fields
        item = payload.to_dict()
    elif isinstance(payload, dict):
        item = payload
    else:
        raise SchemaValidationError(
            f"Expected dict or TimelineArtifact, got {type(payload).__name__}"
        )

    # 1. Validate incidentId
    incident_id = item.get("incidentId") or item.get("incident_id") or item.get("IncidentID")
    if not incident_id or not isinstance(incident_id, str) or not incident_id.strip():
        raise SchemaValidationError("Field 'incidentId' must be a non-empty string.")
    incident_id = incident_id.strip()

    # 2. Validate artifactType
    artifact_type = (
        item.get("artifactType") or item.get("artifact_type") or item.get("ArtifactType")
    )
    if not artifact_type or not isinstance(artifact_type, str) or not artifact_type.strip():
        raise SchemaValidationError("Field 'artifactType' must be a non-empty string.")
    artifact_type = artifact_type.strip()

    # 3. Validate timestamp
    raw_timestamp = item.get("timestamp") or item.get("Timestamp")
    if raw_timestamp is None:
        raise SchemaValidationError("Field 'timestamp' is required.")
    normalized_ts = normalize_timestamp(raw_timestamp)

    # 4. Validate source
    source = item.get("source") or item.get("Source")
    if not source or not isinstance(source, str) or not source.strip():
        raise SchemaValidationError("Field 'source' must be a non-empty string.")
    source = source.strip()

    # 5. Validate data (JSON object)
    data = item.get("data")
    if data is None and "Data" in item:
        data = item["Data"]
    if data is None:
        raise SchemaValidationError("Field 'data' is required.")
    if not isinstance(data, dict):
        raise SchemaValidationError(
            f"Field 'data' must be a JSON object (dict), got {type(data).__name__}."
        )

    # Verify JSON serialization
    try:
        json.dumps(data)
    except (TypeError, ValueError) as err:
        raise SchemaValidationError(
            f"Field 'data' contains non-JSON-serializable content: {err}"
        ) from err

    # 6. Validate id
    artifact_id = item.get("id")
    if not artifact_id or not isinstance(artifact_id, str) or not artifact_id.strip():
        # Generate stable ID if missing
        artifact_id = generate_artifact_id(incident_id, normalized_ts, source, artifact_type, data)
    else:
        artifact_id = artifact_id.strip()

    return TimelineArtifact(
        id=artifact_id,
        incident_id=incident_id,
        artifact_type=artifact_type,
        timestamp=normalized_ts,
        source=source,
        data=data,
    )


def convert_plaso_event(
    event: dict[str, Any],
    incident_id: str,
    default_source: str = "plaso",
) -> TimelineArtifact:
    """Convert a parsed Plaso timeline event entry into a validated TimelineArtifact."""
    if not incident_id or not isinstance(incident_id, str) or not incident_id.strip():
        raise SchemaValidationError("incident_id must be provided as a non-empty string.")
    incident_id = incident_id.strip()

    if not isinstance(event, dict):
        raise SchemaValidationError(f"Expected event dictionary, got {type(event).__name__}")

    # Extract timestamp from Plaso fields
    raw_ts = (
        event.get("timestamp")
        or event.get("Timestamp")
        or event.get("datetime")
        or event.get("date_time")
        or event.get("time")
    )
    if raw_ts is None:
        raise SchemaValidationError(
            f"Plaso event has no timestamp field (keys present: {list(event.keys())})"
        )
    normalized_ts = normalize_timestamp(raw_ts)

    # Extract artifactType
    artifact_type = (
        event.get("data_type")
        or event.get("artifactType")
        or event.get("artifact_type")
        or event.get("ArtifactType")
        or event.get("parser")
        or event.get("DocType")
        or "plaso:timeline_event"
    )
    if not isinstance(artifact_type, str) or not artifact_type.strip():
        artifact_type = "plaso:timeline_event"
    artifact_type = artifact_type.strip()

    # Extract source
    source = (
        event.get("source_long")
        or event.get("source_short")
        or event.get("display_name")
        or event.get("filename")
        or event.get("source")
        or event.get("Source")
        or default_source
    )
    if not isinstance(source, str) or not source.strip():
        source = default_source
    source = source.strip()

    # Extract payload data: if event has a nested 'data' dict, use it;
    # otherwise capture the event dict fields
    if "data" in event and isinstance(event["data"], dict):
        data = dict(event["data"])
    else:
        # Preserve original fields
        data = {k: v for k, v in event.items() if k not in ("incidentId", "IncidentID")}

    # Validate JSON serializability of data
    try:
        json.dumps(data)
    except (TypeError, ValueError) as err:
        raise SchemaValidationError(f"Parsed Plaso event contains non-JSON data: {err}") from err

    # Deterministic or existing ID
    raw_id = event.get("id") or event.get("uuid")
    artifact_id = generate_artifact_id(
        incident_id,
        normalized_ts,
        source,
        artifact_type,
        data,
        seed_id=str(raw_id) if raw_id else None,
    )

    return TimelineArtifact(
        id=artifact_id,
        incident_id=incident_id,
        artifact_type=artifact_type,
        timestamp=normalized_ts,
        source=source,
        data=data,
    )

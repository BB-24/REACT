"""Timeline artifact schema definitions, validation, and conversion helpers.

Covers:
- Person 3 / Issue #33 / REQ-3.6: Cosmos DB Core (SQL) API Serverless
- Canonical Timeline Artifact Schema for incident investigation records
- Plaso/Log2Timeline output normalization into structured Cosmos DB items
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
from datetime import datetime, timezone
from typing import Any


class SchemaValidationError(ValueError):
    """Raised when a timeline artifact fails schema validation."""


def normalize_timestamp(raw_value: Any) -> str:
    """Normalize raw timestamp into ISO-8601 UTC with trailing 'Z'."""
    if raw_value is None:
        raise SchemaValidationError("Timestamp cannot be null/None.")

    if isinstance(raw_value, (int, float)):
        # Common Plaso epoch formats: microseconds or seconds
        try:
            val = float(raw_value)
            if val > 1e14:  # microseconds
                dt = datetime.fromtimestamp(val / 1e6, tz=timezone.utc)
            elif val > 1e11:  # milliseconds
                dt = datetime.fromtimestamp(val / 1e3, tz=timezone.utc)
            else:  # seconds
                dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except (ValueError, OverflowError, OSError) as exc:
            raise SchemaValidationError(
                f"Invalid numeric epoch timestamp '{raw_value}': {exc}"
            ) from exc

    if isinstance(raw_value, datetime):
        if raw_value.tzinfo is None:
            raw_value = raw_value.replace(tzinfo=timezone.utc)
        else:
            raw_value = raw_value.astimezone(timezone.utc)
        return raw_value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    if isinstance(raw_value, str):
        cleaned = raw_value.strip()
        if not cleaned:
            raise SchemaValidationError("Timestamp string cannot be empty or whitespace.")

        # If already formatted with 'Z'
        if cleaned.endswith("Z"):
            try:
                dt = datetime.fromisoformat(cleaned[:-1]).replace(tzinfo=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                pass

        try:
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError as exc:
            raise SchemaValidationError(
                f"Cannot parse timestamp '{raw_value}' into valid UTC datetime: {exc}"
            ) from exc

    raise SchemaValidationError(f"Unsupported timestamp type: {type(raw_value).__name__}")


def generate_artifact_id(
    incident_id: str,
    timestamp: str,
    source: str,
    artifact_type: str,
    data: dict[str, Any],
    seed_id: str | None = None,
) -> str:
    """Generate a deterministic, stable unique item identifier for Cosmos DB."""
    if seed_id and str(seed_id).strip():
        cleaned_seed = str(seed_id).strip()
        return (
            f"art-{incident_id}-{cleaned_seed}"
            if not cleaned_seed.startswith("art-")
            else cleaned_seed
        )

    hasher = hashlib.sha256()
    hasher.update(incident_id.encode("utf-8"))
    hasher.update(b"|")
    hasher.update(timestamp.encode("utf-8"))
    hasher.update(b"|")
    hasher.update(source.encode("utf-8"))
    hasher.update(b"|")
    hasher.update(artifact_type.encode("utf-8"))
    hasher.update(b"|")
    payload = json.dumps(data, sort_keys=True, default=str)
    hasher.update(payload.encode("utf-8"))
    return f"art-{incident_id}-{hasher.hexdigest()[:16]}"


@dataclasses.dataclass(frozen=True)
class TimelineArtifact:
    """Canonical model for forensic timeline items stored in Cosmos DB."""

    id: str
    incidentId: str
    artifactType: str
    timestamp: str
    source: str
    data: dict[str, Any]

    def to_cosmos_item(self) -> dict[str, Any]:
        """Convert dataclass to a JSON-compatible Cosmos DB document dictionary."""
        item = dataclasses.asdict(self)
        item["IncidentID"] = self.incidentId
        return item


def validate_timeline_artifact(artifact: dict[str, Any] | TimelineArtifact) -> TimelineArtifact:
    """Validate a timeline artifact dictionary against the canonical schema."""
    if isinstance(artifact, TimelineArtifact):
        d = artifact.to_cosmos_item()
    elif isinstance(artifact, dict):
        d = copy.deepcopy(artifact)
    else:
        raise SchemaValidationError(
            f"Expected dict or TimelineArtifact, got {type(artifact).__name__}"
        )

    incident_id = d.get("incidentId") or d.get("IncidentID")
    if not incident_id or not isinstance(incident_id, str) or not incident_id.strip():
        raise SchemaValidationError(f"Invalid or missing 'incidentId': {incident_id!r}")
    incident_id = incident_id.strip()

    artifact_type = d.get("artifactType") or d.get("DocType")
    if not artifact_type or not isinstance(artifact_type, str) or not artifact_type.strip():
        raise SchemaValidationError(f"Invalid or missing 'artifactType': {artifact_type!r}")
    artifact_type = artifact_type.strip()

    source = (
        d.get("source")
        or d.get("Source")
        or d.get("sourceType")
        or d.get("SourceType")
        or "unknown"
    )
    if not isinstance(source, str) or not source.strip():
        source = "unknown"
    source = source.strip()

    raw_ts = d.get("timestamp") or d.get("Timestamp") or d.get("datetime")
    if raw_ts is None:
        raise SchemaValidationError("Artifact is missing required 'timestamp' field.")
    normalized_ts = normalize_timestamp(raw_ts)

    data = d.get("data")
    if data is None:
        skip_keys = {
            "id",
            "incidentId",
            "IncidentID",
            "artifactType",
            "DocType",
            "timestamp",
            "Timestamp",
            "source",
            "Source",
            "sourceType",
            "SourceType",
        }
        data = {k: v for k, v in d.items() if k not in skip_keys}
    elif not isinstance(data, dict):
        raise SchemaValidationError(
            f"'data' attribute must be a dictionary, got {type(data).__name__}"
        )

    try:
        json.dumps(data, default=str)
    except (TypeError, ValueError) as exc:
        raise SchemaValidationError(f"'data' payload is not JSON-serializable: {exc}") from exc

    raw_id = d.get("id") or d.get("ID")
    item_id = generate_artifact_id(
        incident_id=incident_id,
        timestamp=normalized_ts,
        source=source,
        artifact_type=artifact_type,
        data=data,
        seed_id=str(raw_id) if raw_id else None,
    )

    return TimelineArtifact(
        id=item_id,
        incidentId=incident_id,
        artifactType=artifact_type,
        timestamp=normalized_ts,
        source=source,
        data=data,
    )

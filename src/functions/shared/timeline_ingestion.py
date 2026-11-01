"""Cosmos DB ingestion engine for forensic timeline artifacts.

Covers:
- Person 3 / Issue #33 / REQ-3.6:
  - Ingestion of parsed Plaso timeline JSON output into Azure Cosmos DB Serverless.
  - Target container: timeline-artifacts with /incidentId partition key.
  - Supports streaming JSON Lines and JSON array payloads.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import pathlib
from collections.abc import Sequence
from typing import Any

from . import clients
from .timeline import (
    SchemaValidationError,
    convert_plaso_event,
    validate_timeline_artifact,
)

logger = logging.getLogger(__name__)


class IngestionError(RuntimeError):
    """Raised when timeline ingestion cannot proceed or fails critically."""


@dataclasses.dataclass
class IngestionSummary:
    """Summary metrics of a timeline ingestion execution."""

    incident_id: str
    total_records: int = 0
    written_records: int = 0
    rejected_records: int = 0
    errors: list[str] = dataclasses.field(default_factory=list)

    @property
    def is_success(self) -> bool:
        """True if at least one record was written and no records were rejected."""
        return self.written_records > 0 and self.rejected_records == 0

    def to_dict(self) -> dict[str, Any]:
        """Convert summary to JSON-serializable dictionary."""
        return {
            "incidentId": self.incident_id,
            "totalRecords": self.total_records,
            "writtenRecords": self.written_records,
            "rejectedRecords": self.rejected_records,
            "success": self.is_success,
            "errors": self.errors,
        }


def parse_timeline_content(
    timeline_source: str | bytes | pathlib.Path | Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse raw timeline content from a file path, string, bytes, or pre-parsed sequence.

    Returns:
        (records, parse_errors) tuple.
    """
    parse_errors: list[str] = []

    # Case 1: Already a sequence of dictionaries
    if isinstance(timeline_source, (list, tuple)):
        valid_dicts = []
        for idx, item in enumerate(timeline_source):
            if isinstance(item, dict):
                valid_dicts.append(item)
            else:
                parse_errors.append(
                    f"Item at index {idx} is not a JSON object: {type(item).__name__}"
                )
        return valid_dicts, parse_errors

    raw_text: str = ""

    # Case 2: Path-like or existing file
    if isinstance(timeline_source, pathlib.Path):
        if not timeline_source.exists():
            raise FileNotFoundError(f"Timeline file not found: {timeline_source}")
        raw_text = timeline_source.read_text(encoding="utf-8")
    elif isinstance(timeline_source, bytes):
        raw_text = timeline_source.decode("utf-8", errors="replace")
    elif isinstance(timeline_source, str):
        # Check if the string is a file path pointing to an existing file
        if len(timeline_source) < 4096 and os.path.exists(timeline_source):
            path = pathlib.Path(timeline_source)
            if not path.is_file():
                raise FileNotFoundError(f"Timeline path is not a file: {timeline_source}")
            raw_text = path.read_text(encoding="utf-8")
        else:
            raw_text = timeline_source

    cleaned = raw_text.strip()
    if not cleaned:
        return [], []

    # Attempt parsing as a complete JSON structure (e.g. JSON array)
    if cleaned.startswith("[") and cleaned.endswith("]"):
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, list):
                records = []
                for idx, elem in enumerate(parsed):
                    if isinstance(elem, dict):
                        records.append(elem)
                    else:
                        parse_errors.append(f"Array element at index {idx} is not a JSON object")
                return records, parse_errors
        except json.JSONDecodeError as err:
            parse_errors.append(f"Invalid JSON array syntax: {err}")

    # Fallback / Standard Plaso output: JSON Lines (one JSON object per line)
    records: list[dict[str, Any]] = []
    for line_no, line in enumerate(cleaned.splitlines(), start=1):
        line_str = line.strip()
        if not line_str:
            continue
        try:
            item = json.loads(line_str)
            if isinstance(item, dict):
                records.append(item)
            else:
                parse_errors.append(f"Line {line_no} does not contain a JSON object")
        except json.JSONDecodeError as err:
            parse_errors.append(f"Line {line_no}: Malformed JSON line: {err}")

    return records, parse_errors


def ingest_timeline(
    timeline_source: str | bytes | pathlib.Path | Sequence[dict[str, Any]],
    incident_id: str,
    container_client: Any | None = None,
    endpoint: str | None = None,
    database_name: str | None = None,
    container_name: str | None = None,
    default_source: str = "plaso",
    stop_on_error: bool = False,
) -> IngestionSummary:
    """Read parsed Plaso timeline output, validate schema, and persist to Cosmos DB.

    Args:
        timeline_source: File path, JSON string, bytes, or list of event dicts.
        incident_id: The partition key identifier for the incident.
        container_client: Optional injected Cosmos DB ContainerClient (used for testing).
        endpoint: Optional Cosmos DB account endpoint override.
        database_name: Optional database name override.
        container_name: Optional container name override.
        default_source: Fallback source name if missing in event.
        stop_on_error: If True, immediately raise on write/conversion failure.

    Returns:
        IngestionSummary containing detailed metrics.
    """
    if not incident_id or not isinstance(incident_id, str) or not incident_id.strip():
        raise SchemaValidationError("incident_id must be provided as a non-empty string.")
    incident_id = incident_id.strip()

    # Resolve Cosmos DB ContainerClient
    if container_client is None:
        try:
            container_client = clients.cosmos_container_client(
                endpoint=endpoint,
                database_name=database_name,
                container_name=container_name,
            )
        except Exception as err:
            raise IngestionError(f"Failed to initialize Cosmos DB container client: {err}") from err

    summary = IngestionSummary(incident_id=incident_id)

    # Parse timeline source
    raw_events, parse_errors = parse_timeline_content(timeline_source)
    for parse_err in parse_errors:
        summary.rejected_records += 1
        summary.total_records += 1
        summary.errors.append(parse_err)
        logger.warning("Timeline parse error for incident %s: %s", incident_id, parse_err)

    if not raw_events and summary.total_records == 0:
        logger.info("Timeline input was empty for incident %s; no records ingested.", incident_id)
        return summary

    for event in raw_events:
        summary.total_records += 1
        try:
            # Normalize to canonical schema
            artifact = convert_plaso_event(
                event, incident_id=incident_id, default_source=default_source
            )
            validated = validate_timeline_artifact(artifact)
            item_doc = validated.to_dict()

            # Persist to Cosmos DB using partition key /incidentId
            container_client.upsert_item(item_doc)
            summary.written_records += 1

        except SchemaValidationError as err:
            summary.rejected_records += 1
            err_msg = f"Schema validation failed: {err}"
            summary.errors.append(err_msg)
            logger.warning("Rejected record for incident %s: %s", incident_id, err_msg)
            if stop_on_error:
                raise IngestionError(err_msg) from err

        except Exception as err:
            summary.rejected_records += 1
            err_msg = f"Database write failed for artifact: {type(err).__name__} - {err}"
            summary.errors.append(err_msg)
            logger.error("Cosmos DB write failure for incident %s: %s", incident_id, err_msg)
            if stop_on_error:
                raise IngestionError(err_msg) from err

    logger.info(
        "Completed timeline ingestion for incident %s: %d written, %d rejected out of %d total records.",
        incident_id,
        summary.written_records,
        summary.rejected_records,
        summary.total_records,
    )
    return summary

"""Phase 3 -- Chain-of-custody hashing (SOP 2, Phase 3).

Subscribed to ``Microsoft.Storage.BlobCreated`` on the enclave container via
Event Grid. On each new artifact it computes a SHA-256 over the blob and appends
one immutable row to Person 3's Azure SQL ledger table.

Two deliberate departures from a naive implementation:

**The blob is streamed, not loaded.** A memory image from a 16 GB VM is 16 GB;
a Consumption-plan Function has roughly 1.5 GB of RAM. The hash is folded chunk
by chunk, so peak memory is one chunk regardless of image size, and the digest
is byte-for-byte identical to hashing the whole file at once.

**Event Grid delivery is at-least-once.** The ledger table is append-only, so a
duplicate row could never be cleaned up. Deduplication therefore happens at
insert time -- see ``shared.ledger.record_evidence``.

This is an HTTP-triggered webhook rather than an ``eventGridTrigger`` binding,
per SOP 2 Phase 3.2, so it also answers the subscription validation handshake.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobClient

from shared import config, ledger

bp = func.Blueprint()

VALIDATION_EVENT = "Microsoft.EventGrid.SubscriptionValidationEvent"
BLOB_CREATED_EVENT = "Microsoft.Storage.BlobCreated"

DEFAULT_CHUNK_BYTES = 8 * 1024 * 1024

_credential = None


def _default_credential():
    global _credential
    if _credential is None:
        _credential = DefaultAzureCredential()
    return _credential


def split_blob_url(blob_url):
    """Return ``(container, blob_name)`` from a blob URL, percent-decoded."""
    path = urlparse(blob_url).path.lstrip("/")
    container, separator, blob_name = path.partition("/")
    if not separator or not blob_name:
        raise ValueError("Malformed blob URL: {0}".format(blob_url))
    return unquote(container), unquote(blob_name)


def sha256_stream(blob_client):
    """Fold a SHA-256 over the blob in chunks. Returns ``(hexdigest, bytes)``.

    Peak memory is one chunk, so a multi-gigabyte memory image hashes inside a
    Consumption-plan Function without ever being fully resident.
    """
    digest = hashlib.sha256()
    total = 0
    downloader = blob_client.download_blob(max_concurrency=1)
    for chunk in downloader.chunks():
        digest.update(chunk)
        total += len(chunk)
    return digest.hexdigest(), total


def _artifact_type(blob_name):
    lowered = blob_name.lower()
    if lowered.endswith(".raw") or lowered.endswith(".lime"):
        return "memory-image"
    if lowered.endswith(".vhd"):
        return "disk-image"
    return "artifact"


def process_blob_created(event, blob_client_factory=None,
                         connection_factory=None):
    """Hash one created blob and append its custody record. Returns a summary."""
    data = event.get("data") or {}
    blob_url = data.get("url")
    if not blob_url:
        raise ValueError("BlobCreated event carried no blob URL.")

    container, blob_name = split_blob_url(blob_url)
    expected_container = config.get("EVIDENCE_CONTAINER", "evidence")
    if container != expected_container:
        logging.info(
            "Ignoring blob in container '%s'; the enclave container is '%s'.",
            container, expected_container,
        )
        return {"blobName": blob_name, "status": "skipped",
                "reason": "outside-enclave-container"}

    chunk_size = config.get_int("HASH_CHUNK_BYTES", DEFAULT_CHUNK_BYTES)
    factory = blob_client_factory or (
        lambda url: BlobClient.from_blob_url(
            url,
            credential=_default_credential(),
            max_chunk_get_size=chunk_size,
        )
    )
    blob_client = factory(blob_url)

    properties = blob_client.get_blob_properties()
    digest, hashed_bytes = sha256_stream(blob_client)

    declared_size = getattr(properties, "size", None)
    if declared_size is not None and declared_size != hashed_bytes:
        # The blob changed underneath us, or the read was truncated. Either way
        # the digest does not describe the stored object, so refuse to record it.
        raise RuntimeError(
            "Size mismatch hashing {0}: blob reports {1} bytes, read {2}. "
            "Refusing to write an unverifiable custody record.".format(
                blob_name, declared_size, hashed_bytes
            )
        )

    metadata = {
        str(key).lower(): value
        for key, value in (getattr(properties, "metadata", None) or {}).items()
    }

    # The acquisition scripts stamp these on the Put Block List commit; the app
    # setting is the fallback when an artifact arrives by another route.
    initiator = metadata.get("initiatorobjectid") or config.get(
        "LOGIC_APP_PRINCIPAL_ID", "unknown"
    )
    incident_id = metadata.get("incidentid") or blob_name.split("/")[0]
    acquired_utc = metadata.get("acquiredutc") or _isoformat(
        getattr(properties, "creation_time", None)
    )

    entry = {
        "IncidentId": incident_id,
        "BlobUri": blob_url,
        "BlobName": blob_name,
        "ArtifactType": _artifact_type(blob_name),
        "SizeBytes": hashed_bytes,
        "Sha256Hash": digest,
        "AcquiredUtc": acquired_utc,
        "RecordedUtc": datetime.now(timezone.utc).isoformat(),
        "InitiatorObjectId": initiator,
        "SourceHost": metadata.get("sourcehost", "unknown"),
    }

    written = ledger.record_evidence(entry, connection_factory=connection_factory)
    logging.info(
        "Custody record for %s: sha256=%s size=%d rows=%d",
        blob_name, digest, hashed_bytes, written,
    )

    result = {
        "blobName": blob_name,
        "sha256": digest,
        "sizeBytes": hashed_bytes,
        "status": "recorded" if written else "duplicate",
    }

    # The witness hash is computed on the target host while the image streams
    # out. Matching it here proves the bytes were not altered in transit.
    witness = metadata.get("witnesssha256")
    if witness:
        result["witnessMatch"] = witness.lower() == digest
        if not result["witnessMatch"]:
            logging.error(
                "INTEGRITY ALERT: witness hash %s from the acquiring host does "
                "not match the enclave hash %s for %s.",
                witness, digest, blob_name,
            )
    return result


def _isoformat(value):
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def handle_custody(req, blob_client_factory=None, connection_factory=None):
    """Core handler, kept free of decorators so it is directly unit-testable."""
    try:
        body = req.get_json()
    except ValueError:
        return _json_response(400, {"error": "Request body is not valid JSON."})

    events = body if isinstance(body, list) else [body]

    # Event Grid proves it owns the endpoint before delivering anything, and
    # this handshake must be answered on its own, ahead of any other work.
    for event in events:
        if isinstance(event, dict) and event.get("eventType") == VALIDATION_EVENT:
            code = (event.get("data") or {}).get("validationCode")
            logging.info("Answering Event Grid subscription validation.")
            return _json_response(200, {"validationResponse": code})

    results = []
    for event in events:
        if not isinstance(event, dict):
            continue
        event_type = event.get("eventType")
        if event_type != BLOB_CREATED_EVENT:
            logging.info("Ignoring unsupported event type '%s'.", event_type)
            results.append({"status": "ignored", "eventType": event_type})
            continue
        results.append(
            process_blob_created(
                event,
                blob_client_factory=blob_client_factory,
                connection_factory=connection_factory,
            )
        )

    return _json_response(200, {"processed": results})


def _json_response(status_code, body):
    return func.HttpResponse(
        json.dumps(body),
        status_code=status_code,
        mimetype="application/json",
    )


@bp.route(route="custody", methods=["POST"])
def chain_of_custody(req: func.HttpRequest) -> func.HttpResponse:
    try:
        return handle_custody(req)
    except Exception as error:  # noqa: BLE001
        # A 5xx makes Event Grid retry with backoff and eventually dead-letter,
        # so a transient SQL or storage fault never loses a custody record.
        logging.exception("Chain-of-custody processing failed.")
        return _json_response(
            500, {"error": "Custody recording failed: {0}".format(error)}
        )

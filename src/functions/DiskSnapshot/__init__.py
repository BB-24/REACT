"""Phase 2b -- Non-volatile disk acquisition (SOP 2, Phase 2 / SRS 3.4).

Runs after the memory image is safely in the enclave. Snapshots every managed
disk attached to the target, then copies each snapshot across the subscription
boundary into the Forensic Enclave resource group.

Requirement mapping:

* **REQ-3.4.1** -- snapshotting is gated on the RAM dump being confirmed. The
  gate is a custody row in the ledger, not the Logic App's word for it: only a
  ledger row proves the bytes arrived *and* hashed cleanly.
* **REQ-3.4.2** -- every snapshot carries ``IncidentId``, ``Timestamp`` and
  ``OriginalVMName`` tags.
* **REQ-3.4.3** -- the enclave copy lives in a different subscription. An
  attacker holding Contributor on the compromised subscription can delete the
  source disks and the source snapshots; the enclave copy is outside their
  RBAC scope entirely.

Memory first, disks second, and never the reverse: snapshotting is a
control-plane operation that can induce I/O and page-cache pressure on the
target, which perturbs exactly the volatile state Phase 2 is trying to preserve.

**Why a manifest blob.** Exporting snapshots to VHD would move terabytes for no
evidentiary gain -- the snapshot is already immutable and already hashed by the
platform. Instead this writes a JSON manifest naming every snapshot, its source
disk and its enclave location. That manifest lands in the evidence container,
raises ``BlobCreated``, and so gets hashed into the ledger by ChainOfCustody on
exactly the same path as the memory image. The chain of custody therefore
covers the disk evidence without moving it.
"""
import hashlib
import json
import logging
import re
from datetime import datetime, timezone

import azure.functions as func

from ChainOfCustody import MEMORY_IMAGE
from NetworkContainment import ContainmentError, parse_target_vm
from shared import clients, config, ledger, sas

bp = func.Blueprint()

SNAPSHOT_PREFIX = "snap"
# Azure caps snapshot names at 80 characters.
MAX_SNAPSHOT_NAME = 80

_DISK_ID = re.compile(
    r"^/subscriptions/(?P<subscription>[^/]+)"
    r"/resourceGroups/(?P<resource_group>[^/]+)"
    r"/providers/Microsoft\.Compute/disks/(?P<name>[^/]+)/?$",
    re.IGNORECASE,
)


class SnapshotError(ValueError):
    """Raised when the target's disks cannot be resolved or snapshotted."""


def collect_managed_disks(vm):
    """Return ``[{'id', 'name', 'role', 'lun'}]`` for every managed disk.

    Unmanaged (page-blob) disks are reported rather than silently dropped: they
    cannot be snapshotted through this API, and an investigator must not be left
    believing a disk was captured when it was not.
    """
    profile = getattr(vm, "storage_profile", None)
    if profile is None:
        raise SnapshotError(
            "VM '{0}' exposes no storage profile.".format(getattr(vm, "name", "?"))
        )

    disks = []
    unmanaged = []

    os_disk = getattr(profile, "os_disk", None)
    if os_disk is not None:
        managed = getattr(os_disk, "managed_disk", None)
        identifier = getattr(managed, "id", None)
        if identifier:
            disks.append(
                {"id": identifier, "name": _disk_name(identifier), "role": "os",
                 "lun": None}
            )
        else:
            unmanaged.append(getattr(os_disk, "name", "os-disk"))

    for data_disk in getattr(profile, "data_disks", None) or []:
        managed = getattr(data_disk, "managed_disk", None)
        identifier = getattr(managed, "id", None)
        if identifier:
            disks.append(
                {
                    "id": identifier,
                    "name": _disk_name(identifier),
                    "role": "data",
                    "lun": getattr(data_disk, "lun", None),
                }
            )
        else:
            unmanaged.append(getattr(data_disk, "name", "data-disk"))

    if not disks:
        raise SnapshotError(
            "VM '{0}' has no managed disks to snapshot.".format(
                getattr(vm, "name", "?")
            )
        )
    return disks, unmanaged


def _disk_name(disk_id):
    match = _DISK_ID.match(disk_id)
    if not match:
        raise SnapshotError("Unrecognised managed disk ID: {0}".format(disk_id))
    return match.group("name")


def snapshot_name(incident_id, disk_name, stamp, suffix=""):
    """Return a collision-free, Azure-legal snapshot name."""
    base = "{0}-{1}-{2}-{3}".format(
        SNAPSHOT_PREFIX, sas.slug(incident_id), sas.slug(disk_name), stamp
    )
    if suffix:
        base = "{0}-{1}".format(base, suffix)
    return base[:MAX_SNAPSHOT_NAME].rstrip("-")


def build_tags(incident_id, vm_name, timestamp, extra=None):
    """REQ-3.4.2. Tag keys are exactly what the SRS names."""
    tags = {
        "IncidentId": str(incident_id),
        "Timestamp": timestamp,
        "OriginalVMName": str(vm_name),
        "react:purpose": "forensic-disk-acquisition",
    }
    tags.update(extra or {})
    return tags


def create_source_snapshot(compute_client, resource_group, name, disk, location,
                           tags):
    """REQ-3.4.1. A full (not incremental) point-in-time copy of one disk."""
    body = {
        "location": location,
        "tags": tags,
        # Full, not incremental: an incremental snapshot is a delta against its
        # predecessors, so it is not self-contained evidence.
        "incremental": False,
        "creation_data": {
            "create_option": "Copy",
            "source_resource_id": disk["id"],
        },
    }
    logging.info("Snapshotting %s disk '%s'.", disk["role"], disk["name"])
    return compute_client.snapshots.begin_create_or_update(
        resource_group, name, body
    ).result()


def copy_to_enclave(enclave_client, resource_group, name, source_snapshot,
                    location, tags):
    """REQ-3.4.3. Copy the snapshot into the enclave subscription.

    ``CopyStart`` is the asynchronous server-side copy: it is what makes a
    cross-subscription (and cross-region) copy possible without staging the data
    through this function.
    """
    body = {
        "location": location,
        "tags": tags,
        "incremental": False,
        "creation_data": {
            "create_option": "CopyStart",
            "source_resource_id": source_snapshot.id,
        },
    }
    logging.info("Copying snapshot '%s' into the forensic enclave.", name)
    return enclave_client.snapshots.begin_create_or_update(
        resource_group, name, body
    ).result()


def serialise_manifest(manifest):
    """Return the exact bytes to be stored, and their SHA-256.

    The digest must be taken over the stored bytes and nothing else, so it can
    never be folded back into the document it describes. It travels in blob
    metadata instead -- the same witness-hash arrangement the acquisition
    scripts use, and it is what lets ChainOfCustody's independently computed
    hash be compared rather than merely trusted.
    """
    body = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    return body, hashlib.sha256(body).hexdigest()


def write_manifest(manifest, incident_id, vm_name, now, credential=None):
    """Store the manifest in the evidence container so custody covers it."""
    account = config.require("EVIDENCE_STORAGE_ACCOUNT")
    container = config.get("EVIDENCE_CONTAINER", "evidence")
    blob_name = sas.build_blob_name(
        incident_id, vm_name, artifact="snapshots", extension="snapshot.json",
        now=now,
    )
    body, witness = serialise_manifest(manifest)

    client = clients.blob_client(
        sas.account_url(account), container, blob_name, cred=credential
    )
    client.upload_blob(
        body,
        overwrite=False,
        metadata={
            "incidentid": str(incident_id),
            "sourcehost": str(vm_name),
            "acquiredutc": now.isoformat(),
            "witnesssha256": witness,
            "acquisitiontool": "react-disksnapshot",
            "initiatorobjectid": str(manifest.get("initiatorObjectId", "")),
        },
    )
    return blob_name, witness


def handle_snapshot(req, credential=None, connection_factory=None):
    """Core handler, kept free of decorators so it is directly unit-testable."""
    try:
        payload = req.get_json()
    except ValueError:
        return _json_response(400, {"error": "Request body is not valid JSON."})

    if not isinstance(payload, dict):
        return _json_response(400, {"error": "Request body must be a JSON object."})

    lowered = {str(key).lower(): value for key, value in payload.items()}
    incident_id = lowered.get("incidentid") or lowered.get("incident_id")
    if not incident_id:
        return _json_response(400, {"error": "Payload must include 'IncidentId'."})

    try:
        subscription, resource_group, vm_name = parse_target_vm(payload)
    except ContainmentError as error:
        return _json_response(400, {"error": str(error)})

    # REQ-3.4.1: the RAM dump must be in the enclave and hashed first.
    skip_gate = str(lowered.get("skipmemorygate", "")).lower() in ("1", "true", "yes")
    memory_record = ledger.find_evidence(
        str(incident_id), MEMORY_IMAGE, connection_factory=connection_factory
    )
    if memory_record is None and not skip_gate:
        return _json_response(
            409,
            {
                "error": (
                    "No memory-image custody record exists for incident {0}. "
                    "Disk snapshotting is gated on confirmed RAM acquisition "
                    "(REQ-3.4.1). Pass 'skipMemoryGate': true only when memory "
                    "acquisition was deliberately skipped.".format(incident_id)
                ),
                "incidentId": str(incident_id),
            },
        )

    credential = credential or clients.credential()
    compute_client = clients.compute_client(subscription, cred=credential)
    vm = compute_client.virtual_machines.get(resource_group, vm_name)

    try:
        disks, unmanaged = collect_managed_disks(vm)
    except SnapshotError as error:
        return _json_response(400, {"error": str(error)})

    enclave_subscription = config.require("FORENSIC_SUBSCRIPTION_ID")
    enclave_group = config.require("FORENSIC_RESOURCE_GROUP")
    enclave_location = config.get("FORENSIC_LOCATION", vm.location)
    enclave_client = clients.compute_client(
        enclave_subscription, cred=credential
    )

    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    tags = build_tags(incident_id, vm_name, now.isoformat())

    captured = []
    for disk in disks:
        source_name = snapshot_name(incident_id, disk["name"], stamp)
        disk_group = _DISK_ID.match(disk["id"]).group("resource_group")

        source_snapshot = create_source_snapshot(
            compute_client, disk_group, source_name, disk, vm.location, tags
        )
        enclave_name = snapshot_name(incident_id, disk["name"], stamp, "enclave")
        enclave_snapshot = copy_to_enclave(
            enclave_client, enclave_group, enclave_name, source_snapshot,
            enclave_location, tags,
        )
        captured.append(
            {
                "diskName": disk["name"],
                "diskRole": disk["role"],
                "lun": disk["lun"],
                "sourceDiskId": disk["id"],
                "sourceSnapshotId": source_snapshot.id,
                "enclaveSnapshotId": enclave_snapshot.id,
                "enclaveSubscriptionId": enclave_subscription,
                "enclaveResourceGroup": enclave_group,
                "sizeGb": getattr(enclave_snapshot, "disk_size_gb", None),
                "completionPercent": getattr(
                    enclave_snapshot, "completion_percent", None
                ),
            }
        )

    initiator = lowered.get("initiatorobjectid") or config.get(
        "LOGIC_APP_PRINCIPAL_ID", "unknown"
    )
    manifest = {
        "incidentId": str(incident_id),
        "originalVmName": vm_name,
        "sourceSubscriptionId": subscription,
        "sourceResourceGroup": resource_group,
        "capturedUtc": now.isoformat(),
        "initiatorObjectId": initiator,
        "tags": tags,
        "snapshots": captured,
        "unmanagedDisksSkipped": unmanaged,
        "memoryCustodyRecord": memory_record,
    }
    manifest_blob, manifest_witness = write_manifest(
        manifest, incident_id, vm_name, now, credential=credential
    )

    if unmanaged:
        logging.warning(
            "Incident %s: %d unmanaged disk(s) on %s could not be snapshotted: %s",
            incident_id, len(unmanaged), vm_name, ", ".join(unmanaged),
        )

    return _json_response(
        200,
        {
            "status": "snapshotted",
            "incidentId": str(incident_id),
            "targetVm": vm_name,
            "snapshotCount": len(captured),
            "snapshots": captured,
            "unmanagedDisksSkipped": unmanaged,
            "manifestBlob": manifest_blob,
            "manifestSha256": manifest_witness,
            "memoryGate": "satisfied" if memory_record else "skipped",
            "custody": "pending-event-grid",
        },
    )


def _json_response(status_code, body):
    return func.HttpResponse(
        json.dumps(body),
        status_code=status_code,
        mimetype="application/json",
    )


@bp.route(route="snapshot", methods=["POST"])
def disk_snapshot(req: func.HttpRequest) -> func.HttpResponse:
    try:
        return handle_snapshot(req)
    except config.ConfigError as error:
        logging.exception("Snapshotting blocked by configuration error.")
        return _json_response(500, {"error": str(error)})
    except Exception as error:  # noqa: BLE001 - the Logic App needs a verdict
        logging.exception("Disk snapshotting failed.")
        return _json_response(
            500, {"error": "Disk snapshotting failed: {0}".format(error)}
        )

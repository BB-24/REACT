"""Unit tests for disk acquisition (REQ-3.4.1 - REQ-3.4.3)."""
import json

import pytest

from DiskSnapshot import (
    SnapshotError,
    build_tags,
    collect_managed_disks,
    handle_snapshot,
    serialise_manifest,
    snapshot_name,
)
from MemoryAcquisition import handle_acquisition
from shared import mocks
from shared.mocks import Model

WINDOWS_VM = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourceGroups/rg-victims"
    "/providers/Microsoft.Compute/virtualMachines/web-01"
)
DISK_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourceGroups/rg-victims"
    "/providers/Microsoft.Compute/disks/web-01-osdisk"
)


def _acquire_memory_first(post, incident="INC-1", vm=WINDOWS_VM):
    """Satisfy the REQ-3.4.1 gate by running acquisition and letting it hash."""
    handle_acquisition(post({"IncidentId": incident, "TargetVM": vm}))
    mocks.drain_events()


# --- Disk enumeration --------------------------------------------------------


def test_os_and_data_disks_are_both_collected():
    vm = Model(
        name="web-01",
        storage_profile=Model(
            os_disk=Model(name="os", managed_disk=Model(id=DISK_ID)),
            data_disks=[
                Model(lun=0, managed_disk=Model(id=DISK_ID.replace("osdisk", "d0")))
            ],
        ),
    )
    disks, unmanaged = collect_managed_disks(vm)
    assert [disk["role"] for disk in disks] == ["os", "data"]
    assert unmanaged == []


def test_unmanaged_disks_are_reported_not_silently_dropped():
    """An investigator must never believe a disk was captured when it was not."""
    vm = Model(
        name="legacy-01",
        storage_profile=Model(
            os_disk=Model(name="os", managed_disk=Model(id=DISK_ID)),
            data_disks=[Model(lun=0, name="page-blob-disk", managed_disk=None)],
        ),
    )
    disks, unmanaged = collect_managed_disks(vm)
    assert len(disks) == 1
    assert unmanaged == ["page-blob-disk"]


def test_vm_with_no_managed_disks_is_rejected():
    vm = Model(
        name="empty",
        storage_profile=Model(os_disk=None, data_disks=[]),
    )
    with pytest.raises(SnapshotError):
        collect_managed_disks(vm)


# --- Tagging (REQ-3.4.2) -----------------------------------------------------


def test_tags_carry_the_three_required_keys():
    tags = build_tags("INC-1", "web-01", "2026-01-01T00:00:00+00:00")
    assert tags["IncidentId"] == "INC-1"
    assert tags["OriginalVMName"] == "web-01"
    assert tags["Timestamp"] == "2026-01-01T00:00:00+00:00"


def test_snapshot_name_is_sanitised_and_capped():
    name = snapshot_name("../../etc", "disk/name", "20260101T000000Z")
    assert ".." not in name and "/" not in name
    assert len(name) <= 80


def test_snapshot_names_differ_between_source_and_enclave_copy():
    stamp = "20260101T000000Z"
    assert snapshot_name("INC-1", "d", stamp) != snapshot_name(
        "INC-1", "d", stamp, "enclave"
    )


# --- Manifest ----------------------------------------------------------------


def test_manifest_digest_covers_exactly_the_stored_bytes():
    """The witness hash must describe the bytes ChainOfCustody will hash, so it
    can never be folded into the document it describes."""
    import hashlib

    body, digest = serialise_manifest({"incidentId": "INC-1", "snapshots": []})
    assert hashlib.sha256(body).hexdigest() == digest


def test_manifest_serialisation_is_deterministic():
    first, digest_one = serialise_manifest({"b": 2, "a": 1})
    second, digest_two = serialise_manifest({"a": 1, "b": 2})
    assert first == second and digest_one == digest_two


# --- The REQ-3.4.1 gate ------------------------------------------------------


def test_snapshotting_is_blocked_until_memory_is_in_the_ledger(
    mock_estate, post, body
):
    response = handle_snapshot(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    assert response.status_code == 409
    assert "memory-image custody record" in body(response)["error"]
    assert mock_estate.snapshots == {}


def test_gate_can_be_overridden_explicitly(mock_estate, post, body):
    response = handle_snapshot(
        post({
            "IncidentId": "INC-1",
            "TargetVM": WINDOWS_VM,
            "skipMemoryGate": True,
        })
    )
    assert response.status_code == 200
    assert body(response)["memoryGate"] == "skipped"


def test_gate_opens_once_the_custody_row_exists(mock_estate, post, body):
    _acquire_memory_first(post)
    response = handle_snapshot(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    assert response.status_code == 200
    assert body(response)["memoryGate"] == "satisfied"


# --- Snapshot and cross-subscription copy (REQ-3.4.1, REQ-3.4.3) -------------


def test_every_disk_is_snapshotted_and_copied_to_the_enclave(
    mock_estate, post, body
):
    _acquire_memory_first(post)
    payload = body(
        handle_snapshot(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    )

    # web-01 is seeded with one OS disk and one data disk.
    assert payload["snapshotCount"] == 2
    for entry in payload["snapshots"]:
        assert entry["sourceSnapshotId"] != entry["enclaveSnapshotId"]
        assert entry["enclaveSubscriptionId"] == mocks.ENCLAVE_SUBSCRIPTION
        assert entry["enclaveResourceGroup"] == mocks.ENCLAVE_RESOURCE_GROUP


def test_enclave_copy_lands_outside_the_compromised_subscription(
    mock_estate, post, body
):
    """REQ-3.4.3: Contributor on the compromised subscription must not reach it."""
    _acquire_memory_first(post)
    payload = body(
        handle_snapshot(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    )
    for entry in payload["snapshots"]:
        assert mocks.COMPROMISED_SUBSCRIPTION in entry["sourceSnapshotId"]
        assert mocks.ENCLAVE_SUBSCRIPTION in entry["enclaveSnapshotId"]
        assert mocks.COMPROMISED_SUBSCRIPTION not in entry["enclaveSnapshotId"]


def test_enclave_copy_uses_copystart(mock_estate, post):
    """CopyStart is what makes a cross-subscription server-side copy possible."""
    _acquire_memory_first(post)
    handle_snapshot(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))

    enclave = [
        snap for snap in mock_estate.snapshots.values()
        if snap.subscription_id == mocks.ENCLAVE_SUBSCRIPTION
    ]
    assert enclave
    assert all(snap.creation_data.create_option == "CopyStart" for snap in enclave)


def test_snapshots_are_full_not_incremental(mock_estate, post):
    """An incremental snapshot is a delta, so it is not self-contained evidence."""
    _acquire_memory_first(post)
    handle_snapshot(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    assert all(
        snap.incremental is False for snap in mock_estate.snapshots.values()
    )


def test_every_snapshot_is_tagged(mock_estate, post):
    _acquire_memory_first(post)
    handle_snapshot(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    for snap in mock_estate.snapshots.values():
        assert snap.tags["IncidentId"] == "INC-1"
        assert snap.tags["OriginalVMName"] == "web-01"
        assert snap.tags["Timestamp"]


# --- Manifest custody --------------------------------------------------------


def test_manifest_lands_in_the_evidence_container_and_is_hashed(
    mock_estate, post, body
):
    _acquire_memory_first(post)
    payload = body(
        handle_snapshot(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    )

    delivered = mocks.drain_events()
    assert delivered[0]["status"] == "recorded"
    assert delivered[0]["witnessMatch"] is True
    assert delivered[0]["sha256"] == payload["manifestSha256"]

    types = [row["ArtifactType"] for row in mock_estate.ledger_rows]
    assert types == ["memory-image", "snapshot-manifest"]


def test_manifest_names_every_snapshot(mock_estate, post, body):
    _acquire_memory_first(post)
    payload = body(
        handle_snapshot(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    )
    stored = mock_estate.get_blob(
        mocks.EVIDENCE_ACCOUNT, mocks.EVIDENCE_CONTAINER, payload["manifestBlob"]
    )
    manifest = json.loads(stored.data)
    assert len(manifest["snapshots"]) == 2
    assert manifest["originalVmName"] == "web-01"
    assert manifest["memoryCustodyRecord"]["Sha256Hash"]


def test_linux_vm_with_two_data_disks_is_fully_captured(mock_estate, post, body):
    linux_vm = WINDOWS_VM.replace("web-01", "db-02")
    _acquire_memory_first(post, incident="INC-9", vm=linux_vm)
    payload = body(
        handle_snapshot(post({"IncidentId": "INC-9", "TargetVM": linux_vm}))
    )
    assert payload["snapshotCount"] == 3


def test_missing_incident_id_returns_400(mock_estate, post):
    assert handle_snapshot(post({"TargetVM": WINDOWS_VM})).status_code == 400

"""Stand-in for ``azure.mgmt.compute.ComputeManagementClient``.

Covers exactly the three operation groups REACT uses: reading VMs and their
managed disks, running the live-response script through the Run Command API
(REQ-3.3.1), and creating/copying snapshots (REQ-3.4.1 - REQ-3.4.3).

The Run Command simulation is the interesting part. Rather than pretending the
script ran, it performs the *effect* the script would have: it synthesises a
memory image, uploads it to the blob the write-only SAS points at, stamps the
same metadata the real ``Acquire-Memory.ps1`` stamps on its Put Block List
commit, and lets the resulting ``BlobCreated`` event flow on to ChainOfCustody.
The pipeline downstream of acquisition is therefore exercised for real.
"""

import hashlib
import json
from urllib.parse import urlparse

from . import _world
from ._world import MockAzureError, Model

# Small enough to hash instantly in a test, large enough to prove the chunked
# hashing path in ChainOfCustody actually loops.
DEFAULT_IMAGE_BYTES = 1024 * 1024


class _Poller:
    """Stand-in for an ``LROPoller``. The mock completes synchronously."""

    def __init__(self, value):
        self._value = value

    def result(self, timeout=None):
        return self._value

    def done(self):
        return True

    def status(self):
        return "Succeeded"


def synthesize_memory_image(seed_text, size_bytes=DEFAULT_IMAGE_BYTES):
    """Return deterministic bytes standing in for a raw memory image.

    Deterministic so a given incident always produces the same SHA-256, which
    makes the custody assertions in the tests stable.
    """
    banner = (
        f"REACT MOCK MEMORY IMAGE -- {seed_text}\n"
        "Not real volatile memory. Replace mock mode with Azure to capture "
        "the genuine article.\n"
    ).encode()

    body = bytearray(banner)
    counter = 0
    while len(body) < size_bytes:
        body.extend(hashlib.sha256(f"{seed_text}:{counter}".encode()).digest())
        counter += 1
    return bytes(body[:size_bytes])


def parse_blob_sas_url(url):
    """Return ``(account, container, blob_name)`` from a blob SAS URL."""
    parsed = urlparse(url)
    account = parsed.netloc.split(".", 1)[0]
    path = parsed.path.lstrip("/")
    container, separator, blob_name = path.partition("/")
    if not separator or not blob_name:
        raise MockAzureError(f"Not a blob SAS URL: {url}")
    return account, container, blob_name


def _flatten_parameters(run_command):
    """Merge plain and protected Run Command parameters into one dict."""
    merged = {}
    for field in ("parameters", "protected_parameters", "protectedParameters"):
        for item in run_command.get(field) or []:
            if isinstance(item, dict):
                merged[item.get("name")] = item.get("value")
            else:
                merged[getattr(item, "name", None)] = getattr(item, "value", None)
    merged.pop(None, None)
    return merged


class _VirtualMachinesOperations:
    def __init__(self, world, subscription_id):
        self._world = world
        self._subscription = subscription_id

    def get(self, resource_group_name, vm_name, **kwargs):
        key = _world.vm_id(self._subscription, resource_group_name, vm_name).lower()
        try:
            return self._world.vms[key]
        except KeyError as exc:
            raise MockAzureError(
                f"VM '{vm_name}' not found in resource group '{resource_group_name}' of subscription "
                f"'{self._subscription}'."
            ) from exc


class _DisksOperations:
    def __init__(self, world, subscription_id):
        self._world = world
        self._subscription = subscription_id

    def get(self, resource_group_name, disk_name, **kwargs):
        key = _world.disk_id(self._subscription, resource_group_name, disk_name).lower()
        try:
            return self._world.disks[key]
        except KeyError as exc:
            raise MockAzureError(
                f"Managed disk '{disk_name}' not found in '{resource_group_name}'."
            ) from exc


class _SnapshotsOperations:
    def __init__(self, world, subscription_id):
        self._world = world
        self._subscription = subscription_id

    def begin_create_or_update(self, resource_group_name, snapshot_name, snapshot, **kwargs):
        payload = snapshot if isinstance(snapshot, dict) else snapshot.as_dict()
        creation = payload.get("creation_data") or payload.get("creationData") or {}
        source = creation.get("source_resource_id") or creation.get("sourceResourceId")
        create_option = creation.get("create_option") or creation.get("createOption") or "Copy"

        if not source:
            raise MockAzureError(
                f"Snapshot '{snapshot_name}' has no creation_data.source_resource_id."
            )
        known = dict(self._world.disks)
        known.update(self._world.snapshots)
        if source.lower() not in known:
            raise MockAzureError(f"Snapshot source '{source}' does not exist.")
        origin = known[source.lower()]

        identifier = _world.snapshot_id(self._subscription, resource_group_name, snapshot_name)
        record = Model(
            id=identifier,
            name=snapshot_name,
            location=payload.get("location", _world.DEFAULT_LOCATION),
            tags=dict(payload.get("tags") or {}),
            incremental=bool(payload.get("incremental", False)),
            disk_size_gb=getattr(origin, "disk_size_gb", None),
            os_type=getattr(origin, "os_type", None),
            provisioning_state="Succeeded",
            # CopyStart is asynchronous on real Azure; the mock lands it
            # immediately and says so, so callers still read the field.
            completion_percent=100.0,
            creation_data=Model(
                create_option=create_option,
                source_resource_id=source,
            ),
            subscription_id=self._subscription,
            resource_group=resource_group_name,
        )
        self._world.snapshots[identifier.lower()] = record
        return _Poller(record)

    def get(self, resource_group_name, snapshot_name, **kwargs):
        key = _world.snapshot_id(self._subscription, resource_group_name, snapshot_name).lower()
        try:
            return self._world.snapshots[key]
        except KeyError as exc:
            raise MockAzureError(
                f"Snapshot '{snapshot_name}' not found in '{resource_group_name}'."
            ) from exc

    def begin_delete(self, resource_group_name, snapshot_name, **kwargs):
        key = _world.snapshot_id(self._subscription, resource_group_name, snapshot_name).lower()
        return _Poller(self._world.snapshots.pop(key, None))


class _RunCommandsOperations:
    """Managed Run Command (``virtualMachines/runCommands``), the v2 API.

    v2 rather than ``begin_run_command`` because it accepts
    ``protected_parameters``: the write-only SAS is a bearer credential and must
    not be readable from the VM's run-command resource afterwards.
    """

    def __init__(self, world, subscription_id):
        self._world = world
        self._subscription = subscription_id

    def begin_create_or_update(
        self, resource_group_name, vm_name, run_command_name, run_command, **kwargs
    ):
        payload = run_command if isinstance(run_command, dict) else run_command.as_dict()
        vm_key = _world.vm_id(self._subscription, resource_group_name, vm_name).lower()
        if vm_key not in self._world.vms:
            raise MockAzureError(f"Cannot run a command on '{vm_name}': VM not found.")
        vm = self._world.vms[vm_key]

        arguments = _flatten_parameters(payload)
        source = payload.get("source") or {}
        script = source.get("script") if isinstance(source, dict) else None

        self._world.run_commands.append(
            {
                "vm": vm_name,
                "runCommandName": run_command_name,
                "resourceGroup": resource_group_name,
                "subscriptionId": self._subscription,
                "scriptLines": len((script or "").splitlines()),
                # Deliberately records only the parameter *names*: the values
                # include the SAS, and this record is readable from the VM.
                "parameterNames": sorted(arguments),
                "invokedUtc": _world.utcnow().isoformat(),
            }
        )

        output = self._simulate_acquisition(vm, arguments)
        result = Model(
            id=f"{vm.id}/runCommands/{run_command_name}",
            name=run_command_name,
            location=vm.location,
            provisioning_state="Succeeded",
            instance_view=Model(
                execution_state="Succeeded",
                exit_code=0,
                output=json.dumps(output),
                error="",
                start_time=_world.utcnow(),
                end_time=_world.utcnow(),
            ),
        )
        return _Poller(result)

    def _simulate_acquisition(self, vm, arguments):
        """Perform what the acquisition script would have done on the host."""
        sas_url = arguments.get("SasUrl")
        if not sas_url:
            raise MockAzureError(
                "The generated script was invoked without a SasUrl parameter; "
                "there is nowhere to stream the image to."
            )
        incident_id = arguments.get("IncidentId", "UNKNOWN")
        account, container, blob_name = parse_blob_sas_url(sas_url)

        size = int(arguments.get("MockImageBytes") or DEFAULT_IMAGE_BYTES)
        image = synthesize_memory_image(f"{incident_id}|{vm.name}", size)
        witness = hashlib.sha256(image).hexdigest()
        acquired_utc = _world.utcnow().isoformat()

        os_type = getattr(getattr(vm.storage_profile, "os_disk", None), "os_type", "Windows")
        tool = "winpmem" if str(os_type).lower() == "windows" else "avml"

        self._world.put_blob(
            account,
            container,
            blob_name,
            image,
            metadata={
                "incidentid": incident_id,
                "sourcehost": vm.name,
                "acquiredutc": acquired_utc,
                "witnesssha256": witness,
                "acquisitiontool": tool,
                "initiatorobjectid": arguments.get(
                    "InitiatorObjectId", _world.LOGIC_APP_PRINCIPAL_ID
                ),
            },
        )
        return {
            "incidentId": incident_id,
            "sourceHost": vm.name,
            "acquiredUtc": acquired_utc,
            "sizeBytes": len(image),
            "witnessSha256": witness,
            "acquisitionTool": tool,
            "mock": True,
        }


class MockComputeManagementClient:
    def __init__(self, credential, subscription_id, **kwargs):
        self._credential = credential
        self.subscription_id = subscription_id
        estate = _world.world()
        self.virtual_machines = _VirtualMachinesOperations(estate, subscription_id)
        self.disks = _DisksOperations(estate, subscription_id)
        self.snapshots = _SnapshotsOperations(estate, subscription_id)
        self.virtual_machine_run_commands = _RunCommandsOperations(estate, subscription_id)

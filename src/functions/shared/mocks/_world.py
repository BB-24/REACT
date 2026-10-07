"""The simulated Azure estate: one process-wide object holding every resource.

Mock mode exists so the whole pipeline -- containment, live-response
acquisition, disk snapshotting, hashing and the custody ledger -- can be run
and demonstrated end to end without an Azure subscription.

The single seam is ``shared.clients``. No module in this project constructs an
Azure SDK client directly, so switching to the real thing is one app setting
(``REACT_MOCK_MODE=false``) and this package is then never imported.

State is held in memory and never persisted. A restart therefore gives a clean,
reproducible estate, which is what lets the same fabric back both the demo and
the unit tests.
"""

import hashlib
import json
import threading
from datetime import UTC, datetime

# Two subscriptions, because REQ-3.4.3 is specifically about crossing the
# boundary between them: the attacker may hold Contributor on the first.
COMPROMISED_SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"
ENCLAVE_SUBSCRIPTION = "00000000-0000-0000-0000-0000000000e1"

TARGET_RESOURCE_GROUP = "rg-victims"
ENCLAVE_RESOURCE_GROUP = "rg-forensic-enclave"
DEFAULT_LOCATION = "eastus"

EVIDENCE_ACCOUNT = "reactenclave01"
EVIDENCE_CONTAINER = "evidence"
TOOLS_CONTAINER = "tools"

KEY_VAULT_URI = "https://react-kv.vault.azure.net/"
STORAGE_KEY_SECRET_NAME = "evidence-storage-key"

# Deterministic, obviously-fake key material. Real enough for the storage SDK
# to sign a SAS with, useless against Azure.
FAKE_ACCOUNT_KEY = "cmVhY3QtbW9jay1hY2NvdW50LWtleS1ub3QtYS1yZWFsLXNlY3JldA=="

LOGIC_APP_PRINCIPAL_ID = "11111111-2222-3333-4444-555555555555"

_LOCK = threading.RLock()


def utcnow():
    return datetime.now(UTC)


class Model:
    """Attribute bag standing in for an ``azure-mgmt`` model object.

    The production code only ever reads attributes off these models, and reads
    the optional ones through ``getattr(..., None)``, so an open bag is a
    faithful enough stand-in without vendoring a copy of every SDK class.
    """

    def __init__(self, **fields):
        for key, value in fields.items():
            setattr(self, key, value)

    def as_dict(self):
        return {key: value for key, value in vars(self).items() if not key.startswith("_")}

    def __repr__(self):
        body = ", ".join(f"{key}={value!r}" for key, value in sorted(vars(self).items()))
        return f"Model({body})"


class MockAzureError(RuntimeError):
    """Raised for conditions Azure itself would reject."""


class ImmutabilityError(MockAzureError):
    """Raised when a write would violate a legal hold or immutability policy."""


# --- ARM resource ID helpers -------------------------------------------------


def _resource_id(subscription, resource_group, provider, kind, name):
    return f"/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/{provider}/{kind}/{name}"


def vm_id(subscription, resource_group, name):
    return _resource_id(subscription, resource_group, "Microsoft.Compute", "virtualMachines", name)


def disk_id(subscription, resource_group, name):
    return _resource_id(subscription, resource_group, "Microsoft.Compute", "disks", name)


def snapshot_id(subscription, resource_group, name):
    return _resource_id(subscription, resource_group, "Microsoft.Compute", "snapshots", name)


def nic_id(subscription, resource_group, name):
    return _resource_id(
        subscription, resource_group, "Microsoft.Network", "networkInterfaces", name
    )


def nsg_id(subscription, resource_group, name):
    return _resource_id(
        subscription,
        resource_group,
        "Microsoft.Network",
        "networkSecurityGroups",
        name,
    )


# --- Storage -----------------------------------------------------------------


class MockContainer:
    """A blob container, including the immutability posture REQ-3.5.1 demands."""

    def __init__(
        self,
        account,
        name,
        legal_hold=False,
        legal_hold_tags=None,
        retention_days=None,
        policy_locked=False,
    ):
        self.account = account
        self.name = name
        self.legal_hold = legal_hold
        self.legal_hold_tags = list(legal_hold_tags or [])
        self.retention_days = retention_days
        self.policy_locked = policy_locked

    def assert_can_overwrite(self, blob_name):
        """Reject the write Azure would reject. This is the whole point of the
        enclave: an attacker who reaches the container still cannot replace an
        image with a doctored one to defeat the hash ledger."""
        if self.legal_hold:
            raise ImmutabilityError(
                f"Blob '{blob_name}' is under legal hold "
                f"({', '.join(self.legal_hold_tags) or 'untagged'}); overwrite "
                "and delete are blocked until the hold is cleared."
            )
        if self.retention_days:
            raise ImmutabilityError(
                f"Blob '{blob_name}' is inside a {self.retention_days}-day time-based retention policy; "
                "overwrite and delete are blocked."
            )


class MockBlob:
    def __init__(self, account, container, name, data, metadata=None, creation_time=None):
        self.account = account
        self.container = container
        self.name = name
        self.data = data
        self.metadata = dict(metadata or {})
        self.creation_time = creation_time or utcnow()

    @property
    def size(self):
        return len(self.data)

    @property
    def url(self):
        return f"https://{self.account}.blob.core.windows.net/{self.container}/{self.name}"

    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()


# --- The estate --------------------------------------------------------------


class World:
    """Every simulated resource, plus the Event Grid queue and the ledger."""

    def __init__(self):
        self.reset()

    def reset(self):
        with _LOCK:
            self.vms = {}
            self.disks = {}
            self.nics = {}
            self.nsgs = {}
            self.snapshots = {}
            self.containers = {}
            self.blobs = {}
            self.secrets = {}
            self.run_commands = []
            self.events = []
            self.ledger_rows = []
            self.blob_created_handlers = []
            seed(self)

    # --- blobs ---------------------------------------------------------------

    def container(self, account, name):
        try:
            return self.containers[(account, name)]
        except KeyError as err:
            raise MockAzureError(
                f"Container '{name}' does not exist on account '{account}'."
            ) from err

    def put_blob(self, account, container, name, data, metadata=None):
        """Store a blob and queue the ``BlobCreated`` event it would raise."""
        with _LOCK:
            holder = self.container(account, container)
            key = (account, container, name)
            if key in self.blobs:
                holder.assert_can_overwrite(name)
            blob = MockBlob(account, container, name, data, metadata)
            self.blobs[key] = blob
            self.events.append(self._blob_created_event(blob))
            return blob

    def get_blob(self, account, container, name):
        try:
            return self.blobs[(account, container, name)]
        except KeyError as err:
            raise MockAzureError(f"Blob '{name}' not found in {account}/{container}.") from err

    def delete_blob(self, account, container, name):
        with _LOCK:
            self.container(account, container).assert_can_overwrite(name)
            self.blobs.pop((account, container, name), None)

    @staticmethod
    def _blob_created_event(blob):
        return {
            "id": hashlib.sha256(
                (blob.url + blob.creation_time.isoformat()).encode("utf-8")
            ).hexdigest(),
            "topic": (
                f"/subscriptions/{ENCLAVE_SUBSCRIPTION}/resourceGroups/{ENCLAVE_RESOURCE_GROUP}/providers"
                f"/Microsoft.Storage/storageAccounts/{blob.account}"
            ),
            "subject": f"/blobServices/default/containers/{blob.container}/blobs/{blob.name}",
            "eventType": "Microsoft.Storage.BlobCreated",
            "eventTime": blob.creation_time.isoformat(),
            "dataVersion": "1.0",
            "data": {
                "api": "PutBlockList",
                "contentType": "application/octet-stream",
                "contentLength": blob.size,
                "blobType": "BlockBlob",
                "url": blob.url,
            },
        }

    # --- Event Grid ----------------------------------------------------------

    def drain_events(self):
        """Deliver queued events to the registered handlers.

        Delivery is explicit rather than fired inside ``put_blob`` because Event
        Grid is asynchronous. Making the caller ask for delivery keeps that
        asynchrony visible instead of pretending the custody row lands in the
        same call that stored the blob.
        """
        with _LOCK:
            pending, self.events = self.events, []
        delivered = []
        for event in pending:
            for handler in list(self.blob_created_handlers):
                delivered.append(handler(event))
        return delivered

    # --- ledger --------------------------------------------------------------

    def append_ledger_row(self, row):
        """Append one row, extending the hash chain that stands in for the
        Azure SQL Ledger digest."""
        with _LOCK:
            previous = self.ledger_rows[-1]["_LedgerDigest"] if self.ledger_rows else "0" * 64
            payload = json.dumps(row, sort_keys=True, default=str)
            stored = dict(row)
            stored["LedgerEntryId"] = len(self.ledger_rows) + 1
            stored["_PreviousDigest"] = previous
            stored["_LedgerDigest"] = hashlib.sha256(
                (previous + payload).encode("utf-8")
            ).hexdigest()
            self.ledger_rows.append(stored)
            return stored

    def verify_ledger(self):
        """Recompute the chain. Returns ``(is_intact, first_bad_entry_id)``."""
        previous = "0" * 64
        for row in self.ledger_rows:
            payload = {
                key: value
                for key, value in row.items()
                if key not in ("LedgerEntryId", "_PreviousDigest", "_LedgerDigest")
            }
            expected = hashlib.sha256(
                (previous + json.dumps(payload, sort_keys=True, default=str)).encode("utf-8")
            ).hexdigest()
            if expected != row["_LedgerDigest"]:
                return False, row["LedgerEntryId"]
            previous = row["_LedgerDigest"]
        return True, None


# --- Seed data ---------------------------------------------------------------


def _add_vm(world, name, os_type, data_disk_count=0, attached_nsg_name=None):
    subscription = COMPROMISED_SUBSCRIPTION
    group = TARGET_RESOURCE_GROUP

    os_disk_name = f"{name}-osdisk"
    world.disks[disk_id(subscription, group, os_disk_name).lower()] = Model(
        id=disk_id(subscription, group, os_disk_name),
        name=os_disk_name,
        location=DEFAULT_LOCATION,
        disk_size_gb=128,
        os_type=os_type,
        tags={},
    )

    data_disk_refs = []
    for index in range(1, data_disk_count + 1):
        data_name = f"{name}-data-{index:02d}"
        world.disks[disk_id(subscription, group, data_name).lower()] = Model(
            id=disk_id(subscription, group, data_name),
            name=data_name,
            location=DEFAULT_LOCATION,
            disk_size_gb=512,
            os_type=None,
            tags={},
        )
        data_disk_refs.append(
            Model(
                lun=index - 1,
                name=data_name,
                managed_disk=Model(id=disk_id(subscription, group, data_name)),
            )
        )

    interface_name = f"{name}-nic"
    existing_nsg = None
    if attached_nsg_name:
        existing_nsg = Model(id=nsg_id(subscription, group, attached_nsg_name))
        world.nsgs[nsg_id(subscription, group, attached_nsg_name).lower()] = Model(
            id=nsg_id(subscription, group, attached_nsg_name),
            name=attached_nsg_name,
            location=DEFAULT_LOCATION,
            security_rules=[],
            tags={},
        )
    world.nics[nic_id(subscription, group, interface_name).lower()] = Model(
        id=nic_id(subscription, group, interface_name),
        name=interface_name,
        location=DEFAULT_LOCATION,
        network_security_group=existing_nsg,
    )

    world.vms[vm_id(subscription, group, name).lower()] = Model(
        id=vm_id(subscription, group, name),
        name=name,
        location=DEFAULT_LOCATION,
        tags={},
        storage_profile=Model(
            os_disk=Model(
                name=os_disk_name,
                os_type=os_type,
                managed_disk=Model(id=disk_id(subscription, group, os_disk_name)),
            ),
            data_disks=data_disk_refs,
        ),
        network_profile=Model(
            network_interfaces=[Model(id=nic_id(subscription, group, interface_name), primary=True)]
        ),
    )


def seed(world):
    """Populate a plausible two-subscription estate."""
    # The compromised production subscription.
    _add_vm(world, "web-01", "Windows", data_disk_count=1, attached_nsg_name="nsg-web-tier")
    _add_vm(world, "db-02", "Linux", data_disk_count=2, attached_nsg_name="nsg-db-tier")

    # The forensic enclave, in its own subscription.
    world.containers[(EVIDENCE_ACCOUNT, EVIDENCE_CONTAINER)] = MockContainer(
        EVIDENCE_ACCOUNT,
        EVIDENCE_CONTAINER,
        legal_hold=True,
        legal_hold_tags=["react-active-investigation"],
        retention_days=2555,
        policy_locked=True,
    )
    # The tool repository is deliberately *not* immutable: WinPmem and AVML get
    # replaced whenever a new build is published.
    world.containers[(EVIDENCE_ACCOUNT, TOOLS_CONTAINER)] = MockContainer(
        EVIDENCE_ACCOUNT, TOOLS_CONTAINER
    )
    for tool in ("winpmem.exe", "avml", "Acquire-Memory.ps1", "acquire-memory.sh"):
        # Written straight into the dict rather than through put_blob: the tool
        # repository is not evidence and must not reach the custody ledger.
        world.blobs[(EVIDENCE_ACCOUNT, TOOLS_CONTAINER, tool)] = MockBlob(
            EVIDENCE_ACCOUNT,
            TOOLS_CONTAINER,
            tool,
            b"MOCK ACQUISITION TOOL PAYLOAD -- " + tool.encode("ascii"),
        )

    world.secrets[(KEY_VAULT_URI, STORAGE_KEY_SECRET_NAME)] = FAKE_ACCOUNT_KEY


WORLD = World()


def world():
    """Return the process-wide simulated estate."""
    return WORLD


def reset():
    """Reseed the estate. Used by tests and the ``/mock/reset`` endpoint."""
    WORLD.reset()
    return WORLD

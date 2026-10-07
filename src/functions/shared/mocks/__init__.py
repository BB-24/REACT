"""Mock Azure fabric for REACT.

Import surface for ``shared.clients`` and the tests. Nothing outside those two
places should reach into the private modules.

To move to real Azure, set ``REACT_MOCK_MODE=false``; ``shared.clients`` then
never imports this package and every call goes to the real SDK. No production
module imports anything from here directly, which is what keeps that switch a
one-line change rather than a refactor.
"""
from ._compute import (
    DEFAULT_IMAGE_BYTES,
    MockComputeManagementClient,
    parse_blob_sas_url,
    synthesize_memory_image,
)
from ._keyvault import MockSecretClient
from ._network import MockNetworkManagementClient
from ._sql import MockSqlConnection, connect as sql_connect
from ._storage import MockBlobClient, MockBlobServiceClient
from ._world import (
    COMPROMISED_SUBSCRIPTION,
    ENCLAVE_RESOURCE_GROUP,
    ENCLAVE_SUBSCRIPTION,
    EVIDENCE_ACCOUNT,
    EVIDENCE_CONTAINER,
    FAKE_ACCOUNT_KEY,
    KEY_VAULT_URI,
    LOGIC_APP_PRINCIPAL_ID,
    STORAGE_KEY_SECRET_NAME,
    TARGET_RESOURCE_GROUP,
    TOOLS_CONTAINER,
    ImmutabilityError,
    MockAzureError,
    Model,
    World,
    reset,
    world,
)


class MockCredential(object):
    """Stand-in for ``DefaultAzureCredential``.

    Never contacted: every mock client ignores the credential it is handed. It
    exists so the call sites keep passing a credential through, which is what
    keeps them identical between mock and real mode.
    """

    def get_token(self, *scopes, **kwargs):
        raise MockAzureError(
            "Mock mode issues no tokens. If something is asking for one, a real "
            "SDK client has leaked past shared.clients."
        )


def register_blob_created_handler(handler):
    """Subscribe ``handler`` to the simulated Event Grid system topic."""
    estate = world()
    if handler not in estate.blob_created_handlers:
        estate.blob_created_handlers.append(handler)
    return handler


def drain_events():
    """Deliver every queued ``BlobCreated`` event. Returns handler results."""
    return world().drain_events()


def snapshot_state():
    """A JSON-serialisable view of the estate, for the ``/mock/state`` endpoint."""
    estate = world()
    intact, first_bad = estate.verify_ledger()
    return {
        "virtualMachines": sorted(vm.name for vm in estate.vms.values()),
        "managedDisks": sorted(disk.name for disk in estate.disks.values()),
        "networkSecurityGroups": sorted(nsg.name for nsg in estate.nsgs.values()),
        "snapshots": [
            {
                "name": snap.name,
                "id": snap.id,
                "subscriptionId": snap.subscription_id,
                "resourceGroup": snap.resource_group,
                "tags": snap.tags,
                "sourceResourceId": snap.creation_data.source_resource_id,
                "createOption": snap.creation_data.create_option,
            }
            for snap in sorted(estate.snapshots.values(), key=lambda s: s.name)
        ],
        "containers": [
            {
                "account": holder.account,
                "name": holder.name,
                "legalHold": holder.legal_hold,
                "legalHoldTags": holder.legal_hold_tags,
                "retentionDays": holder.retention_days,
                "policyLocked": holder.policy_locked,
            }
            for holder in sorted(
                estate.containers.values(), key=lambda c: (c.account, c.name)
            )
        ],
        "blobs": [
            {
                "container": blob.container,
                "name": blob.name,
                "sizeBytes": blob.size,
                "metadata": blob.metadata,
            }
            for blob in sorted(
                estate.blobs.values(), key=lambda b: (b.container, b.name)
            )
        ],
        "runCommands": list(estate.run_commands),
        "pendingEvents": len(estate.events),
        "ledger": {
            "rows": list(estate.ledger_rows),
            "chainIntact": intact,
            "firstTamperedEntryId": first_bad,
        },
    }


__all__ = [
    "COMPROMISED_SUBSCRIPTION",
    "DEFAULT_IMAGE_BYTES",
    "ENCLAVE_RESOURCE_GROUP",
    "ENCLAVE_SUBSCRIPTION",
    "EVIDENCE_ACCOUNT",
    "EVIDENCE_CONTAINER",
    "FAKE_ACCOUNT_KEY",
    "KEY_VAULT_URI",
    "LOGIC_APP_PRINCIPAL_ID",
    "STORAGE_KEY_SECRET_NAME",
    "TARGET_RESOURCE_GROUP",
    "TOOLS_CONTAINER",
    "ImmutabilityError",
    "MockAzureError",
    "MockBlobClient",
    "MockBlobServiceClient",
    "MockComputeManagementClient",
    "MockCredential",
    "MockNetworkManagementClient",
    "MockSecretClient",
    "MockSqlConnection",
    "Model",
    "World",
    "drain_events",
    "parse_blob_sas_url",
    "register_blob_created_handler",
    "reset",
    "snapshot_state",
    "sql_connect",
    "synthesize_memory_image",
    "world",
]

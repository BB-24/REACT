"""The single seam between REACT and Azure.

Every Azure client this application uses is constructed here and nowhere else.
That gives one switch -- the ``REACT_MOCK_MODE`` application setting -- between
the simulated estate in ``shared.mocks`` and the real SDK, and it means no
business logic has to know which it is talking to.

Turning mock mode off is the whole migration: ``shared.mocks`` is then never
imported, and each factory below returns the genuine client with a
``DefaultAzureCredential`` behind it.

Mock mode is off by default. A missing setting in production must fail closed
towards real Azure, never silently towards fabricated evidence.
"""
import logging

from . import config

MOCK_SETTING = "REACT_MOCK_MODE"

_credential = None
_warned = False


def mock_mode():
    """True when the simulated estate should be used instead of Azure."""
    enabled = config.get_bool(MOCK_SETTING, False)
    global _warned
    if enabled and not _warned:
        # Loud, once per process. Evidence produced in mock mode is synthetic
        # and must never be mistaken for the real thing in a case file.
        logging.warning(
            "REACT is running in MOCK MODE. No Azure resource is being touched "
            "and every artifact produced is synthetic. Set %s=false to use real "
            "Azure services.", MOCK_SETTING,
        )
        _warned = True
    return enabled


def credential():
    """Return the managed-identity credential, cached across warm invocations."""
    if mock_mode():
        from . import mocks

        return mocks.MockCredential()

    global _credential
    if _credential is None:
        from azure.identity import DefaultAzureCredential

        _credential = DefaultAzureCredential()
    return _credential


def compute_client(subscription_id, cred=None):
    """Client for VMs, managed disks, snapshots and Run Commands."""
    if mock_mode():
        from . import mocks

        return mocks.MockComputeManagementClient(
            cred or credential(), subscription_id
        )
    from azure.mgmt.compute import ComputeManagementClient

    return ComputeManagementClient(cred or credential(), subscription_id)


def network_client(subscription_id, cred=None):
    """Client for NSGs and network interfaces."""
    if mock_mode():
        from . import mocks

        return mocks.MockNetworkManagementClient(
            cred or credential(), subscription_id
        )
    from azure.mgmt.network import NetworkManagementClient

    return NetworkManagementClient(cred or credential(), subscription_id)


def blob_service_client(account_url, cred=None):
    """Blob service client, used to mint user-delegation keys."""
    if mock_mode():
        from . import mocks

        return mocks.MockBlobServiceClient(account_url, cred or credential())
    from azure.storage.blob import BlobServiceClient

    return BlobServiceClient(account_url, credential=cred or credential())


def blob_client_from_url(blob_url, cred=None, max_chunk_get_size=None):
    """Blob client for an artifact already in the enclave, addressed by URL."""
    if mock_mode():
        from . import mocks

        return mocks.MockBlobClient.from_blob_url(
            blob_url, max_chunk_get_size=max_chunk_get_size
        )
    from azure.storage.blob import BlobClient

    return BlobClient.from_blob_url(
        blob_url,
        credential=cred or credential(),
        max_chunk_get_size=max_chunk_get_size,
    )


def blob_client(account_url, container, blob_name, cred=None):
    """Blob client for a specific container and blob name."""
    if mock_mode():
        from . import mocks

        account = account_url.split("//", 1)[-1].split(".", 1)[0]
        return mocks.MockBlobClient(account, container, blob_name)
    from azure.storage.blob import BlobClient

    return BlobClient(
        account_url, container, blob_name, credential=cred or credential()
    )


def secret_client(vault_uri, cred=None):
    """Key Vault secrets client (REQ-3.3.3)."""
    if mock_mode():
        from . import mocks

        return mocks.MockSecretClient(vault_uri, cred or credential())
    from azure.keyvault.secrets import SecretClient

    return SecretClient(vault_url=vault_uri, credential=cred or credential())


def sql_connection():
    """Open a connection to the Azure SQL Ledger database.

    ``SQL_CONNECTION_STRING`` is expected to use
    ``Authentication=ActiveDirectoryMsi`` so that no password ever exists.
    """
    if mock_mode():
        from . import mocks

        return mocks.sql_connect()
    import pyodbc

    return pyodbc.connect(config.require("SQL_CONNECTION_STRING"), timeout=30)

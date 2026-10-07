"""Short-lived, write-only SAS tokens for the forensic enclave container.

The acquisition scripts run *on the compromised host*, so whatever credential we
hand them must be assumed compromised too. Two properties keep that survivable:

* **Write-only.** The token carries create/write/add and nothing else. An
  attacker who scrapes it from the host's process list cannot read back other
  incidents' memory images, cannot list the container, and cannot delete or
  overwrite-then-re-upload evidence to defeat the hash ledger.
* **Short-lived.** Default 60-minute expiry (REQ: SOP 2, Phase 2.3).

Two minting modes are supported, selected by the ``SAS_MODE`` app setting:

``user-delegation`` (default)
    The SAS is signed with a user delegation key obtained over AAD using the
    Function App's managed identity. No storage account key exists anywhere in
    the system, so there is no long-lived secret to leak or rotate.

``key-vault``
    The literal SOP 2 Phase 2.3 reading: pull the storage account key from Azure
    Key Vault and sign with it. Kept for environments where the enclave storage
    account has not been moved off shared-key auth yet.
"""

import re
from datetime import UTC, datetime, timedelta

from azure.storage.blob import BlobSasPermissions, generate_blob_sas

from . import clients, config

DEFAULT_TTL_MINUTES = 60
# Backdate the token so a few minutes of clock drift on the target host does not
# make a freshly minted SAS look "not yet valid".
CLOCK_SKEW_MINUTES = 5

_UNSAFE_PATH_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def _default_credential():
    """The managed-identity credential, or its mock-mode stand-in."""
    return clients.credential()


def account_url(account=None):
    """Return the blob service endpoint for the evidence storage account."""
    account = account or config.require("EVIDENCE_STORAGE_ACCOUNT")
    suffix = config.get("STORAGE_ENDPOINT_SUFFIX", "core.windows.net")
    return f"https://{account}.blob.{suffix}"


def slug(value):
    """Reduce arbitrary text to a filesystem- and URL-safe path segment."""
    cleaned = _UNSAFE_PATH_CHARS.sub("-", str(value or "unknown")).strip("-.")
    return cleaned or "unknown"


def build_blob_name(incident_id, target_name, artifact="memory", extension="raw", now=None):
    """Return the enclave blob path for one acquired artifact.

    Layout is ``<incident>/<host>/<artifact>-<utc timestamp>.<ext>`` so that a
    single incident's evidence stays contiguous and a re-run never silently
    overwrites an earlier image.
    """
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    return f"{slug(incident_id)}/{slug(target_name)}/{slug(artifact)}-{stamp}.{extension}"


def _account_key_from_key_vault(credential=None):
    vault_uri = config.require("KEY_VAULT_URI")
    secret_name = config.get("STORAGE_KEY_SECRET_NAME", "evidence-storage-key")
    client = clients.secret_client(vault_uri, cred=credential)
    return client.get_secret(secret_name).value


def _mint(blob_name, permission, ttl_minutes, account, container, credential, now):
    """Sign one blob-scoped SAS. Returns ``(url_with_sas, expires_on)``."""
    account = account or config.require("EVIDENCE_STORAGE_ACCOUNT")
    ttl = ttl_minutes or config.get_int("SAS_TTL_MINUTES", DEFAULT_TTL_MINUTES)

    issued_at = now or datetime.now(UTC)
    start = issued_at - timedelta(minutes=CLOCK_SKEW_MINUTES)
    expiry = issued_at + timedelta(minutes=ttl)

    sas_args = {
        "account_name": account,
        "container_name": container,
        "blob_name": blob_name,
        "permission": permission,
        "start": start,
        "expiry": expiry,
        "protocol": "https",
    }

    mode = config.get("SAS_MODE", "user-delegation").lower()
    if mode == "user-delegation":
        service = clients.blob_service_client(account_url(account), cred=credential)
        delegation_key = service.get_user_delegation_key(
            key_start_time=start, key_expiry_time=expiry
        )
        token = generate_blob_sas(user_delegation_key=delegation_key, **sas_args)
    elif mode == "key-vault":
        token = generate_blob_sas(account_key=_account_key_from_key_vault(credential), **sas_args)
    else:
        raise config.ConfigError(
            f"SAS_MODE must be 'user-delegation' or 'key-vault', got '{mode}'."
        )

    url = f"{account_url(account)}/{container}/{blob_name}?{token}"
    return url, expiry


def mint_write_only_sas(
    blob_name, ttl_minutes=None, account=None, container=None, credential=None, now=None
):
    """Mint a write-only blob SAS and return ``(url_with_sas, expires_on)``.

    REQ-3.3.3. The returned URL embeds the token. Treat it as a secret: hand it
    to the target host through Run Command's *protected* parameters and never
    write it to a log, a trace, or a resource tag.
    """
    return _mint(
        blob_name,
        # No read, no list, no delete: upload-only by construction.
        BlobSasPermissions(create=True, write=True, add=True),
        ttl_minutes,
        account,
        container or config.get("EVIDENCE_CONTAINER", "evidence"),
        credential,
        now,
    )


def mint_read_only_sas(
    blob_name, ttl_minutes=None, account=None, container=None, credential=None, now=None
):
    """Mint a read-only SAS for one blob in the tool repository (REQ-3.3.2).

    The acquisition binaries are fetched by the target host, so this token is
    exposed to a compromised machine exactly as the upload token is. Read-only
    and blob-scoped means the worst case is re-downloading a tool the attacker
    could have obtained from the vendor anyway -- it grants no path to the
    evidence container, which lives under a different token entirely.
    """
    return _mint(
        blob_name,
        BlobSasPermissions(read=True),
        ttl_minutes,
        account,
        container or config.get("TOOLS_CONTAINER", "tools"),
        credential,
        now,
    )

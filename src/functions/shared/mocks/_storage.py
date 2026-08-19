"""Stand-ins for ``BlobServiceClient`` and ``BlobClient``.

The SAS token these produce is signed for real -- ``generate_blob_sas`` is the
genuine SDK function, handed fake key material -- so every assertion about
permissions, expiry and scope in ``test_sas.py`` exercises the real code path.
The token simply will not authenticate against Azure, which is the point.
"""
from azure.storage.blob import UserDelegationKey

from . import _world
from ._world import Model, MockAzureError

DEFAULT_CHUNK_BYTES = 4 * 1024 * 1024

# Obviously-fake identifiers, so a delegation key that leaks into a log is
# recognisable as mock output rather than a real tenant's.
MOCK_SIGNED_OID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
MOCK_SIGNED_TID = "ffffffff-0000-1111-2222-333333333333"


def _stamp(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


class _Downloader(object):
    def __init__(self, data, chunk_bytes):
        self._data = data
        self._chunk = max(int(chunk_bytes or DEFAULT_CHUNK_BYTES), 1)

    def chunks(self):
        for offset in range(0, len(self._data), self._chunk):
            yield self._data[offset:offset + self._chunk]

    def readall(self):
        return self._data


class MockBlobClient(object):
    def __init__(self, account, container, blob_name, chunk_bytes=None):
        self.account_name = account
        self.container_name = container
        self.blob_name = blob_name
        self._chunk_bytes = chunk_bytes or DEFAULT_CHUNK_BYTES
        self._world = _world.world()

    @classmethod
    def from_blob_url(cls, blob_url, credential=None, max_chunk_get_size=None,
                      **kwargs):
        from ._compute import parse_blob_sas_url

        account, container, blob_name = parse_blob_sas_url(blob_url)
        return cls(account, container, blob_name, chunk_bytes=max_chunk_get_size)

    @property
    def url(self):
        return "https://{0}.blob.core.windows.net/{1}/{2}".format(
            self.account_name, self.container_name, self.blob_name
        )

    def _blob(self):
        return self._world.get_blob(
            self.account_name, self.container_name, self.blob_name
        )

    def exists(self):
        key = (self.account_name, self.container_name, self.blob_name)
        return key in self._world.blobs

    def get_blob_properties(self):
        blob = self._blob()
        return Model(
            name=blob.name,
            size=blob.size,
            metadata=dict(blob.metadata),
            creation_time=blob.creation_time,
            last_modified=blob.creation_time,
            etag='"{0}"'.format(blob.sha256()[:16]),
            blob_type="BlockBlob",
        )

    def download_blob(self, max_concurrency=1, **kwargs):
        return _Downloader(self._blob().data, self._chunk_bytes)

    def upload_blob(self, data, overwrite=False, metadata=None, **kwargs):
        if hasattr(data, "read"):
            data = data.read()
        if isinstance(data, str):
            data = data.encode("utf-8")
        key = (self.account_name, self.container_name, self.blob_name)
        if key in self._world.blobs and not overwrite:
            raise MockAzureError(
                "Blob '{0}' already exists and overwrite was not requested.".format(
                    self.blob_name
                )
            )
        return self._world.put_blob(
            self.account_name, self.container_name, self.blob_name, data, metadata
        )


class MockBlobServiceClient(object):
    def __init__(self, account_url, credential=None, **kwargs):
        self.url = account_url
        self.account_name = account_url.split("//", 1)[-1].split(".", 1)[0]
        self._credential = credential

    def get_user_delegation_key(self, key_start_time, key_expiry_time, **kwargs):
        """Return a delegation key the real ``generate_blob_sas`` can sign with.

        On Azure this call is what requires the Storage Blob Delegator role and
        is why no account key needs to exist. Here it hands back fake material
        with the same shape.
        """
        key = UserDelegationKey()
        key.signed_oid = MOCK_SIGNED_OID
        key.signed_tid = MOCK_SIGNED_TID
        key.signed_start = _stamp(key_start_time)
        key.signed_expiry = _stamp(key_expiry_time)
        key.signed_service = "b"
        key.signed_version = "2021-08-06"
        key.value = _world.FAKE_ACCOUNT_KEY
        return key

    def get_blob_client(self, container, blob, **kwargs):
        return MockBlobClient(self.account_name, container, blob)

"""Pytest configuration and mocks for Azure SDK modules."""

import json
import sys
from types import ModuleType
from unittest.mock import MagicMock

# Stub azure modules if not installed in local environment
if "azure" not in sys.modules:
    azure_mod = ModuleType("azure")
    func_mod = ModuleType("azure.functions")
    storage_mod = ModuleType("azure.storage")
    blob_mod = ModuleType("azure.storage.blob")

    class FakeHttpRequest:
        def __init__(self, method: str, url: str, body: bytes = b"", headers: dict | None = None):
            self.method = method
            self.url = url
            self._body = body
            self.headers = headers or {}

        def get_json(self):
            return json.loads(self._body.decode("utf-8"))

    class FakeHttpResponse:
        def __init__(
            self, body: str = "", *, status_code: int = 200, mimetype: str = "application/json"
        ):
            self.body = body
            self.status_code = status_code
            self.mimetype = mimetype

    class FakeBlobSasPermissions:
        def __init__(
            self,
            read=False,
            add=False,
            create=False,
            write=False,
            delete=False,
            tag=False,
            list=False,
        ):
            self.read = read
            self.add = add
            self.create = create
            self.write = write
            self.delete = delete

    def fake_generate_blob_sas(*args, **kwargs):
        return "sv=2024-05-04&sr=b&sig=fake_sas_signature_123456"

    func_mod.HttpRequest = FakeHttpRequest
    func_mod.HttpResponse = FakeHttpResponse
    azure_mod.functions = func_mod

    blob_mod.BlobSasPermissions = FakeBlobSasPermissions
    blob_mod.generate_blob_sas = fake_generate_blob_sas
    storage_mod.blob = blob_mod
    azure_mod.storage = storage_mod

    sys.modules["azure"] = azure_mod
    sys.modules["azure.functions"] = func_mod
    sys.modules["azure.storage"] = storage_mod
    sys.modules["azure.storage.blob"] = blob_mod
    sys.modules["azure.identity"] = MagicMock()
    sys.modules["azure.mgmt"] = MagicMock()
    sys.modules["azure.mgmt.network"] = MagicMock()
    sys.modules["azure.mgmt.compute"] = MagicMock()

"""Pytest configuration and mocks for Azure SDK modules."""

import importlib.util
import json
import sys
from types import ModuleType
from unittest.mock import MagicMock


def _azure_sdk_missing() -> bool:
    """True when the real azure-functions SDK is not importable here.

    Checking ``sys.modules`` alone is not enough: it is empty before anything
    imports azure, which would make these stubs shadow an *installed* SDK in CI
    and break submodule imports such as ``azure.mgmt.network.models``.
    """
    try:
        return importlib.util.find_spec("azure.functions") is None
    except ImportError:
        # Parent package missing entirely -> genuinely unavailable.
        return True


# Stub azure modules only if the real SDK is not installed in this environment.
if _azure_sdk_missing():
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

        def get_body(self):
            # Mirrors the real azure.functions API, which returns bytes.
            return self.body.encode("utf-8") if isinstance(self.body, str) else self.body

    class FakeBlueprint:
        """Stand-in for azure.functions.Blueprint supporting @bp.route(...)."""

        def __init__(self, *args, **kwargs):
            self.routes = []

        def route(self, *args, **kwargs):
            def decorator(func):
                self.routes.append((args, kwargs))
                return func

            return decorator

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

    class FakeUserDelegationKey:
        """Stand-in for azure.storage.blob.UserDelegationKey."""

        def __init__(self, *args, **kwargs):
            pass

    def fake_generate_blob_sas(*args, **kwargs):
        return "sv=2024-05-04&sr=b&sig=fake_sas_signature_123456"

    func_mod.HttpRequest = FakeHttpRequest
    func_mod.HttpResponse = FakeHttpResponse
    func_mod.Blueprint = FakeBlueprint
    azure_mod.functions = func_mod

    blob_mod.BlobSasPermissions = FakeBlobSasPermissions
    blob_mod.generate_blob_sas = fake_generate_blob_sas
    blob_mod.UserDelegationKey = FakeUserDelegationKey
    storage_mod.blob = blob_mod
    azure_mod.storage = storage_mod

    sys.modules["azure"] = azure_mod
    sys.modules["azure.functions"] = func_mod
    sys.modules["azure.storage"] = storage_mod
    sys.modules["azure.storage.blob"] = blob_mod
    sys.modules["azure.identity"] = MagicMock()
    sys.modules["azure.mgmt"] = MagicMock()
    sys.modules["azure.mgmt.network"] = MagicMock()
    # ``azure.mgmt.network`` is a MagicMock (not a package), so submodule imports
    # like ``from azure.mgmt.network.models import NetworkSecurityGroup`` fail
    # unless the submodule is registered explicitly. Same for compute.models.
    sys.modules["azure.mgmt.network.models"] = MagicMock()
    sys.modules["azure.mgmt.compute"] = MagicMock()
    sys.modules["azure.mgmt.compute.models"] = MagicMock()

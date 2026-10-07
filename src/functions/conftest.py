"""Put the function app root on sys.path so tests can import the blueprints.

The Functions host adds the app root automatically at runtime; pytest does not.
"""
import json
import os
import sys

import pytest

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)


MOCK_SETTINGS = {
    "REACT_MOCK_MODE": "true",
    "EVIDENCE_STORAGE_ACCOUNT": "reactenclave01",
    "EVIDENCE_CONTAINER": "evidence",
    "TOOLS_CONTAINER": "tools",
    "SAS_MODE": "user-delegation",
    "SAS_TTL_MINUTES": "60",
    "KEY_VAULT_URI": "https://react-kv.vault.azure.net/",
    "STORAGE_KEY_SECRET_NAME": "evidence-storage-key",
    "AZURE_SUBSCRIPTION_ID": "00000000-0000-0000-0000-000000000001",
    "TARGET_RESOURCE_GROUP": "rg-victims",
    "FORENSIC_SUBSCRIPTION_ID": "00000000-0000-0000-0000-0000000000e1",
    "FORENSIC_RESOURCE_GROUP": "rg-forensic-enclave",
    "FORENSIC_LOCATION": "eastus",
    "LOGIC_APP_PRINCIPAL_ID": "11111111-2222-3333-4444-555555555555",
    "SQL_CONNECTION_STRING": "mock-connection-string",
}


@pytest.fixture
def mock_estate(monkeypatch):
    """A freshly seeded mock estate with the Event Grid subscription attached.

    Opt-in rather than autouse: the tests that predate mock mode assert against
    hand-built doubles and must keep running with it off, which is also what
    proves the production path does not depend on this fixture.
    """
    from shared import mocks

    for name, value in MOCK_SETTINGS.items():
        monkeypatch.setenv(name, value)

    estate = mocks.reset()
    from ChainOfCustody import process_blob_created

    mocks.register_blob_created_handler(process_blob_created)
    try:
        yield estate
    finally:
        mocks.reset()


@pytest.fixture
def post():
    """Build an ``HttpRequest`` carrying a JSON body."""
    import azure.functions as func

    def _post(body):
        return func.HttpRequest(
            method="POST",
            url="/",
            body=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

    return _post


@pytest.fixture
def body():
    """Decode a function's JSON response body."""
    def _body(response):
        return json.loads(response.get_body())

    return _body

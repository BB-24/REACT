"""Tests for the mock fabric's own guarantees, and for the client seam.

The mock is load-bearing for every other test in this suite, so the properties
it claims to reproduce -- immutability, append-only ledger semantics, at-least-
once event delivery -- are asserted here rather than assumed.
"""
import pytest

from DiskSnapshot import handle_snapshot
from MemoryAcquisition import handle_acquisition
from shared import clients, config, mocks
from shared.mocks import ImmutabilityError, MockAzureError

WINDOWS_VM = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourceGroups/rg-victims"
    "/providers/Microsoft.Compute/virtualMachines/web-01"
)


# --- The client seam ---------------------------------------------------------


def test_mock_mode_is_off_by_default(monkeypatch):
    """A missing setting must fail closed towards real Azure: fabricating
    evidence silently is far worse than failing to reach a subscription."""
    monkeypatch.delenv("REACT_MOCK_MODE", raising=False)
    assert clients.mock_mode() is False


@pytest.mark.parametrize("value", ["false", "0", "no", "off", "FALSE"])
def test_falsy_strings_do_not_enable_mock_mode(monkeypatch, value):
    """Azure app settings are always strings, so 'false' must not be truthy."""
    monkeypatch.setenv("REACT_MOCK_MODE", value)
    assert clients.mock_mode() is False


@pytest.mark.parametrize("value", ["true", "1", "yes", "on", "TRUE"])
def test_truthy_strings_enable_mock_mode(monkeypatch, value):
    monkeypatch.setenv("REACT_MOCK_MODE", value)
    assert clients.mock_mode() is True


def test_ambiguous_boolean_is_rejected(monkeypatch):
    monkeypatch.setenv("REACT_MOCK_MODE", "maybe")
    with pytest.raises(config.ConfigError):
        clients.mock_mode()


def test_mock_credential_never_issues_a_token(mock_estate):
    """If anything asks for one, a real SDK client has leaked past the seam."""
    with pytest.raises(MockAzureError):
        clients.credential().get_token("https://storage.azure.com/.default")


# --- Immutability (REQ-3.5.1) ------------------------------------------------


def test_evidence_container_is_seeded_under_legal_hold(mock_estate):
    container = mock_estate.container(
        mocks.EVIDENCE_ACCOUNT, mocks.EVIDENCE_CONTAINER
    )
    assert container.legal_hold is True
    assert container.legal_hold_tags == ["react-active-investigation"]
    assert container.policy_locked is True


def test_legal_hold_blocks_overwriting_evidence(mock_estate):
    """The attack this defeats: replace an image with a doctored one so its
    hash matches a forged ledger row."""
    mock_estate.put_blob(
        mocks.EVIDENCE_ACCOUNT, mocks.EVIDENCE_CONTAINER, "INC-1/web-01/m.raw",
        b"original",
    )
    with pytest.raises(ImmutabilityError):
        mock_estate.put_blob(
            mocks.EVIDENCE_ACCOUNT, mocks.EVIDENCE_CONTAINER,
            "INC-1/web-01/m.raw", b"tampered",
        )


def test_legal_hold_blocks_deleting_evidence(mock_estate):
    mock_estate.put_blob(
        mocks.EVIDENCE_ACCOUNT, mocks.EVIDENCE_CONTAINER, "INC-1/web-01/m.raw",
        b"original",
    )
    with pytest.raises(ImmutabilityError):
        mock_estate.delete_blob(
            mocks.EVIDENCE_ACCOUNT, mocks.EVIDENCE_CONTAINER, "INC-1/web-01/m.raw"
        )


def test_tool_repository_stays_mutable(mock_estate):
    """Tools get replaced as new builds ship; they are not evidence."""
    mock_estate.put_blob(
        mocks.EVIDENCE_ACCOUNT, mocks.TOOLS_CONTAINER, "winpmem.exe", b"v2"
    )
    assert mock_estate.get_blob(
        mocks.EVIDENCE_ACCOUNT, mocks.TOOLS_CONTAINER, "winpmem.exe"
    ).data == b"v2"


# --- Event Grid --------------------------------------------------------------


def test_blob_creation_queues_an_event_rather_than_dispatching_inline(mock_estate):
    """Event Grid is asynchronous; pretending otherwise would hide the gap the
    custody design has to tolerate."""
    mock_estate.put_blob(
        mocks.EVIDENCE_ACCOUNT, mocks.EVIDENCE_CONTAINER, "INC-1/web-01/m.raw",
        b"data",
    )
    assert len(mock_estate.events) == 1
    assert mock_estate.ledger_rows == []


def test_draining_delivers_and_empties_the_queue(mock_estate, post):
    handle_acquisition(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    assert mocks.drain_events()
    assert mock_estate.events == []


def test_tool_uploads_do_not_reach_the_custody_ledger(mock_estate):
    """Hashing WinPmem into the chain of custody would be noise, and the Event
    Grid filter in main.bicep excludes the tools container for the same reason."""
    mock_estate.put_blob(
        mocks.EVIDENCE_ACCOUNT, mocks.TOOLS_CONTAINER, "winpmem.exe", b"v2"
    )
    delivered = mocks.drain_events()
    assert delivered[0]["status"] == "skipped"
    assert mock_estate.ledger_rows == []


def test_duplicate_delivery_is_recorded_once(mock_estate, post):
    """Event Grid delivers at least once and the ledger cannot be cleaned up."""
    handle_acquisition(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    event = mock_estate.events[0]

    first = mock_estate.drain_events()
    mock_estate.events.append(event)
    second = mock_estate.drain_events()

    assert first[0]["status"] == "recorded"
    assert second[0]["status"] == "duplicate"
    assert len(mock_estate.ledger_rows) == 1


# --- Ledger semantics (REQ-3.5.3) --------------------------------------------


def test_ledger_rejects_update_and_delete(mock_estate):
    connection = clients.sql_connection()
    cursor = connection.cursor()
    for statement in (
        "UPDATE dbo.EvidenceLedger SET Sha256Hash = ?",
        "DELETE FROM dbo.EvidenceLedger",
    ):
        with pytest.raises(MockAzureError):
            cursor.execute(statement, ["x"])


def test_unrecognised_statements_fail_loudly(mock_estate):
    """Returning an empty result would be read as 'no evidence recorded'."""
    cursor = clients.sql_connection().cursor()
    with pytest.raises(MockAzureError):
        cursor.execute("SELECT * FROM dbo.EvidenceLedger", [])


def test_ledger_chain_is_intact_after_a_full_run(mock_estate, post):
    handle_acquisition(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    mocks.drain_events()
    handle_snapshot(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    mocks.drain_events()

    intact, first_bad = mock_estate.verify_ledger()
    assert intact is True and first_bad is None
    assert len(mock_estate.ledger_rows) == 2


def test_tampering_with_a_recorded_hash_breaks_the_chain(mock_estate, post):
    """This is what the Azure SQL Ledger digest gives us in production, and
    what makes a custody row worth more than a log line."""
    handle_acquisition(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    mocks.drain_events()

    mock_estate.ledger_rows[0]["Sha256Hash"] = "0" * 64
    intact, first_bad = mock_estate.verify_ledger()
    assert intact is False
    assert first_bad == 1


# --- Estate snapshot ---------------------------------------------------------


def test_state_view_is_json_serialisable(mock_estate, post):
    import json

    handle_acquisition(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))
    mocks.drain_events()
    handle_snapshot(post({"IncidentId": "INC-1", "TargetVM": WINDOWS_VM}))

    state = json.loads(json.dumps(mocks.snapshot_state(), default=str))
    assert state["ledger"]["chainIntact"] is True
    assert len(state["snapshots"]) == 4  # two disks, source + enclave each

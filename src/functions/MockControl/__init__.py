"""Control surface for the simulated estate. Registered only in mock mode.

These endpoints exist so the pipeline can be driven and inspected without an
Azure subscription: look at the estate, deliver the queued Event Grid events,
verify the ledger chain, and reset between runs.

``function_app.py`` registers this blueprint only when ``REACT_MOCK_MODE`` is
on, so none of it is reachable in a real deployment. Even so, every route sits
behind the function-level auth key like the rest of the app.
"""
import json
import logging

import azure.functions as func

from shared import clients, mocks

bp = func.Blueprint()


def _json_response(status_code, body):
    return func.HttpResponse(
        json.dumps(body, indent=2, default=str),
        status_code=status_code,
        mimetype="application/json",
    )


def _guard():
    """Refuse to act if mock mode was turned off after registration."""
    if not clients.mock_mode():
        return _json_response(
            409, {"error": "Mock mode is not enabled; there is no estate to act on."}
        )
    return None


@bp.route(route="mock/state", methods=["GET"])
def mock_state(req: func.HttpRequest) -> func.HttpResponse:
    """The whole simulated estate: VMs, disks, snapshots, blobs, ledger."""
    blocked = _guard()
    if blocked:
        return blocked
    return _json_response(200, mocks.snapshot_state())


@bp.route(route="mock/drain", methods=["POST"])
def mock_drain(req: func.HttpRequest) -> func.HttpResponse:
    """Deliver queued ``BlobCreated`` events to ChainOfCustody.

    Event Grid is asynchronous, so the mock queues rather than dispatching
    inline. This is the step that stands in for that delivery.
    """
    blocked = _guard()
    if blocked:
        return blocked
    delivered = mocks.drain_events()
    logging.info("Mock Event Grid delivered %d event(s).", len(delivered))
    return _json_response(
        200, {"delivered": len(delivered), "results": delivered}
    )


@bp.route(route="mock/ledger/verify", methods=["GET"])
def mock_verify_ledger(req: func.HttpRequest) -> func.HttpResponse:
    """Recompute the ledger hash chain, as ``sys.sp_verify_database_ledger``
    would on Azure SQL."""
    blocked = _guard()
    if blocked:
        return blocked
    intact, first_bad = mocks.world().verify_ledger()
    return _json_response(
        200 if intact else 500,
        {
            "chainIntact": intact,
            "firstTamperedEntryId": first_bad,
            "rowCount": len(mocks.world().ledger_rows),
        },
    )


@bp.route(route="mock/reset", methods=["POST"])
def mock_reset(req: func.HttpRequest) -> func.HttpResponse:
    """Reseed the estate, then re-attach the Event Grid subscription."""
    blocked = _guard()
    if blocked:
        return blocked
    mocks.reset()
    # reset() clears the handler list along with everything else, so the
    # simulated subscription has to be re-established or events would go
    # nowhere and custody would silently stop being recorded.
    wire_event_grid()
    return _json_response(200, {"status": "reset", "estate": mocks.snapshot_state()})


def wire_event_grid():
    """Subscribe ChainOfCustody to the simulated ``BlobCreated`` topic."""
    from ChainOfCustody import process_blob_created

    return mocks.register_blob_created_handler(process_blob_created)

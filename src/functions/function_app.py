"""Azure Functions v2 application root for REACT automated forensic pipeline.

Registers all pipeline blueprints:
- NetworkContainment (SOP 2 Phase 1)
- MemoryAcquisition (SOP 2 Phase 2)
- DiskSnapshot (SOP 2 Phase 2b)
- ChainOfCustody (SOP 2 Phase 3)
"""

import json
import logging

import azure.functions as func
from ChainOfCustody import bp as chain_of_custody_bp
from DiskSnapshot import bp as disk_snapshot_bp
from MemoryAcquisition import bp as memory_acquisition_bp
from NetworkContainment import bp as network_containment_bp
from shared import clients

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

app.register_blueprint(network_containment_bp)
app.register_blueprint(memory_acquisition_bp)
app.register_blueprint(disk_snapshot_bp)
app.register_blueprint(chain_of_custody_bp)


@app.route(route="health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(
            {
                "status": "healthy",
                "mockMode": clients.mock_mode(),
                "simulationLabel": "SIMULATED — synthetic data; no Azure resources or live machines touched.",
            }
        ),
        status_code=200,
        mimetype="application/json",
    )


@app.route(route="mock/state", methods=["GET"])
def mock_state(req: func.HttpRequest) -> func.HttpResponse:
    if not clients.mock_mode():
        return func.HttpResponse(
            json.dumps({"error": "Mock mode is not active."}),
            status_code=403,
            mimetype="application/json",
        )
    from shared import mocks

    return func.HttpResponse(
        json.dumps(mocks.snapshot_state()),
        status_code=200,
        mimetype="application/json",
    )


@app.route(route="mock/reset", methods=["POST"])
def mock_reset(req: func.HttpRequest) -> func.HttpResponse:
    if not clients.mock_mode():
        return func.HttpResponse(
            json.dumps({"error": "Mock mode is not active."}),
            status_code=403,
            mimetype="application/json",
        )
    from shared import mocks

    mocks.reset()
    return func.HttpResponse(
        json.dumps({"status": "reset", "message": "Simulated Azure estate reseeded to initial state."}),
        status_code=200,
        mimetype="application/json",
    )


if clients.mock_mode():
    logging.info(
        "Mock mode active for REACT Function App (SIMULATED — synthetic data; no Azure resources or live machines touched)."
    )

logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)


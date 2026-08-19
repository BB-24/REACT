"""Azure Functions v2 application root for the REACT incident-response backend.

Each function lives in its own package and exposes a ``func.Blueprint``; this
module does nothing but register them. Keeping the blueprints in separate
directories preserves the per-directory ownership defined in
``.github/CODEOWNERS`` -- Person 2 owns NetworkContainment/, MemoryAcquisition/,
DiskSnapshot/ and ChainOfCustody/, Person 3 owns ReportGenerator/ -- so the
three of us never edit the same file.

The response pipeline, in order:

1. ``POST /api/contain``  -- isolate the VM                    (SOP 2 Phase 1)
2. ``POST /api/acquire``  -- stream memory to the enclave      (SOP 2 Phase 2)
3. ``POST /api/snapshot`` -- snapshot and copy the disks       (SRS 3.4)
4. ``POST /api/custody``  -- Event Grid webhook; hash + ledger (SRS 3.5)

Steps 1-3 are driven by the Logic App in order. Step 4 is not called by anyone:
Event Grid invokes it whenever a blob lands in the enclave container.
"""
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

# ReportGenerator is Person 3's blueprint. It is registered here once that
# package exposes a `bp` symbol:
#     from ReportGenerator import bp as report_generator_bp
#     app.register_blueprint(report_generator_bp)

if clients.mock_mode():
    # Mock mode only: the control endpoints and the in-process stand-in for the
    # Event Grid system topic. Neither is imported when running against Azure.
    from MockControl import bp as mock_control_bp, wire_event_grid

    app.register_blueprint(mock_control_bp)
    wire_event_grid()
    logging.warning(
        "Mock estate active. Drive the pipeline with POST /api/contain -> "
        "/api/acquire -> /api/mock/drain -> /api/snapshot -> /api/mock/drain, "
        "and inspect it with GET /api/mock/state."
    )

logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(
    logging.WARNING
)

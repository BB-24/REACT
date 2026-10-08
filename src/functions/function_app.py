"""Azure Functions v2 application root for REACT memory acquisition.

Registers the MemoryAcquisition blueprint (SOP 2 Phase 2).
"""

import logging

import azure.functions as func
from MemoryAcquisition import bp as memory_acquisition_bp
from shared import clients

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

app.register_blueprint(memory_acquisition_bp)

if clients.mock_mode():
    logging.info("Mock mode active for MemoryAcquisition endpoint.")

logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)

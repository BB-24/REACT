"""Azure Functions v2 application root for REACT response functions.

Registers NetworkContainment and MemoryAcquisition blueprints.
"""

import logging

import azure.functions as func
from MemoryAcquisition import bp as memory_acquisition_bp
from NetworkContainment import bp as network_containment_bp
from shared import clients

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

app.register_blueprint(network_containment_bp)
app.register_blueprint(memory_acquisition_bp)

if clients.mock_mode():
    logging.info("Mock mode active for MemoryAcquisition endpoint.")

logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)

"""Azure Functions v2 application root for the REACT incident-response backend.

Each function lives in its own package and exposes a ``func.Blueprint``; this
module does nothing but register them. Keeping the blueprints in separate
directories preserves the per-directory ownership defined in
``.github/CODEOWNERS`` -- Person 2 owns NetworkContainment/ and ChainOfCustody/,
Person 3 owns ReportGenerator/ -- so the three of us never edit the same file.
"""
import logging

import azure.functions as func

from ChainOfCustody import bp as chain_of_custody_bp
from NetworkContainment import bp as network_containment_bp

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

app.register_blueprint(network_containment_bp)
app.register_blueprint(chain_of_custody_bp)

# ReportGenerator is Person 3's blueprint. It is registered here once that
# package exposes a `bp` symbol:
#     from ReportGenerator import bp as report_generator_bp
#     app.register_blueprint(report_generator_bp)

logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(
    logging.WARNING
)

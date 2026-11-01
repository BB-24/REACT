"""Azure Functions blueprint for forensic timeline ingestion into Cosmos DB."""

from __future__ import annotations

import json
import logging

import azure.functions as func
from shared import timeline_ingestion
from shared.timeline import SchemaValidationError

logger = logging.getLogger(__name__)

bp = func.Blueprint()


@bp.route(route="timeline/ingest", methods=["POST"])
def ingest_timeline_http(req: func.HttpRequest) -> func.HttpResponse:
    """HTTP trigger to ingest Plaso timeline output into Cosmos DB Serverless."""
    try:
        body = req.get_json()
    except Exception as err:
        return func.HttpResponse(
            json.dumps({"error": f"Invalid JSON request body: {err}"}),
            status_code=400,
            mimetype="application/json",
        )

    if not isinstance(body, dict):
        return func.HttpResponse(
            json.dumps({"error": "Request body must be a JSON object"}),
            status_code=400,
            mimetype="application/json",
        )

    incident_id = body.get("incidentId") or body.get("IncidentID")
    if not incident_id or not isinstance(incident_id, str) or not incident_id.strip():
        return func.HttpResponse(
            json.dumps({"error": "Missing required field 'incidentId'"}),
            status_code=400,
            mimetype="application/json",
        )

    timeline_source = body.get("timelinePath") or body.get("events") or body.get("timelineContent")
    if timeline_source is None:
        return func.HttpResponse(
            json.dumps(
                {"error": "Missing required field 'timelinePath', 'events', or 'timelineContent'"}
            ),
            status_code=400,
            mimetype="application/json",
        )

    try:
        summary = timeline_ingestion.ingest_timeline(
            timeline_source=timeline_source,
            incident_id=incident_id.strip(),
        )
        status_code = 200 if summary.written_records > 0 or summary.total_records == 0 else 207
        return func.HttpResponse(
            json.dumps(summary.to_dict()),
            status_code=status_code,
            mimetype="application/json",
        )
    except SchemaValidationError as err:
        return func.HttpResponse(
            json.dumps({"error": str(err)}),
            status_code=400,
            mimetype="application/json",
        )
    except Exception as err:
        logger.error("Timeline ingestion failed: %s", err)
        return func.HttpResponse(
            json.dumps({"error": f"Ingestion failed: {err}"}),
            status_code=500,
            mimetype="application/json",
        )

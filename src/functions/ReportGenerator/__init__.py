"""Azure Function HTTP Trigger for automated forensic PDF report generation.

Covers:
- Person 3 / Issue #34: [P3-4] Implement ReportGenerator Azure Function
- Routes: /api/GenerateReport, /api/ReportGenerator, /api/report/generate
- Input: JSON {"IncidentID": "<incident-id>", "format": "pdf"}
- Output: PDF stored in immutable WORM 'reports' container with 202 Accepted status
"""

from __future__ import annotations

import json
import logging

import azure.functions as func
from shared.reporting import generate_and_store_report

bp = func.Blueprint()


def _json_response(status_code: int, payload: dict) -> func.HttpResponse:
    return func.HttpResponse(
        body=json.dumps(payload),
        status_code=status_code,
        mimetype="application/json",
    )


def handle_generate_report(req: func.HttpRequest) -> func.HttpResponse:
    """Core request processing for report generation."""
    try:
        body = req.get_json()
    except (ValueError, TypeError, AttributeError) as exc:
        return _json_response(400, {"error": f"Invalid JSON in request body: {exc}"})

    if not isinstance(body, dict):
        return _json_response(400, {"error": "Request body must be a JSON object."})

    incident_id = body.get("IncidentID") or body.get("incidentId")
    if not incident_id or not isinstance(incident_id, str) or not incident_id.strip():
        return _json_response(
            400,
            {"error": "Missing or empty required parameter: 'IncidentID'"},
        )

    clean_incident_id = incident_id.strip()
    format_type = str(body.get("format", "pdf")).strip().lower()

    if format_type not in ("pdf", "html"):
        return _json_response(
            400,
            {"error": f"Unsupported report format: '{format_type}'. Supported: 'pdf', 'html'."},
        )

    try:
        result = generate_and_store_report(
            incident_id=clean_incident_id,
            format_type=format_type,
        )
        return _json_response(202, result)
    except Exception as exc:
        logging.error("Failed to generate report for incident %s: %s", clean_incident_id, exc)
        return _json_response(
            500,
            {"error": f"Report generation failed: {exc}"},
        )


@bp.route(route="GenerateReport", methods=["POST"])
def generate_report_http(req: func.HttpRequest) -> func.HttpResponse:
    """OpenAPI canonical endpoint: POST /api/GenerateReport."""
    return handle_generate_report(req)


@bp.route(route="ReportGenerator", methods=["POST"])
def report_generator_alias(req: func.HttpRequest) -> func.HttpResponse:
    """Legacy/direct blueprint alias: POST /api/ReportGenerator."""
    return handle_generate_report(req)


@bp.route(route="report/generate", methods=["POST"])
def report_generate_path_alias(req: func.HttpRequest) -> func.HttpResponse:
    """RESTful path alias: POST /api/report/generate."""
    return handle_generate_report(req)

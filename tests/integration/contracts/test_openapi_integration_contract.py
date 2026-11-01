"""Verify the documented Person 2/3 OpenAPI contract matches the Logic App."""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def _resolve_schema(document, schema):
    if "$ref" in schema:
        pointer = schema["$ref"].removeprefix("#/").split("/")
        resolved = document
        for key in pointer:
            resolved = resolved[key]
        schema = resolved
    if "allOf" in schema:
        merged = {"properties": {}, "required": []}
        for item in schema["allOf"]:
            part = _resolve_schema(document, item)
            merged["properties"].update(part.get("properties", {}))
            merged["required"].extend(part.get("required", []))
        schema = merged
    return schema


def _request_schema(document, path, method="post"):
    operation = document["paths"][path][method]
    return _resolve_schema(
        document,
        operation["requestBody"]["content"]["application/json"]["schema"],
    )


class TestOpenApiIntegrationContract(unittest.TestCase):
    def setUp(self):
        self.openapi = json.loads(
            (ROOT / "docs" / "integration-openapi.json").read_text(encoding="utf-8")
        )
        self.workflow = json.loads(
            (ROOT / "src" / "logic-apps" / "workflow.json").read_text(encoding="utf-8")
        )
        self.playbook = json.loads(
            (ROOT / "src" / "logic-apps" / "incident-response-playbook.json").read_text(
                encoding="utf-8"
            )
        )

    def test_required_person_two_and_three_operations_are_defined(self):
        expected = {
            "/triggers/manual/run": "post",
            "/status": "get",
            "/api/ProcessEvidence": "post",
            "/api/GenerateReport": "post",
        }
        for path, method in expected.items():
            with self.subTest(path=path):
                self.assertIn(path, self.openapi["paths"])
                self.assertIn(method, self.openapi["paths"][path])
                self.assertIn("security", self.openapi["paths"][path][method])

    def test_logic_app_authentication_audiences_are_parameterized(self):
        parameters = self.workflow["parameters"]
        self.assertIn("acquisitionStatusAudience", parameters)
        self.assertIn("analysisApiAudience", parameters)

        module = (ROOT / "iac" / "modules" / "logic-app.bicep").read_text(encoding="utf-8")
        self.assertIn("param acquisitionStatusAudience string", module)
        self.assertIn("param analysisApiAudience string", module)

    def test_acquisition_contract_matches_logic_app_request(self):
        schema = _request_schema(self.openapi, "/triggers/manual/run")
        required = set(schema["required"])
        self.assertTrue(
            {
                "IncidentID",
                "TargetVM",
                "IPAddress",
                "SubscriptionID",
                "EvidenceBlobUri",
            }.issubset(required)
        )

        actions = self.workflow["actions"]["High_Or_Critical_Severity_Only"]["actions"]
        acquisition = actions["Containment_Test_Mode"]["else"]["actions"][
            "Check_Containment_Success"
        ]["actions"]["Start_Acquisition_Workflow"]["inputs"]
        self.assertEqual(set(acquisition["body"]), set(schema["properties"]))
        self.assertIn(
            "api-version",
            [
                parameter["name"]
                for parameter in self.openapi["paths"]["/triggers/manual/run"]["post"]["parameters"]
            ],
        )

        arm_parameters = self.playbook["parameters"]
        self.assertNotIn("defaultValue", arm_parameters["acquisitionArmRequestUrl"])
        self.assertNotIn("defaultValue", arm_parameters["acquisitionStatusUrl"])
        self.assertIn("acquisitionStatusAudience", arm_parameters)

        playbook_definition = self.playbook["resources"][0]["properties"]["definition"]
        playbook_actions = playbook_definition["actions"]["High_Or_Critical_Severity_Only"][
            "actions"
        ]["Check_Containment_Success"]["actions"]
        playbook_acquisition = playbook_actions["Start_Acquisition_Workflow"]["inputs"]
        self.assertEqual(set(playbook_acquisition["body"]), set(schema["properties"]))

    def test_status_contract_uses_incident_id_and_terminal_failure(self):
        operation = self.openapi["paths"]["/status"]["get"]
        incident_id = operation["parameters"][0]
        self.assertEqual(incident_id["name"], "incidentId")
        self.assertEqual(incident_id["in"], "query")
        status_schema = self.openapi["components"]["schemas"]["AcquisitionStatus"]
        self.assertIn("Completed", status_schema["properties"]["status"]["enum"])
        self.assertIn("Failed", status_schema["properties"]["status"]["enum"])

        actions = self.workflow["actions"]["High_Or_Critical_Severity_Only"]["actions"]
        success = actions["Containment_Test_Mode"]["else"]["actions"]["Check_Containment_Success"][
            "actions"
        ]
        until = success["Wait_For_Evidence_Acquisition"]
        self.assertIn("'Failed'", until["expression"])
        acquisition_check = success["Check_Acquisition_Completed"]
        self.assertIn("Start_Analysis_Pipeline", acquisition_check["actions"])
        self.assertIn("Record_Acquisition_Failure", acquisition_check["else"]["actions"])

    def test_analysis_contract_matches_logic_app_analysis_payload(self):
        schema = _request_schema(self.openapi, "/api/ProcessEvidence")
        required = set(schema["required"])
        self.assertTrue(
            {
                "IncidentID",
                "TargetVM",
                "IPAddress",
                "SubscriptionID",
                "IncidentSeverity",
                "EvidenceBlobUri",
                "ContainmentDetails",
                "PipelineStatus",
                "Timestamp",
            }.issubset(required)
        )

        actions = self.workflow["actions"]["High_Or_Critical_Severity_Only"]["actions"]
        analysis = actions["Containment_Test_Mode"]["else"]["actions"]["Check_Containment_Success"][
            "actions"
        ]["Check_Acquisition_Completed"]["actions"]["Start_Analysis_Pipeline"]["inputs"]
        self.assertEqual(set(analysis["body"]), set(schema["properties"]))
        self.assertIn("authentication", analysis)
        self.assertIn("analysisApiAudience", self.playbook["parameters"])

        playbook_definition = self.playbook["resources"][0]["properties"]["definition"]
        playbook_analysis = playbook_definition["actions"]["High_Or_Critical_Severity_Only"][
            "actions"
        ]["Check_Containment_Success"]["actions"]["Check_Acquisition_Completed"]["actions"][
            "Start_Analysis_Pipeline"
        ]["inputs"]
        self.assertEqual(set(playbook_analysis["body"]), set(schema["properties"]))
        self.assertIn("authentication", playbook_analysis)

    def test_openapi_local_references_resolve(self):
        def verify(value):
            if isinstance(value, dict):
                if "$ref" in value:
                    self.assertTrue(value["$ref"].startswith("#/"))
                    target = self.openapi
                    for part in value["$ref"][2:].split("/"):
                        target = target[part]
                    self.assertIsNotNone(target)
                for child in value.values():
                    verify(child)
            elif isinstance(value, list):
                for child in value:
                    verify(child)

        verify(self.openapi)

    def test_cosmos_artifact_schemas_include_partition_and_required_artifact_types(self):
        schemas = self.openapi["components"]["schemas"]
        self.assertIn(
            "/IncidentID",
            schemas["ForensicArtifactRecord"]["description"],
        )
        for name, artifact_type in (
            ("ProcessArtifact", "process"),
            ("NetworkConnectionArtifact", "networkConnection"),
            ("TimelineEventArtifact", "timelineEvent"),
        ):
            with self.subTest(artifact=name):
                schema = schemas[name]
                self.assertIn("IncidentID", schema["required"])
                self.assertIn("artifactType", schema["required"])
                self.assertEqual(schema["properties"]["artifactType"]["const"], artifact_type)

    def test_report_trigger_contract_is_incident_scoped(self):
        schema = _request_schema(self.openapi, "/api/GenerateReport")
        self.assertEqual(schema["required"], ["IncidentID"])
        self.assertEqual(
            self.openapi["paths"]["/api/GenerateReport"]["post"]["responses"]["202"]["description"],
            "Report generation accepted.",
        )


if __name__ == "__main__":
    unittest.main()

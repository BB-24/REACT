
# Automated Testing Guide (`testing-guide.md`)

This guide outlines the testing framework, test directory layout, and execution instructions for the **Automated Cloud Forensic Pipeline (REACT / AACFP)** across all sub-components and integration boundaries (**Person 1**, **Person 2**, and **Person 3**).

---

## 1. Test Architecture & Structure

The repository maintains two primary testing tiers:
1. **Unit Tests (`tests/unit/` & `tests/test_network_containment.py`)**: Validate individual functions, algorithms, parameters, schemas, and error boundaries in total isolation using local stubs and mocks.
2. **Integration & Contract Tests (`tests/integration/`)**: Validate cross-tier payload schemas, multi-step orchestration workflows, data handoffs, and complete pipeline simulations.

```
tests/
├── conftest.py                              # Universal Azure SDK / Storage / Functions mocks
├── test_network_containment.py              # Primary Network Containment Azure Function unit tests
│
├── unit/                                    # Role-Specific Unit Test Suites
│   ├── __init__.py
│   ├── test_person1_orchestration.py        # Person 1: Webhook parsing, NSG rules, NIC swaps, tag bypass
│   ├── test_person2_acquisition_ledger.py   # Person 2: SAS generation, pathing, Event Grid, SQL ledger
│   └── test_person3_analysis_reporting.py   # Person 3: Plaso/Volatility schemas, Cosmos DB, PDF data model
│
└── integration/                             # Cross-Role & End-to-End Integration Suites
    ├── __init__.py
    ├── contracts/
    │   └── test_payload_contracts.py        # Schema validation against docs/payload-contract.json
    ├── p1p2/
    │   └── test_p1_p2_orchestration.py      # P1 Logic App -> P2 Containment & Acquisition handoff
    ├── p2p3/
    │   └── test_p2_p3_handoff.py            # P2 Evidence layout & hashes -> P3 Analysis ingestion
    ├── p1p3/
    │   └── test_p1_p3_reporting.py          # P1 Context & containment -> P3 PDF Report Generator
    └── e2e/
        └── test_e2e_pipeline.py             # Full end-to-end multi-tier pipeline execution simulations
```

---

## 2. Test Suites by Role & Responsibility

### 🟦 **Person 1: Cloud Orchestration & Infrastructure Security**
- **Test Files**: [`tests/unit/test_person1_orchestration.py`](file:///c:/BHAVYA/Acer%20I5/IT%20PERSONAL/NFSU%20%28CSE%29/SEM%207/PROJECT/code%20repository/tests/unit/test_person1_orchestration.py), [`tests/test_network_containment.py`](file:///c:/BHAVYA/Acer%20I5/IT%20PERSONAL/NFSU%20%28CSE%29/SEM%207/PROJECT/code%20repository/tests/test_network_containment.py)
- **Requirements Covered**: `REQ-3.1` (Triggering & Ingestion), `REQ-3.2` (Network Containment)
- **What is Tested**:
  - Webhook JSON schema compliance, entity extraction (`IncidentID`, `TargetVM`, `IPAddress`, `SubscriptionID`).
  - Severity gating: `High` and `Critical` proceed; `Low` and `Medium` are rejected or bypassed.
  - NSG naming sanitization and 80-character maximum enforcement.
  - Isolation NSG rule generation (Priority 100 Storage Egress, 4095 Inbound Deny, 4096 Outbound Deny).
  - Target VM primary NIC discovery and async ARM NSG swapping.
  - `Critical-Infrastructure: True` tag detection returning `status: "Bypassed"` without isolating the host.

### 🟩 **Person 2: Evidence Acquisition & Cryptographic Chain of Custody**
- **Test File**: [`tests/unit/test_person2_acquisition_ledger.py`](file:///c:/BHAVYA/Acer%20I5/IT%20PERSONAL/NFSU%20%28CSE%29/SEM%207/PROJECT/code%20repository/tests/unit/test_person2_acquisition_ledger.py)
- **Requirements Covered**: `REQ-3.3` (Memory Acquisition), `REQ-3.4` (Disk Acquisition), `REQ-3.5` (Chain of Custody)
- **What is Tested**:
  - Live memory extraction direct-to-blob streaming contracts without local disk caching.
  - Tool download SAS tokens (read-only, scoped to `tools` container) vs Evidence SAS tokens.
  - Short-lived write-only SAS minting (`create`, `write`, `add` permissions only, 60-min TTL, clock skew handling).
  - Deterministic enclave storage paths: `<incident>/<host>/<artifact>-<timestamp>.<ext>`.
  - Event Grid `Microsoft.Storage.BlobCreated` event parsing and payload extraction.
  - SHA-256 cryptographic hashing algorithms on acquired evidence chunks.
  - Azure SQL Database Ledger metadata record schema validation (`EvidenceLedger` table).

### 🟨 **Person 3: Automated Forensic Analysis & PDF Reporting Engine**
- **Test File**: [`tests/unit/test_person3_analysis_reporting.py`](file:///c:/BHAVYA/Acer%20I5/IT%20PERSONAL/NFSU%20%28CSE%29/SEM%207/PROJECT/code%20repository/tests/unit/test_person3_analysis_reporting.py)
- **Requirements Covered**: `REQ-3.6` (Automated Analysis & PDF Reporting)
- **What is Tested**:
  - Plaso / Log2Timeline parsed event normalization for Cosmos DB ingestion.
  - Volatility 3 memory findings data models (malfind injected code blocks, suspicious PIDs).
  - Cosmos DB Serverless document schema and partition key alignment (`/IncidentID`).
  - PDF Report data compiler context assembly (Incident metadata, Containment, Ledger hashes, Findings).
  - Explicit warning banner generation for `Critical-Infrastructure` bypasses.
  - Graceful degradation and warning generation on partial or failed evidence collection.

### 🌐 **Multi-Tier Integration & E2E Contracts**
- **Test Files**: [`tests/integration/`](file:///c:/BHAVYA/Acer%20I5/IT%20PERSONAL/NFSU%20%28CSE%29/SEM%207/PROJECT/code%20repository/tests/integration/)
- **What is Tested**:
  - `contracts/test_payload_contracts.py`: Strict schema validation against [`docs/payload-contract.json`](file:///c:/BHAVYA/Acer%20I5/IT%20PERSONAL/NFSU%20%28CSE%29/SEM%207/PROJECT/code%20repository/docs/payload-contract.json).
  - `p1p2/test_p1_p2_orchestration.py`: Logic App webhook -> Network Containment -> Acquisition workflow handoff.
  - `p2p3/test_p2_p3_handoff.py`: Enclave blob layout -> Chain of Custody hashes -> Analysis ingestion.
  - `p1p3/test_p1_p3_reporting.py`: Incident context & containment details -> PDF Report Generator.
  - `e2e/test_e2e_pipeline.py`: Complete incident lifecycle simulations (Happy path, Critical Infrastructure, Non-Severe early exit, and failure handling).

---

## 3. How to Run Tests Locally

### 3.1 Prerequisites
Ensure Python 3.10+ is installed and dependencies are available:
```bash
pip install pytest pytest-cov pytest-mock ruff
pip install -r src/functions/requirements.txt
```

> [!NOTE]
> All Azure SDK dependencies and cloud calls are automatically stubbed via [`tests/conftest.py`](file:///c:/BHAVYA/Acer%20I5/IT%20PERSONAL/NFSU%20%28CSE%29/SEM%207/PROJECT/code%20repository/tests/conftest.py), allowing tests to execute rapidly in disconnected, local environments without Azure credentials.

---

### 3.2 Running the Full Test Suite
To run all 56+ unit and integration tests:
```bash
pytest -v
```

---

### 3.3 Running Tests by Role

#### Run Person 1 Tests (Orchestration & Network Containment):
```bash
pytest tests/unit/test_person1_orchestration.py tests/test_network_containment.py -v
```

#### Run Person 2 Tests (Acquisition & SQL Ledger):
```bash
pytest tests/unit/test_person2_acquisition_ledger.py -v
```

#### Run Person 3 Tests (Analysis & Report Generation):
```bash
pytest tests/unit/test_person3_analysis_reporting.py -v
```

---

### 3.4 Running Tests by Integration Tier

#### Run Payload Contract Tests:
```bash
pytest tests/integration/contracts/ -v
```

#### Run P1 ↔ P2 Orchestration Tests:
```bash
pytest tests/integration/p1p2/ -v
```

#### Run P2 ↔ P3 Handoff Tests:
```bash
pytest tests/integration/p2p3/ -v
```

#### Run P1 ↔ P3 Reporting Tests:
```bash
pytest tests/integration/p1p3/ -v
```

#### Run End-to-End Pipeline Simulations:
```bash
pytest tests/integration/e2e/ -v
```

---

### 3.5 Generating Code Coverage Reports
Generate a terminal and HTML coverage report for the Python functions:
```bash
pytest --cov=src/functions --cov-report=term-missing --cov-report=html:coverage_html
```
Open `coverage_html/index.html` in any web browser to view per-line coverage.

---

### 3.6 Code Quality & Formatting Checks
Run the Ruff linter and formatter:
```bash
# Check code style and common bugs
ruff check src/ tests/

# Check formatting
ruff format --check src/ tests/

# Automatically fix format issues
ruff format src/ tests/
```

---

### 3.7 Forensic Analyzer Container (Plaso Timeline)

The forensic analyzer container performs artifact triage and timeline extraction from disk images and log artifacts using Plaso (`log2timeline` and `psort`).

#### 3.7.1 Local Verification Script
Run the automated verification script that verifies Docker availability, prepares sample evidence, builds the image, and executes verification:
```bash
bash src/containers/forensic-analyzer/verify-local.sh
```

#### 3.7.2 Manual Local Docker Commands

1. **Build the container image**:
```bash
docker build -t react-forensic-analyzer src/containers/forensic-analyzer
```

2. **Execute timeline extraction with read-only sample evidence**:
```bash
docker run --rm \
  -v "$(pwd)/sample-evidence:/workspace/input:ro" \
  -v "$(pwd)/sample-evidence-output:/workspace/output" \
  react-forensic-analyzer
```

3. **Execute with direct default parser set (optional)**:
```bash
docker run --rm \
  -e PLASO_PARSERS="default" \
  -v "$(pwd)/sample-evidence:/workspace/input:ro" \
  -v "$(pwd)/sample-evidence-output:/workspace/output" \
  react-forensic-analyzer
```

#### 3.7.3 Expected Logs

- **Standard Execution (Configured Parsers Mode)**:
```text
[forensic-entrypoint] Running log2timeline using configured parsers mode: amcache,bash_history,bencode,...
[forensic-entrypoint] Extraction completed successfully using configured parsers mode.
[forensic-entrypoint] Running psort and writing JSON timeline to /workspace/output/timeline.json.
[forensic-entrypoint] Timeline generation completed successfully: /workspace/output/timeline.json
```

- **Parser Fallback Execution (When configured parser list contains unsupported names)**:
```text
[forensic-entrypoint] Running log2timeline using configured parsers mode: amcache,bash_history,bencode,...
[forensic-entrypoint] WARNING: log2timeline failed with configured parsers (...). Safely retrying using Plaso default parser set mode...
[forensic-entrypoint] Running log2timeline using Plaso default parser set mode.
[forensic-entrypoint] Extraction completed successfully using Plaso default parser set mode.
[forensic-entrypoint] Running psort and writing JSON timeline to /workspace/output/timeline.json.
[forensic-entrypoint] Timeline generation completed successfully: /workspace/output/timeline.json
```

#### 3.7.4 Expected Exit Codes
- `0`: Successful execution. Input was parsed and a non-empty timeline JSON file was written.
- `1`: Failure. Occurs if `/workspace/input` does not exist, no evidence files are found, or tool execution fails.

#### 3.7.5 Output Path and Evidence Preservation
- **Timeline Output**: Written to `/workspace/output/timeline.json` (mapped to host output directory).
- **Input Preservation**: Evidence is mounted read-only (`:ro`) at `/workspace/input`. The container operates without mutating evidence files, upholding cryptographic chain of custody integrity.

#### 3.7.6 Azure Container Instances (ACI) Guidance
- **Task Lifecycle**: Deploy as a single-run batch job with `restartPolicy: "Never"` or `"OnFailure"`.
- **Volume Mounts**:
  - Mount the evidence share (Azure File Share or Blob NFS/BlobFuse) to `/workspace/input` with `readOnly: true`.
  - Mount the results share to `/workspace/output` with write permissions.
- **Resource Sizing**: Allocate a minimum of 2 vCPUs and 4 GiB memory to accommodate Plaso memory requirements during parsing.
- **Environment Variables**:
  - `FORENSIC_INPUT_DIR`: `/workspace/input`
  - `FORENSIC_OUTPUT_DIR`: `/workspace/output`
  - `PLASO_PARSERS`: `default` (or specific compatible parser list)
- *Note: Downstream Cosmos DB indexing and PDF reporting are executed by separate pipeline stages after container exit and should not be bundled inside this container.*

---

---

### 3.9 ReportGenerator Azure Function (Issue #34 — P3-4)

Issue #34 implements the automated forensic PDF reporting pipeline for Person 3. It aggregates investigation data from Cosmos DB Serverless and Azure SQL Ledger, renders a structured report using Jinja2, converts the HTML to PDF using WeasyPrint (with standard PDF fallback), and stores the resulting PDF in the locked WORM `reports` container.

#### 3.9.1 ReportGenerator Architecture

```text
[ Logic App / SOC Analyst ]
            |
            v  POST /api/GenerateReport {"IncidentID": "INC-2026-001"}
+-------------------------------------------------------------------------+
|                  ReportGenerator Azure Function                         |
|  - Validates IncidentID request parameter                               |
|  - Aggregates investigation data:                                       |
|      * Cosmos DB: timeline events, process findings, network connections|
|      * SQL Ledger: evidence records, cryptographic integrity digest     |
|  - Jinja2 Template: formats 6 required forensic investigation sections  |
|  - WeasyPrint / PDF Generator: compiles valid standard PDF              |
|  - Azure Blob Storage: uploads PDF into 'reports' WORM container        |
+-------------------------------------------------------------------------+
            |                                         |
            v                                         v
   [ Cosmos DB Core SQL ]                    [ Azure SQL Ledger ]
 (timeline-artifacts container)               (dbo.EvidenceLedger)
            |                                         |
            +--------------------+--------------------+
                                 |
                                 v
                     [ reports Container ]
             (Immutable WORM storage, 7-year retention)
```

#### 3.9.2 Azure HTTP Function Endpoints & Payload Contracts

The ReportGenerator blueprint registers the following endpoints:

| Route | Method | Description |
|---|---|---|
| `/api/GenerateReport` | `POST` | Canonical OpenAPI 1.0.0 endpoint |
| `/api/ReportGenerator` | `POST` | Blueprint name alias |
| `/api/report/generate` | `POST` | RESTful path alias |

**Request Body (`application/json`):**
```json
{
  "IncidentID": "INC-2026-001",
  "format": "pdf"
}
```
*Note: Both `IncidentID` and `incidentId` are supported. Optional `format` parameter accepts `"pdf"` (default) or `"html"`.*

**Success Response (`202 Accepted`):**
```json
{
  "status": "Accepted",
  "incidentId": "INC-2026-001",
  "reportId": "RPT-INC-2026-001-20261024010000-a1b2c3",
  "format": "pdf",
  "container": "reports",
  "blobName": "INC-2026-001/RPT-INC-2026-001-20261024010000-a1b2c3.pdf",
  "blobUri": "https://reactevidence.blob.core.windows.net/reports/INC-2026-001/RPT-INC-2026-001-20261024010000-a1b2c3.pdf",
  "sizeBytes": 42180,
  "sha256": "3a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b",
  "generatedUtc": "2026-10-24T01:00:00.000000Z"
}
```

**Client Error Responses (`400 Bad Request`):**
- Missing `IncidentID`: `{"error": "Missing or empty required parameter: 'IncidentID'"}`
- Empty `IncidentID`: `{"error": "Missing or empty required parameter: 'IncidentID'"}`
- Invalid JSON: `{"error": "Invalid JSON in request body: ..."}`
- Unsupported format: `{"error": "Unsupported report format: 'docx'. Supported: 'pdf', 'html'."}`

**Server Error Response (`500 Internal Server Error`):**
- Storage / database / compilation failure: `{"error": "Report generation failed: ..."}`

#### 3.9.3 Cosmos DB & SQL Ledger Data Integration

- **Cosmos DB (`timeline-artifacts`)**:
  - Partition Key: `/incidentId`
  - Query: `SELECT * FROM c WHERE c.incidentId = @incidentId OR c.IncidentID = @incidentId`
  - Normalizes Plaso timeline events, process listings (e.g. Volatility `windows.malfind`), network connection tuples (`source_ip`, `destination_ip`, `protocol`), and parsed evidence items.
- **SQL Ledger (`dbo.EvidenceLedger`)**:
  - Query: `SELECT ... FROM dbo.EvidenceLedger WHERE IncidentId = ? ORDER BY LedgerEntryId ASC`
  - Retrieves evidence metadata: `BlobName`, `ArtifactType`, `SizeBytes`, `Sha256Hash`, `AcquiredUtc`, `RecordedUtc`.
  - Performs cryptographic ledger verification via `ledger.verify_custody_integrity()`.

#### 3.9.4 Jinja2 Report Template Structure

The template at [`src/functions/ReportGenerator/report_template.html`](file:///C:/Users/Jyesh/REACT/src/functions/ReportGenerator/report_template.html) renders the 6 required forensic sections:

1. **Incident Metadata**: Incident ID, target VM hostname, IP address, severity badge, containment/isolation status, UTC generation timestamp, and classification banner.
2. **Evidence Inventory (with Hashes)**: Tabular inventory listing evidence artifact names, artifact types, formatted sizes (B/KB/MB/GB), acquisition timestamps, and SHA-256 cryptographic digests.
3. **Process Listings**: Executed process listings, PIDs, PPIDs, executable paths/commands, execution timestamps, and anomaly/injection findings.
4. **Network Connections**: Active and persistent network connection tuples (Protocol, Source IP/Port, Destination IP/Port, State, Threat Analysis).
5. **Timeline Events**: Chronologically sorted forensic timeline events parsed by Plaso/Log2Timeline with event sources and parsed message bodies.
6. **Chain of Custody Verification**: Cryptographic ledger integrity status banner (`VERIFIED`, `FAILED`, or `VERIFICATION UNAVAILABLE`), ledger block information, and complete custody transfer history.

*Security Note: Jinja2 autoescaping is strictly enforced (`autoescape=True`) to prevent Cross-Site Scripting (XSS) from unverified artifact payloads.*

#### 3.9.5 Reports Blob Storage & WORM Immutability

- **Container**: `reports` (defined in `iac/main.bicep` as `resource reportsContainer`)
- **WORM Policy**: 7-year time-based immutability policy (`retentionDays: 2555`) with versioning enabled and optional legal hold tags applied at provisioning time.
- **Blob Naming**: `{incidentId}/{reportId}.pdf`
- **Metadata**: Each report blob is stamped with `IncidentID`, `ReportId`, `Sha256`, `GeneratedUtc`, `ContentType: application/pdf`, and `WORM: true`.
- **Immutability Protection**: Overwrites are rejected with `ImmutabilityError` / `409 Conflict`.

#### 3.9.6 WeasyPrint PDF Generation & Environment Guidance

- **WeasyPrint**: In Linux production environments (Azure Functions Linux consumption / Dedicated App Service / Container), WeasyPrint converts HTML+CSS into printable PDF documents using Pango and Cairo.
  - Native Linux package dependencies:
    ```bash
    sudo apt-get update && sudo apt-get install -y libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
    ```
- **Windows / Development Fallback**: On Windows development workstations where GTK/Pango C libraries are not installed, `shared.reporting` automatically falls back to generating a valid, standard PDF-1.4 binary buffer. This allows unit and integration test suites to pass 100% offline without requiring external C libraries.

#### 3.9.7 Required Environment Variables & Application Settings

| Setting | Mock Default | Azure Production Example |
|---|---|---|
| `REACT_MOCK_MODE` | `true` | `false` |
| `REPORTS_CONTAINER` | `reports` | `reports` |
| `EVIDENCE_ACCOUNT` | `reactenclave01` | `reactevidence` |
| `EVIDENCE_STORAGE_URL` | `https://reactenclave01.blob.core.windows.net` | `https://<account>.blob.core.windows.net` |
| `COSMOS_DB_ENDPOINT` | `https://mock-react-cosmos.documents.azure.com:443/` | `https://react-cosmos.documents.azure.com:443/` |
| `COSMOS_DB_DATABASE` | `react-forensic-db` | `react-forensic-db` |
| `COSMOS_DB_CONTAINER` | `timeline-artifacts` | `timeline-artifacts` |
| `SQL_CONNECTION_STRING` | *(mocked in memory)* | `Server=tcp:react-sql.database.windows.net,1433;Database=reactdfir;Authentication=ActiveDirectoryMsi;` |

#### 3.9.8 Running Issue #34 Tests Locally

Install dependencies:
```bash
pip install -r src/functions/requirements.txt
pip install pytest pytest-mock ruff
```

Run focused ReportGenerator unit tests:
```bash
pytest tests/unit/test_person3_report_generator.py -v
```

Expected output:
```text
tests/unit/test_person3_report_generator.py .................... [100%]
20 passed in ~1.7s
```

Run lint and format checks:
```bash
ruff check src/functions tests/
ruff format --check src/functions tests/
```

#### 3.9.9 Local Azure Function Execution with Core Tools

Start the Function App locally in simulated mock mode:
```bash
cd src/functions
REACT_MOCK_MODE=true func start
```

Trigger report generation via HTTP POST:
```bash
curl -X POST http://localhost:7071/api/GenerateReport \
  -H "Content-Type: application/json" \
  -d '{"IncidentID": "INC-2026-DEMO-001"}'
```

## 4. Continuous Integration (CI/CD)

The test suite runs automatically on GitHub Actions in two workflows:

1. **[`REACT CI Pipeline`](file:///c:/BHAVYA/Acer%20I5/IT%20PERSONAL/NFSU%20%28CSE%29/SEM%207/PROJECT/code%20repository/.github/workflows/ci-pipeline.yaml)**:
   - Runs on every `push` and `pull_request` to `main`.
   - Validates Bicep templates, scans for secrets via Gitleaks, runs Ruff, executes test matrix across Python 3.10, 3.11, and 3.12, builds the forensic Docker container, and scans images with Trivy.

2. **[`REACT Integration & Contract Tests`](file:///c:/BHAVYA/Acer%20I5/IT%20PERSONAL/NFSU%20%28CSE%29/SEM%207/PROJECT/code%20repository/.github/workflows/integration-tests.yml)**:
   - Dedicated workflow with `workflow_dispatch` support.
   - Allows selecting specific test suites (`all`, `contracts`, `p1p2`, `p2p3`, `p1p3`, `e2e`) on demand.

---

## 5. Adding New Tests

When adding new capabilities or endpoint handoffs:
1. Place unit tests for standalone helper functions under `tests/unit/test_person<N>_*.py`.
2. Place multi-component handoff or payload contract tests under `tests/integration/<tier>/`.
3. If new Azure SDK client types are introduced, declare their mock stand-ins in [`tests/conftest.py`](file:///c:/BHAVYA/Acer%20I5/IT%20PERSONAL/NFSU%20%28CSE%29/SEM%207/PROJECT/code%20repository/tests/conftest.py) to prevent environment import errors.
4. Verify tests pass locally and format code with `ruff format src tests` before committing.

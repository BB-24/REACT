
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

### 3.8 Cosmos DB Serverless + Timeline Schema (Issue #33 — P3-3)

Issue #33 implements Person 3 forensic timeline ingestion into Azure Cosmos DB Core (SQL) API Serverless.

#### 3.8.1 What Was Implemented

| Component | Description |
|---|---|
| `iac/modules/cosmos-db.bicep` | Bicep module: Cosmos DB Serverless account, `react-forensic-db` database, `timeline-artifacts` container with `/incidentId` partition key |
| `iac/main.bicep` | Updated to deploy the Cosmos DB module and pass endpoint/database/container to Function App settings |
| `src/functions/shared/timeline.py` | Timeline artifact schema, `validate_timeline_artifact()`, `convert_plaso_event()`, `normalize_timestamp()` |
| `src/functions/shared/timeline_ingestion.py` | `ingest_timeline()` engine — reads JSON Lines / JSON array output, validates schema, upserts to Cosmos DB |
| `src/functions/shared/mocks/_cosmos.py` | In-memory mock Cosmos DB client for offline tests |
| `src/functions/shared/mocks/__init__.py` | Updated to export mock Cosmos classes |
| `src/functions/shared/clients.py` | Added `cosmos_client()` and `cosmos_container_client()` helpers |
| `src/functions/requirements.txt` | Added `azure-cosmos>=4.5.0` |
| `src/functions/TimelineIngestion/__init__.py` | Azure Functions HTTP trigger blueprint for timeline ingestion |
| `tests/unit/test_person3_timeline_schema.py` | 22 focused unit tests covering schema, ingestion, and HTTP trigger |
| `tests/conftest.py` | Added `azure.cosmos` stub so tests run without the SDK installed |

#### 3.8.2 Timeline Artifact Schema

Every item stored in the Cosmos DB `timeline-artifacts` container follows this contract:

```json
{
  "id": "art-INC-2026-001-a1b2c3d4e5f6a7b8",
  "incidentId": "INC-2026-001",
  "IncidentID": "INC-2026-001",
  "artifactType": "syslog:line",
  "timestamp": "2026-10-24T00:01:05.000000Z",
  "source": "/var/log/syslog",
  "data": {
    "message": "sshd accepted publickey for azureuser",
    "parser": "syslog",
    "pid": 1234
  }
}
```

- **Partition key**: `/incidentId` — all artifacts for an incident are co-located.
- **`id`**: Deterministic SHA-256 prefix hash of `(incidentId, timestamp, source, artifactType, data)`, or preserved from the Plaso event's existing `id`/`uuid` field.
- **`timestamp`**: Always normalized to UTC ISO-8601 (`Z` suffix). Accepts Plaso microsecond integers, ISO strings, or `datetime` objects.

#### 3.8.3 Local Setup and Dependency Installation

```bash
pip install pytest pytest-mock ruff
pip install -r src/functions/requirements.txt
```

#### 3.8.4 Running Issue #33 Tests Locally (Mock-Based — No Azure Required)

Run focused Issue #33 tests in isolation:
```bash
pytest tests/unit/test_person3_timeline_schema.py -v
```

Run with mock mode enabled explicitly:
```bash
REACT_MOCK_MODE=true pytest tests/unit/test_person3_timeline_schema.py -v
```

Expected output:
```text
22 passed in ~0.15s
```

#### 3.8.5 Schema Validation Tests

Covered test scenarios in `tests/unit/test_person3_timeline_schema.py`:
- Valid artifact schema round-trip
- Missing/empty `incidentId` (parametrized: `""`, `"   "`, `None`, `12345`)
- Missing `artifactType`, `source`, `timestamp`, `data` (parametrized per field)
- Non-dict `data` and non-JSON-serializable `data` values
- Timestamp normalization: Plaso microseconds, ISO strings, UTC offset conversion
- Stable and unique artifact ID generation and seed-ID preservation
- Correct conversion of representative Plaso timeline events
- Successful ingestion with mocked Cosmos DB container
- Partition key `/incidentId` consistency and read isolation
- Empty timeline input (zero records, no failure)
- Malformed JSON Lines handling (valid lines still ingest, malformed rejected)
- Database write failures recorded without false success reporting
- Idempotent re-ingestion via `upsert_item`
- HTTP trigger blueprint: success path and missing `incidentId` 400 response

#### 3.8.6 Infrastructure Provisioning (Cosmos DB Serverless)

> [!NOTE]
> No real Azure resources are provisioned during unit tests. The in-memory `MockCosmosClient` is used automatically when `REACT_MOCK_MODE=true`.

**Infrastructure Prerequisites:**
- Azure CLI >= 2.55
- Contributor rights on target resource group
- Bicep CLI (included in `az bicep`)

**Deploy Cosmos DB Serverless module alongside existing enclave:**
```bash
az deployment group create   --resource-group rg-forensic-enclave   --template-file iac/main.bicep   --parameters sqlAdminObjectId=<aad-object-id>                sqlAdminLogin=<aad-group-name>                namePrefix=react
```

The `cosmosDb` module in `main.bicep` provisions:
- Azure Cosmos DB Serverless account: `react-cosmos-<suffix>`
- Database: `react-forensic-db`
- Container: `timeline-artifacts` with partition key `/incidentId`
- Built-in Data Contributor RBAC role assigned to Function App managed identity

**Required environment variables (populated automatically via Bicep outputs):**
| Variable | Description | Example |
|---|---|---|
| `COSMOS_DB_ENDPOINT` | Cosmos DB account endpoint | `https://react-cosmos-abc12345.documents.azure.com:443/` |
| `COSMOS_DB_DATABASE` | Database name | `react-forensic-db` |
| `COSMOS_DB_CONTAINER` | Container name | `timeline-artifacts` |
| `REACT_MOCK_MODE` | `false` for real Azure, `true` for offline tests | `false` |

#### 3.8.7 Running Ingestion Against a Test Incident (Live Azure)

> [!IMPORTANT]
> Live Azure integration requires valid `COSMOS_DB_ENDPOINT`, `COSMOS_DB_DATABASE`, `COSMOS_DB_CONTAINER` and managed identity credentials.

```python
import os

os.environ["COSMOS_DB_ENDPOINT"] = "https://your-cosmos.documents.azure.com:443/"
os.environ["COSMOS_DB_DATABASE"] = "react-forensic-db"
os.environ["COSMOS_DB_CONTAINER"] = "timeline-artifacts"
os.environ["REACT_MOCK_MODE"] = "false"

from src.functions.shared.timeline_ingestion import ingest_timeline

summary = ingest_timeline(
    timeline_source="/workspace/output/timeline.json",
    incident_id="INC-2026-001",
)
print(f"Written: {summary.written_records}, Rejected: {summary.rejected_records}")
```

Expected successful output:
```text
Written: <N>, Rejected: 0
```

#### 3.8.8 Verifying Persisted Records in Cosmos DB (Azure Portal)

1. Navigate to Azure Portal → Cosmos DB account → `react-forensic-db` → `timeline-artifacts`
2. Select **Data Explorer** → run query:
   ```sql
   SELECT * FROM c WHERE c.incidentId = 'INC-2026-001'
   ```
3. Confirm documents have `id`, `incidentId`, `artifactType`, `timestamp`, `source`, and `data`.

#### 3.8.9 Cleanup Instructions

```bash
# Remove the Cosmos DB account (irreversible for serverless, data is deleted)
az cosmosdb delete --name react-cosmos-<suffix> --resource-group rg-forensic-enclave --yes
```

> [!WARNING]
> Serverless Cosmos DB does not support a soft-delete period. Deleting the account removes all timeline artifacts permanently.

---

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


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

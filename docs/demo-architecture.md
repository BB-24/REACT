# REACT Mid-Semester Demo Architecture & Safety Boundary

> **MANDATORY NOTICE**  
> **SIMULATED — synthetic data; no Azure resources or live machines touched.**

---

## 1. Local Composition & Workflow Stages

The mid-semester prototype demonstrates the end-to-end REACT automated incident-response and forensic pipeline completely offline, backed by the in-memory simulated Azure fabric in `src/functions/shared/mocks/`.

```
[ Sentinel Incident Alert (Simulated) ]
                 │
                 ▼
[ Stage 1: Ingestion & Contract Validation ]
  - Payload schema validated against docs/payload-contract.json
  - Target VM resolved from simulated estate (rg-victims)
                 │
                 ▼
[ Stage 2: Network Containment ]
  - Evaluates Critical-Infrastructure tag
  - If Normal: attaches Forensic-Isolation-NSG-<id> (Deny-All + Storage Egress)
  - If Critical-Infrastructure:True: logs warning & records BYPASSED policy
  - Prepares single-blob upload SAS metadata
                 │
                 ▼
[ Stage 3: Live Volatile Memory Acquisition ]
  - Detects OS (Windows/Linux) from simulated VM storage profile
  - Synthesizes platform-specific bootstrap script (PowerShell / Bash)
  - Dispatches Managed Run Command to target VM
  - Streams synthetic memory dump to enclave storage (evidence container)
                 │
                 ▼
[ Stage 4: Chain-of-Custody & Ledger ]
  - Simulated Event Grid topic delivers Microsoft.Storage.BlobCreated
  - ChainOfCustody handler folds SHA-256 chunk-by-chunk (8 MB chunks)
  - Compares computed hash against host witness hash (Integrity Check)
  - Appends tamper-evident row with cryptographic digest chain into Ledger
                 │
                 ▼
[ Stage 5: Non-Volatile Disk Snapshotting ]
  - Gated on REQ-3.4.1 (verifies memory-image custody row exists in Ledger)
  - Enumerates managed OS and Data disks
  - Creates point-in-time snapshots and copies across subscription boundary to Enclave
  - Emits JSON snapshot manifest blob into evidence container & triggers Ledger entry
                 │
                 ▼
[ Stage 6: Forensic Analysis & Timeline ]
  - Forensic analyzer processes synthetic evidence fixtures (syslog, auth.log)
  - Extracts timestamped security timeline events (SSH, sudo, service activity)
                 │
                 ▼
[ Stage 7: Evidence Package & Summary Report ]
  - Assembles sanitized case record: containment status, artifact hashes, ledger chain
  - Sanitizes all outputs: zero SAS tokens, bearer keys, or credentials exposed
```

---

## 2. Component Implementation Status Matrix

| Pipeline Stage | Cloud Implementation Target | Mid-Sem Prototype Status | Local Composition Mechanism |
| :--- | :--- | :--- | :--- |
| **Ingress Trigger** | Logic App Webhook (`workflow.json`) | **Simulated Orchestrator** | Local Python scenario runner (`scripts/demo.py`) validates contract and dispatches stages |
| **Network Isolation** | `NetworkContainment` Azure Function | **Implemented (Simulated Fabric)** | `NetworkContainment.handle_containment` / `main` using `MockNetworkManagementClient` |
| **Memory Acquisition** | `MemoryAcquisition` Azure Function | **Implemented (Simulated Fabric)** | `MemoryAcquisition.handle_acquisition` using `MockComputeManagementClient` Run Command |
| **Evidence Storage** | Azure Blob Storage (Immutable Enclave) | **Implemented (Simulated Fabric)** | `MockBlobClient` in `shared.mocks._storage` with legal hold & immutability checks |
| **Custody Hashing** | `ChainOfCustody` Azure Function | **Implemented (Simulated Fabric)** | `ChainOfCustody.process_blob_created` via `mocks.drain_events()` |
| **Evidence Ledger** | Azure SQL Database (Ledger table) | **Implemented (Simulated Fabric)** | `MockSqlConnection` in `shared.mocks._sql` with SHA-256 hash chaining |
| **Disk Acquisition** | `DiskSnapshot` Azure Function | **Implemented (Simulated Fabric)** | `DiskSnapshot.handle_snapshot` using `MockComputeManagementClient` cross-subscription copy |
| **Forensic Analysis** | Docker Container (`forensic-analyzer`) | **Implemented (Fixture-based)** | Local timeline parser / Docker verification using `sample-evidence/` |
| **Report Generation** | `ReportGenerator` Azure Function | **Simulated / Local Generator** | Structured HTML/JSON demo report renderer with safe metadata |

---

## 3. Safety Boundary: How the Demo Remains 100% Offline

1. **Explicit Mock Mode Enforcement**:
   - `REACT_MOCK_MODE=true` is strictly required in the runtime environment.
   - If `REACT_MOCK_MODE` is unset or false, the demo runner refuses execution immediately (fail closed).
2. **Mock Credential Guard**:
   - `shared.mocks.MockCredential` explicitly throws `MockAzureError` if `get_token()` is ever called. Any inadvertent attempt to communicate with Microsoft Entra ID or Azure REST APIs immediately terminates execution.
3. **No External Network Seams**:
   - Every SDK client factory in `src/functions/shared/clients.py` intercepts requests when `mock_mode()` is active, redirecting calls to process-memory dictionaries and models.
4. **Credential & Secret Sanitization**:
   - All generated demo metadata, logs, and outputs filter out SAS query parameters, account keys, and bearer tokens.
5. **Deterministic In-Memory State & Reset**:
   - State is stored in memory in `shared.mocks._world.WORLD`. Calling reset completely re-initializes the simulated subscriptions (`00000000-0000-0000-0000-000000000001` and `00000000-0000-0000-0000-0000000000e1`) without disk persistence or residue.

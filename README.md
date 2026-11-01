# Project REACT — Rapid Evidence Acquisition & Containment Toolkit

[![Tests](https://img.shields.io/badge/Tests-129%20Passing-brightgreen.svg)](#testing--verification)
[![Code Style: Ruff](https://img.shields.io/badge/Code%20Style-Ruff-blue.svg)](#linting--formatting)
[![Safety: Mock Mode](https://img.shields.io/badge/Mode-Safe%20Offline%20Simulation-amber.svg)](#safety-boundaries--mock-mode-guarantee)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](#prerequisites)

> **LIVE DEMO AVAILABLE:** [`scripts/run-azure-demo.ps1`](scripts/run-azure-demo.ps1) operates on pre-deployed Azure resources and a disposable VM; it does not deploy infrastructure or create VMs. Network containment, memory acquisition, and optional snapshots are real Azure actions and require explicit confirmations.
>
> **OFFLINE TEST MODE:** `scripts/demo.py` is a separate synthetic simulation that does not contact Azure or collect forensic evidence. It is for local testing, not the live reviewer walkthrough.

---

## 1. Overview & Problem Statement

When a cloud virtual machine is compromised (such as during a ransomware outbreak or active C2 intrusion), Security Operations Centers face a critical conflict:
- **Deallocating or stopping the VM** wipes volatile RAM immediately, destroying memory-resident malware, unencrypted keys, injected code, and active network connections.
- **Leaving the VM uncontained** allows attackers to pivot laterally across the virtual network or execute anti-forensic wiper scripts.

**Project REACT** provides automated, forensic-grade incident response for cloud infrastructure:
1. **Network Containment:** Isolates the compromised host at the network layer using a deny-by-default isolation NSG while keeping the VM powered on and memory intact.
2. **Volatile Memory Streaming:** Generates targeted OS-specific bootstraps (WinPmem for Windows, AVML for Linux) executed via Managed Run Command to stream RAM dumps straight to an enclave blob container without writing memory dump files to the victim's disk.
3. **Chain of Custody & SQL Ledger:** Hashing service folds SHA-256 digests over incoming streams, compares with target witness hashes, and records immutable custody entries into an Azure SQL Ledger with cryptographic hash chaining.
4. **Non-Volatile Disk Acquisition:** Gated on verified memory custody, captures crash-consistent managed disk snapshots and replicates them across subscription boundaries into the Forensic Enclave.
5. **Timeline Analysis:** Ingests forensic evidence into analysis pipelines to produce timestamped event timelines.

---

## 2. Offline Simulation Architecture & Implementation Status

The diagram below describes the **local synthetic simulator**, not a live
Azure deployment. Use the live Azure walkthrough in section 4 when presenting
the deployed Functions and Azure resources.

```
                       COMPROMISED SUBSCRIPTION (0000...0001)
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   ┌──────────────────────────┐             ┌─────────────────────────────┐   │
│   │   Target VM (web-01)     │◄────────────┤ Forensic-Isolation-NSG      │   │
│   │   [MOCKED RESOURCE]      │             │ DenyAll / Egress Storage    │   │
│   │                          │             │ [LOCALLY APPLIED MOCK]      │   │
│   └─────────────┬────────────┘             └─────────────────────────────┘   │
│                 │                                                            │
│                 │ WinPmem / AVML Stream (No disk writes)                     │
│                 ▼                                                            │
└─────────────────┼────────────────────────────────────────────────────────────┘
                  │ Cross-Subscription Boundary (RBAC Enclave Vault)
                  ▼
                       FORENSIC ENCLAVE SUBSCRIPTION (0000...00e1)
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   ┌──────────────────────────┐             ┌─────────────────────────────┐   │
│   │ Immutable Blob Storage   │             │ Azure SQL Ledger            │   │
│   │ (Legal Hold Active)      ├────────────►│ (Cryptographic Hash Chain)  │   │
│   │ [MOCKED FABRIC]          │ Event Grid  │ [MOCKED FABRIC]             │   │
│   └─────────────┬────────────┘             └─────────────────────────────┘   │
│                 │                                                            │
│                 ▼                                                            │
│   ┌──────────────────────────┐             ┌─────────────────────────────┐   │
│   │ Disk Snapshot Enclave    │             │ Forensic Analyzer           │   │
│   │ (Crash-Consistent Copy)  │             │ (Syslog & Auth Timelines)   │   │
│   │ [MOCKED RESOURCE]        │             │ [LOCAL / DOCKER]            │   │
│   └──────────────────────────┘             └─────────────────────────────┘   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Component Status Matrix

| Component | Repository Path | Mid-Sem Prototype Status | Implementation Mode |
| :--- | :--- | :--- | :--- |
| **Network Containment** | `src/functions/NetworkContainment/` | **Implemented & Verified** | Blueprints & mock handlers (`handle_containment`) |
| **Live Memory Acquisition** | `src/functions/MemoryAcquisition/` | **Implemented & Verified** | Run Command generation & stream token dispatch |
| **Chain of Custody** | `src/functions/ChainOfCustody/` | **Implemented & Verified** | SHA-256 chunked stream hashing & witness check |
| **SQL Custody Ledger** | `src/functions/shared/ledger.py` | **Implemented & Verified** | Cryptographic block-digest chain in `shared.mocks` |
| **Disk Snapshotting** | `src/functions/DiskSnapshot/` | **Implemented & Verified** | REQ-3.4.1 memory gate & cross-sub copy |
| **Forensic Analyzer** | `src/containers/forensic-analyzer/` | **Implemented & Verified** | Plaso/Docker & built-in fixture fallback parser |
| **Logic App Orchestrator**| `src/logic-apps/workflow.json` | **Simulated Prototype** | Cloud definition; simulated locally via `demo.py` |
| **Cloud Infrastructure** | `iac/main.bicep` | **Deployment Ready** | Bicep templates for cloud deployment |

---

## 3. Prerequisites

- **Operating System:** Windows, Linux, or macOS.
- **Python:** 3.10, 3.11, or 3.12.
- **Dependencies:** Install requirements:
  ```bash
  pip install -r src/functions/requirements.txt pytest ruff
  ```
- **Live Azure walkthrough:** An authenticated Azure CLI session, an existing live-mode Function App, its custody Event Grid subscription, and an already-running disposable VM tagged `REACT-Demo=true` are required.
- **Offline simulator:** An Azure account is not required; it uses synthetic data and in-memory resources only.

---

## 4. Quick Start & Demo Launch

Choose the live Azure walkthrough for reviewer demonstrations or the offline
simulator for local testing:

### Option A: Live Azure Reviewer Walkthrough

For a live demonstration, use the PowerShell orchestrator with an existing
Function App and a **disposable, pre-tagged test VM**:

```powershell
$targetVmId = az vm show --resource-group $env:TARGET_RG --name web-01 --query id --output tsv

.\scripts\run-azure-demo.ps1 `
  -FunctionAppName $env:FUNC_APP_NAME `
  -FunctionAppResourceGroup $env:ENCLAVE_RG `
  -TargetVmId $targetVmId `
  -Scenario Standard `
  -CaptureDiskSnapshots `
  -ConfirmLiveActions
```

For a no-change preflight, add `-PreflightOnly` and omit
`-CaptureDiskSnapshots -ConfirmLiveActions`.

The script verifies the Azure CLI context, Function App live-mode settings,
custody Event Grid subscription, target resource-group scope, and
`REACT-Demo=true` VM tag before it can act.
It calls the deployed containment and acquisition Functions, waits for custody
verification, and optionally requests disk snapshots. It does **not** deploy
infrastructure or create VMs. Network isolation, memory collection, and disk
snapshots affect real Azure resources and require typed confirmations.

For a critical-infrastructure policy-bypass demonstration, use a separate
disposable VM tagged `REACT-Demo=true` and `Critical-Infrastructure=true`, then
run the same command with `-Scenario CriticalBypass`. The script expects
containment to be bypassed and continues with acquisition.

The script writes a secret-free recovery summary under `$env:TEMP`. After the
review and acquisition are complete, restore the original NIC NSG associations
with:

```powershell
.\scripts\run-azure-demo.ps1 -RestoreFrom "<path-to-run-summary.json>" -ConfirmRestore
```

It will only restore NICs still attached to the isolation NSG created for that
incident. It does not delete evidence, snapshots, the enclave, or test VMs.

### Offline Option B: Interactive Terminal Runner

Run the interactive terminal menu:
```bash
python scripts/demo.py
```
Presents a guided menu to run scenarios, inspect prerequisites, or reset the estate.

### Offline Option C: Non-Interactive CLI Scenario Execution

Run individual scenarios or all scenarios directly:
```bash
# Verify prerequisites
python scripts/demo.py --check

# Run Scenario 1: High-Severity Incident Response
python scripts/demo.py --scenario 1

# Run Scenario 2: Critical Infrastructure Bypass Policy
python scripts/demo.py --scenario 2

# Run Scenario 3: Simulated Failure Handling
python scripts/demo.py --scenario 3

# Run ALL 3 scenarios in sequence
python scripts/demo.py --scenario all

# Reset simulated in-memory Azure estate
python scripts/demo.py --reset
```

---

## 5. Offline Simulation Scenarios

### Scenario 1: High-Severity Incident Response (Standard Containment)
- **Target:** `web-01` (Windows Server 2022 in `rg-victims`)
- **Severity:** `High`
- **Execution Flow:**
  1. *Ingestion:* Sentinel alert validated against [`docs/payload-contract.json`](docs/payload-contract.json).
  2. *Containment:* Attaches `Forensic-Isolation-NSG-INC-2026-DEMO-01` to `web-01-nic`. Denies all inbound and outbound traffic except outbound storage egress. Captures previous NSG (`nsg-web-tier`) for post-incident recovery.
  3. *Memory Acquisition:* Detects Windows OS; synthesizes PowerShell WinPmem bootstrap; dispatches Managed Run Command; streams raw RAM dump to enclave container without touching disk.
  4. *Chain of Custody:* Folds SHA-256 over blob chunks; matches host witness hash; writes entry to SQL Ledger with cryptographic block digest.
  5. *Disk Acquisition:* Gated on memory ledger row (REQ-3.4.1); takes crash-consistent snapshots of OS and data disks; copies snapshots to Forensic Enclave; generates snapshot manifest blob.
  6. *Forensic Timeline:* Analyzes evidence fixtures to extract authentication and privileged execution events.

### Scenario 2: Critical Infrastructure Bypass Policy
- **Target:** `db-02` (Linux SCADA / Core DB in `rg-victims`)
- **Severity:** `Critical`
- **Tags:** `{"Critical-Infrastructure": "True"}`
- **Execution Flow:**
  1. *Policy Evaluation:* `NetworkContainment` detects `Critical-Infrastructure: True`. Per emergency response policy, network isolation is **bypassed** to maintain vital operational availability.
  2. *Uninterrupted Acquisition:* Forensic capture proceeds regardless! Synthesizes Bash AVML bootstrap staged in tmpfs (`/dev/shm`), streams memory dump, snapshots disks, and records custody in the Ledger.
  3. *Outcome:* Zero downtime for critical services while preserving evidentiary integrity.

### Scenario 3: Simulated Failure Handling (Safe Cutoff)
- **Target:** `ghost-vm-99` (Non-existent VM)
- **Execution Flow:**
  1. *Containment Attempt:* `handle_containment` attempts to locate `ghost-vm-99` in `rg-victims` and encounters a target resolution error.
  2. *Transparent Reporting:* HTTP 500 error is surfaced with root-cause diagnostic ("VM 'ghost-vm-99' not found").
  3. *Safe Cutoff:* Downstream memory and disk acquisitions are safely skipped. The system **does not fabricate success** or invent false evidence.

---

## 6. Safety Boundaries & Mock Mode Guarantee

1. **Fail-Closed Mode:** If `REACT_MOCK_MODE=false` is detected during demo execution, the orchestrator raises `SafetyError` and immediately aborts startup to prevent any connection to live cloud environments.
2. **Token Rejection Guard:** `MockCredential` overrides token issuance. If any component attempts to contact Entra ID, it throws `MockAzureError`.
3. **In-Memory Volatility:** All simulated Azure resources (VMs, NICs, disks, blobs, ledger entries) reside exclusively in Python memory (`shared.mocks._world`). Restarting or running `--reset` returns the estate to a clean baseline.
4. **Credential Sanitization:** All outputs, logs, and dashboard views sanitize SAS tokens (`?[REDACTED_SAS_TOKEN]`) and bearer credentials.

---

## 7. Testing & Verification

Project REACT maintains an automated test suite verifying unit functionality, payload contracts, mock isolation, and end-to-end integration:

```bash
# Run the entire test suite (129 tests)
pytest -q

# Run demo-specific scenario and safety tests
pytest tests/test_demo_scenarios.py -q

# Run code style & static analysis
ruff check .
```

### Verified Test Summary

```
tests/integration/contracts/test_payload_contracts.py  ........ [  6%]
tests/integration/e2e/test_e2e_pipeline.py            ...      [  8%]
tests/integration/p1p2/test_p1_p2_orchestration.py     ....     [ 11%]
tests/integration/p1p3/test_p1_p3_reporting.py        ...      [ 14%]
tests/integration/p2p3/test_p2_p3_handoff.py          ...      [ 16%]
tests/test_demo_scenarios.py                          ........ [ 22%]
tests/test_network_containment.py                     ......   [ 27%]
tests/unit/test_person1_orchestration.py              ........ [ 33%]
src/functions/tests/test_disk_snapshot.py             ........ [ 59%]
src/functions/tests/test_memory_acquisition.py        ........ [ 80%]
src/functions/tests/test_sas.py                       ........ [100%]

============================== 129 passed in 4.82s ==============================
```

---

## 8. Presentation & Reviewer Resources

- **Presenter Script (3-5 Minutes):** [`docs/demo-presenter-script.md`](docs/demo-presenter-script.md)
- **Detailed Architecture & Boundary Document:** [`docs/demo-architecture.md`](docs/demo-architecture.md)
- **Recorded Fallback Log & Outputs:** [`docs/demo-fallback-log.md`](docs/demo-fallback-log.md)
- **Implementation Status Log:** [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md)
- **Standard Payload Contract:** [`docs/payload-contract.json`](docs/payload-contract.json)

---

## 9. Troubleshooting

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| `SafetyError: REACT_MOCK_MODE is set to 'false'` | Environment variable set to false | Run `set REACT_MOCK_MODE=true` (Windows) or `export REACT_MOCK_MODE=true` (Linux/Mac). |
| `Address already in use: 8080` | Port 8080 occupied by another application | Specify an alternative port: `python scripts/demo.py --web --port 8085` |
| `ModuleNotFoundError: No module named 'src'` | Working directory is not repository root | Execute commands from the repository root directory. |
| Docker container verification fails | Docker Desktop daemon not running | The demo includes a built-in Python timeline parser fallback. To run container verification, ensure Docker Desktop is started and retry [`src/containers/forensic-analyzer/verify-local.sh`](src/containers/forensic-analyzer/verify-local.sh). |

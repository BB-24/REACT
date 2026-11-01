# REACT Demo Verification & Fallback Capture Log

> **MANDATORY NOTICE**  
> **SIMULATED — synthetic data; no Azure resources or live machines touched.**  
> *This document contains verbatim recorded output from verified demo executions, providing a complete presentation fallback in the event of local workstation or container runtime disruption.*

---

## 1. Automated Test Suite Execution Record

Command:
```powershell
pytest -q
```

Output:
```
........................................................................ [ 55%]
.........................................................                [100%]
129 passed in 4.82s
```

Linting Verification:
```powershell
ruff check .
```

Output:
```
All checks passed!
```

---

## 2. Prerequisites Verification Run (`--check`)

Command:
```powershell
python scripts/demo.py --check
```

Output:
```
==============================================================================
  NOTICE: SIMULATED — synthetic data; no Azure resources or live machines touched.
==============================================================================


--- Prerequisites Verification ---

  [PASS] Python >= 3.10
         3.12.10
  [PASS] REACT_MOCK_MODE Enabled
         Process-local simulated Azure fabric is active (safe)
  [PASS] Mock Credential Token Guard
         MockCredential rejects token requests to protect live Azure
  [PASS] Sample Evidence Fixtures
         sample-evidence/syslog.log and auth.log present
  [PASS] Azure Functions Blueprints
         NetworkContainment, MemoryAcquisition, DiskSnapshot, ChainOfCustody registered

Result: ALL CHECKS PASSED
```

---

## 3. Scenario 1 Execution Record: High-Severity Incident Response

Command:
```powershell
python scripts/demo.py --scenario 1
```

Verbatim Output:
```
==============================================================================
  NOTICE: SIMULATED — synthetic data; no Azure resources or live machines touched.
==============================================================================

Scenario 1: High-Severity Incident Response (Standard Containment & Full Acquisition)
Simulates automated containment, volatile RAM acquisition, ledger recording, and disk snapshotting for a compromised Windows web server.

  Incident ID : INC-2026-DEMO-01
  Target VM   : web-01
  Outcome     : SUCCEEDED

Execution Stages:
------------------------------------------------------------------------------
  1. [COMPLETED] Incident Alert Ingestion & Contract Validation
     Summary : Ingested Sentinel alert payload; validated schema fields (REQ-P1).
     Details :
       {
         "incidentId": "INC-2026-DEMO-01",
         "target": "web-01 (Windows Server 2022)",
         "severity": "High",
         "resourceGroup": "rg-victims"
       }

  2. [COMPLETED] Network Isolation (Forensic NSG)
     Summary : Target VM isolated via deny-by-default NSG; original NSG preserved for recovery.
     Details :
       {
         "isolationNsg": "Forensic-Isolation-NSG-INC-2026-DEMO-01",
         "interfacesContained": [
           {
             "nic": "web-01-nic",
             "previousNsgId": "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-victims/providers/Microsoft.Network/networkSecurityGroups/nsg-web-tier",
             "changed": true
           }
         ],
         "egressAllowed": "Storage.eastus only (outbound memory streaming)",
         "inboundAccess": "Deny-All (Lateral movement blocked)"
       }

  3. [COMPLETED] Live-Response RAM Acquisition (WinPmem)
     Summary : Synthesized PowerShell bootstrap and dispatched Managed Run Command. Streamed volatile RAM directly to Enclave Blob Storage.
     Details :
       {
         "targetPlatform": "windows",
         "tool": "winpmem.exe",
         "blobName": "INC-2026-DEMO-01/web-01/memory-20261101T084534Z.raw",
         "runCommand": "REACT-Acquire-INC-2026-DEMO-01",
         "diskTamperingAvoided": "Zero memory-dump bytes written to target disk (tmpfs/streamed)"
       }

  4. [COMPLETED] Chain of Custody & SQL Ledger Verification
     Summary : Streamed blob hash verified chunk-by-chunk; tamper-evident row appended to SQL Ledger with cryptographic hash chain.
     Details :
       {
         "eventsProcessed": 1,
         "sha256": "eb53592da11f81bba3fde6642e3efe799907772b940c47aef62403ac32db7a6d",
         "sizeBytes": 1048576,
         "ledgerEntryId": 1,
         "ledgerDigest": "dba7202d9f537bd7a9963c0716bc30a3daaf303400c5880667b00ea58ea7d491",
         "witnessHashMatch": true
       }

  5. [COMPLETED] Disk Acquisition & Cross-Subscription Enclave Copy
     Summary : Point-in-time disk snapshots created and copied to Forensic Enclave subscription. Manifest registered in Ledger.
     Details :
       {
         "memoryGate": "satisfied",
         "snapshotCount": 2,
         "snapshots": [
           {
             "disk": "web-01-osdisk",
             "role": "os",
             "enclaveCopy": "snap-INC-2026-DEMO-01-web-01-osdisk-20261101T084534Z-enclave"
           },
           {
             "disk": "web-01-data-01",
             "role": "data",
             "enclaveCopy": "snap-INC-2026-DEMO-01-web-01-data-01-20261101T084534Z-enclave"
           }
         ],
         "manifestBlob": "INC-2026-DEMO-01/web-01/snapshots-20261101T084534Z.snapshot.json",
         "manifestSha256": "1ab463278fc6b8070e86cf67c89c923d6158dfc0489b47cfec5c16a439e2af24"
       }

  6. [COMPLETED] Forensic Analysis & Timeline Extraction
     Summary : Analyzed synthetic syslog and auth evidence fixtures. Extracted key forensic timeline events.
     Details :
       {
         "fixtureSource": "sample-evidence/ (syslog.log, auth.log)",
         "timelineEventsCount": 6,
         "sampleEvents": [
           {
             "source": "auth.log",
             "raw": "Oct 24 00:01:15 web-server-01 sshd[4321]: Accepted publickey for azureuser from 10.0.1.4 port 52341 ssh2",
             "summary": "SSH Authentication Succeeded"
           },
           {
             "source": "auth.log",
             "raw": "Oct 24 00:02:30 web-server-01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by azureuser(uid=1000)",
             "summary": "Privilege Escalation to root (sudo session opened)"
           },
           {
             "source": "auth.log",
             "raw": "Oct 24 00:03:00 web-server-01 sudo: pam_unix(sudo:session): session closed for user root",
             "summary": "Privileged session closed"
           }
         ],
         "suspiciousFindings": [
           "Privileged session opened for user root via azureuser (Oct 24 00:02:30)",
           "Inbound SSH session accepted from 10.0.1.4 (Oct 24 00:01:15)"
         ]
       }

------------------------------------------------------------------------------
Sanitized Evidence Dossier (Zero Exposed Secrets):
  {
    "incidentId": "INC-2026-DEMO-01",
    "targetHost": "web-01",
    "containmentStatus": "Contained (Isolation NSG active)",
    "memoryImage": {
      "path": "INC-2026-DEMO-01/web-01/memory-20261101T084534Z.raw",
      "sha256": "eb53592da11f81bba3fde6642e3efe799907772b940c47aef62403ac32db7a6d",
      "sizeBytes": 1048576,
      "chainOfCustody": "Immutable & Verified"
    },
    "diskManifest": {
      "blob": "INC-2026-DEMO-01/web-01/snapshots-20261101T084534Z.snapshot.json",
      "sha256": "1ab463278fc6b8070e86cf67c89c923d6158dfc0489b47cfec5c16a439e2af24"
    },
    "ledgerIntegrity": {
      "chainIntact": true,
      "totalLedgerRows": 2
    }
  }
```

---

## 4. Scenario 2 Execution Record: Critical Infrastructure Bypass

Command:
```powershell
python scripts/demo.py --scenario 2
```

Verbatim Output:
```
==============================================================================
  NOTICE: SIMULATED — synthetic data; no Azure resources or live machines touched.
==============================================================================

Scenario 2: Critical Infrastructure Incident Response (Containment Bypass Policy)
Demonstrates policy-based network isolation bypass for critical infrastructure (SCADA/Core DB) while volatile memory acquisition and forensic capture proceed uninterrupted.

  Incident ID : INC-2026-DEMO-02
  Target VM   : db-02
  Outcome     : SUCCEEDED

Execution Stages:
------------------------------------------------------------------------------
  1. [COMPLETED] Incident Alert Ingestion & Contract Validation
     Summary : Ingested Sentinel alert for critical VM; verified schema contract.
     Details :
       {
         "incidentId": "INC-2026-DEMO-02",
         "target": "db-02 (Linux Production Database)",
         "severity": "Critical",
         "tags": {
           "Critical-Infrastructure": "True",
           "Role": "SCADA-CoreDatabase"
         }
       }

  2. [BYPASSED] Network Containment Policy Evaluation
     Summary : Critical-Infrastructure tag detected. Network isolation SKIPPED to preserve continuous availability. Forensic acquisition proceeds.
     Details :
       {
         "status": "bypassed",
         "reason": "Critical-Infrastructure tag set to True",
         "action": "Network isolation skipped; acquisition proceeds",
         "networkInterfaceTouched": false,
         "availabilityImpact": "Zero downtime; network links remained active"
       }

  3. [COMPLETED] Live-Response RAM Acquisition (AVML in /dev/shm)
     Summary : Dispatched Bash AVML bootstrap into tmpfs (/dev/shm). Streamed RAM dump to Enclave Blob Storage while system continued running.
     Details :
       {
         "targetPlatform": "linux",
         "tool": "avml",
         "stagingDir": "/dev/shm (RAM - Zero disk footprint)",
         "blobName": "INC-2026-DEMO-02/db-02/memory-20261101T084534Z.raw"
       }

  4. [COMPLETED] Chain of Custody & SQL Ledger Verification
     Summary : Hashed live Linux memory image into Ledger; verified witness integrity match.
     Details :
       {
         "sha256": "87f316fda623ddfb19e7100e5116ce734bc8efb76ba0b62fdf4342ce534d9425",
         "sizeBytes": 1048576,
         "ledgerEntryId": 1,
         "ledgerDigest": "c819b58bad3008f034971f8bafa2786317443852a62298fc8e03acf289b8a462"
       }

  5. [COMPLETED] Disk Acquisition (OS Disk + 2 Data Disks)
     Summary : Captured crash-consistent snapshots of OS and data disks into Forensic Enclave without disturbing live services.
     Details :
       {
         "snapshotCount": 3,
         "memoryGate": "satisfied",
         "manifestBlob": "INC-2026-DEMO-02/db-02/snapshots-20261101T084534Z.snapshot.json"
       }

------------------------------------------------------------------------------
Sanitized Evidence Dossier (Zero Exposed Secrets):
  {
    "incidentId": "INC-2026-DEMO-02",
    "targetHost": "db-02",
    "containmentStatus": "Bypassed (Critical Infrastructure Protection Policy)",
    "policyJustification": "Target tagged Critical-Infrastructure:True; isolation prevented to avoid operational outage",
    "memoryImage": {
      "path": "INC-2026-DEMO-02/db-02/memory-20261101T084534Z.raw",
      "sha256": "87f316fda623ddfb19e7100e5116ce734bc8efb76ba0b62fdf4342ce534d9425"
    },
    "ledgerIntegrity": {
      "chainIntact": true,
      "totalLedgerRows": 2
    }
  }
```

---

## 5. Scenario 3 Execution Record: Simulated Failure Handling

Command:
```powershell
python scripts/demo.py --scenario 3
```

Verbatim Output:
```
==============================================================================
  NOTICE: SIMULATED — synthetic data; no Azure resources or live machines touched.
==============================================================================

Scenario 3: Simulated Failure Handling (Target Resolution Failure)
Demonstrates robust error handling when a target VM cannot be resolved. The pipeline halts safely and reports actionable diagnostics without generating false-positive evidence.

  Incident ID : INC-2026-DEMO-FAIL
  Target VM   : ghost-vm-99
  Outcome     : FAILED

Execution Stages:
------------------------------------------------------------------------------
  1. [COMPLETED] Incident Alert Ingestion & Schema Validation
     Summary : Ingested incident payload for target 'ghost-vm-99'.
     Details :
       {
         "IncidentID": "INC-2026-DEMO-FAIL",
         "TargetVM": "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-victims/providers/Microsoft.Compute/virtualMachines/ghost-vm-99",
         "IPAddress": "192.0.2.99",
         "SubscriptionID": "00000000-0000-0000-0000-000000000001",
         "IncidentSeverity": "High",
         "ResourceGroupName": "rg-victims"
       }

  2. [FAILED] Network Containment Execution
     Summary : Target VM 'ghost-vm-99' was not found in resource group 'rg-victims'. Containment failed safely.
     Details :
       {
         "statusCode": 500,
         "error": "VM 'ghost-vm-99' not found in resource group 'rg-victims' of subscription '00000000-0000-0000-0000-000000000001'.",
         "resolution": "Verify target VM ARM ID in Sentinel entity mapping."
       }

  3. [SKIPPED] Live Memory Acquisition
     Summary : Safely aborted: Memory acquisition cannot proceed without confirmed target resolution.
     Details :
       {
         "reason": "Upstream containment failed"
       }

  4. [SKIPPED] Disk Snapshotting
     Summary : Safely aborted: REQ-3.4.1 memory gate cannot be satisfied.
     Details :
       {
         "reason": "No memory image acquired or ledger row written"
       }

------------------------------------------------------------------------------
Sanitized Evidence Dossier (Zero Exposed Secrets):
  {
    "incidentId": "INC-2026-DEMO-FAIL",
    "status": "Pipeline Halted at Containment",
    "diagnostic": "Target VM 'ghost-vm-99' not found in resource group 'rg-victims'",
    "evidenceProduced": "None (No false or fabricated evidence generated)"
  }
```

---

## 6. Estate Reset Verification (`--reset`)

Command:
```powershell
python scripts/demo.py --reset
```

Output:
```
==============================================================================
  NOTICE: SIMULATED — synthetic data; no Azure resources or live machines touched.
==============================================================================

Estate Reset Successful!
  Message: Simulated Azure estate reseeded to initial state.
  Simulated VMs in rg-victims: db-02, web-01
```

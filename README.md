# Automated Cloud Forensic Pipeline (AACFP)

Automated cloud forensic response pipeline providing real-time containment, state isolation, evidence acquisition, and immutable ledger logging for compromised virtual machines in Azure.

---

## Architecture & Module Ownership

| Role | Responsibility | Owned Directories |
| :--- | :--- | :--- |
| **Person 1 (@BB-24)** | Cloud Orchestration & Infrastructure Security | `/iac/modules/`, `/iac/main.bicep`, `/src/logic-apps/` |
| **Person 2 (@gitforg)** | Serverless Containment, Acquisition & Handoff | `/src/functions/NetworkContainment/`, `/src/functions/ChainOfCustody/`, `/src/scripts/` |
| **Person 3 (@jyeshthachouhan14)** | Evidence Analysis, Ledger Schema & Reporting | `/src/containers/`, `/src/functions/ReportGenerator/`, `/iac/scripts/` |

---

## Workflow Overview

```
[Security Alert / Webhook]
           │ (IncidentID, TargetVM, IPAddress, SubscriptionID, IncidentSeverity)
           ▼
[Azure Logic App Orchestrator (aacfp-incident-response)]
           │
           ├─► 1. Containment: Python Azure Function (`NetworkContainment`)
           │      └─ Dynamic NSG: Forensic-Isolation-NSG-<IncidentID>
           │      └─ Rules: DenyAll (4095/4096), Allow Storage Egress (100)
           │      └─ Action: Swap primary NIC NSG to isolate VM
           │
           ├─► 2. Acquisition Handoff: Person 2 Trigger
           │      └─ Target Blob: https://<storage>.blob.core.windows.net/evidence/{IncidentID}/{TargetVM}.raw
           │      └─ Status Polling: Until Acquisition = Completed
           │
           └─► 3. Analysis & Ledger Handoff: Person 3 Trigger
                  └─ Partition Key: /IncidentID
                  └─ Audit Metadata & SQL Ledger Logging
```

---

## Deployment Instructions

### Prerequisites
- Azure CLI (`az`) with Bicep installed (`az bicep install`).
- Target Azure subscription with `Owner` or `User Access Administrator` + `Contributor` rights.

### Deploy Infrastructure (Phases 1-3)
```bash
az deployment sub create \
  --location eastus \
  --template-file iac/main.bicep \
  --parameters location=eastus
```

### Run Tests
```bash
python -m unittest tests/test_network_containment.py
```

### Detailed Documentation & Validation Guide
See [`docs/orchestration.md`](file:///docs/orchestration.md) for the end-to-end Phase 4 testing and validation guide.

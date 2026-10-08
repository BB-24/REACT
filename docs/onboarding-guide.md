# Person 2 / Person 3 Onboarding Guide

**Purpose**: Step-by-step guide for Person 2 (Acquisition) and Person 3 (Analysis) to register their endpoints with the AACFP orchestration pipeline.

**Owner**: Person 1 (@BB-24) — Cloud Orchestration & Infrastructure Security

**Audience**: @gitforg (Person 2), @jyeshthachouhan14 (Person 3)

---

## 1. Overview

The Logic App Orchestrator (`aacfp-incident-response`) calls three external endpoints during incident response:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Logic App Orchestrator                       │
│                   (aacfp-incident-response)                     │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
   │  Person 1   │ │  Person 2   │ │  Person 3   │
   │ Containment │ │ Acquisition │ │  Analysis   │
   │  Function   │ │  Workflow   │ │  Pipeline   │
   └─────────────┘ └─────────────┘ └─────────────┘
```

**You (Person 2/3) must provide:**
1. **ARM Trigger URL** — For Logic App to start your workflow
2. **Status Endpoint** — For Logic App to poll completion
3. **Contract Compliance** — Request/Response schemas must match

---

## 2. Person 2: Evidence Acquisition Onboarding

### 2.1 Required Endpoints

| Endpoint | Method | Purpose | Called By |
|----------|--------|---------|-----------|
| **Acquisition Trigger** | `POST` | Start evidence acquisition for an incident | Logic App `Start_Acquisition_Workflow` |
| **Acquisition Status** | `GET` | Poll until `status: "Completed"` | Logic App `Wait_For_Evidence_Acquisition` |

### 2.2 Acquisition Trigger Contract

**Request (Logic App → Person 2)**:
```http
POST {acquisitionArmRequestUrl}
Content-Type: application/json
Authorization: Bearer <ManagedIdentityToken>  # Audience: https://management.azure.com/

{
  "IncidentID": "INC-2026-0001",
  "TargetVM": "/subscriptions/.../virtualMachines/suspicious-vm-01",
  "IPAddress": "203.0.113.25",
  "SubscriptionID": "11111111-1111-1111-1111-111111111111",
  "IncidentSeverity": "High",
  "EvidenceBlobUri": "https://forensicevidence.blob.core.windows.net/evidence/INC-2026-0001/suspicious-vm-01.raw"
}
```

**Required Response**:
```http
HTTP/1.1 202 Accepted
Content-Type: application/json
Location: {statusUrl}?incidentId=INC-2026-0001
Retry-After: 30

{
  "status": "Accepted",
  "incidentId": "INC-2026-0001",
  "statusUrl": "https://your-acquisition-func.azurewebsites.net/api/status"
}
```

### 2.3 Acquisition Status Contract

**Request (Logic App → Person 2)**:
```http
GET {acquisitionStatusUrl}?incidentId=INC-2026-0001
Authorization: Bearer <ManagedIdentityToken>
```

**Required Response**:
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "Completed",  // or "InProgress", "Failed"
  "incidentId": "INC-2026-0001",
  "evidenceBlobUri": "https://forensicevidence.blob.core.windows.net/evidence/INC-2026-0001/suspicious-vm-01.raw",
  "completedAt": "2026-01-15T10:30:00Z",
  "sizeBytes": 10737418240
}
```

> **Polling Logic**: Logic App polls every 30 seconds, max 60 attempts (30 min timeout). Return `"Completed"` to proceed.
---

## 2.4 Registration Steps

1. **Deploy Your Acquisition Workflow**
   - Create Logic App / Function App / Container App in your RG
   - Implement the two endpoints above
   - Enable **System-Assigned Managed Identity**

2. **Provide URLs to Person 1**
   ```bash
   # Share these with @BB-24 (via secure channel or PR)
   ACQUISITION_ARM_REQUEST_URL="https://management.azure.com/subscriptions/.../workflows/your-acquisition/triggers/manual/run?api-version=2016-06-01"
   ACQUISITION_STATUS_URL="https://your-acquisition-func.azurewebsites.net/api/status"
   ```

3. **Person 1 Updates Bicep Parameters**
   In `iac/modules/logic-app.bicep` (or parameter file):
   ```bicep
   param acquisitionArmRequestUrl string = '<YOUR_ARM_TRIGGER_URL>'
   param acquisitionStatusUrl string = '<YOUR_STATUS_URL>'
   ```

4. **Grant Logic App Access to Your Trigger**
   - Your ARM trigger URL requires **Logic App Contributor** or **Workflow Trigger Access** on your workflow
   - Person 1's Logic App Managed Identity (`aacfp-incident-response`) must have this role

   ```bash
   # Run by Person 2 (you) after deploying your workflow
   PRINCIPAL_ID=$(az ad sp show --id <Person1-LogicApp-PrincipalId> --query id -o tsv)
   az role assignment create \
     --assignee $PRINCIPAL_ID \
     --role "Logic App Contributor" \
     --scope /subscriptions/<YOUR_SUB>/resourceGroups/<YOUR_RG>/providers/Microsoft.Logic/workflows/<YOUR_WORKFLOW>
   ```

5. **Test Integration**
   ```bash
   # Person 1 triggers test from their Logic App
   # You verify: trigger received → acquisition started → status returns "Completed"
   ```

---

## 3. Person 3: Evidence Analysis Onboarding

### 3.1 Required Endpoint

| Endpoint | Method | Purpose | Called By |
|----------|--------|---------|-----------|
| **Analysis Pipeline** | `POST` | Start forensic analysis with evidence metadata | Logic App `Start_Analysis_Pipeline` |

### 3.2 Analysis Pipeline Contract

**Request (Logic App → Person 3)**:
```http
POST {analysisPipelineUrl}
Content-Type: application/json

{
  "IncidentID": "INC-2026-0001",
  "TargetVM": "/subscriptions/.../virtualMachines/suspicious-vm-01",
  "IPAddress": "203.0.113.25",
  "SubscriptionID": "11111111-1111-1111-1111-111111111111",
  "IncidentSeverity": "High",
  "EvidenceBlobUri": "https://forensicevidence.blob.core.windows.net/evidence/INC-2026-0001/suspicious-vm-01.raw",
  "ContainmentDetails": {
    "status": "Contained",
    "IncidentID": "INC-2026-0001",
    "NetworkInterface": "/subscriptions/.../networkInterfaces/vm-nic",
    "IsolationNSG": "Forensic-Isolation-NSG-INC-2026-0001",
    "PreviousNSGId": "/subscriptions/.../networkSecurityGroups/original-nsg"
  },
  "PipelineStatus": "AcquisitionCompleted",
  "Timestamp": "2026-01-15T10:30:00Z"
}
```

**Required Response**:
```http
HTTP/1.1 202 Accepted
Content-Type: application/json

{
  "status": "Accepted",
  "incidentId": "INC-2026-0001",
  "analysisId": "ANL-2026-0001",
  "partitionKey": "INC-2026-0001"
}
```

> **Partition Key**: `IncidentID` is used as Cosmos DB partition key (as per `docs/payload-contract.json`)

### 3.3 Registration Steps

1. **Deploy Your Analysis Pipeline**
   - Function App / Container App / Logic App with HTTP trigger
   - Implement endpoint above
   - Enable **System-Assigned Managed Identity** (for downstream access)

2. **Provide URL to Person 1**
   ```bash
   ANALYSIS_PIPELINE_URL="https://your-analysis-func.azurewebsites.net/api/ProcessEvidence"
   ```

3. **Person 1 Updates Bicep Parameter**
   ```bicep
   param analysisPipelineUrl string = '<YOUR_ANALYSIS_URL>'
   ```

4. **Configure Evidence Storage Access**
   - Your pipeline needs **Storage Blob Data Reader** on the evidence container
   - Grant to your Managed Identity:
   ```bash
   az role assignment create \
     --assignee <YOUR_IDENTITY_PRINCIPAL_ID> \
     --role "Storage Blob Data Reader" \
     --scope /subscriptions/<SUB>/resourceGroups/Forensic-Enclave-RG/providers/Microsoft.Storage/storageAccounts/forensicevidence/blobServices/default/containers/evidence
   ```

5. **Test Integration**
   - Person 1 runs test incident
   - You verify: payload received → analysis started → results written to Cosmos DB with `IncidentID` partition key
---

## 4. Shared Requirements (Both Persons)

### 4.1 Security Baseline Compliance

Your endpoints **must** meet [Security Baseline](./security-baseline.md):

- [ ] Private Endpoint enabled (no public access)
- [ ] Managed Identity only (no keys in code)
- [ ] Diagnostic logs → Log Analytics
- [ ] Tags: `Application=AACFP`, `Owner=<your-handle>`, `Environment=Production`
- [ ] TLS 1.2 minimum

### 4.2 Authentication

| Call Direction | Auth Method |
|----------------|-------------|
| Logic App → Your Endpoint | **Managed Identity** (Azure AD token, audience = your endpoint) |
| Your Endpoint → Azure Resources | **Managed Identity** (your own identity) |

**Logic App sends token**:
```json
"authentication": {
  "type": "ManagedServiceIdentity",
  "audience": "https://<your-endpoint-hostname>"
}
```

Your endpoint must validate:
- Token audience matches your endpoint
- Issuer = `https://sts.windows.net/<tenant-id>/`
- Claim `appid` = Person 1 Logic App client ID

### 4.3 Error Handling

| Scenario | Your Response | Logic App Behavior |
|----------|---------------|-------------------|
| Transient failure (5xx) | `503 Retry-After: 30` | Retries (built-in) |
| Invalid payload (400) | `400 { error: "..." }` | Marks action Failed |
| Business logic error | `422 { error: "..." }` | Marks action Failed |
| Success | `200/202 { status: "..." }` | Proceeds to next step |

---

## 5. Testing Checklist

### Person 2 (Acquisition)
- [ ] `POST /triggers/manual/run` accepts payload, returns `202` + `Location` header
- [ ] `GET /status?incidentId=X` returns `200` with `status: "InProgress"` → eventually `"Completed"`
- [ ] Evidence blob written to `evidence/{IncidentID}/{VMName}.raw`
- [ ] Managed Identity can write to evidence storage account
- [ ] Person 1 Logic App identity can trigger your workflow

### Person 3 (Analysis)
- [ ] `POST /api/ProcessEvidence` accepts full payload, returns `202`
- [ ] Reads evidence blob from `EvidenceBlobUri` (validates SAS/MI access)
- [ ] Writes results to Cosmos DB with `IncidentID` as partition key
- [ ] Returns `analysisId` for tracking

---

## 6. Contact & Support

| Role | Contact | Responsibility |
|------|---------|----------------|
| Person 1 (Orchestration) | @BB-24 | Logic App deployment, parameter updates, integration testing |
| Person 2 (Acquisition) | @gitforg | Acquisition workflow, evidence storage, status endpoint |
| Person 3 (Analysis) | @jyeshthachouhan14 | Analysis pipeline, Cosmos DB schema, results reporting |
| Platform/Infra | @platform-team | Private endpoints, DNS, networking, Policy |

---

## 7. Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-09-28 | @BB-24 | Initial onboarding guide |

---

## 8. Related Documents

- [Automated Testing Guide](./testing-guide.md) — Unit & integration test execution guide
- [Orchestration Overview](./orchestration.md) — Full architecture
- [Payload Contract](./payload-contract.json) — JSON Schema for all payloads
- [Security Baseline](./security-baseline.md) — Compliance requirements
- [Disaster Recovery](./disaster-recovery.md) — DR endpoints for your components
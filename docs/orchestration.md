# Cloud Orchestration & Infrastructure Security (`orchestration.md`)

This document serves as the authoritative guide for **Person 1 (@BB-24)** covering the Cloud Orchestration, Azure Logic App Webhook Trigger, and Network Isolation Azure Function for the Automated Forensic Pipeline.

---

## 1. Architecture Overview

```
                          ┌────────────────────────────────────────────────────────┐
                          │         Compromised-Environment-RG                     │
                          │  ┌──────────────┐          ┌────────────────────────┐  │
                          │  │ Target VM    │◄─────────┤ Isolation NSG          │  │
                          │  │ (Suspicious) │          │ DenyAll / AllowStorage │  │
                          │  └──────┬───────┘          └────────────────────────┘  │
                          └─────────┼──────────────────────────────────────────────┘
                                    │ Sever SSH/RDP & isolate
                                    │
┌───────────────────────────────────┴──────────────────────────────────────────────┐
│                           Forensic-Enclave-RG                                    │
│                                                                                  │
│ ┌───────────────────────────┐      HTTP POST      ┌──────────────────────────┐   │
│ │ Logic App Webhook         ├────────────────────►│ Containment Function     │   │
│ │ (Orchestrator)            │                     │ (Python - Managed Id)    │   │
│ └─────────────┬─────────────┘                     └──────────────────────────┘   │
│               │                                                                  │
│               ├──────────────────────────────────► Person 2 (Acquisition)        │
│               │   Passes Evidence Blob URI                                       │
│               │                                                                  │
│               └──────────────────────────────────► Person 3 (Cosmos DB/Analysis) │
│                   Passes Partition Key & Metadata                                │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Standardized Payload Contract (Person 1)

The ingress Webhook trigger and downstream calls enforce the standard JSON schema defined in [`docs/payload-contract.json`](file:///c:/BHAVYA/Acer%20I5/IT%20PERSONAL/NFSU%20%28CSE%29/Projects/REACT/REACT/docs/payload-contract.json):

### Required Schema Payload Example:
```json
{
  "IncidentID": "INC-2026-0001",
  "TargetVM": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Compute/virtualMachines/suspicious-vm-01",
  "IPAddress": "203.0.113.25",
  "SubscriptionID": "11111111-1111-1111-1111-111111111111",
  "IncidentSeverity": "High",
  "ResourceGroupName": "Compromised-Environment-RG"
}
```

### Contract Field Specifications:

| Field Name | Type | Required | Description & Validation |
| :--- | :--- | :--- | :--- |
| `IncidentID` | `string` | **Yes** | Unique identifier for the incident. Serves as Cosmos DB Partition Key (`/IncidentID`) for Person 3. |
| `TargetVM` | `string` | **Yes** | Full ARM Resource ID of target VM (`/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}`). |
| `IPAddress` | `string` | **Yes** | Public/Private IP address associated with the compromised VM. |
| `SubscriptionID` | `string` | **Yes** | Azure Subscription UUID (`^[0-9a-fA-F-]{36}$`). Must match the subscription in `TargetVM`. |
| `IncidentSeverity` | `string` | **Yes** | Severity level (`Low`, `Medium`, `High`, `Critical`). Network containment executes when severity is `High` or `Critical`. |
| `ResourceGroupName` | `string` | No | Optional explicit resource group name containing the target VM. |

---

## 3. Phase-by-Phase Implementation Details

### Phase 1: Cloud Foundation & Identity
1. **Resource Groups**:
   - `Compromised-Environment-RG`: Houses target VMs and vulnerable network assets.
   - `Forensic-Enclave-RG`: Houses isolation logic, forensic storage, Logic Apps, and analysis engines.
2. **Compute Provisioning**:
   - Azure Logic App (Consumption plan, System-Assigned Managed Identity).
   - Azure Function App (Linux, Python 3.11 runtime, System-Assigned Managed Identity).
3. **IAM & Role Assignments**:
   - When `targetResourceGroup` is set and mock mode is disabled, the Function App Managed Identity is granted `Network Contributor` (ID `4d97b98b-1d4f-4787-a291-c67834d212e7`) only at that resource-group scope. Leave `targetResourceGroup` empty for mock-only deployments.

### Phase 2: Python Network Containment (`NetworkContainment`)
1. **Authentication**: `DefaultAzureCredential()` detects local identity in development and Managed Identity in Azure.
2. **NSG Construction**: Programmatically creates `Forensic-Isolation-NSG-<IncidentID>`:
   - Priority `100` (`Outbound` / `Allow` / Destination: `Storage` service tag).
   - Priority `101+` (`Outbound` / `Allow` / Destination: Evidence Private Endpoints if specified).
   - Priority `4095` (`Inbound` / `Deny` / Destination: `*`).
   - Priority `4096` (`Outbound` / `Deny` / Destination: `*`).
3. **NIC Swap Execution**: Replaces the network security group on every VM NIC with the isolation NSG and triggers the ARM updates. The response records each NIC's previous association and exposes the primary NIC's prior NSG as `PreviousNSGId`.

### Phase 3: Logic App Orchestration & Handoff Contracts
1. **Sequential Action Pipeline**:
   - `Parse_Incident` -> Validates schema & severity (`High`).
   - `Call_Network_Containment` -> Calls Python Function App.
   - `Start_Acquisition_Workflow` -> Calls Person 2 acquisition trigger with Blob URI template: `https://<storage>.blob.core.windows.net/evidence/{IncidentID}/{TargetVMName}.raw`
   - `Wait_For_Evidence_Acquisition` -> Polls status until `Completed`.
   - `Start_Analysis_Pipeline` -> Calls Person 3 Cosmos DB / Analysis engine with Partition Key `IncidentID`.
2. The endpoint paths, request/response payloads, bearer-token requirements,
   and Cosmos artifact schemas are defined in
   [`integration-openapi.json`](./integration-openapi.json). The report
   trigger is specified for callers but is not yet invoked by this workflow.

### Secure deployment order

1. Deploy [`main.mg.bicep`](../iac/main.mg.bicep) at the management-group
   scope. It creates `Compromised-Environment-RG` in the workload subscription
   and `Forensic-Enclave-RG` in the separate forensic subscription, then
   deploys the enclave stack to the latter. See
   [`multi-subscription-deployment.md`](./multi-subscription-deployment.md)
   for the required permissions and `what-if` workflow.
2. The Function managed identity receives Network Contributor only on the
   configured workload resource group. The role assignment is omitted in mock
   mode. Set `evidenceStoragePrivateEndpointPrefixes` if Storage Private Link
   is used; isolation allows HTTPS to those prefixes and the configured
   regional Storage service tag.
3. Configure the acquisition and analysis endpoints owned by Persons 2 and 3,
   then deploy [`logic-app.bicep`](../iac/modules/logic-app.bicep) to the
   enclave resource group. Its endpoint parameters are required; the module
   no longer falls back to placeholder URLs. Supply the Function URL as a
   secure parameter and grant the Logic App identity only the downstream
   permissions it needs.
4. Verify the Function App route `/api/NetworkContainment`, the HTTP trigger
   URL, managed identity role scope, and Logic App run history before sending
   a test event. Never use a production target for the first run.

---

## 4. Independent Validation & Testing

Use the guarded, step-by-step disposable-VM procedure in
[`p1-p2-postman-evidence.md`](./p1-p2-postman-evidence.md) as the source of truth
for webhook testing, connectivity checks, Logic App run-history verification,
evidence export, and NSG restoration. It requires explicit opt-in and a target
in the dedicated demo resource group; do not use the older `test-victim-vm`
example or test against production resources.

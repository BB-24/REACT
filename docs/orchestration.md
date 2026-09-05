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
   - Function App Managed Identity is granted `Network Contributor` (ID `4d3025cd-af43-4a71-b66d-5710428f242c`) strictly scoped to `Compromised-Environment-RG`.

### Phase 2: Python Network Containment (`NetworkContainment`)
1. **Authentication**: `DefaultAzureCredential()` detects local identity in development and Managed Identity in Azure.
2. **NSG Construction**: Programmatically creates `Forensic-Isolation-NSG-<IncidentID>`:
   - Priority `100` (`Outbound` / `Allow` / Destination: `Storage` service tag).
   - Priority `101+` (`Outbound` / `Allow` / Destination: Evidence Private Endpoints if specified).
   - Priority `4095` (`Inbound` / `Deny` / Destination: `*`).
   - Priority `4096` (`Outbound` / `Deny` / Destination: `*`).
3. **NIC Swap Execution**: Fetches the VM's primary NIC, replaces `network_security_group` reference with the isolation NSG, and triggers async ARM update.

### Phase 3: Logic App Orchestration & Handoff Contracts
1. **Sequential Action Pipeline**:
   - `Parse_Incident` -> Validates schema & severity (`High`).
   - `Call_Network_Containment` -> Calls Python Function App.
   - `Start_Acquisition_Workflow` -> Calls Person 2 acquisition trigger with Blob URI template: `https://<storage>.blob.core.windows.net/evidence/{IncidentID}/{TargetVMName}.raw`
   - `Wait_For_Evidence_Acquisition` -> Polls status until `Completed`.
   - `Start_Analysis_Pipeline` -> Calls Person 3 Cosmos DB / Analysis engine with Partition Key `IncidentID`.

---

## 4. Phase 4: Step-by-Step Guide for Independent Validation & Testing

Follow these steps to validate the automated orchestration pipeline end-to-end:

### Step 4.1: Staging the Environment
1. Deploy a temporary Linux target VM in `Compromised-Environment-RG`:
   ```bash
   az vm create \
     --resource-group Compromised-Environment-RG \
     --name test-victim-vm \
     --image Ubuntu2204 \
     --admin-username azureuser \
     --generate-ssh-keys \
     --public-ip-address-dns-name test-victim-vm-dns
   ```
2. Open an active SSH session to `test-victim-vm`:
   ```bash
   ssh azureuser@<VM_PUBLIC_IP>
   ```
   *Keep this terminal window open during test execution.*

### Step 4.2: Triggering the Webhook
1. Retrieve the Logic App HTTP Webhook POST URL from Azure Portal or CLI:
   ```bash
   LOGIC_APP_URL=$(az logic workflow show \
     --resource-group Forensic-Enclave-RG \
     --name aacfp-incident-response \
     --query "accessControl.triggers.Incident_Webhook.secretKeys[0]" -o tsv)
   ```
2. Fire a synthetic payload using `curl` or Postman:
   ```bash
   curl -X POST "$LOGIC_APP_WEBHOOK_URL" \
     -H "Content-Type: application/json" \
     -d '{
       "IncidentID": "INC-TEST-9999",
       "TargetVM": "/subscriptions/<YOUR_SUBSCRIPTION_ID>/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Compute/virtualMachines/test-victim-vm",
       "IPAddress": "203.0.113.25",
       "SubscriptionID": "<YOUR_SUBSCRIPTION_ID>",
       "IncidentSeverity": "High",
       "ResourceGroupName": "Compromised-Environment-RG"
     }'
   ```

### Step 4.3: Verification Checklist
1. **Logic App Execution**: Check Logic App **Run History** in Azure Portal. All actions (`Call_Network_Containment`, `Start_Acquisition_Workflow`, `Start_Analysis_Pipeline`) should show status `Succeeded` (green checks).
2. **Function Log Output**: Check Function App log stream to confirm:
   `Incident INC-TEST-9999: attached isolation NSG Forensic-Isolation-NSG-INC-TEST-9999 to NIC test-victim-vmVMNic`
3. **Instant Connection Severance**: Return to your open SSH terminal window. You should see:
   `client_loop: send disconnect: Connection reset by peer` or terminal freeze. Attempting a new `ssh` command must time out.
4. **NSG Rules Verification**: Confirm the new NSG is bound to the target VM's NIC:
   ```bash
   az network nic show \
     --resource-group Compromised-Environment-RG \
     --name test-victim-vmVMNic \
     --query "networkSecurityGroup.id"
   ```

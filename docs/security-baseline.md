# Security Baseline

**Purpose**: Define mandatory Azure Policy definitions, resource configurations, and compliance standards for the Automated Cloud Forensic Pipeline (AACFP).

**Owner**: Person 1 (@BB-24) — Cloud Orchestration & Infrastructure Security

**Compliance Standard**: Aligned with **CIS Azure Foundations Benchmark v2.0**, **NIST 800-53 Rev.5**, **ISO 27001:2022**

---

## 1. Mandatory Resource Tags

All AACFP resources **must** carry these tags (enforced via Azure Policy):

| Tag | Required | Values | Purpose |
|-----|----------|--------|---------|
| `Application` | ✅ | `AACFP` | Cost allocation, resource grouping |
| `Project` | ✅ | `Forensic-Containment-Pipeline` | Project identification |
| `Environment` | ✅ | `Production` \| `Staging` \| `Development` | Environment classification |
| `CostCenter` | ✅ | `Security-Operations` | Chargeback |
| `Owner` | ✅ | `BB-24` \| `gitforg` \| `jyeshthachouhan14` | Accountability |
| `DataClassification` | ✅ | `Confidential` \| `Restricted` | Data handling requirements |
| `IncidentID` | Conditional | `INC-YYYY-NNNN` | Applied to isolation NSG, ephemeral resources |

**Policy**: `Require AACFP Tags` (built-in `Microsoft.Authorization/policyDefinitions/1e30110a-5ceb-460c-a204-c1c3969c6d62` with custom parameters)

---

## 2. Network Security Group Baseline

### 2.1 Required NSG Rules (All Subnets)

| Priority | Name | Direction | Access | Protocol | Source | Destination | Port | Description |
|----------|------|-----------|--------|----------|--------|-------------|------|-------------|
| 100 | Allow-AzureLoadBalancer | Inbound | Allow | * | AzureLoadBalancer | * | * | Health probes |
| 110 | Allow-Storage-ServiceTag | Outbound | Allow | * | * | Storage | * | Evidence upload |
| 120 | Allow-EventGrid-ServiceTag | Outbound | Allow | * | * | EventGrid | * | Webhook delivery |
| 130 | Allow-AppInsights-ServiceTag | Outbound | Allow | * | * | AzureMonitor | * | Telemetry |
| 4095 | Deny-All-Inbound | Inbound | Deny | * | * | * | * | Default deny |
| 4096 | Deny-All-Outbound | Outbound | Deny | * | * | * | * | Default deny |

### 2.2 Isolation NSG Rules (Created by Function)

| Priority | Name | Direction | Access | Protocol | Source | Destination | Port | Description |
|----------|------|-----------|--------|----------|--------|-------------|------|-------------|
| 100 | Allow-Storage-Egress | Outbound | Allow | * | * | Storage | * | Evidence preservation |
| 101+ | Allow-PrivateEndpoints | Outbound | Allow | * | * | <PrivateEndpointIPs> | * | Configurable per env |
| 4095 | Deny-All-Inbound | Inbound | Deny | * | * | * | * | Total isolation |
| 4096 | Deny-All-Outbound | Outbound | Deny | * | * | * | * | Total isolation |

**Policy**: Custom policy to audit NSGs missing baseline rules.
---

## 3. Private Endpoint Requirements

| Resource | Private Endpoint Required | DNS Zone | Subnet |
|----------|---------------------------|----------|--------|
| Storage Account (Function runtime) | ✅ Yes | `privatelink.blob.core.windows.net` | `Forensic-Enclave-Subnet` |
| Storage Account (Evidence) | ✅ Yes | `privatelink.blob.core.windows.net` | `Forensic-Enclave-Subnet` |
| Function App | ✅ Yes | `privatelink.azurewebsites.net` | `Forensic-Enclave-Subnet` |
| Logic App | ✅ Yes | `privatelink.logic.azure.com` | `Forensic-Enclave-Subnet` |
| App Insights | ✅ Yes | `privatelink.monitor.azure.com` | `Forensic-Enclave-Subnet` |
| Key Vault | ✅ Yes | `privatelink.vaultcore.azure.net` | `Forensic-Enclave-Subnet` |

**Policy**: `Deploy Private Endpoints for PaaS` (custom initiative)

---

## 4. Identity & Access Management

### 4.1 Managed Identities

| Resource | Identity Type | Role Assignments |
|----------|---------------|------------------|
| Function App (`aacfp-containment-*`) | System-Assigned | **Network Contributor** on `Compromised-Environment-RG` |
| Logic App (`aacfp-incident-response`) | System-Assigned | **Logic App Contributor** on `Forensic-Enclave-RG` (for DR deployment) |
| Function App (DR) | System-Assigned | **Network Contributor** on `Compromised-Environment-RG-DR` |

### 4.2 RBAC Principles

- **Least Privilege**: No `Owner` or `Contributor` at subscription level for identities
- **No User-Assigned Identities** for runtime (System-Assigned only)
- **Conditional Access**: Function App access restricted to Logic App Managed Identity via **Easy Auth** (future)
- **PIM**: Human access via Privileged Identity Management (eligible, not active)

### 4.3 Key Vault

| Secret | Rotation | Access Policy |
|--------|----------|---------------|
| Function App Package SAS URI | 90 days | Function App (Get) |
| Logic App Parameter Values | On change | Logic App (Get) |
| Storage Account Keys | 90 days | None (use MI) |
---

## 5. Azure Policy Definitions (Custom)

### 5.1 Policy: `AACFP-Isolation-NSG-Naming`
```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        { "field": "type", "equals": "Microsoft.Network/networkSecurityGroups" },
        { "field": "tags['Application']", "equals": "AACFP" },
        { "not": { "field": "name", "like": "Forensic-Isolation-NSG-*" } }
      ]
    },
    "then": { "effect": "deny" }
  }
}
```

### 5.2 Policy: `AACFP-Function-Private-Endpoint`
```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        { "field": "type", "equals": "Microsoft.Web/sites" },
        { "field": "tags['Application']", "equals": "AACFP" },
        { "field": "kind", "like": "functionapp*" }
      ]
    },
    "then": {
      "effect": "deployIfNotExists",
      "details": {
        "type": "Microsoft.Web/sites/privateEndpointConnections",
        "deployment": { ... }
      }
    }
  }
}
```

### 5.3 Policy: `AACFP-LogicApp-EntraAuth`
```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        { "field": "type", "equals": "Microsoft.Logic/workflows" },
        { "field": "tags['Application']", "equals": "AACFP" }
      ]
    },
    "then": {
      "effect": "auditIfNotExists",
      "details": {
        "type": "Microsoft.Logic/workflows/accessControl",
        "existenceCondition": {
          "field": "Microsoft.Logic/workflows/accessControl.triggers.allowedCallerIpAddresses",
          "exists": "true"
        }
      }
    }
  }
}
```

---

## 6. Policy Initiative: `AACFP-Security-Baseline`

| Policy | Effect | Category |
|--------|--------|----------|
| Require AACFP Tags | Deny | Governance |
| Allowed Locations (East US, West US 2) | Deny | Governance |
| AACFP Isolation NSG Naming | Deny | Network |
| AACFP Function Private Endpoint | DeployIfNotExists | Network |
| AACFP Logic App Entra Auth | AuditIfNotExists | Identity |
| Storage Account Secure Transfer | Deny | Data Protection |
| Storage Account Minimum TLS 1.2 | Deny | Data Protection |
| Key Vault Purge Protection | Deny | Data Protection |
| Diagnostic Logs Enabled | AuditIfNotExists | Monitoring |

**Assignment Scope**: Subscription or Management Group containing AACFP RGs
---

## 7. Network Security

| Control | Implementation |
|---------|----------------|
| **DDoS Protection** | Standard tier on VNet containing `Forensic-Enclave-Subnet` |
| **Flow Logs** | Enabled on all NSGs → Log Analytics workspace |
| **Network Watcher** | Enabled in region; packet capture for incident investigation |
| **Service Endpoints** | `Microsoft.Storage`, `Microsoft.EventGrid`, `Microsoft.AzureMonitor` on Function subnet |
| **IP Restrictions** | Function App: Allow only Logic App outbound IPs + Azure Resource Manager |

---

## 8. Data Protection

| Data Type | Encryption | Retention | Backup |
|-----------|------------|-----------|--------|
| Function Code (Storage) | AES-256 (Microsoft-managed) | N/A | GRS |
| Function Logs (App Insights) | AES-256 | 90 days (configurable) | N/A |
| Logic App Run History | AES-256 | 90 days | N/A |
| Evidence Blobs (Person 2) | AES-256 + CMK (Customer-managed) | 7 years | GRS + Immutable Blob |
| Audit Ledger (Person 3) | AES-256 + CMK | 7 years | Multi-region Cosmos DB |

---

## 9. Monitoring & Alerting (Security)

| Alert | KQL Query | Severity |
|-------|-----------|----------|
| Function App identity granted excessive roles | `AzureActivity | where OperationName == "Create role assignment" | where Properties contains "Network Contributor" and Caller != "aacfp-containment-*"` | High |
| NSG created without AACFP tags | `AzureActivity | where OperationName == "Create or Update Network Security Group" | where Tags !has "Application" or Tags['Application'] != "AACFP"` | Medium |
| Logic App triggered by unknown source | `AzureDiagnostics | where ResourceType == "WORKFLOWS" | where CallerIpAddress !in (known_ips) | where OperationName == "WorkflowTrigger"` | High |
| Storage account public access enabled | `AzureActivity | where OperationName == "Update Storage Account" | where Properties contains "allowBlobPublicAccess=true"` | Critical |

---

## 10. Compliance Mapping

| Control | CIS v2.0 | NIST 800-53 | ISO 27001 |
|---------|----------|-------------|-----------|
| Tag Enforcement | 1.1, 1.2 | CM-8, RA-5 | A.8.1.1, A.8.1.2 |
| Private Endpoints | 3.1, 3.3 | SC-7, SC-8 | A.13.1.1, A.13.1.3 |
| NSG Default Deny | 3.4, 3.5 | SC-7, AC-4 | A.13.1.1, A.13.2.1 |
| Managed Identity Only | 1.22, 1.23 | IA-2, IA-4 | A.9.2.3, A.9.4.2 |
| Diagnostic Logs | 2.1, 2.2 | AU-2, AU-3 | A.12.4.1, A.12.4.3 |
| Encryption at Rest | 3.10, 3.11 | SC-28 | A.10.1.1, A.13.2.3 |
| Key Vault Purge Protection | 8.3 | SC-12 | A.10.1.1 |

---

## 11. Exception Process

1. **Request**: Submit GitHub Issue with `security-exception` label
2. **Review**: @BB-24 + Security Team within 2 business days
3. **Approval**: Documented in Policy Assignment `exemptions` array
4. **Expiration**: Max 90 days; must renew or remediate
5. **Audit**: Quarterly review of all exceptions

---

## 12. Related Documents

- [Orchestration Overview](./orchestration.md) — Architecture context
- [Disaster Recovery](./disaster-recovery.md) — DR resources must meet baseline
- [Cost Model](./cost-model.md) — Tags enable cost allocation
- [Onboarding Guide](./onboarding-guide.md) — Person 2/3 endpoints must comply

---

## 13. Implementation Checklist

- [ ] Create custom Policy Definitions (Section 5)
- [ ] Create Policy Initiative `AACFP-Security-Baseline`
- [ ] Assign Initiative at Subscription scope
- [ ] Configure Diagnostic Settings → Log Analytics
- [ ] Enable DDoS Protection on Forensic VNet
- [ ] Create Private DNS Zones for all PaaS
- [ ] Configure Key Vault with Purge Protection
- [ ] Set up Security Alerts (Section 9)
- [ ] Document Exception Process in team wiki
# Multi-subscription Bicep deployment

The management-group entry point
[`iac/main.mg.bicep`](../iac/main.mg.bicep) places compromised workloads and
forensic services in separate subscriptions:

```text
Management Group
├── Compromised subscription
│   └── Compromised-Environment-RG
└── Forensic subscription
    └── Forensic-Enclave-RG
        ├── Evidence Storage, Key Vault, SQL Ledger, Event Grid
        └── Function App (system-assigned managed identity)
```

The Function App identity receives Network Contributor only at
`Compromised-Environment-RG`, and only when `enableMockMode` is false. No role
is assigned at subscription or management-group scope.

The enclave deploys a Blob Storage private endpoint and disables Storage public
network access by default. The Function App is VNet-integrated to reach the
private endpoint. By default, the template creates `react-vnet-<suffix>` with
separate subnets: `10.250.0.0/24` for the private endpoint and
`10.250.1.0/24` delegated to `Microsoft.Web/serverFarms` for Function App
integration. Override `vnetAddressPrefix`, `subnetAddressPrefix`, and
`functionIntegrationSubnetAddressPrefix` if these ranges overlap existing
networks.

To use an existing VNet, pass `privateEndpointSubnetId` for a subnet with
private-endpoint network policies disabled and `functionIntegrationSubnetId`
for a separate subnet in the same VNet delegated to `Microsoft.Web/serverFarms`.
The Function integration subnet must have sufficient address space (at least
`/28`; `/24` is recommended). Do not use the private-endpoint subnet for
Function App integration. Keep `storagePublicNetworkAccess` set to `Disabled`
unless an explicitly approved alternate private connectivity design is in
place.

## Prerequisites

- Both subscription IDs must be different and accessible from the deployment
  identity. The deployment template takes them as explicit parameters; verify
  they are not accidentally swapped.
- Both subscriptions must be descendants of the management group being deployed
  to.
- The deployment identity must be allowed to create management-group and
  subscription deployments, create resource groups in both subscriptions, and
  deploy the enclave resources in the forensic subscription.
- To create the Function identity's role assignment in the compromised
  subscription, the deployment identity also needs
  `Microsoft.Authorization/roleAssignments/write` at the target resource group
  (typically Owner or User Access Administrator there). Network Contributor
  alone is insufficient to grant this role.
- Supply `sqlAdminObjectId` and `sqlAdminLogin` for a Microsoft Entra
  administrator. Do not put credentials, Function keys, or signed URLs in
  parameter files.

## Preview and deploy

Run from the repository root in PowerShell. Use actual subscription and
management-group IDs in a protected local parameter file or replace the
placeholders interactively:

```powershell
$managementGroupId = '<management-group-id>'
$compromisedSubscriptionId = '<workload-subscription-guid>'
$forensicSubscriptionId = '<forensic-subscription-guid>'
$deploymentLocation = 'eastus'
$resourceLocation = 'eastus'

if ($compromisedSubscriptionId -eq $forensicSubscriptionId) {
    throw 'The compromised and forensic subscriptions must be different.'
}

az deployment mg what-if `
    --management-group-id $managementGroupId `
    --location $deploymentLocation `
    --template-file iac/main.mg.bicep `
    --parameters `
        compromisedSubscriptionId=$compromisedSubscriptionId `
        forensicSubscriptionId=$forensicSubscriptionId `
        location=$resourceLocation `
        sqlAdminObjectId='<entra-object-id>' `
        sqlAdminLogin='<entra-group-display-name>'
```

Review the preview for the two resource groups, forensic resources, and the
Function identity role assignment scoped only to the compromised resource
group. Do not proceed if the subscriptions, scopes, or planned changes are
unexpected. Deployment requires separate explicit approval:

```powershell
az deployment mg create `
    --management-group-id $managementGroupId `
    --location $deploymentLocation `
    --template-file iac/main.mg.bicep `
    --parameters `
        compromisedSubscriptionId=$compromisedSubscriptionId `
        forensicSubscriptionId=$forensicSubscriptionId `
        location=$resourceLocation `
        sqlAdminObjectId='<entra-object-id>' `
        sqlAdminLogin='<entra-group-display-name>'
```

The deployment uses incremental mode. It does not configure or deploy
workload VMs. On the workload side, it creates the resource group and the
scoped role assignment; the application and evidence services are deployed
into the forensic resource group.

For an existing forensic resource group, the lower-level
[`iac/main.bicep`](../iac/main.bicep) can still be deployed directly at
resource-group scope. Pass `forensicSubscriptionId` for the current enclave
subscription and `targetSubscriptionId` plus `targetResourceGroup` for the
approved workload boundary. This direct mode does not create either resource
group.

## Validation

Build each Bicep source before previewing:

```powershell
az bicep build --file iac/main.mg.bicep
az bicep build --file iac/main.bicep
az bicep build --file iac/modules/resource-groups.bicep
az bicep build --file iac/modules/resource-group.bicep
az bicep build --file iac/modules/rbac.bicep
```

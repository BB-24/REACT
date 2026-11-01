/*
  Management-group deployment entry point for the REACT multi-subscription
  topology. It creates the workload and forensic resource groups in their
  respective subscriptions, then deploys the forensic enclave and its
  workload-scoped Function managed-identity role assignment.

  Deploy with:
    az deployment mg create \
      --management-group-id <management-group-id> \
      --location <deployment-location> \
      --template-file iac/main.mg.bicep \
      --parameters compromisedSubscriptionId=<workload-subscription-id> \
                   forensicSubscriptionId=<forensic-subscription-id> \
                   location=<resource-region> \
                   sqlAdminObjectId=<aad-object-id> \
                   sqlAdminLogin=<aad-group-name>
*/

targetScope = 'managementGroup'

@description('Subscription that contains compromised workloads.')
@minLength(36)
@maxLength(36)
param compromisedSubscriptionId string

@description('Separate subscription that contains the forensic enclave and evidence vault.')
@minLength(36)
@maxLength(36)
param forensicSubscriptionId string

@description('Resource group created for compromised workloads.')
param compromisedResourceGroupName string = 'Compromised-Environment-RG'

@description('Resource group created for forensic services and evidence.')
param forensicResourceGroupName string = 'Forensic-Enclave-RG'

@description('Azure region for both resource groups and the forensic enclave.')
param location string

@description('Optional tags applied to both resource groups.')
param tags object = {}

@description('Short prefix used to derive globally unique forensic resource names.')
@minLength(3)
@maxLength(11)
param namePrefix string = 'react'

@description('Object ID of the Microsoft Entra user or group that administers SQL.')
param sqlAdminObjectId string

@description('Display name of the SQL administrator user or group.')
param sqlAdminLogin string

@description('Evidence container name.')
param evidenceContainerName string = 'evidence'

@description('Tool repository container name.')
param toolsContainerName string = 'tools'

@minValue(1)
@maxValue(146000)
@description('Time-based evidence retention in days.')
param retentionDays int = 2555

@description('Locking is irreversible; leave disabled for initial deployment.')
param lockRetentionPolicy bool = false

@description('Legal hold tags applied when the evidence container is created.')
param legalHoldTags array = [
  'react-active-investigation'
]

@minValue(5)
@maxValue(1440)
@description('Lifetime of write-only evidence upload SAS tokens in minutes.')
param sasTtlMinutes int = 60

@description('Object ID of the Logic App managed identity that triggers the response.')
param logicAppPrincipalId string = ''

@description('Storage Private Endpoint IP addresses or CIDR prefixes allowed by the isolation NSG.')
param evidenceStoragePrivateEndpointPrefixes array = []

@description('Deploy with mock mode enabled. Mock deployments never grant workload access.')
param enableMockMode bool = false

module resourceGroups 'modules/resource-groups.bicep' = {
  name: 'react-resource-groups-${uniqueString(compromisedSubscriptionId, forensicSubscriptionId, compromisedResourceGroupName, forensicResourceGroupName)}'
  scope: managementGroup()
  params: {
    compromisedSubscriptionId: compromisedSubscriptionId
    forensicSubscriptionId: forensicSubscriptionId
    compromisedResourceGroupName: compromisedResourceGroupName
    forensicResourceGroupName: forensicResourceGroupName
    location: location
    tags: tags
  }
}

module forensicEnclave 'main.bicep' = {
  name: 'react-forensic-enclave-${uniqueString(forensicSubscriptionId, forensicResourceGroupName)}'
  scope: resourceGroup(forensicSubscriptionId, forensicResourceGroupName)
  dependsOn: [
    resourceGroups
  ]
  params: {
    location: location
    namePrefix: namePrefix
    sqlAdminObjectId: sqlAdminObjectId
    sqlAdminLogin: sqlAdminLogin
    evidenceContainerName: evidenceContainerName
    toolsContainerName: toolsContainerName
    retentionDays: retentionDays
    lockRetentionPolicy: lockRetentionPolicy
    legalHoldTags: legalHoldTags
    sasTtlMinutes: sasTtlMinutes
    logicAppPrincipalId: logicAppPrincipalId
    forensicSubscriptionId: forensicSubscriptionId
    targetSubscriptionId: compromisedSubscriptionId
    targetResourceGroup: compromisedResourceGroupName
    evidenceStoragePrivateEndpointPrefixes: evidenceStoragePrivateEndpointPrefixes
    enableMockMode: enableMockMode
  }
}

output compromisedSubscription string = compromisedSubscriptionId
output forensicSubscription string = forensicSubscriptionId
output compromisedResourceGroup string = compromisedResourceGroupName
output forensicResourceGroup string = forensicResourceGroupName
output functionAppName string = forensicEnclave.outputs.functionAppName
output functionPrincipalId string = forensicEnclave.outputs.functionPrincipalId
output storageAccountName string = forensicEnclave.outputs.storageAccountName
output enclaveResourceGroup string = forensicEnclave.outputs.enclaveResourceGroup

// Management-group module that creates each resource group in its own
// subscription. The contained subscription deployments are incremental.
targetScope = 'managementGroup'

@description('Subscription that contains compromised workloads.')
param compromisedSubscriptionId string

@description('Separate subscription that contains the forensic enclave.')
param forensicSubscriptionId string

@description('Resource group for compromised workloads.')
param compromisedResourceGroupName string

@description('Resource group for forensic services and evidence.')
param forensicResourceGroupName string

@description('Azure region for the resource groups.')
param location string

@description('Optional tags applied to both resource groups.')
param tags object = {}

module compromisedResourceGroup 'resource-group.bicep' = {
  name: 'create-compromised-rg-${uniqueString(compromisedSubscriptionId, compromisedResourceGroupName)}'
  scope: subscription(compromisedSubscriptionId)
  params: {
    name: compromisedResourceGroupName
    location: location
    tags: union(tags, {
      Purpose: 'CompromisedEnvironment'
      ManagedBy: 'AACFP'
    })
  }
}

module forensicResourceGroup 'resource-group.bicep' = {
  name: 'create-forensic-rg-${uniqueString(forensicSubscriptionId, forensicResourceGroupName)}'
  scope: subscription(forensicSubscriptionId)
  params: {
    name: forensicResourceGroupName
    location: location
    tags: union(tags, {
      Purpose: 'ForensicEnclave'
      ManagedBy: 'AACFP'
    })
  }
}

output compromisedResourceGroupId string = compromisedResourceGroup.outputs.resourceGroupId
output forensicResourceGroupId string = forensicResourceGroup.outputs.resourceGroupId

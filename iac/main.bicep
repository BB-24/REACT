targetScope = 'subscription'

@description('Primary Azure region for all resources.')
param location string = 'eastus'

@description('Name of the compromised environment resource group.')
param compromisedEnvironmentRgName string = 'Compromised-Environment-RG'

@description('Name of the forensic enclave resource group.')
param forensicEnclaveRgName string = 'Forensic-Enclave-RG'

@description('Base name for the Containment Function App.')
param functionAppName string = 'aacfp-containment-${uniqueString(subscription().id, location)}'

@description('Storage Account name for the Function App runtime (3-24 lowercase alphanumeric characters).')
param functionStorageName string = 'aacfpstg${uniqueString(subscription().id, location)}'

@description('Name for the incident-response Logic App.')
param logicAppName string = 'aacfp-incident-response'

@description('Standard tags applied across all deployed resources.')
param tags object = {
  Application: 'AACFP'
  Project: 'Forensic-Containment-Pipeline'
  Environment: 'Production'
}

// 1. Provision Resource Groups (Subscription Scope)
module resourceGroups 'modules/resource-groups.bicep' = {
  name: 'deploy-resource-groups'
  params: {
    compromisedEnvironmentRgName: compromisedEnvironmentRgName
    forensicEnclaveRgName: forensicEnclaveRgName
    location: location
    tags: tags
  }
}

// 2. Deploy Network Containment Function App (Forensic Enclave RG)
module containmentFunction 'modules/containment-function.bicep' = {
  name: 'deploy-containment-function'
  scope: resourceGroup(forensicEnclaveRgName)
  dependsOn: [
    resourceGroups
  ]
  params: {
    location: location
    functionAppName: functionAppName
    storageAccountName: take(toLower(functionStorageName), 24)
    tags: tags
  }
}

// 3. Grant Network Contributor to Function Managed Identity on Compromised Environment RG
module containmentRbac 'modules/rbac.bicep' = {
  name: 'deploy-containment-rbac'
  scope: resourceGroup(compromisedEnvironmentRgName)
  dependsOn: [
    resourceGroups
  ]
  params: {
    principalId: containmentFunction.outputs.functionAppPrincipalId
  }
}

// 4. Deploy Logic App Orchestrator (Forensic Enclave RG)
module logicApp 'modules/logic-app.bicep' = {
  name: 'deploy-logic-app'
  scope: resourceGroup(forensicEnclaveRgName)
  dependsOn: [
    resourceGroups
  ]
  params: {
    location: location
    logicAppName: logicAppName
    containmentFunctionUrl: containmentFunction.outputs.containmentFunctionUrl
    tags: tags
  }
}

output compromisedEnvironmentResourceGroupName string = compromisedEnvironmentRgName
output forensicEnclaveResourceGroupName string = forensicEnclaveRgName
output containmentFunctionAppId string = containmentFunction.outputs.functionAppId
output containmentFunctionPrincipalId string = containmentFunction.outputs.functionAppPrincipalId
output containmentFunctionUrl string = containmentFunction.outputs.containmentFunctionUrl
output logicAppId string = logicApp.outputs.logicAppId
output logicAppPrincipalId string = logicApp.outputs.principalId

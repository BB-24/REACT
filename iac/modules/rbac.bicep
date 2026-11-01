@description('Principal ID of the Function App Managed Identity to grant permissions.')
param principalId string

@description('Built-in Network Contributor role definition ID.')
var networkContributorRoleId = '4d97b98b-1d4f-4787-a291-c67834d212e7'

resource networkContributorRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  scope: subscription()
  name: networkContributorRoleId
}

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, principalId, networkContributorRoleId)
  scope: resourceGroup()
  properties: {
    roleDefinitionId: networkContributorRole.id
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: 'Grant Network Contributor on Compromised-Environment-RG to Forensic Containment Function App'
  }
}

output roleAssignmentId string = roleAssignment.id

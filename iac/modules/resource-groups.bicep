// Deploy this module at subscription scope. These resource groups deliberately
// separate potentially compromised assets from the forensic evidence enclave.
targetScope = 'subscription'

@description('Name of the compromised environment resource group.')
param compromisedEnvironmentRgName string = 'Compromised-Environment-RG'

@description('Name of the forensic enclave resource group.')
param forensicEnclaveRgName string = 'Forensic-Enclave-RG'

@description('Azure region for both resource groups.')
param location string

@description('Optional tags applied consistently to both resource groups.')
param tags object = {}

resource compromisedEnvironmentRg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: compromisedEnvironmentRgName
  location: location
  tags: union(tags, {
    Purpose: 'CompromisedEnvironment'
    ManagedBy: 'AACFP'
  })
}

resource forensicEnclaveRg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: forensicEnclaveRgName
  location: location
  tags: union(tags, {
    Purpose: 'ForensicEnclave'
    ManagedBy: 'AACFP'
  })
}


output compromisedEnvironmentResourceGroupName string = compromisedEnvironmentRg.name
output forensicEnclaveResourceGroupName string = forensicEnclaveRg.name

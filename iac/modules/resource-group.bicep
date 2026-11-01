// Deploy this module at subscription scope to create one resource group.
targetScope = 'subscription'

@description('Name of the resource group to create.')
param name string

@description('Azure region for the resource group.')
param location string

@description('Optional tags applied to the resource group.')
param tags object = {}

resource resourceGroupResource 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: name
  location: location
  tags: tags
}

output resourceGroupId string = resourceGroupResource.id

@description('Location for the Cosmos DB account.')
param location string = resourceGroup().location

@minLength(3)
@maxLength(44)
@description('Globally unique name for the Cosmos DB account (lowercase, alphanumeric, hyphens).')
param accountName string

@description('Database name for forensic artifacts.')
param databaseName string = 'react-forensic-db'

@description('Container name for timeline artifacts.')
param containerName string = 'timeline-artifacts'

@description('Optional principal ID (e.g. Function App managed identity) to grant Cosmos DB Built-in Data Contributor role.')
param principalId string = ''

@description('Tags applied to Cosmos DB resources.')
param tags object = {}

resource cosmosAccount 'Microsoft.DocumentDB/databaseAccounts@2023-11-15' = {
  name: toLower(accountName)
  location: location
  tags: union(tags, {
    'react:purpose': 'forensic-timeline-storage'
    'react:component': 'person3-analysis'
  })
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    capabilities: [
      {
        name: 'EnableServerless'
      }
    ]
    locations: [
      {
        locationName: location
        failoverPriority: 0
        isZoneRedundant: false
      }
    ]
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
    }
    publicNetworkAccess: 'Enabled'
  }
}

resource sqlDatabase 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2023-11-15' = {
  parent: cosmosAccount
  name: databaseName
  properties: {
    resource: {
      id: databaseName
    }
  }
}

resource timelineContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2023-11-15' = {
  parent: sqlDatabase
  name: containerName
  properties: {
    resource: {
      id: containerName
      partitionKey: {
        paths: [
          '/incidentId'
        ]
        kind: 'Hash'
        version: 2
      }
      indexingPolicy: {
        indexingMode: 'consistent'
        automatic: true
        includedPaths: [
          {
            path: '/*'
          }
        ]
        excludedPaths: [
          {
            path: '/"_etag"/?'
          }
        ]
      }
    }
  }
}

// Built-in Cosmos DB Data Contributor role definition ID
var cosmosDataContributorRoleId = '00000000-0000-0000-0000-000000000002'

resource roleAssignment 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2023-11-15' = if (!empty(principalId)) {
  parent: cosmosAccount
  name: guid(cosmosAccount.id, principalId, cosmosDataContributorRoleId)
  properties: {
    roleDefinitionId: '${cosmosAccount.id}/sqlRoleDefinitions/${cosmosDataContributorRoleId}'
    principalId: principalId
    scope: cosmosAccount.id
  }
}

output accountName string = cosmosAccount.name
output endpoint string = cosmosAccount.properties.documentEndpoint
output databaseName string = sqlDatabase.name
output containerName string = timelineContainer.name
output partitionKey string = '/incidentId'

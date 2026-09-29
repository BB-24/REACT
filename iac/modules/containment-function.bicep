@description('Region for the Function App resources.')
param location string = resourceGroup().location

@description('Globally unique Function App name.')
param functionAppName string

@description('Globally unique Storage Account name for the Function App runtime.')
param storageAccountName string

@description('Azure Functions deployment package URI, including a SAS token when private.')
@secure()
param packageUri string = ''

@description('Runtime version. The application code targets Python 3.10+.')
param linuxFxVersion string = 'PYTHON|3.11'

@description('Optional application settings, such as EVIDENCE_STORAGE_PRIVATE_ENDPOINT_PREFIXES.')
param appSettings object = {}

@description('Optional tags applied to all resources in this module.')
param tags object = {}

var defaultAppSettings = [
  { name: 'AzureWebJobsStorage', value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}' }
  { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
  { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'python' }
  { name: 'REGION_NAME', value: location }
]

var runFromPackageSetting = !empty(packageUri) ? [
  { name: 'WEBSITE_RUN_FROM_PACKAGE', value: packageUri }
] : []

var customAppSettings = [
  for setting in items(appSettings): {
    name: setting.key
    value: string(setting.value)
  }
]

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  tags: tags
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

resource hostingPlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: '${functionAppName}-plan'
  location: location
  tags: tags
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: { type: 'SystemAssigned' }
  tags: tags
  properties: {
    serverFarmId: hostingPlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: linuxFxVersion
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appSettings: concat(defaultAppSettings, runFromPackageSetting, customAppSettings)
    }
  }
}

output functionAppId string = functionApp.id
output functionAppPrincipalId string = functionApp.identity.principalId
output functionAppDefaultHostName string = functionApp.properties.defaultHostName
output containmentFunctionUrl string = 'https://${functionApp.properties.defaultHostName}/api/NetworkContainment'


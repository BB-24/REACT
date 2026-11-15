/*
  REACT -- Forensic Enclave infrastructure.

  Deploys the evidence side of the platform: the immutable storage account, the
  Key Vault that backs SAS minting, the Event Grid system topic that drives
  chain-of-custody hashing, the Azure SQL Ledger database, and the Function App
  that runs it all.

  Requirement mapping:
    REQ-3.3.3  Key Vault + the RBAC that lets the Function App mint 60-minute
               write-only SAS tokens (user-delegation by default, so no account
               key has to exist at all).
    REQ-3.4.3  A dedicated enclave resource group, deployed under a
               subscription separate from the workloads being investigated.
    REQ-3.5.1  Immutable storage (versioning + a locked time-based retention
               policy) with a legal hold applied at container creation.
    REQ-3.5.2  Event Grid system topic subscribed to BlobCreated, delivering to
               the ChainOfCustody webhook.
    REQ-3.5.3  Azure SQL database with ledger enabled and digests published to
               immutable storage.

  Scope is the enclave resource group:
      az deployment group create \
        --resource-group rg-forensic-enclave \
        --template-file iac/main.bicep \
        --parameters sqlAdminObjectId=<aad-object-id> \
                     sqlAdminLogin=<aad-group-name>
*/

targetScope = 'resourceGroup'

// --- Parameters --------------------------------------------------------------

@description('Location for every resource in the enclave.')
param location string = resourceGroup().location

@minLength(3)
@maxLength(11)
@description('Short prefix; resource names are derived from it plus a hash.')
param namePrefix string = 'react'

@description('Object ID of the AAD user or group that administers the SQL server.')
param sqlAdminObjectId string

@description('Display name of that AAD user or group.')
param sqlAdminLogin string

@description('Evidence container name. Must match the EVIDENCE_CONTAINER app setting.')
param evidenceContainerName string = 'evidence'

@description('Tool repository container. Must match the TOOLS_CONTAINER app setting.')
param toolsContainerName string = 'tools'

@minValue(1)
@maxValue(146000)
@description('Time-based retention in days. Default is seven years.')
param retentionDays int = 2555

@description('Lock the retention policy. Irreversible: a locked policy cannot be shortened or removed, only extended. Leave false while testing.')
param lockRetentionPolicy bool = false

@description('Legal hold tags applied to the evidence container at creation (REQ-3.5.1).')
param legalHoldTags array = [
  'react-active-investigation'
]

@description('Lifetime of the write-only upload SAS, in minutes (REQ-3.3.3).')
@minValue(5)
@maxValue(1440)
param sasTtlMinutes int = 60

@description('Object ID of the Logic App managed identity that triggers the response.')
param logicAppPrincipalId string = ''

@description('Subscription ID where this forensic enclave is deployed.')
param forensicSubscriptionId string = subscription().subscriptionId

@description('Workload subscription containing the VMs under investigation. May differ from this deployment subscription.')
param targetSubscriptionId string = subscription().subscriptionId

@description('Resource group containing those VMs.')
param targetResourceGroup string = ''

@description('Storage Private Endpoint IP addresses or CIDR prefixes allowed by the isolation NSG.')
param evidenceStoragePrivateEndpointPrefixes array = []

@description('Existing subnet resource ID delegated to Microsoft.Web/serverFarms for Function App VNet integration. Required when using an existing private endpoint subnet.')
param functionIntegrationSubnetId string = ''

@description('Address prefix used for the Function App integration subnet when this template creates the enclave VNet.')
param functionIntegrationSubnetAddressPrefix string = '10.250.1.0/24'

@description('Deploy with the mock estate enabled. Never true for a real enclave.')
param enableMockMode bool = false

@allowed([
  'Enabled'
  'Disabled'
])
@description('Storage account public network access. The Function App is VNet-integrated to the Storage private endpoint.')
param storagePublicNetworkAccess string = 'Disabled'

@description('Existing subnet resource ID for the Storage private endpoint. Leave empty to create the enclave VNet and subnet.')
param privateEndpointSubnetId string = ''

@description('Address prefix used when this template creates the enclave VNet.')
param vnetAddressPrefix string = '10.250.0.0/16'

@description('Address prefix used for the private-endpoint subnet when this template creates the enclave VNet.')
param subnetAddressPrefix string = '10.250.0.0/24'

var suffix = uniqueString(forensicSubscriptionId, resourceGroup().id)
var storageAccountName = toLower('${namePrefix}enc${substring(suffix, 0, 8)}')
var keyVaultName = '${namePrefix}-kv-${substring(suffix, 0, 8)}'
var functionAppName = '${namePrefix}-fn-${substring(suffix, 0, 8)}'
var hostingPlanName = '${namePrefix}-plan-${substring(suffix, 0, 8)}'
var sqlServerName = '${namePrefix}-sql-${substring(suffix, 0, 8)}'
var sqlDatabaseName = '${namePrefix}dfir'
var systemTopicName = '${namePrefix}-evidence-topic'
var appInsightsName = '${namePrefix}-ai-${substring(suffix, 0, 8)}'
var actualVnetName = '${namePrefix}-vnet-${substring(suffix, 0, 8)}'
var subnetName = 'Forensic-Enclave-Subnet'
var functionIntegrationSubnetName = 'Function-Integration-Subnet'
var actualFunctionIntegrationSubnetId = empty(privateEndpointSubnetId)
  ? resourceId('Microsoft.Network/virtualNetworks/subnets', actualVnetName, functionIntegrationSubnetName)
  : functionIntegrationSubnetId
var cosmosAccountName = toLower('${namePrefix}-cosmos-${substring(suffix, 0, 8)}')
var cosmosDatabaseName = 'react-forensic-db'
var cosmosContainerName = 'timeline-artifacts'

// Built-in role definition IDs.
var storageBlobDataContributor = subscriptionResourceId(
  forensicSubscriptionId,
  'Microsoft.Authorization/roleDefinitions',
  'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
)
var storageBlobDelegator = subscriptionResourceId(
  forensicSubscriptionId,
  'Microsoft.Authorization/roleDefinitions',
  'db58b8e5-c6ad-4a2a-8342-4190687cbf4a'
)
var keyVaultSecretsUser = subscriptionResourceId(
  forensicSubscriptionId,
  'Microsoft.Authorization/roleDefinitions',
  '4633458b-17de-408a-b874-0445c86b69e6'
)

// --- Evidence storage (REQ-3.5.1) -------------------------------------------

resource evidenceStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: {
    // Zone-redundant: evidence must survive a datacentre failure mid-case.
    name: 'Standard_ZRS'
  }
  kind: 'StorageV2'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    accessTier: 'Hot'
    // Version-level immutability is the prerequisite for a container-scoped
    // policy that a legal hold can then pin.
    immutableStorageWithVersioning: {
      enabled: true
    }
    allowBlobPublicAccess: false
    allowSharedKeyAccess: true // Required only for SAS_MODE=key-vault; see note.
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: storagePublicNetworkAccess
    networkAcls: {
      // When storagePublicNetworkAccess is Disabled, access is mediated via
      // Private Endpoints on the Forensic-Enclave-Subnet, with trusted Azure services bypassed.
      bypass: 'AzureServices'
      defaultAction: storagePublicNetworkAccess == 'Enabled' ? 'Allow' : 'Deny'
    }
  }
  tags: {
    'react:purpose': 'forensic-enclave'
  }
}

resource blobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: evidenceStorage
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 30
    }
    isVersioningEnabled: true
  }
}

// Primary evidence container
resource evidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobServices
  name: evidenceContainerName
  properties: {
    publicAccess: 'None'
    immutableStorageWithVersioning: {
      enabled: true
    }
    metadata: {
      purpose: 'chain-of-custody-evidence'
    }
  }
}

// P2-5 Required WORM containers
resource memoryDumpsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobServices
  name: 'memory-dumps'
  properties: {
    publicAccess: 'None'
    immutableStorageWithVersioning: {
      enabled: true
    }
    metadata: {
      purpose: 'volatile-memory-dumps'
    }
  }
}

resource diskSnapshotsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobServices
  name: 'disk-snapshots'
  properties: {
    publicAccess: 'None'
    immutableStorageWithVersioning: {
      enabled: true
    }
    metadata: {
      purpose: 'disk-snapshots'
    }
  }
}

resource analysisOutputContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobServices
  name: 'analysis-output'
  properties: {
    publicAccess: 'None'
    immutableStorageWithVersioning: {
      enabled: true
    }
    metadata: {
      purpose: 'forensic-analysis-output'
    }
  }
}

resource reportsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobServices
  name: 'reports'
  properties: {
    publicAccess: 'None'
    immutableStorageWithVersioning: {
      enabled: true
    }
    metadata: {
      purpose: 'forensic-investigation-reports'
    }
  }
}

// The tool repository holds WinPmem/AVML and the acquisition scripts. It is
// deliberately mutable: tools get replaced as new builds are published, and
// nothing in here is evidence.
resource toolsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobServices
  name: toolsContainerName
  properties: {
    publicAccess: 'None'
    metadata: {
      purpose: 'acquisition-tool-repository'
    }
  }
}

// 7-year time-based immutability policies (2555 days) across all required evidence containers (REQ-3.5.1 / P2-5)
resource evidenceRetentionPolicy 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: evidenceContainer
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: retentionDays
    allowProtectedAppendWrites: false
  }
}

resource memoryDumpsRetentionPolicy 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: memoryDumpsContainer
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: retentionDays
    allowProtectedAppendWrites: false
  }
}

resource diskSnapshotsRetentionPolicy 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: diskSnapshotsContainer
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: retentionDays
    allowProtectedAppendWrites: false
  }
}

resource analysisOutputRetentionPolicy 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: analysisOutputContainer
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: retentionDays
    allowProtectedAppendWrites: false
  }
}

resource reportsRetentionPolicy 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: reportsContainer
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: retentionDays
    allowProtectedAppendWrites: false
  }
}

// --- Legal hold (REQ-3.5.1 / P2-5) -------------------------------------------

// A legal hold is applied through a data-management action (`setLegalHold`),
// not a declarable resource, so ARM cannot express it directly. This script
// runs at deployment time, which is what makes the hold "automatically applied
// upon container creation" as the requirement demands.
resource legalHoldIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-legalhold-${substring(suffix, 0, 8)}'
  location: location
}

resource legalHoldRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: evidenceStorage
  name: guid(evidenceStorage.id, legalHoldIdentity.id, 'contributor')
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '17d1049b-9a84-46fb-8f53-869881c3d3ab' // Storage Account Contributor
    )
    principalId: legalHoldIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource applyLegalHold 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: '${namePrefix}-apply-legal-hold'
  location: location
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${legalHoldIdentity.id}': {}
    }
  }
  properties: {
    azCliVersion: '2.59.0'
    retentionInterval: 'PT1H'
    timeout: 'PT30M'
    environmentVariables: [
      { name: 'ACCOUNT', value: evidenceStorage.name }
      { name: 'GROUP', value: resourceGroup().name }
      { name: 'CONTAINERS', value: '${evidenceContainerName} memory-dumps disk-snapshots analysis-output reports' }
      { name: 'TAGS', value: join(legalHoldTags, ' ') }
    ]
    scriptContent: '''
      set -euo pipefail
      for c in $CONTAINERS; do
        echo "Processing legal hold on container: $c"
        existing=$(az storage container legal-hold show \
          --account-name "$ACCOUNT" --resource-group "$GROUP" \
          --container-name "$c" --query "tags" -o tsv 2>/dev/null || echo "")
        if [ -n "$existing" ]; then
          echo "Legal hold already present on $c: $existing"
        else
          az storage container legal-hold set \
            --account-name "$ACCOUNT" --resource-group "$GROUP" \
            --container-name "$c" --tags $TAGS
          echo "Legal hold applied to $c: $TAGS"
        fi

        # Verify hold is active and fail deployment if not active (prevents false reporting)
        has_hold=$(az storage container legal-hold show \
          --account-name "$ACCOUNT" --resource-group "$GROUP" \
          --container-name "$c" --query "hasLegalHold" -o tsv)
        if [ "$has_hold" != "true" ]; then
          echo "ERROR: Legal hold verification failed on container $c" >&2
          exit 1
        fi
      done
      echo "Legal hold successfully verified on all evidence containers."
    '''
  }
  dependsOn: [
    legalHoldRoleAssignment
    evidenceRetentionPolicy
    memoryDumpsRetentionPolicy
    diskSnapshotsRetentionPolicy
    analysisOutputRetentionPolicy
    reportsRetentionPolicy
  ]
}

// Locking is separated and opt-in because it cannot be undone: once locked, the
// retention period can only be extended, and the container cannot be deleted
// until every blob in it ages out. Deploy unlocked, verify, then lock.
resource lockRetention 'Microsoft.Resources/deploymentScripts@2023-08-01' = if (lockRetentionPolicy) {
  name: '${namePrefix}-lock-retention'
  location: location
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${legalHoldIdentity.id}': {}
    }
  }
  properties: {
    azCliVersion: '2.59.0'
    retentionInterval: 'PT1H'
    timeout: 'PT30M'
    environmentVariables: [
      { name: 'ACCOUNT', value: evidenceStorage.name }
      { name: 'GROUP', value: resourceGroup().name }
      { name: 'CONTAINERS', value: '${evidenceContainerName} memory-dumps disk-snapshots analysis-output reports' }
    ]
    scriptContent: '''
      set -euo pipefail
      for c in $CONTAINERS; do
        etag=$(az storage container immutability-policy show \
          --account-name "$ACCOUNT" --resource-group "$GROUP" \
          --container-name "$c" --query etag -o tsv)
        state=$(az storage container immutability-policy show \
          --account-name "$ACCOUNT" --resource-group "$GROUP" \
          --container-name "$c" --query state -o tsv)
        if [ "$state" = "Locked" ]; then
          echo "Immutability policy already locked on $c."
        else
          az storage container immutability-policy lock \
            --account-name "$ACCOUNT" --resource-group "$GROUP" \
            --container-name "$c" --if-match "$etag"
          echo "Immutability policy locked on $c."
        fi
      done
    '''
  }
  dependsOn: [
    applyLegalHold
  ]
}

// --- Private Endpoints & DNS (REQ-3.5.1 / P2-5) -------------------------------

resource enclaveVnet 'Microsoft.Network/virtualNetworks@2023-11-01' = if (empty(privateEndpointSubnetId)) {
  name: actualVnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetAddressPrefix
      ]
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: subnetAddressPrefix
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
      {
        name: functionIntegrationSubnetName
        properties: {
          addressPrefix: functionIntegrationSubnetAddressPrefix
          delegations: [
            {
              name: 'functionAppDelegation'
              properties: {
                serviceName: 'Microsoft.Web/serverFarms'
              }
            }
          ]
        }
      }
    ]
  }
}

var targetSubnetId = empty(privateEndpointSubnetId) ? resourceId('Microsoft.Network/virtualNetworks/subnets', actualVnetName, subnetName) : privateEndpointSubnetId

resource storagePrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${evidenceStorage.name}-blob-pe'
  location: location
  properties: {
    subnet: {
      id: targetSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${evidenceStorage.name}-blob-connection'
        properties: {
          privateLinkServiceId: evidenceStorage.id
          groupIds: [
            'blob'
          ]
        }
      }
    ]
  }
  dependsOn: [
    enclaveVnet
  ]
}

resource blobPrivateDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.blob.${environment().suffixes.storage}'
  location: 'global'
}

resource blobPrivateDnsZoneVnetLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = if (empty(privateEndpointSubnetId)) {
  parent: blobPrivateDnsZone
  name: '${actualVnetName}-link'
  location: 'global'
  properties: {
    virtualNetwork: {
      id: resourceId('Microsoft.Network/virtualNetworks', actualVnetName)
    }
    registrationEnabled: false
  }
  dependsOn: [
    enclaveVnet
  ]
}

resource storagePrivateEndpointDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = {
  parent: storagePrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'privatelink-blob-core-windows-net'
        properties: {
          privateDnsZoneId: blobPrivateDnsZone.id
        }
      }
    ]
  }
}

// --- Key Vault (REQ-3.3.3) ---------------------------------------------------

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    // Non-negotiable in an enclave: without it, an attacker with vault-delete
    // rights could purge the key material a case depends on.
    enablePurgeProtection: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
  }
}

// --- Event Grid system topic (REQ-3.5.2) -------------------------------------

resource systemTopic 'Microsoft.EventGrid/systemTopics@2023-12-15-preview' = {
  name: systemTopicName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    source: evidenceStorage.id
    topicType: 'Microsoft.Storage.StorageAccounts'
  }
}

resource custodySubscription 'Microsoft.EventGrid/systemTopics/eventSubscriptions@2023-12-15-preview' = {
  parent: systemTopic
  name: 'chain-of-custody'
  properties: {
    destination: {
      endpointType: 'WebHook'
      properties: {
        // The function key is part of this URL, which is why the whole template
        // output is treated as sensitive. Event Grid answers the validation
        // handshake against this endpoint before any event is delivered.
        endpointUrl: 'https://${functionApp.properties.defaultHostName}/api/custody?code=${listKeys('${functionApp.id}/host/default', '2022-09-01').functionKeys.default}'
        maxEventsPerBatch: 1
        preferredBatchSizeInKilobytes: 64
      }
    }
    filter: {
      includedEventTypes: [
        'Microsoft.Storage.BlobCreated'
      ]
      // Only the evidence container. The tool repository raises BlobCreated
      // too, and hashing WinPmem into the custody ledger would be noise.
      subjectBeginsWith: '/blobServices/default/containers/${evidenceContainerName}/'
      enableAdvancedFilteringOnArrays: true
    }
    retryPolicy: {
      // A custody record must not be lost to a transient SQL failure.
      maxDeliveryAttempts: 30
      eventTimeToLiveInMinutes: 1440
    }
    deadLetterDestination: {
      endpointType: 'StorageBlob'
      properties: {
        resourceId: evidenceStorage.id
        blobContainerName: deadLetterContainer.name
      }
    }
  }
}

resource deadLetterContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobServices
  name: 'custody-deadletter'
  properties: {
    publicAccess: 'None'
  }
}

// --- Azure SQL Ledger (REQ-3.5.3) -------------------------------------------

resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: sqlServerName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    version: '12.0'
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Enabled'
    // AAD-only: no SQL login, therefore no password to leak or rotate.
    administrators: {
      administratorType: 'ActiveDirectory'
      principalType: 'Group'
      login: sqlAdminLogin
      sid: sqlAdminObjectId
      tenantId: subscription().tenantId
      azureADOnlyAuthentication: true
    }
  }
}

resource allowAzureServices 'Microsoft.Sql/servers/firewallRules@2023-05-01-preview' = {
  parent: sqlServer
  name: 'AllowAllWindowsAzureIps'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

resource ledgerDatabase 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
  parent: sqlServer
  name: sqlDatabaseName
  location: location
  sku: {
    name: 'GP_S_Gen5'
    tier: 'GeneralPurpose'
    family: 'Gen5'
    capacity: 2
  }
  properties: {
    // Every table created without an explicit option becomes a ledger table,
    // and the setting cannot be turned off afterwards.
    isLedgerOn: true
    autoPauseDelay: 60
    minCapacity: json('0.5')
    zoneRedundant: false
  }
}

// Publishing digests to immutable storage is what makes the ledger provable to
// a third party: without it, a sufficiently privileged insider could rebuild
// the database and regenerate a self-consistent digest history.
resource ledgerDigestUpload 'Microsoft.Sql/servers/databases/ledgerDigestUploads@2023-05-01-preview' = {
  parent: ledgerDatabase
  name: 'current'
  properties: {
    digestStorageEndpoint: 'https://${evidenceStorage.name}.blob.${environment().suffixes.storage}'
  }
  dependsOn: [
    ledgerDigestRoleAssignment
  ]
}

resource ledgerDigestRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: evidenceStorage
  name: guid(evidenceStorage.id, sqlServer.id, 'blob-contributor')
  properties: {
    roleDefinitionId: storageBlobDataContributor
    principalId: sqlServer.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// --- Function App ------------------------------------------------------------

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
}

resource hostingPlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: hostingPlanName
  location: location
  sku: {
    // Elastic Premium: hashing a multi-gigabyte image needs more than the
    // Consumption plan's 10-minute ceiling and its cold-start behaviour.
    name: 'EP1'
    tier: 'ElasticPremium'
  }
  properties: {
    maximumElasticWorkerCount: 4
  }
  kind: 'elastic'
}

// --- Cosmos DB Serverless (REQ-3.6 / P3-3) -----------------------------------

module cosmosDb 'modules/cosmos-db.bicep' = {
  name: 'cosmosDbDeployment'
  params: {
    location: location
    accountName: cosmosAccountName
    databaseName: cosmosDatabaseName
    containerName: cosmosContainerName
    tags: {
      'react:purpose': 'forensic-enclave'
    }
  }
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: hostingPlan.id
    httpsOnly: true
    virtualNetworkSubnetId: actualFunctionIntegrationSubnetId
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      functionAppScaleLimit: 4
      appSettings: [
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'python' }
        {
          name: 'AzureWebJobsStorage__accountName'
          value: evidenceStorage.name
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }

        // --- REACT settings ---
        { name: 'REACT_MOCK_MODE', value: string(enableMockMode) }
        { name: 'EVIDENCE_STORAGE_ACCOUNT', value: evidenceStorage.name }
        { name: 'EVIDENCE_CONTAINER', value: evidenceContainerName }
        { name: 'TOOLS_CONTAINER', value: toolsContainerName }
        { name: 'STORAGE_ENDPOINT_SUFFIX', value: environment().suffixes.storage }

        // user-delegation needs no account key at all; 'key-vault' is the
        // fallback for accounts still on shared-key auth (REQ-3.3.3).
        { name: 'SAS_MODE', value: 'user-delegation' }
        { name: 'SAS_TTL_MINUTES', value: string(sasTtlMinutes) }
        { name: 'KEY_VAULT_URI', value: keyVault.properties.vaultUri }
        { name: 'STORAGE_KEY_SECRET_NAME', value: 'evidence-storage-key' }

        {
          name: 'SQL_CONNECTION_STRING'
          value: 'Driver={ODBC Driver 18 for SQL Server};Server=tcp:${sqlServer.properties.fullyQualifiedDomainName},1433;Database=${sqlDatabaseName};Authentication=ActiveDirectoryMsi;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;'
        }
        { name: 'LEDGER_TABLE', value: 'dbo.EvidenceLedger' }
        { name: 'COSMOS_DB_ENDPOINT', value: cosmosDb.outputs.endpoint }
        { name: 'COSMOS_DB_DATABASE', value: cosmosDb.outputs.databaseName }
        { name: 'COSMOS_DB_CONTAINER', value: cosmosDb.outputs.containerName }

        { name: 'FORENSIC_SUBSCRIPTION_ID', value: forensicSubscriptionId }
        { name: 'FORENSIC_RESOURCE_GROUP', value: resourceGroup().name }
        { name: 'FORENSIC_LOCATION', value: location }
        { name: 'AZURE_SUBSCRIPTION_ID', value: targetSubscriptionId }
        { name: 'TARGET_RESOURCE_GROUP', value: targetResourceGroup }
        { name: 'LOGIC_APP_PRINCIPAL_ID', value: logicAppPrincipalId }

        { name: 'HASH_CHUNK_BYTES', value: '8388608' }
        { name: 'EVIDENCE_STORAGE_SERVICE_TAG', value: 'Storage.${location}' }
        {
          name: 'EVIDENCE_STORAGE_PRIVATE_ENDPOINT_PREFIXES'
          value: join(evidenceStoragePrivateEndpointPrefixes, ',')
        }
        { name: 'ACQUISITION_TIMEOUT_SECONDS', value: '5400' }
      ]
    }
  }
}

// Target permissions are opt-in and limited to the configured target resource
// group. Mock deployments never receive a role assignment on workload assets.
module networkContainmentRbac 'modules/rbac.bicep' = if (!enableMockMode && !empty(targetResourceGroup)) {
  name: 'network-containment-rbac'
  scope: resourceGroup(targetSubscriptionId, targetResourceGroup)
  params: {
    principalId: functionApp.identity.principalId
  }
}

// --- Role assignments --------------------------------------------------------

resource functionBlobContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: evidenceStorage
  name: guid(evidenceStorage.id, functionApp.id, 'blob-contributor')
  properties: {
    roleDefinitionId: storageBlobDataContributor
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Storage Blob Delegator is what permits user-delegation SAS minting -- the
// reason no storage account key needs to exist (REQ-3.3.3).
resource functionBlobDelegator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: evidenceStorage
  name: guid(evidenceStorage.id, functionApp.id, 'blob-delegator')
  properties: {
    roleDefinitionId: storageBlobDelegator
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource functionKeyVaultSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: keyVault
  name: guid(keyVault.id, functionApp.id, 'secrets-user')
  properties: {
    roleDefinitionId: keyVaultSecretsUser
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

var cosmosDataContributorRoleId = '00000000-0000-0000-0000-000000000002'

resource functionCosmosContributor 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2023-11-15' = {
  name: '${cosmosAccountName}/${guid(cosmosAccountName, functionApp.id, cosmosDataContributorRoleId)}'
  properties: {
    roleDefinitionId: '${resourceId('Microsoft.DocumentDB/databaseAccounts', cosmosAccountName)}/sqlRoleDefinitions/${cosmosDataContributorRoleId}'
    principalId: functionApp.identity.principalId
    scope: resourceId('Microsoft.DocumentDB/databaseAccounts', cosmosAccountName)
  }
  dependsOn: [
    cosmosDb
  ]
}

// --- Outputs -----------------------------------------------------------------

output storageAccountName string = evidenceStorage.name
output evidenceContainer string = evidenceContainerName
output toolsContainer string = toolsContainerName
output keyVaultUri string = keyVault.properties.vaultUri
output functionAppName string = functionApp.name
output functionAppHostName string = functionApp.properties.defaultHostName
output functionPrincipalId string = functionApp.identity.principalId
output sqlServerFqdn string = sqlServer.properties.fullyQualifiedDomainName
output sqlDatabaseName string = ledgerDatabase.name
output systemTopicName string = systemTopic.name
output enclaveResourceGroup string = resourceGroup().name
output enclaveSubscriptionId string = subscription().subscriptionId

// P2-5 Outputs
output storagePrivateEndpointId string = storagePrivateEndpoint.id
output storagePrivateEndpointName string = storagePrivateEndpoint.name
output blobPrivateDnsZoneId string = blobPrivateDnsZone.id
output memoryDumpsContainer string = memoryDumpsContainer.name
output diskSnapshotsContainer string = diskSnapshotsContainer.name
output analysisOutputContainer string = analysisOutputContainer.name
output reportsContainer string = reportsContainer.name
output cosmosDbEndpoint string = cosmosDb.outputs.endpoint
output cosmosDbDatabase string = cosmosDb.outputs.databaseName
output cosmosDbContainer string = cosmosDb.outputs.containerName

@description('Grant this identity Network Contributor + Reader + Disk Snapshot rights on the TARGET subscription, and a contained DB user on the ledger database. See iac/scripts/init-sql-ledger.sql.')
output postDeploymentPrincipal string = functionApp.identity.principalId

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

@description('Subscription containing the VMs under investigation.')
param targetSubscriptionId string = subscription().subscriptionId

@description('Resource group containing those VMs.')
param targetResourceGroup string = ''

@description('Deploy with the mock estate enabled. Never true for a real enclave.')
param enableMockMode bool = false

var suffix = uniqueString(resourceGroup().id)
var storageAccountName = toLower('${namePrefix}enc${substring(suffix, 0, 8)}')
var keyVaultName = '${namePrefix}-kv-${substring(suffix, 0, 8)}'
var functionAppName = '${namePrefix}-fn-${substring(suffix, 0, 8)}'
var hostingPlanName = '${namePrefix}-plan-${substring(suffix, 0, 8)}'
var sqlServerName = '${namePrefix}-sql-${substring(suffix, 0, 8)}'
var sqlDatabaseName = '${namePrefix}dfir'
var systemTopicName = '${namePrefix}-evidence-topic'
var appInsightsName = '${namePrefix}-ai-${substring(suffix, 0, 8)}'

// Built-in role definition IDs.
var storageBlobDataContributor = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
)
var storageBlobDelegator = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'db58b8e5-c6ad-4a2a-8342-4190687cbf4a'
)
var keyVaultSecretsUser = subscriptionResourceId(
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
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      // The compromised VM must be able to reach this account to stream its
      // memory image out, so the account cannot be fully private. Egress from
      // the target is already narrowed to the Storage service tag by the
      // isolation NSG that NetworkContainment builds.
      bypass: 'AzureServices'
      defaultAction: 'Allow'
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

resource retentionPolicy 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: evidenceContainer
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: retentionDays
    // Blobs must be hashable the instant they land, so reads during the
    // acquisition window cannot be blocked by the policy.
    allowProtectedAppendWrites: false
  }
}

// --- Legal hold (REQ-3.5.1) --------------------------------------------------

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
      { name: 'CONTAINER', value: evidenceContainerName }
      { name: 'TAGS', value: join(legalHoldTags, ' ') }
    ]
    scriptContent: '''
      set -euo pipefail
      # Idempotent: re-running a deployment must not fail on an existing hold.
      existing=$(az storage container legal-hold show \
        --account-name "$ACCOUNT" --resource-group "$GROUP" \
        --container-name "$CONTAINER" --query "tags" -o tsv || echo "")
      if [ -n "$existing" ]; then
        echo "Legal hold already present: $existing"
      else
        az storage container legal-hold set \
          --account-name "$ACCOUNT" --resource-group "$GROUP" \
          --container-name "$CONTAINER" --tags $TAGS
        echo "Legal hold applied: $TAGS"
      fi
    '''
  }
  dependsOn: [
    legalHoldRoleAssignment
    retentionPolicy
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
      { name: 'CONTAINER', value: evidenceContainerName }
    ]
    scriptContent: '''
      set -euo pipefail
      etag=$(az storage container immutability-policy show \
        --account-name "$ACCOUNT" --resource-group "$GROUP" \
        --container-name "$CONTAINER" --query etag -o tsv)
      state=$(az storage container immutability-policy show \
        --account-name "$ACCOUNT" --resource-group "$GROUP" \
        --container-name "$CONTAINER" --query state -o tsv)
      if [ "$state" = "Locked" ]; then
        echo "Immutability policy already locked."
      else
        az storage container immutability-policy lock \
          --account-name "$ACCOUNT" --resource-group "$GROUP" \
          --container-name "$CONTAINER" --if-match "$etag"
        echo "Immutability policy locked."
      fi
    '''
  }
  dependsOn: [
    applyLegalHold
  ]
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

        { name: 'FORENSIC_SUBSCRIPTION_ID', value: subscription().subscriptionId }
        { name: 'FORENSIC_RESOURCE_GROUP', value: resourceGroup().name }
        { name: 'FORENSIC_LOCATION', value: location }
        { name: 'AZURE_SUBSCRIPTION_ID', value: targetSubscriptionId }
        { name: 'TARGET_RESOURCE_GROUP', value: targetResourceGroup }
        { name: 'LOGIC_APP_PRINCIPAL_ID', value: logicAppPrincipalId }

        { name: 'HASH_CHUNK_BYTES', value: '8388608' }
        { name: 'EVIDENCE_STORAGE_SERVICE_TAG', value: 'Storage.${location}' }
        { name: 'ACQUISITION_TIMEOUT_SECONDS', value: '5400' }
      ]
    }
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

@description('Grant this identity Network Contributor + Reader + Disk Snapshot rights on the TARGET subscription, and a contained DB user on the ledger database. See iac/scripts/init-sql-ledger.sql.')
output postDeploymentPrincipal string = functionApp.identity.principalId

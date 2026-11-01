@description('Region for the Logic App.')
param location string = resourceGroup().location

@description('Name of the incident-response Logic App.')
param logicAppName string = 'aacfp-incident-response'

@description('Function endpoint used for isolation. Prefer a function key or Entra ID protected endpoint.')
@secure()
param containmentFunctionUrl string

@description('ARM trigger-run endpoint for the acquisition workflow owned by Person 2 (for example .../triggers/manual/run?api-version=2016-06-01).')
param acquisitionArmRequestUrl string

@description('Endpoint that returns evidence acquisition status. It must return { status: "Completed" } when ready and { status: "Failed" } on terminal failure.')
param acquisitionStatusUrl string

@description('Microsoft Entra token audience accepted by the acquisition status API.')
param acquisitionStatusAudience string

@description('Endpoint for Person 3 analysis pipeline.')
@secure()
param analysisPipelineUrl string

@description('Microsoft Entra token audience accepted by the analysis API.')
param analysisApiAudience string

@description('Blob URI format string. {0} is IncidentID and {1} is the target VM name.')
param evidenceBlobUriTemplate string

@description('Optional tags to apply to the Logic App.')
param tags object = {}

// The definition is kept independently to make the orchestration reviewable
// and testable outside the deployment template.
var workflowDefinition = loadJsonContent('../../src/logic-apps/workflow.json')

resource incidentResponseWorkflow 'Microsoft.Logic/workflows@2019-05-01' = {
  name: logicAppName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  tags: union(tags, {
    Application: 'AACFP'
    Component: 'IncidentResponseOrchestrator'
  })
  properties: {
    state: 'Enabled'
    definition: workflowDefinition
    parameters: {
      containmentFunctionUrl: { value: containmentFunctionUrl }
      acquisitionArmRequestUrl: { value: acquisitionArmRequestUrl }
      acquisitionStatusUrl: { value: acquisitionStatusUrl }
      acquisitionStatusAudience: { value: acquisitionStatusAudience }
      analysisPipelineUrl: { value: analysisPipelineUrl }
      analysisApiAudience: { value: analysisApiAudience }
      evidenceBlobUriTemplate: { value: evidenceBlobUriTemplate }
    }
  }
}

output logicAppId string = incidentResponseWorkflow.id
output principalId string = incidentResponseWorkflow.identity.principalId

@description('Region for the Logic App.')
param location string = resourceGroup().location

@description('Name of the incident-response Logic App.')
param logicAppName string = 'aacfp-incident-response'

@description('Function endpoint used for isolation. Prefer a function key or Entra ID protected endpoint.')
@secure()
param containmentFunctionUrl string

@description('ARM trigger-run endpoint for the acquisition workflow owned by Person 2 (for example .../triggers/manual/run?api-version=2016-06-01).')
param acquisitionArmRequestUrl string = '${environment().resourceManager}providers/Microsoft.Logic/workflows/dummy-acquisition/triggers/manual/run?api-version=2016-06-01'

@description('Endpoint that returns evidence acquisition status. It must return { status: "Completed" } when ready.')
param acquisitionStatusUrl string = '${environment().resourceManager}providers/Microsoft.Logic/workflows/dummy-acquisition/status'


@description('Endpoint for Person 3 analysis pipeline.')
param analysisPipelineUrl string = 'https://forensic-analysis.azurewebsites.net/api/ProcessEvidence'

@description('Blob URI format string. {0} is IncidentID and {1} is the target VM name.')
param evidenceBlobUriTemplate string = 'https://forensicevidence.blob.${environment().suffixes.storage}/evidence/{0}/{1}.raw'



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
      analysisPipelineUrl: { value: analysisPipelineUrl }
      evidenceBlobUriTemplate: { value: evidenceBlobUriTemplate }
    }
  }
}

output logicAppId string = incidentResponseWorkflow.id
output principalId string = incidentResponseWorkflow.identity.principalId

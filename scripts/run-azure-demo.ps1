[CmdletBinding(DefaultParameterSetName = "Run")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$FunctionAppName,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$FunctionAppResourceGroup,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$TargetVmId,

    [Parameter(ParameterSetName = "Run")]
    [string]$FunctionAppSubscriptionId,

    [Parameter(ParameterSetName = "Run")]
    [ValidateSet("Standard", "CriticalBypass")]
    [string]$Scenario = "Standard",

    [Parameter(ParameterSetName = "Run")]
    [string]$IncidentId,

    [Parameter(ParameterSetName = "Run")]
    [string]$IncidentIpAddress,

    [Parameter(ParameterSetName = "Run")]
    [ValidateSet("High", "Critical")]
    [string]$IncidentSeverity = "High",

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(1, 180)]
    [int]$StatusTimeoutMinutes = 30,

    [Parameter(ParameterSetName = "Run")]
    [switch]$CaptureDiskSnapshots,

    [Parameter(ParameterSetName = "Run")]
    [switch]$PreflightOnly,

    [Parameter(ParameterSetName = "Run")]
    [switch]$ConfirmLiveActions,

    [Parameter(Mandatory = $true, ParameterSetName = "Restore")]
    [string]$RestoreFrom,

    [Parameter(Mandatory = $true, ParameterSetName = "Restore")]
    [switch]$ConfirmRestore
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Stage {
    param([string]$Message)

    Write-Host ""
    Write-Host ">> $Message" -ForegroundColor Cyan
}

function Invoke-AzCli {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $output = & az @Arguments --only-show-errors 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $details = ($output | Out-String).Trim()
        if ($details) {
            throw "Azure CLI command failed (exit $exitCode): $details"
        }
        throw "Azure CLI command failed (exit $exitCode)."
    }

    return ($output | Out-String).Trim()
}

function Invoke-AzJson {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $text = Invoke-AzCli -Arguments $Arguments
    if (-not $text) {
        return $null
    }

    try {
        return $text | ConvertFrom-Json
    }
    catch {
        throw "Azure CLI returned invalid JSON for a read-only query."
    }
}

function Get-TagValue {
    param(
        [object]$Tags,
        [string]$Name
    )

    if ($null -eq $Tags) {
        return $null
    }

    $property = $Tags.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
    if ($property) {
        return [string]$property.Value
    }

    return $null
}

function Invoke-FunctionApi {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet("GET", "POST")][string]$Method,
        [Parameter(Mandatory = $true)][string]$FunctionHostName,
        [Parameter(Mandatory = $true)][string]$FunctionKey,
        [object]$Body,
        [int]$TimeoutSeconds = 60
    )

    $encodedKey = [uri]::EscapeDataString($FunctionKey)
    $uri = "https://$FunctionHostName/api/$Path?code=$encodedKey"
    $requestParameters = @{
        Uri         = $uri
        Method      = $Method
        TimeoutSec  = $TimeoutSeconds
        ErrorAction = "Stop"
    }

    if ($null -ne $Body) {
        $requestParameters.ContentType = "application/json"
        $requestParameters.Body = $Body | ConvertTo-Json -Depth 20 -Compress
    }

    try {
        return Invoke-RestMethod @requestParameters
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($statusCode) {
            throw "Function request to /api/$Path failed with HTTP $statusCode. Check Function App logs; response details are omitted."
        }
        throw "Function request to /api/$Path failed. Check Function App availability and logs; response details are omitted."
    }
}

function Save-RunSummary {
    param(
        [Parameter(Mandatory = $true)][object]$Summary,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $Summary | ConvertTo-Json -Depth 20 | Set-Content -Path $Path -Encoding UTF8
}

function Restore-NetworkState {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Run summary not found: $Path"
    }

    try {
        $summary = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw "Could not read the run summary as JSON."
    }

    if (-not $summary.incidentId -or -not $summary.isolationNsgId -or -not $summary.nics) {
        throw "Run summary does not contain the network recovery information."
    }

    $restoreItems = @($summary.nics | Where-Object { $_.changed -eq $true })
    if ($restoreItems.Count -eq 0) {
        Write-Host "No NIC changes are recorded for incident $($summary.incidentId)." -ForegroundColor Yellow
        return
    }

    Write-Stage "Verifying containment state before restoration"
    foreach ($item in $restoreItems) {
        $current = Invoke-AzJson -Arguments @(
            "network", "nic", "show",
            "--ids", $item.id,
            "--query", "{id:id,nsgId:networkSecurityGroup.id}",
            "--output", "json"
        )
        if ([string]$current.nsgId -ine [string]$summary.isolationNsgId) {
            throw "NIC '$($item.id)' no longer has the incident isolation NSG. No NICs were restored to avoid overwriting a later network change."
        }
    }

    $expectedConfirmation = "RESTORE $($summary.incidentId)"
    Write-Host "This will restore the saved NSG association on $($restoreItems.Count) NIC(s)." -ForegroundColor Yellow
    $confirmation = Read-Host "Type '$expectedConfirmation' to continue"
    if ($confirmation -cne $expectedConfirmation) {
        throw "Restoration was not confirmed. No NICs were changed."
    }

    foreach ($item in $restoreItems) {
        Write-Host "Restoring NIC $($item.id) ..."
        if ($item.previousNsgId) {
            Invoke-AzCli -Arguments @(
                "network", "nic", "update",
                "--ids", $item.id,
                "--network-security-group", $item.previousNsgId,
                "--output", "none"
            ) | Out-Null
        }
        else {
            Invoke-AzCli -Arguments @(
                "network", "nic", "update",
                "--ids", $item.id,
                "--remove", "networkSecurityGroup",
                "--output", "none"
            ) | Out-Null
        }

        $verified = Invoke-AzJson -Arguments @(
            "network", "nic", "show",
            "--ids", $item.id,
            "--query", "{id:id,nsgId:networkSecurityGroup.id}",
            "--output", "json"
        )
        if ([string]$verified.nsgId -ine [string]$item.previousNsgId) {
            throw "Restoration verification failed for NIC '$($item.id)'. Review its NSG association manually."
        }
    }

    $summary.networkRestoredUtc = [DateTime]::UtcNow.ToString("o")
    Save-RunSummary -Summary $summary -Path $Path
    Write-Host "Original NSG associations restored and verified. The incident NSG was left in place for review." -ForegroundColor Green
}

if ($PSCmdlet.ParameterSetName -eq "Restore") {
    Restore-NetworkState -Path $RestoreFrom
    return
}

$functionKey = $null
$summary = $null
$summaryPath = $null

try {
    $incidentPattern = "^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$"
    if (-not $IncidentId) {
        $IncidentId = "INC-DEMO-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))"
    }
    if ($IncidentId -notmatch $incidentPattern) {
        throw "IncidentId must be 1-63 letters, digits, underscores, or hyphens and begin with a letter or digit."
    }

    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "Azure CLI ('az') is required. Install it and sign in with 'az login' before running this script."
    }

    Write-Stage "Checking Azure CLI sign-in and active subscription"
    $account = Invoke-AzJson -Arguments @(
        "account", "show",
        "--query", "{id:id,tenantId:tenantId,user:user.name}",
        "--output", "json"
    )
    if (-not $FunctionAppSubscriptionId) {
        $FunctionAppSubscriptionId = [string]$account.id
    }
    if (-not $FunctionAppSubscriptionId) {
        throw "Could not determine the Function App subscription. Sign in with 'az login' and select a subscription."
    }

    $targetPattern = "^/subscriptions/(?<subscription>[^/]+)/resourceGroups/(?<resourceGroup>[^/]+)/providers/Microsoft\.Compute/virtualMachines/(?<name>[^/]+)/?$"
    if ($TargetVmId -notmatch $targetPattern) {
        throw "TargetVmId must be a full Azure VM resource ID."
    }
    $targetSubscriptionId = $Matches.subscription
    $targetResourceGroup = $Matches.resourceGroup
    $targetVmName = $Matches.name
    $TargetVmId = $TargetVmId.TrimEnd("/")

    Write-Stage "Verifying the existing Function App and its live-mode scope"
    $functionApp = Invoke-AzJson -Arguments @(
        "functionapp", "show",
        "--name", $FunctionAppName,
        "--resource-group", $FunctionAppResourceGroup,
        "--subscription", $FunctionAppSubscriptionId,
        "--query", "{host:defaultHostName,state:state,httpsOnly:httpsOnly}",
        "--output", "json"
    )
    if (-not $functionApp.host -or $functionApp.state -ne "Running" -or $functionApp.httpsOnly -ne $true) {
        throw "Function App must be running and HTTPS-only."
    }

    $settings = Invoke-AzJson -Arguments @(
        "functionapp", "config", "appsettings", "list",
        "--name", $FunctionAppName,
        "--resource-group", $FunctionAppResourceGroup,
        "--subscription", $FunctionAppSubscriptionId,
        "--query", "[?name=='REACT_MOCK_MODE' || name=='AZURE_SUBSCRIPTION_ID' || name=='TARGET_RESOURCE_GROUP' || name=='FORENSIC_SUBSCRIPTION_ID' || name=='FORENSIC_RESOURCE_GROUP'].{name:name,value:value}",
        "--output", "json"
    )
    $settingMap = @{}
    foreach ($setting in @($settings)) {
        if ($setting.name) {
            $settingMap[[string]$setting.name] = [string]$setting.value
        }
    }
    if ($settingMap["REACT_MOCK_MODE"] -ine "false") {
        throw "The Function App must have REACT_MOCK_MODE=false. No target action was attempted."
    }
    if ($settingMap["AZURE_SUBSCRIPTION_ID"] -ine $targetSubscriptionId -or
        $settingMap["TARGET_RESOURCE_GROUP"] -ine $targetResourceGroup) {
        throw "Target VM subscription/resource group does not match the Function App's configured target boundary."
    }
    if (-not $settingMap["FORENSIC_SUBSCRIPTION_ID"] -or -not $settingMap["FORENSIC_RESOURCE_GROUP"]) {
        throw "Function App is missing its forensic subscription or resource-group configuration."
    }

    Write-Stage "Verifying Event Grid is wired to the custody Function"
    $systemTopics = Invoke-AzJson -Arguments @(
        "eventgrid", "system-topic", "list",
        "--resource-group", $settingMap["FORENSIC_RESOURCE_GROUP"],
        "--subscription", $settingMap["FORENSIC_SUBSCRIPTION_ID"],
        "--query", "[].name",
        "--output", "json"
    )
    $custodySubscriptionReady = $false
    foreach ($systemTopicName in @($systemTopics)) {
        if (-not $systemTopicName) {
            continue
        }

        $eventSubscriptions = Invoke-AzJson -Arguments @(
            "eventgrid", "system-topic", "event-subscription", "list",
            "--resource-group", $settingMap["FORENSIC_RESOURCE_GROUP"],
            "--system-topic-name", [string]$systemTopicName,
            "--subscription", $settingMap["FORENSIC_SUBSCRIPTION_ID"],
            "--query", "[].{endpoint:destination.properties.endpointUrl,state:provisioningState}",
            "--output", "json"
        )
        foreach ($eventSubscription in @($eventSubscriptions)) {
            $endpoint = [string]$eventSubscription.endpoint
            if ($eventSubscription.state -eq "Succeeded" -and
                $endpoint -match "^https://$([regex]::Escape([string]$functionApp.host))/api/(custody|ChainOfCustody)(\?|$)") {
                $custodySubscriptionReady = $true
                break
            }
        }
        if ($custodySubscriptionReady) {
            break
        }
    }
    if (-not $custodySubscriptionReady) {
        throw "No succeeded Event Grid subscription targeting this Function App's custody endpoint was found. Enable and verify custody delivery before running live acquisition."
    }

    Write-Stage "Verifying the target is disposable, running, and in the requested scenario"
    $vm = Invoke-AzJson -Arguments @(
        "vm", "show",
        "--ids", $TargetVmId,
        "--query", "{id:id,name:name,location:location,tags:tags,nics:networkProfile.networkInterfaces[].{id:id,primary:primary}}",
        "--output", "json"
    )
    if ($vm.id -ine $TargetVmId -or -not $vm.nics) {
        throw "Target VM could not be verified or has no attached NICs."
    }

    $demoTag = Get-TagValue -Tags $vm.tags -Name "REACT-Demo"
    if ($demoTag -ine "true") {
        throw "Target VM must already have the tag REACT-Demo=true. This script never tags or provisions a target."
    }
    $criticalTag = Get-TagValue -Tags $vm.tags -Name "Critical-Infrastructure"
    $isCriticalInfrastructure = $criticalTag -ieq "true"
    if ($Scenario -eq "Standard" -and $isCriticalInfrastructure) {
        throw "Standard scenario refuses a Critical-Infrastructure VM. Use a disposable, non-critical target."
    }
    if ($Scenario -eq "CriticalBypass" -and -not $isCriticalInfrastructure) {
        throw "CriticalBypass scenario requires the Critical-Infrastructure=true tag on a disposable test VM."
    }

    $powerState = Invoke-AzCli -Arguments @(
        "vm", "get-instance-view",
        "--ids", $TargetVmId,
        "--query", "instanceView.statuses[?starts_with(code, 'PowerState/')].displayStatus | [0]",
        "--output", "tsv"
    )
    if ($powerState -notmatch "running") {
        throw "Target VM must be running for a live memory acquisition. Reported state: '$powerState'."
    }

    $nicIds = @($vm.nics | ForEach-Object { [string]$_.id })
    $primaryNic = $vm.nics | Where-Object { $_.primary -eq $true } | Select-Object -First 1
    if (-not $primaryNic) {
        $primaryNic = $vm.nics | Select-Object -First 1
    }
    $primaryNicDetails = Invoke-AzJson -Arguments @(
        "network", "nic", "show",
        "--ids", $primaryNic.id,
        "--query", "{privateIp:ipConfigurations[0].privateIPAddress}",
        "--output", "json"
    )
    if (-not $IncidentIpAddress) {
        $IncidentIpAddress = [string]$primaryNicDetails.privateIp
    }
    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse($IncidentIpAddress, [ref]$parsedIp)) {
        throw "Could not determine a valid target IP address. Supply -IncidentIpAddress explicitly."
    }

    $originalNics = @()
    foreach ($nicId in $nicIds) {
        $nic = Invoke-AzJson -Arguments @(
            "network", "nic", "show",
            "--ids", $nicId,
            "--query", "{id:id,nsgId:networkSecurityGroup.id}",
            "--output", "json"
        )
        $originalNics += [pscustomobject]@{
            id             = [string]$nic.id
            previousNsgId  = $nic.nsgId
            changed        = $false
        }
    }

    Write-Host "Azure subscription: $($account.id)"
    Write-Host "Function App:       $FunctionAppName ($($functionApp.host))"
    Write-Host "Target VM:          $targetVmName"
    Write-Host "Target resource ID: $TargetVmId"
    Write-Host "Target IP:          $IncidentIpAddress"
    Write-Host "Scenario:           $Scenario"
    Write-Host "Target state:       $powerState"
    Write-Host "Forensic destination: $($settingMap['FORENSIC_RESOURCE_GROUP']) in $($settingMap['FORENSIC_SUBSCRIPTION_ID'])"

    Write-Stage "Checking Function App health and retrieving a host function key"
    $functionKeyText = Invoke-AzCli -Arguments @(
        "functionapp", "keys", "list",
        "--name", $FunctionAppName,
        "--resource-group", $FunctionAppResourceGroup,
        "--subscription", $FunctionAppSubscriptionId,
        "--query", "functionKeys.default",
        "--output", "tsv"
    )
    $functionKey = $functionKeyText.Trim()
    if (-not $functionKey -or $functionKey -eq "None") {
        throw "Could not retrieve the Function App default function key. Check signed-in permissions; no key was displayed."
    }

    $health = Invoke-FunctionApi `
        -Path "health" `
        -Method "GET" `
        -FunctionHostName $functionApp.host `
        -FunctionKey $functionKey
    if ($health.status -ne "healthy" -or $health.mockMode -ne $false) {
        throw "Function App health check did not confirm healthy live mode. No target action was attempted."
    }
    Write-Host "Function App health: healthy; mock mode disabled." -ForegroundColor Green

    if ($PreflightOnly) {
        Write-Host "Preflight passed. No containment, acquisition, snapshots, or other target changes were made." -ForegroundColor Green
        return
    }
    if (-not $ConfirmLiveActions) {
        throw "Live actions require -ConfirmLiveActions. Preflight did not change Azure resources."
    }

    $confirmationPhrase = "RUN $IncidentId"
    Write-Host ""
    Write-Host "LIVE ACTION WARNING" -ForegroundColor Yellow
    if ($Scenario -eq "Standard") {
        Write-Host "This will replace the NSG association on all target VM NICs, then run memory acquisition."
    }
    else {
        Write-Host "Containment must be bypassed by policy. This will run memory acquisition on the tagged disposable VM."
    }
    Write-Host "Memory artifacts are real data and will be written to the configured forensic storage."
    $confirmation = Read-Host "Type '$confirmationPhrase' to continue"
    if ($confirmation -cne $confirmationPhrase) {
        throw "Live actions were not confirmed. No target action was attempted."
    }

    $summaryPath = Join-Path $env:TEMP "react-demo-$IncidentId.json"
    $summary = [ordered]@{
        schemaVersion       = 1
        incidentId          = $IncidentId
        scenario            = $Scenario
        targetVmId          = $TargetVmId
        functionAppName     = $FunctionAppName
        startedUtc          = [DateTime]::UtcNow.ToString("o")
        status              = "started"
        containmentStatus   = $null
        isolationNsgName    = $null
        isolationNsgId      = $null
        nics                = $originalNics
        memoryAcquisition   = $null
        custody             = $null
        diskSnapshots       = $null
        networkRestoredUtc  = $null
        secretsPersisted    = $false
    }
    Save-RunSummary -Summary $summary -Path $summaryPath

    $payload = @{
        IncidentID       = $IncidentId
        TargetVM         = $TargetVmId
        IPAddress        = $IncidentIpAddress
        SubscriptionID   = $targetSubscriptionId
        IncidentSeverity = $IncidentSeverity
        ResourceGroupName = $targetResourceGroup
    }

    if ($Scenario -eq "Standard") {
        Write-Stage "Calling the live NetworkContainment Function"
        $containment = Invoke-FunctionApi `
            -Path "NetworkContainment" `
            -Method "POST" `
            -FunctionHostName $functionApp.host `
            -FunctionKey $functionKey `
            -Body $payload `
            -TimeoutSeconds 300

        if ($containment.status -ine "Contained") {
            throw "Containment did not return the expected Contained result. No acquisition was started."
        }

        $summary.containmentStatus = [string]$containment.status
        $summary.isolationNsgName = [string]$containment.IsolationNSG
        if (-not $summary.isolationNsgName) {
            throw "Containment succeeded but did not return an isolation NSG name. Keep the saved run summary and review the NIC state manually."
        }

        $summary.isolationNsgId = "/subscriptions/$targetSubscriptionId/resourceGroups/$targetResourceGroup/providers/Microsoft.Network/networkSecurityGroups/$($summary.isolationNsgName)"
        foreach ($change in @($containment.NICContainment)) {
            $nicName = [string]$change.nic
            $savedNic = $summary.nics | Where-Object {
                $_.id.TrimEnd("/").Split("/")[-1] -ieq $nicName
            } | Select-Object -First 1
            if (-not $savedNic) {
                throw "Containment changed NIC '$nicName', but it was not present in the preflight inventory. Do not restore automatically; inspect the NIC and run summary."
            }
            $savedNic.previousNsgId = $change.previousNsgId
            $savedNic.changed = [bool]$change.changed
        }
        Save-RunSummary -Summary $summary -Path $summaryPath

        $nsg = Invoke-AzJson -Arguments @(
            "network", "nsg", "show",
            "--resource-group", $targetResourceGroup,
            "--name", $summary.isolationNsgName,
            "--subscription", $targetSubscriptionId,
            "--query", "{id:id}",
            "--output", "json"
        )
        if ($nsg.id -ine $summary.isolationNsgId) {
            throw "Could not verify the incident isolation NSG resource ID. The recovery summary was saved; inspect the NICs before restoring."
        }
        Write-Host "Containment:       $($summary.containmentStatus)"
        Write-Host "Isolation NSG:     $($summary.isolationNsgName)"
        Write-Host "Recovery summary:  $summaryPath"
    }
    else {
        Write-Stage "Verifying the critical-infrastructure containment bypass"
        $containment = Invoke-FunctionApi `
            -Path "NetworkContainment" `
            -Method "POST" `
            -FunctionHostName $functionApp.host `
            -FunctionKey $functionKey `
            -Body $payload `
            -TimeoutSeconds 300
        if ($containment.status -ine "Bypassed") {
            throw "CriticalBypass scenario did not return the expected Bypassed result. No acquisition was started."
        }
        $summary.containmentStatus = [string]$containment.status
        Save-RunSummary -Summary $summary -Path $summaryPath
        Write-Host "Containment: BYPASSED by the Critical-Infrastructure policy." -ForegroundColor Yellow
    }

    $acquisitionConfirmation = "ACQUIRE $IncidentId"
    Write-Host ""
    Write-Host "Memory acquisition runs against the live VM and stores the resulting evidence in Azure." -ForegroundColor Yellow
    $confirmation = Read-Host "Type '$acquisitionConfirmation' to dispatch acquisition"
    if ($confirmation -cne $acquisitionConfirmation) {
        throw "Memory acquisition was not confirmed. The existing containment state has not been changed."
    }

    Write-Stage "Calling the live MemoryAcquisition Function"
    $acquisition = Invoke-FunctionApi `
        -Path "MemoryAcquisition" `
        -Method "POST" `
        -FunctionHostName $functionApp.host `
        -FunctionKey $functionKey `
        -Body $payload `
        -TimeoutSeconds 5400
    if ($acquisition.status -ine "acquired") {
        throw "MemoryAcquisition did not report acquired status. Review Function and Run Command logs."
    }

    $summary.memoryAcquisition = [ordered]@{
        status          = [string]$acquisition.status
        jobId           = [string]$acquisition.jobId
        incidentId      = [string]$acquisition.incidentId
        targetVm        = [string]$acquisition.targetVm
        platform        = [string]$acquisition.platform
        blobName        = [string]$acquisition.blobName
        runCommandName  = [string]$acquisition.runCommandName
        custody         = [string]$acquisition.custody
    }
    Save-RunSummary -Summary $summary -Path $summaryPath
    Write-Host "Acquisition:      $($acquisition.status)"
    Write-Host "Platform/tool:    $($acquisition.platform)"
    Write-Host "Evidence blob:    $($acquisition.blobName)"
    Write-Host "Custody status:   awaiting Event Grid verification"

    Write-Stage "Waiting for chain-of-custody verification"
    $deadline = [DateTime]::UtcNow.AddMinutes($StatusTimeoutMinutes)
    $custody = $null
    do {
        Start-Sleep -Seconds 15
        $encodedIncidentId = [uri]::EscapeDataString($IncidentId)
        $encodedKey = [uri]::EscapeDataString($functionKey)
        $statusUrl = "https://$($functionApp.host)/api/status?incidentId=$encodedIncidentId&code=$encodedKey"
        try {
            $custody = Invoke-RestMethod -Uri $statusUrl -Method GET -TimeoutSec 30 -ErrorAction Stop
        }
        catch {
            throw "Custody status request failed. Check Event Grid, Function App, and SQL Ledger logs; response details are omitted."
        }

        Write-Host "  $([DateTime]::UtcNow.ToString('u'))  $($custody.status)"
        if ($custody.status -ieq "Completed") {
            break
        }
        if ($custody.status -ieq "Failed") {
            throw "Custody verification reported failure. Disk snapshots were not requested."
        }
    } while ([DateTime]::UtcNow -lt $deadline)

    if (-not $custody -or $custody.status -ine "Completed") {
        throw "Custody was not verified within $StatusTimeoutMinutes minute(s). Disk snapshots were not requested."
    }

    $summary.custody = [ordered]@{
        status      = [string]$custody.status
        sha256      = [string]$custody.sha256
        sizeBytes   = $custody.sizeBytes
        recordedUtc = [string]$custody.recordedUtc
    }
    Save-RunSummary -Summary $summary -Path $summaryPath
    Write-Host "Custody:          verified"
    Write-Host "SHA-256:          $($custody.sha256)"
    Write-Host "Bytes:            $($custody.sizeBytes)"

    if ($CaptureDiskSnapshots) {
        $snapshotConfirmation = "SNAPSHOT $IncidentId"
        Write-Host ""
        Write-Host "Disk snapshots create additional billable Azure resources and evidence copies." -ForegroundColor Yellow
        $confirmation = Read-Host "Type '$snapshotConfirmation' to create disk snapshots"
        if ($confirmation -cne $snapshotConfirmation) {
            throw "Disk snapshot creation was not confirmed."
        }

        Write-Stage "Calling DiskSnapshotAcquisition after custody verification"
        $snapshot = Invoke-FunctionApi `
            -Path "DiskSnapshotAcquisition" `
            -Method "POST" `
            -FunctionHostName $functionApp.host `
            -FunctionKey $functionKey `
            -Body $payload `
            -TimeoutSeconds 1800
        if ($snapshot.status -ine "snapshotted" -or $snapshot.memoryGate -ine "satisfied") {
            throw "DiskSnapshotAcquisition did not confirm a snapshot with the memory gate satisfied."
        }

        $summary.diskSnapshots = [ordered]@{
            status             = [string]$snapshot.status
            snapshotCount      = $snapshot.snapshotCount
            snapshotResourceIds = @($snapshot.snapshotResourceIds)
            manifestBlob       = [string]$snapshot.manifestBlob
            manifestSha256     = [string]$snapshot.manifestSha256
            memoryGate         = [string]$snapshot.memoryGate
        }
        Write-Host "Snapshots:        $($snapshot.snapshotCount)"
        Write-Host "Memory gate:      $($snapshot.memoryGate)"
    }
    else {
        Write-Host "Disk snapshots:   not requested (use -CaptureDiskSnapshots to opt in)." -ForegroundColor Yellow
    }

    $summary.status = "completed"
    $summary.finishedUtc = [DateTime]::UtcNow.ToString("o")
    Save-RunSummary -Summary $summary -Path $summaryPath

    Write-Stage "Reviewer summary"
    Write-Host "Mode:             LIVE Azure resources; disposable test target only"
    Write-Host "Incident:         $IncidentId"
    Write-Host "Containment:      $($summary.containmentStatus)"
    Write-Host "Memory custody:   $($summary.custody.status)"
    if ($summary.diskSnapshots) {
        Write-Host "Disk snapshots:   $($summary.diskSnapshots.snapshotCount)"
    }
    Write-Host "Run summary:      $summaryPath"
    if ($Scenario -eq "Standard" -and @($summary.nics | Where-Object { $_.changed }).Count -gt 0) {
        Write-Host ""
        Write-Host "The VM remains contained. Restore saved NIC associations after reviewer inspection with:" -ForegroundColor Yellow
        Write-Host ".\scripts\run-azure-demo.ps1 -RestoreFrom `"$summaryPath`" -ConfirmRestore"
    }
    Write-Host "Evidence and snapshots are retained in Azure; this script does not delete them." -ForegroundColor Yellow
}
catch {
    if ($summary -and $summaryPath) {
        $summary.status = "incomplete"
        $summary.finishedUtc = [DateTime]::UtcNow.ToString("o")
        Save-RunSummary -Summary $summary -Path $summaryPath
        Write-Host "Recovery summary saved at: $summaryPath" -ForegroundColor Yellow
    }
    throw
}
finally {
    $functionKey = $null
    $functionKeyText = $null
}

<#
.SYNOPSIS
    Streams Windows physical memory straight into the forensic enclave without
    ever writing an image file to the target's disk (SOP 2, Phase 2).

.DESCRIPTION
    WinPmem writes the raw image to stdout. This script reads that stream in
    fixed-size blocks and uploads each one with the Azure Blob "Put Block" REST
    operation, then commits them with "Put Block List".

    Put Block is what makes the no-disk-write requirement achievable. The plain
    "Put Blob" call needs a Content-Length for the entire body, which cannot be
    known for a live stream, and Azure Blob Storage does not accept chunked
    transfer-encoding. Piping WinPmem into AzCopy is not an option either --
    AzCopy cannot read from stdin. Slicing the stream into individually sized
    blocks sidesteps both constraints, and only one block is ever resident.

    A SHA-256 is folded over the stream as it passes through. That "witness
    hash" is stamped into the blob metadata, and the ChainOfCustody function
    compares it against the hash it computes server-side. A mismatch means the
    bytes changed between the target and the enclave.

    Writing the image to disk would overwrite unallocated space that may itself
    be evidence, and on a compromised host it hands the attacker a copy of the
    very artifact being collected.

.PARAMETER SasUrl
    Write-only blob SAS URL from the NetworkContainment function's `uploadUrl`
    response field. Valid for 60 minutes by default.

.PARAMETER IncidentId
    Incident identifier, stamped into the blob metadata for the ledger.

.PARAMETER WinPmemPath
    Path to a WinPmem build that supports writing to stdout.

.PARAMETER WinPmemArgs
    Arguments passed to WinPmem. Must direct output to stdout.

.PARAMETER BlockSizeMB
    Size of each Put Block call. 64 MB gives a 3.2 TB ceiling against Azure's
    50,000-block limit.

.EXAMPLE
    .\Acquire-Memory.ps1 -SasUrl $url -IncidentId "INC-2024-0042"

.NOTES
    Requires an elevated session: WinPmem loads a kernel driver.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SasUrl,
    [Parameter(Mandatory = $true)][string]$IncidentId,
    [string]$WinPmemPath = "$PSScriptRoot\tools\winpmem.exe",
    [string]$WinPmemArgs = '-',
    [ValidateRange(4, 256)][int]$BlockSizeMB = 64,
    [string]$InitiatorObjectId = '',
    [string]$StorageApiVersion = '2021-08-06'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Net.Http

$AZURE_MAX_BLOCKS = 50000

function Write-Step {
    param([string]$Message)
    Write-Host ("[{0:u}] {1}" -f (Get-Date).ToUniversalTime(), $Message)
}

function New-BlockId {
    param([int]$Index)
    # Every block ID must decode to the same byte length, hence the D8 pad.
    [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($Index.ToString('D8')))
}

function Invoke-PutBlock {
    param(
        [System.Net.Http.HttpClient]$Client,
        [string]$Url,
        [string]$BlockId,
        [byte[]]$Buffer,
        [int]$Count
    )
    $uri = '{0}&comp=block&blockid={1}' -f $Url, [uri]::EscapeDataString($BlockId)
    $content = New-Object System.Net.Http.ByteArrayContent($Buffer, 0, $Count)
    $content.Headers.Add('x-ms-version', $StorageApiVersion)
    try {
        $response = $Client.PutAsync($uri, $content).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {
            $detail = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            throw ("Put Block {0} failed: {1} {2} -- {3}" -f `
                    $BlockId, [int]$response.StatusCode, $response.ReasonPhrase, $detail)
        }
    }
    finally {
        $content.Dispose()
    }
}

function Invoke-PutBlockList {
    param(
        [System.Net.Http.HttpClient]$Client,
        [string]$Url,
        [System.Collections.Generic.List[string]]$BlockIds,
        [hashtable]$Metadata
    )
    $xml = New-Object System.Text.StringBuilder
    [void]$xml.Append('<?xml version="1.0" encoding="utf-8"?><BlockList>')
    foreach ($id in $BlockIds) {
        [void]$xml.Append('<Latest>').Append($id).Append('</Latest>')
    }
    [void]$xml.Append('</BlockList>')

    $uri = '{0}&comp=blocklist' -f $Url
    $content = New-Object System.Net.Http.StringContent(
        $xml.ToString(), [Text.Encoding]::UTF8, 'application/xml')
    $content.Headers.Add('x-ms-version', $StorageApiVersion)
    $content.Headers.Add('x-ms-blob-content-type', 'application/octet-stream')
    foreach ($key in $Metadata.Keys) {
        if ($Metadata[$key]) {
            $content.Headers.Add(('x-ms-meta-{0}' -f $key), [string]$Metadata[$key])
        }
    }
    try {
        $response = $Client.PutAsync($uri, $content).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {
            $detail = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            throw ("Put Block List failed: {0} {1} -- {2}" -f `
                    [int]$response.StatusCode, $response.ReasonPhrase, $detail)
        }
    }
    finally {
        $content.Dispose()
    }
}

# --- Preconditions -----------------------------------------------------------

if ($SasUrl -notmatch '\?') {
    throw 'SasUrl does not carry a query string; it is not a SAS URL.'
}
if ($WinPmemArgs -notmatch '(^|\s)-(\s|$)' -and $WinPmemArgs -notlike '*stdout*') {
    throw ("WinPmemArgs must direct output to stdout (pass '-'). Got '{0}'. " +
        "Writing a .raw file to the target disk is forbidden by SOP 2." -f $WinPmemArgs)
}
if (-not (Test-Path -LiteralPath $WinPmemPath)) {
    throw ("WinPmem not found at '{0}'." -f $WinPmemPath)
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator rights are required: WinPmem loads a kernel driver.'
}

# --- Acquisition -------------------------------------------------------------

$acquiredUtc = (Get-Date).ToUniversalTime().ToString('o')
Write-Step ("Starting memory acquisition for incident {0} on {1}." -f $IncidentId, $env:COMPUTERNAME)
Write-Step ("Block size {0} MB; no image file will touch local disk." -f $BlockSizeMB)

$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName = $WinPmemPath
$startInfo.Arguments = $WinPmemArgs
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true

$process = $null
$client = New-Object System.Net.Http.HttpClient
$client.Timeout = [TimeSpan]::FromMinutes(10)
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$blockIds = New-Object System.Collections.Generic.List[string]
$buffer = New-Object byte[] ($BlockSizeMB * 1MB)
$index = 0
$totalBytes = [long]0

try {
    $process = [System.Diagnostics.Process]::Start($startInfo)
    $stream = $process.StandardOutput.BaseStream

    while ($true) {
        # A pipe returns short reads; fill the buffer before uploading so every
        # block except the last is exactly BlockSizeMB.
        $filled = 0
        while ($filled -lt $buffer.Length) {
            $read = $stream.Read($buffer, $filled, $buffer.Length - $filled)
            if ($read -le 0) { break }
            $filled += $read
        }
        if ($filled -eq 0) { break }

        [void]$sha256.TransformBlock($buffer, 0, $filled, $null, 0)

        $blockId = New-BlockId -Index $index
        Invoke-PutBlock -Client $client -Url $SasUrl -BlockId $blockId `
            -Buffer $buffer -Count $filled
        $blockIds.Add($blockId)

        $index++
        $totalBytes += $filled
        if ($index -ge $AZURE_MAX_BLOCKS) {
            throw ("Reached Azure's {0}-block limit. Re-run with a larger " +
                "-BlockSizeMB." -f $AZURE_MAX_BLOCKS)
        }
        if ($index % 10 -eq 0) {
            Write-Step ("Uploaded {0} blocks ({1:N2} GB)." -f $index, ($totalBytes / 1GB))
        }
    }

    [void]$sha256.TransformFinalBlock((New-Object byte[] 0), 0, 0)
    $witnessHash = ($sha256.Hash | ForEach-Object { $_.ToString('x2') }) -join ''

    if ($blockIds.Count -eq 0) {
        $stderr = $process.StandardError.ReadToEnd()
        throw ("WinPmem produced no output. stderr: {0}" -f $stderr)
    }

    Write-Step ("Committing {0} blocks ({1:N2} GB)." -f $blockIds.Count, ($totalBytes / 1GB))
    Invoke-PutBlockList -Client $client -Url $SasUrl -BlockIds $blockIds -Metadata @{
        'incidentid'        = $IncidentId
        'sourcehost'        = $env:COMPUTERNAME
        'acquiredutc'       = $acquiredUtc
        'witnesssha256'     = $witnessHash
        'acquisitiontool'   = 'winpmem'
        'initiatorobjectid' = $InitiatorObjectId
    }

    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        # The upload already succeeded, so surface this as a warning rather than
        # discarding a possibly complete image.
        Write-Warning ("WinPmem exited with code {0}: {1}" -f `
                $process.ExitCode, $process.StandardError.ReadToEnd())
    }

    Write-Step ("Acquisition complete. Witness SHA-256: {0}" -f $witnessHash)
    [pscustomobject]@{
        IncidentId    = $IncidentId
        SourceHost    = $env:COMPUTERNAME
        AcquiredUtc   = $acquiredUtc
        SizeBytes     = $totalBytes
        Blocks        = $blockIds.Count
        WitnessSha256 = $witnessHash
    }
}
finally {
    if ($null -ne $process -and -not $process.HasExited) { $process.Kill() }
    if ($null -ne $process) { $process.Dispose() }
    $sha256.Dispose()
    $client.Dispose()
    # Zero the buffer so the last block of physical memory does not linger in
    # this process's working set.
    if ($null -ne $buffer) { [Array]::Clear($buffer, 0, $buffer.Length) }
}

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AgentPath
)

$ErrorActionPreference = "Stop"
$serviceName = "BlacklistInevitableAgent"
$probeRoot = Join-Path $env:ProgramFiles "BlacklistInevitableWfpProbe"
$probeExe = Join-Path $probeRoot "blacklist-inevitable-wfp-acl-probe.exe"
$stateRoot = Join-Path $env:ProgramData "blacklist-inevitable"
$reportDirectory = Join-Path $stateRoot "Agent"
$reportPath = Join-Path $reportDirectory "wfp-acl-probe.json"
$artifactPath = Join-Path $env:RUNNER_TEMP "wfp-service-sid-probe.json"
$serviceCreated = $false

function Invoke-Icacls {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $output = & (Join-Path $env:WINDIR "System32\icacls.exe") @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed: $($output -join ' ')"
    }
}

try {
    if (-not (Test-Path -LiteralPath $AgentPath -PathType Leaf)) {
        throw "The dedicated WFP ACL probe executable is missing: $AgentPath"
    }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw "A service named $serviceName already exists on the disposable CI runner."
    }

    New-Item -ItemType Directory -Path $probeRoot -Force | Out-Null
    Copy-Item -LiteralPath $AgentPath -Destination $probeExe -Force
    New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
    Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue

    $binaryPath = '"' + $probeExe + '"'
    New-Service -Name $serviceName -DisplayName "blacklist-inevitable WFP ACL probe" -BinaryPathName $binaryPath -StartupType Manual -ErrorAction Stop | Out-Null
    $serviceCreated = $true

    $serviceConfiguration = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $serviceConfiguration -or $serviceConfiguration.StartName -ne "LocalSystem") {
        throw "The temporary WFP probe service was not registered as LocalSystem."
    }

    $account = [System.Security.Principal.NTAccount]::new("NT SERVICE\$serviceName")
    $serviceSid = $account.Translate([System.Security.Principal.SecurityIdentifier])
    $sidText = $serviceSid.Value

    # Reproduce the installer's minimum executable read access and add only the
    # test service SID to this disposable runner's probe paths.
    $programFilesRoot = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
    Invoke-Icacls @($programFilesRoot, "/grant", ("*" + $sidText + ":(RX)"), "/C")
    Invoke-Icacls @($probeRoot, "/grant", ("*" + $sidText + ":(OI)(CI)(RX)"), "/T", "/C")
    Invoke-Icacls @($stateRoot, "/grant", ("*" + $sidText + ":(OI)(CI)(RX)"), "/T", "/C")
    Invoke-Icacls @($reportDirectory, "/grant", ("*" + $sidText + ":(OI)(CI)(M)"), "/T", "/C")

    $sidTypeOutput = & (Join-Path $env:WINDIR "System32\sc.exe") sidtype $serviceName restricted 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not configure SERVICE_SID_TYPE_RESTRICTED: $($sidTypeOutput -join ' ')"
    }
    $queryOutput = & (Join-Path $env:WINDIR "System32\sc.exe") qsidtype $serviceName 2>&1
    if ($LASTEXITCODE -ne 0 -or (($queryOutput -join [Environment]::NewLine) -notmatch "RESTRICTED")) {
        throw "SCM did not confirm SERVICE_SID_TYPE_RESTRICTED: $($queryOutput -join ' ')"
    }

    Start-Service -Name $serviceName -ErrorAction Stop
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $reportPath -PathType Leaf) { break }
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        $serviceQuery = & (Join-Path $env:WINDIR "System32\sc.exe") query $serviceName 2>&1
        throw "The restricted Agent service did not produce its WFP ACL report. Service state: $($serviceQuery -join ' ')"
    }

    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if ($report.schema_version -ne 1 -or
        $report.service_name -ne $serviceName -or
        $report.service_sid_type -ne "RESTRICTED" -or
        $report.traffic_filters_committed -ne $false -or
        $report.outcome -notin @("access_granted", "access_blocked")) {
        throw "The restricted Agent WFP ACL probe returned an invalid or unsafe report."
    }

    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $artifactPath -Encoding utf8
    Write-Host "Restricted service SID: $sidText"
    Write-Host "WFP access result: $($report.outcome)"
    Write-Host "WFP access detail: $($report.detail)"
    Write-Host "No traffic filter was committed."
}
finally {
    if ($serviceCreated) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & (Join-Path $env:WINDIR "System32\sc.exe") delete $serviceName 2>&1 | Out-Null
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while ([DateTime]::UtcNow -lt $deadline) {
            if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Milliseconds 250
        }
    }
}

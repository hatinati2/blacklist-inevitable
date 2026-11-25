$ErrorActionPreference = "Stop"

$installerDirectory = Join-Path $PSScriptRoot "..\src-tauri\target\release\bundle\nsis"
$installer = Get-ChildItem -Path $installerDirectory -Filter "*.exe" -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $installer) {
    throw "No NSIS installer was found in $installerDirectory"
}

function Wait-ForInstallerProcess {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [int]$TimeoutSeconds = 180
    )

    if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
        $processId = $Process.Id
        $taskkill = Join-Path $env:WINDIR "System32\taskkill.exe"
        & $taskkill /PID $processId /T /F | Out-Null
        throw "$Label did not exit within $TimeoutSeconds seconds. The process tree was terminated to prevent a hung CI job."
    }

    $Process.Refresh()
    return $Process.ExitCode
}

Write-Host "Installing $($installer.Name) silently..."
$install = Start-Process -FilePath $installer.FullName -ArgumentList @("/S") -PassThru
$installExitCode = Wait-ForInstallerProcess -Process $install -Label "The NSIS installer"
if ($installExitCode -ne 0) {
    throw "The NSIS installer exited with code $installExitCode."
}
$install.Dispose()

$uninstallRoot = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
$entry = Get-ChildItem -Path $uninstallRoot -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue } |
    Where-Object { $_.DisplayName -eq "blacklist-inevitable" } |
    Select-Object -First 1

if (-not $entry -or -not $entry.UninstallString) {
    throw "The per-machine installer did not register an HKLM uninstall entry for blacklist-inevitable."
}

if ($entry.UninstallString -match '^"([^"]+)"') {
    $uninstallerPath = $Matches[1]
} else {
    $uninstallerPath = ($entry.UninstallString -split '\s+', 2)[0]
}

if (-not (Test-Path -LiteralPath $uninstallerPath -PathType Leaf)) {
    throw "The registered uninstaller was not found: $uninstallerPath"
}

$installDirectory = Split-Path -Parent $uninstallerPath
$appPath = Join-Path $installDirectory "blacklist-inevitable.exe"

function Get-InstalledApplicationProcesses {
    param([Parameter(Mandatory = $true)][string]$ExecutablePath)

    return @(
        Get-CimInstance -ClassName Win32_Process -Filter "Name='blacklist-inevitable.exe'" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ExecutablePath -and
                [string]::Equals($_.ExecutablePath, $ExecutablePath, [System.StringComparison]::OrdinalIgnoreCase)
            }
    )
}

function Stop-InstalledApplicationProcesses {
    param(
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [int]$TimeoutSeconds = 20
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $taskkill = Join-Path $env:WINDIR "System32\taskkill.exe"
    do {
        $processes = @(Get-InstalledApplicationProcesses -ExecutablePath $ExecutablePath)
        if ($processes.Count -eq 0) {
            return
        }
        foreach ($process in $processes) {
            & $taskkill /PID $process.ProcessId /T /F 2>&1 | Out-Null
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)

    $remaining = @(Get-InstalledApplicationProcesses -ExecutablePath $ExecutablePath)
    if ($remaining.Count -gt 0) {
        $ids = ($remaining | ForEach-Object { $_.ProcessId }) -join ", "
        throw "The installed desktop application process could not be stopped before uninstall (PID(s): $ids)."
    }
}

$resourcesDirectory = Join-Path $installDirectory "resources"
$agentPath = Join-Path $resourcesDirectory "blacklist-inevitable-agent.exe"
$serviceHelper = Join-Path $resourcesDirectory "windows-agent-service.ps1"
$wfpAclHelper = Join-Path $resourcesDirectory "windows-agent-wfp-acl.ps1"
$publisherPinPath = Join-Path $resourcesDirectory "agent-publisher-thumbprint.txt"

foreach ($requiredFile in @($appPath, $agentPath, $serviceHelper, $wfpAclHelper, $publisherPinPath)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "A required installed application/Agent resource is missing: $requiredFile"
    }
}

foreach ($helperPath in @($serviceHelper, $wfpAclHelper)) {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($helperPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        throw "A bundled Windows Agent helper contains PowerShell syntax errors ($helperPath): $($parseErrors -join '; ')"
    }
}

$publisherThumbprint = (Get-Content -LiteralPath $publisherPinPath -Raw -Encoding ascii).Trim().ToUpperInvariant()
$service = Get-Service -Name "BlacklistInevitableAgent" -ErrorAction SilentlyContinue
if ($publisherThumbprint -eq "UNCONFIGURED") {
    if ($service) {
        throw "The unsigned CI package unexpectedly registered the privileged Agent service."
    }
    Write-Host "Unsigned CI build correctly leaves the LocalSystem Agent service unregistered."
} else {
    if ($publisherThumbprint -notmatch '^[A-F0-9]{40}$') {
        throw "The installed Agent publisher pin is malformed."
    }
    foreach ($signedFile in @($installer.FullName, $agentPath)) {
        $signature = Get-AuthenticodeSignature -FilePath $signedFile
        if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Thumbprint -ne $publisherThumbprint) {
            throw "A privileged Agent deployment binary is not validly signed by the pinned publisher: $signedFile"
        }
    }
    if (-not $service) {
        throw "The signed installer did not register the Windows Agent service."
    }
    $service.Refresh()
    if ($service.Status -ne "Running") {
        throw "The signed installer did not start the Windows Agent service."
    }
    $serviceDetails = Get-CimInstance -ClassName Win32_Service -Filter "Name='BlacklistInevitableAgent'"
    if (-not $serviceDetails -or $serviceDetails.StartName -ne "LocalSystem") {
        throw "The Agent service is not configured to run under the required LocalSystem identity."
    }
    if ($serviceDetails.PathName -notlike "*$agentPath*") {
        throw "The Agent service image path does not match the signed Agent executable in Program Files."
    }
    $sidOutput = (& (Join-Path $env:WINDIR "System32\sc.exe") qsidtype "BlacklistInevitableAgent" 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $sidOutput -notmatch "RESTRICTED") {
        throw "The Agent service did not retain the restricted service SID type."
    }
    $journalDirectory = Join-Path $env:ProgramData "blacklist-inevitable\Agent"
    if (-not (Test-Path -LiteralPath $journalDirectory -PathType Container)) {
        throw "The Agent did not provision its protected recovery-journal directory."
    }
}

Write-Host "Launching the installed desktop application..."
$appProcess = Start-Process -FilePath $appPath -WorkingDirectory $installDirectory -PassThru
try {
    Start-Sleep -Seconds 6
    $appProcess.Refresh()
    if ($appProcess.HasExited) {
        throw "The desktop application exited during its startup smoke test (code: $($appProcess.ExitCode))."
    }
}
finally {
    if (-not $appProcess.HasExited) {
        [void]$appProcess.CloseMainWindow()
        if (-not $appProcess.WaitForExit(5000)) {
            $taskkill = Join-Path $env:WINDIR "System32\taskkill.exe"
            & $taskkill /PID $appProcess.Id /T /F 2>&1 | Out-Null
            [void]$appProcess.WaitForExit(10000)
        }
    }
    Stop-InstalledApplicationProcesses -ExecutablePath $appPath
}

Write-Host "Uninstalling the application silently..."
$uninstall = Start-Process -FilePath $uninstallerPath -ArgumentList @("/S") -PassThru
$uninstallExitCode = Wait-ForInstallerProcess -Process $uninstall -Label "The NSIS uninstaller"
if ($uninstallExitCode -ne 0) {
    throw "The NSIS uninstaller exited with code $uninstallExitCode."
}
$uninstall.Dispose()

$removalDeadline = [DateTime]::UtcNow.AddSeconds(15)
while ((Test-Path -LiteralPath $appPath) -and [DateTime]::UtcNow -lt $removalDeadline) {
    Start-Sleep -Milliseconds 250
}
if (Test-Path -LiteralPath $appPath) {
    throw "The application executable remains after uninstallation: $appPath"
}

$remainingService = Get-Service -Name "BlacklistInevitableAgent" -ErrorAction SilentlyContinue
if ($remainingService) {
    throw "The Windows Agent service remains registered after application uninstallation."
}

if ($publisherThumbprint -ne "UNCONFIGURED") {
    $journalDirectory = Join-Path $env:ProgramData "blacklist-inevitable\Agent"
    if (-not (Test-Path -LiteralPath $journalDirectory -PathType Container)) {
        throw "Uninstallation unexpectedly removed the Agent recovery-journal directory."
    }
}

Write-Host "Windows installer smoke test passed: per-machine install, desktop launch, Agent trust gate, service removal, and uninstall."

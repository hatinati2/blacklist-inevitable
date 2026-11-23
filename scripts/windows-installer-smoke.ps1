$ErrorActionPreference = "Stop"

$installerDirectory = Join-Path $PSScriptRoot "..\src-tauri\target\release\bundle\nsis"
$installer = Get-ChildItem -Path $installerDirectory -Filter "*.exe" -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $installer) {
    throw "No NSIS installer was found in $installerDirectory"
}

Write-Host "Installing $($installer.Name) silently..."
$install = Start-Process -FilePath $installer.FullName -ArgumentList @("/S") -Wait -PassThru
if ($install.ExitCode -ne 0) {
    throw "The NSIS installer exited with code $($install.ExitCode)."
}

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
$resourcesDirectory = Join-Path $installDirectory "resources"
$agentPath = Join-Path $resourcesDirectory "blacklist-inevitable-agent.exe"
$serviceHelper = Join-Path $resourcesDirectory "windows-agent-service.ps1"
$publisherPinPath = Join-Path $resourcesDirectory "agent-publisher-thumbprint.txt"

foreach ($requiredFile in @($appPath, $agentPath, $serviceHelper, $publisherPinPath)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "A required installed application/Agent resource is missing: $requiredFile"
    }
}

$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($serviceHelper, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    throw "The bundled Windows Agent service helper contains PowerShell syntax errors: $($parseErrors -join '; ')"
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
        Stop-Process -Id $appProcess.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $appProcess.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
}

Write-Host "Uninstalling the application silently..."
$uninstall = Start-Process -FilePath $uninstallerPath -ArgumentList @("/S") -Wait -PassThru
if ($uninstall.ExitCode -ne 0) {
    throw "The NSIS uninstaller exited with code $($uninstall.ExitCode)."
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

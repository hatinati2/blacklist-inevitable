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

$uninstallRoot = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
$entry = Get-ChildItem -Path $uninstallRoot -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue } |
    Where-Object { $_.DisplayName -eq "blacklist-inevitable" } |
    Select-Object -First 1

if (-not $entry -or -not $entry.UninstallString) {
    throw "The installer did not register an uninstall entry for blacklist-inevitable."
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
if (-not (Test-Path -LiteralPath $appPath -PathType Leaf)) {
    throw "The installed application executable was not found: $appPath"
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

Write-Host "Windows installer smoke test passed: install, launch, and uninstall."
